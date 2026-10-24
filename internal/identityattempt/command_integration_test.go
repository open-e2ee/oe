package identityattempt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/open-e2ee/oe/internal/app"
	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const commandPrivateTarget = `{"kind":"subject","subject":"PRIVATE_COMMAND_SUBJECT","profileSource":"installed"}`
const commandObservation = `{"operationId":"read_one","scope":` + scopeWire + `,"target":{"kind":"subject"},"observedVersion":0,"observedState":"active","currentHead":null,"application":{"kind":"unbound-subject"}}`
const commandClerk = `{"mode":"provider-bound","provider":"clerk","algorithms":["RS256"],"issuer":"https://members.clerk.accounts.dev","subjectClaim":"sub","authorizedParties":["https://chat.example"]}`
const commandFirebase = `{"mode":"provider-bound","provider":"firebase","algorithms":["RS256"],"issuer":"https://securetoken.google.com/my-project","audience":"my-project","subjectClaim":"sub"}`

type commandStoreFactory struct {
	location          identityattempt.Location
	opens, bootstraps int
	failure           error
}

func (f *commandStoreFactory) Open() (*identityattempt.Store, error) {
	f.opens++
	if f.failure != nil {
		return nil, f.failure
	}
	return identityattempt.Open(f.location)
}

func (f *commandStoreFactory) BootstrapFirstUse(ctx context.Context, declaration identityattempt.FirstUse) (*identityattempt.Store, error) {
	f.bootstraps++
	if f.failure != nil {
		return nil, f.failure
	}
	return identityattempt.BootstrapFirstUse(ctx, f.location, declaration)
}

type commandPacket struct {
	action string
	body   []byte
}

// Real app.Run, the actual control client and real native Store compose here.
// The loopback server is synthetic. It grants no Console/native Relay credit.
type commandFixture struct {
	t                *testing.T
	server           *httptest.Server
	directory        string
	factory          *commandStoreFactory
	dependencies     app.Dependencies
	current          identity.CurrentContext
	mu               sync.Mutex
	packets          []commandPacket
	state            string
	lifeState        string
	lose             string
	override         string
	capabilities     identity.NativeCapabilities
	before           func(string)
	environment      map[string]string
	environmentKind  string
	targetReads      int
	targetChange     func(*identity.TargetObservation)
	retentionChanges []control.Change
	cancelDenied     bool
}

func newCommandFixture(t *testing.T, desired string) *commandFixture {
	t.Helper()
	f := &commandFixture{t: t, directory: t.TempDir(), state: "applied", lifeState: "converged",
		current: integrationDecode[identity.CurrentContext](t, currentWire), environment: map[string]string{}, environmentKind: "sandbox",
		capabilities: identity.NativeCapabilities{Clerk: "available", Firebase: "available"}}
	f.factory = &commandStoreFactory{location: identityattempt.FixtureLocation(t)}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	actual, err := control.New(f.server.URL, f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	credentials := credential.NewMemory()
	profile, err := credential.Profile(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Set(profile, credential.Credential{AccessToken: "owned_command_token", Source: "keychain"}); err != nil {
		t.Fatal(err)
	}
	f.dependencies = app.Dependencies{API: actual, Identities: actual, IdentityAttempts: f.factory, HTTP: f.server.Client(), Store: credentials,
		WorkingDir: f.directory, Getenv: func(name string) string { return f.environment[name] }}
	f.writeDesired(desired)
	return f
}

func (f *commandFixture) writeDesired(wire string) {
	f.t.Helper()
	configuration := config.New("sample")
	if wire != "" {
		target := integrationDecode[identity.SelectionTarget](f.t, wire)
		configuration.Environments.Sandbox.Identity = &target
		clone, err := target.Clone()
		if err != nil {
			f.t.Fatal(err)
		}
		configuration.Environments.Production.Identity = &clone
	}
	if err := config.Create(filepath.Join(f.directory, config.Filename), configuration); err != nil {
		f.t.Fatal(err)
	}
}

func (f *commandFixture) requests(action string) []commandPacket {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []commandPacket
	for _, packet := range f.packets {
		if packet.action == action {
			result = append(result, commandPacket{packet.action, bytes.Clone(packet.body)})
		}
	}
	return result
}

func (f *commandFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer owned_command_token" {
		f.t.Error("command bearer address changed")
		w.WriteHeader(401)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Error("packet read failed")
		w.WriteHeader(500)
		return
	}
	action := r.URL.Query().Get("action")
	if action == "" {
		action = r.URL.Path
	}
	f.mu.Lock()
	f.packets = append(f.packets, commandPacket{action, bytes.Clone(data)})
	f.mu.Unlock()
	if f.before != nil {
		f.before(action)
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/auth/session":
		_ = json.NewEncoder(w).Encode(control.Session{SchemaVersion: 1, User: control.SessionUser{ID: "owned_user", Email: "owned@example.com"}, Organization: control.SessionOrganization{ID: "org_fixture", Name: "Owned fixture"}})
		return
	case "/v1/projects/sample":
		receipts := true
		environment := &control.ProjectEnvironment{State: control.ProductionActive, Revision: "4", RelayReceipts: &receipts, DeliveryRetentionSeconds: 86400, AttachmentRetentionSeconds: 86400, RelayURL: "https://relay.example/signal/v1/connection/pk_public"}
		_ = json.NewEncoder(w).Encode(control.Project{Slug: "sample", Writer: "config", Sandbox: environment, Production: environment})
		return
	case "/v1/projects/sample/deploys/plan":
		var request control.PlanRequest
		if json.Unmarshal(data, &request) != nil {
			f.t.Error("plan input failed")
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(control.Plan{ID: "owned_plan", ProjectSlug: "sample", Environment: request.Environment, ExpectedRevision: "4", Changes: f.retentionChanges})
		return
	case "/v1/deploys":
		_ = json.NewEncoder(w).Encode(control.Deployment{ID: "owned_deploy", Revision: "5", Status: "applied", RelayURL: "https://relay.example/signal/v1/connection/pk_public"})
		return
	case "/v1/projects/sample/identity":
	default:
		f.t.Error("unexpected command endpoint", r.URL.Path)
		w.WriteHeader(500)
		return
	}
	var body map[string]json.RawMessage
	if len(data) > 0 && json.Unmarshal(data, &body) != nil {
		f.t.Error("invalid command body")
		w.WriteHeader(500)
		return
	}
	if action != "current" {
		var selector string
		if json.Unmarshal(body["action"], &selector) != nil || selector != action {
			f.t.Error("command selector mismatch")
		}
	}
	f.mu.Lock()
	current, err := f.current.Clone()
	f.mu.Unlock()
	if err != nil {
		f.t.Error("invalid current fixture", err)
		w.WriteHeader(500)
		return
	}
	current.Precondition.Scope.EnvironmentKind = r.URL.Query().Get("environment")
	if f.lose == action {
		f.lose = ""
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			f.t.Error("lost reply fixture cannot hijack")
			w.WriteHeader(500)
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			f.t.Error(err)
			return
		}
		_ = connection.Close()
		return
	}
	if f.cancelDenied && (action == "selection-cancel" || action == "keys-cancel") {
		w.WriteHeader(409)
		_, _ = io.WriteString(w, `{"code":"IDENTITY_CONFLICT"}`)
		return
	}
	if f.override != "" && (action == "select" || action == "keys-replace" || action == "apply" || action == "resume") {
		_, _ = io.WriteString(w, f.override)
		return
	}
	switch action {
	case "current":
		_ = json.NewEncoder(w).Encode(current)
	case "keys-read":
		if body["selectionOperationId"] == nil {
			_ = json.NewEncoder(w).Encode(current)
			return
		}
		f.writeSelectionResult(w, body, "keys-only")
	case "preview":
		delete(body, "action")
		encoded, err := json.Marshal(body)
		var request identity.PreviewRequest
		if err != nil || json.Unmarshal(encoded, &request) != nil {
			f.t.Error("actual preview request did not qualify")
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(identity.PreviewResult{Kind: request.Kind, ExpectedConfigurationVersion: request.ExpectedConfigurationVersion, Target: request.Target, Keys: request.Keys, Current: current, NativeCapabilities: f.capabilities})
	case "target":
		observation := integrationDecode[identity.TargetObservation](f.t, commandObservation)
		f.targetReads++
		if f.targetReads > 1 {
			observation.OperationID = identity.TextFromUnits([]uint16{'r', 'e', 'a', 'd', '_', 't', 'w', 'o'})
		}
		observation.Scope.EnvironmentKind = current.Precondition.Scope.EnvironmentKind
		if f.targetChange != nil {
			f.targetChange(&observation)
		}
		_ = json.NewEncoder(w).Encode(observation)
	case "prepare":
		var state string
		if json.Unmarshal(body["state"], &state) != nil {
			f.t.Error("prepare state missing")
		}
		f.writePrepared(w, current.Precondition.Scope, state)
	case "apply", "operation", "resume":
		f.writeLifecycleResult(w, body, current.Precondition.Scope)
	case "select", "selection-operation", "selection-cancel":
		f.writeSelectionResult(w, body, "")
	case "keys-replace", "keys-cancel":
		f.writeSelectionResult(w, body, "keys-only")
	default:
		f.t.Error("unexpected identity action", action)
		w.WriteHeader(500)
	}
}

func (f *commandFixture) writePrepared(w io.Writer, scope identity.Scope, state string) {
	id, err := identity.Text(preparedID)
	if err != nil {
		f.t.Error(err)
		return
	}
	_ = json.NewEncoder(w).Encode(identity.Preparation{OperationID: identity.TextFromUnits([]uint16{'p', 'r', 'e', 'p', 'a', 'r', 'e'}), PreparedOperationID: id, Scope: scope,
		ExpectedLifecycleVersion: 0, State: state, Target: identity.LifecyclePublicTarget{Kind: "subject"}})
}

func (f *commandFixture) writeSelectionResult(w io.Writer, body map[string]json.RawMessage, kind string) {
	var id string
	for _, field := range []string{"selectedOperationId", "selectionOperationId", "operationId"} {
		if body[field] != nil {
			if json.Unmarshal(body[field], &id) != nil {
				f.t.Error("selected ID invalid")
			}
			break
		}
	}
	result := map[string]any{"operationId": id, "state": f.state, "configurationVersion": 2, "admissionRevision": 1}
	if kind != "" {
		result["kind"] = kind
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (f *commandFixture) writeLifecycleResult(w io.Writer, body map[string]json.RawMessage, scope identity.Scope) {
	var id string
	for _, field := range []string{"lifecycleOperationId", "operationId"} {
		if body[field] != nil {
			if json.Unmarshal(body[field], &id) != nil {
				f.t.Error("lifecycle selected ID invalid")
			}
			break
		}
	}
	state := "suspended"
	if body["state"] != nil {
		if json.Unmarshal(body["state"], &state) != nil {
			f.t.Error("lifecycle state invalid")
		}
	}
	original, err := identity.Text(id)
	if err != nil {
		f.t.Error(err)
		return
	}
	version := identity.SafeInteger(1)
	result := identity.LifecycleStatus{Operation: identity.LifecycleOperation{Scope: scope, Target: identity.LifecyclePublicTarget{Kind: "subject"}, OperationID: original, ExpectedVersion: 0},
		Version: &version, State: state, EffectiveState: "active", Status: f.lifeState}
	_ = json.NewEncoder(w).Encode(result)
}

func (f *commandFixture) run(args ...string) (int, string, string) {
	f.t.Helper()
	var stdout, stderr bytes.Buffer
	dependencies := f.dependencies
	dependencies.Out, dependencies.Err = &stdout, &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := append([]string{"--json", "--control-url", f.server.URL, "--env", f.environmentKind}, args...)
	exit := app.Run(ctx, command, dependencies)
	if strings.Contains(stdout.String()+stderr.String(), "PRIVATE_COMMAND_SUBJECT") || strings.Contains(stdout.String()+stderr.String(), "owned_command_token") {
		f.t.Fatal("command leaked private target or credential")
	}
	return exit, stdout.String(), stderr.String()
}

func (f *commandFixture) slot(kind identityattempt.Kind) identityattempt.Slot {
	f.t.Helper()
	base, err := identity.ParseControlBaseURL(f.server.URL)
	if err != nil {
		f.t.Fatal(err)
	}
	slot, err := identityattempt.NewSlot(base, "org_fixture", "sample", f.environmentKind, kind)
	if err != nil {
		f.t.Fatal(err)
	}
	return slot
}

func (f *commandFixture) observation(kind identityattempt.Kind) identityattempt.Observation {
	f.t.Helper()
	store, err := identityattempt.Open(f.factory.location)
	if err != nil {
		f.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observed, err := store.Inspect(ctx, f.slot(kind))
	if err != nil {
		f.t.Fatal("actual store observation failed", err)
	}
	return observed
}

func (f *commandFixture) retained(kind identityattempt.Kind) *identityattempt.Attempt {
	f.t.Helper()
	observed := f.observation(kind)
	envelope, valid := observed.Envelope()
	if !valid {
		f.t.Fatal("actual ready envelope missing")
	}
	retained, err := envelope.RetainedAttempt()
	if err != nil {
		f.t.Fatal(err)
	}
	return retained
}

func (f *commandFixture) enrollLifecycle(original identity.LifecycleAttempt) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store, err := identityattempt.BootstrapFirstUse(ctx, f.factory.location, identityattempt.NamespaceNeverUsed)
	if err != nil {
		f.t.Fatal(err)
	}
	lease, err := store.EnrollFirstUse(ctx, f.slot(identityattempt.Lifecycle), identityattempt.SlotNeverUsed)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			f.t.Error(err)
		}
	}()
	envelope, err := lease.Read(ctx)
	if err != nil {
		f.t.Fatal(err)
	}
	attempt, err := identityattempt.NewLifecycleAttempt(original)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := lease.Retain(ctx, envelope, attempt); !errors.Is(err, identityattempt.ErrContinuationUnsupported) {
		f.t.Fatal("new retention did not refuse a synthetic historical ID", err)
	}
	identityattempt.FixtureRetainHistoricalLifecycle(f.t, ctx, lease, envelope, original)
}

func TestPublicCommandActualStoreSelectionSettlesAndReturnsOriginalID(t *testing.T) {
	for _, target := range []string{`{"mode":"device-owned"}`, commandClerk, commandFirebase} {
		f := newCommandFixture(t, target)
		exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
		if exit != 0 || len(f.requests("select")) != 1 || f.factory.bootstraps != 1 {
			t.Fatal("actual app/store selection did not qualify", exit, out, stderr)
		}
		if f.retained(identityattempt.Selection) != nil {
			t.Fatal("exact applied receipt did not settle actual retained state")
		}
		var body struct {
			OperationID string `json:"operationId"`
		}
		if json.Unmarshal(f.requests("select")[0].body, &body) != nil || body.OperationID == "" || !strings.Contains(out, body.OperationID) {
			t.Fatal("settled output lost actual original ID")
		}
		for _, field := range []string{"publishableKey", "precondition", "policyFingerprint", "PRIVATE_COMMAND_SUBJECT"} {
			if strings.Contains(out, field) {
				t.Fatal("safe result exposed retained authority", field)
			}
		}
	}
}

func TestPublicCommandActualStoreLostReplyReplaysExactOriginal(t *testing.T) {
	f := newCommandFixture(t, commandClerk)
	f.lose = "select"
	exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit == 0 || len(f.requests("select")) != 1 {
		t.Fatal("lost reply fixture did not qualify", exit, out, stderr)
	}
	if !strings.Contains(out, "oe identity operation status --kind selection --env sandbox") {
		t.Fatal("lost reply omitted the exact read-only retained next step")
	}
	original := f.retained(identityattempt.Selection)
	if original == nil {
		t.Fatal("lost reply erased retained command")
	}
	command, err := original.SelectionCommand()
	if err != nil {
		t.Fatal(err)
	}
	f.writeDesired(commandFirebase)
	f.environment["OE_OPERATION_ID"] = string(command.OperationID)
	exit, out, stderr = f.run("identity", "operation", "retry", "--kind", "selection")
	packets := f.requests("select")
	if exit != 0 || len(packets) != 2 || !bytes.Equal(packets[0].body, packets[1].body) {
		t.Fatal("retained retry used new config, ID or authority", exit, out, stderr)
	}
	if f.retained(identityattempt.Selection) != nil {
		t.Fatal("exact retry did not settle state")
	}
}

func TestPublicCommandActualStoreKeysUsesSeparateKind(t *testing.T) {
	f := newCommandFixture(t, configuredWire)
	path := filepath.Join(f.directory, "public-keys.json")
	if err := os.WriteFile(path, []byte("["+strings.Replace(keyWire, "key-one", "key-two", 1)+"]"), 0600); err != nil {
		t.Fatal(err)
	}
	exit, out, stderr := f.run("identity", "keys", "rotate", "--keys", path, "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 0 || len(f.requests("keys-replace")) != 1 || f.retained(identityattempt.KeysOnly) != nil {
		t.Fatal("actual keys command failed", exit, out, stderr)
	}
	if f.observation(identityattempt.Selection).State() != identityattempt.AbsentSlot {
		t.Fatal("keys command occupied selection kind")
	}
}

func TestPublicCommandActualStoreLifecycleUsesFreshCorrelationAndPreparedID(t *testing.T) {
	for _, action := range []string{"suspend", "activate"} {
		t.Run(action, func(t *testing.T) {
			f := newCommandFixture(t, "")
			f.dependencies.In = strings.NewReader(commandPrivateTarget)
			exit, out, stderr := f.run("identity", "lifecycle", action, "--target-stdin", "--confirm-state-never-used", "--confirm-slot-never-used")
			if exit != 0 || len(f.requests("target")) != 2 || len(f.requests("prepare")) != 1 || len(f.requests("apply")) != 1 {
				t.Fatal("actual prepared lifecycle flow failed", exit, out, stderr)
			}
			if !strings.Contains(out, preparedID) || f.retained(identityattempt.Lifecycle) != nil {
				t.Fatal("prepared operation identity was lost")
			}
			var body struct {
				OperationID string `json:"operationId"`
				State       string `json:"state"`
			}
			if json.Unmarshal(f.requests("apply")[0].body, &body) != nil || body.OperationID != preparedID {
				t.Fatal("read correlation became apply authority")
			}
			expected := "suspended"
			if action == "activate" {
				expected = "active"
			}
			if body.State != expected {
				t.Fatal("state activation was confused with retained resume")
			}
		})
	}
}

func TestPublicCommandActualStoreHistoricalStatusNeedsSameIDResume(t *testing.T) {
	f := newCommandFixture(t, "")
	original := integrationDecode[identity.LifecycleAttempt](t, `{"operationId":"historical_exact_001","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	f.enrollLifecycle(original)
	exit, out, stderr := f.run("identity", "operation", "status", "--kind", "lifecycle")
	if exit != 6 || !strings.Contains(out, "IDENTITY_CONTINUATION_REQUIRED") || f.retained(identityattempt.Lifecycle) == nil {
		t.Fatal("status convergence cleared actual occupied record", exit, out, stderr)
	}
	f.dependencies.In = strings.NewReader("")
	exit, out, stderr = f.run("identity", "operation", "resume", "--kind", "lifecycle")
	if exit != 0 || len(f.requests("resume")) != 1 || len(f.requests("prepare")) != 0 || f.retained(identityattempt.Lifecycle) != nil {
		t.Fatal("same-ID minimal continuation failed", exit, out, stderr)
	}
	if !strings.Contains(out, "historical_exact_001") || !strings.Contains(out, `"serviceReadiness":"unverified"`) {
		t.Fatal("exact receipt claimed current service authority")
	}
}

func TestPublicCommandActualStorePreparedCancellationKeepsOriginalForBothProviders(t *testing.T) {
	for _, target := range []string{commandClerk, commandFirebase} {
		f := newCommandFixture(t, target)
		f.state = "prepared"
		exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
		if exit != 6 {
			t.Fatal("prepared fixture did not retain", exit, out, stderr)
		}
		original := f.retained(identityattempt.Selection)
		if original == nil {
			t.Fatal("prepared original absent")
		}
		selected, err := original.SelectionCommand()
		if err != nil {
			t.Fatal(err)
		}
		f.capabilities = identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}
		f.state = "aborted"
		exit, out, stderr = f.run("identity", "operation", "cancel", "--kind", "selection")
		if exit != 0 || f.retained(identityattempt.Selection) != nil {
			t.Fatal("authorized cancellation failed under capability closure", exit, out, stderr)
		}
		packets := f.requests("selection-cancel")
		if len(packets) != 1 {
			t.Fatal("cancellation replayed unexpectedly")
		}
		var body struct {
			OperationID string `json:"operationId"`
			Selected    string `json:"selectionOperationId"`
		}
		if json.Unmarshal(packets[0].body, &body) != nil || body.Selected != string(selected.OperationID) || body.OperationID == body.Selected || body.OperationID == "" {
			t.Fatal("cancellation replaced original identity")
		}
	}
}

func TestPublicCommandActualStoreSettledRefusalDoesNotBecomeSuccess(t *testing.T) {
	for _, state := range []string{"refused", "deleted"} {
		f := newCommandFixture(t, commandFirebase)
		f.state = state
		exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
		if exit != 1 || !strings.Contains(out, `"status":"`+state+`"`) || f.retained(identityattempt.Selection) != nil {
			t.Fatal("settled refusal lost actual state", exit, out, stderr)
		}
	}
}

func TestPublicCommandActualStoreInvalidOrUnavailableReplyKeepsOriginal(t *testing.T) {
	for _, name := range []string{"malformed", "oversized", "wrong-kind", "wrong-selected-id"} {
		t.Run(name, func(t *testing.T) {
			f := newCommandFixture(t, commandClerk)
			switch name {
			case "malformed":
				f.override = `{"private":"PRIVATE_RESPONSE_SENTINEL"}`
			case "oversized":
				f.override = strings.Repeat(" ", 1048577)
			case "wrong-kind":
				f.override = `{"kind":"keys-only","operationId":"other_001","state":"applied","configurationVersion":2,"admissionRevision":1}`
			case "wrong-selected-id":
				f.override = `{"operationId":"other_001","state":"applied","configurationVersion":2,"admissionRevision":1}`
			}
			exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
			if exit == 0 || f.retained(identityattempt.Selection) == nil || len(f.requests("select")) != 1 {
				t.Fatal("bad reply erased retained original", exit, out, stderr)
			}
			if strings.Contains(out+stderr, "PRIVATE_RESPONSE_SENTINEL") {
				t.Fatal("raw unavailable response leaked")
			}
		})
	}
}

func TestPublicCommandActualStoreFactoryCannotFallBack(t *testing.T) {
	f := newCommandFixture(t, commandClerk)
	f.factory.failure = identityattempt.ErrUnsafe
	exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit == 0 || f.factory.opens != 1 || f.factory.bootstraps != 0 || len(f.requests("select")) != 0 {
		t.Fatal("explicit owned factory fell back", exit, out, stderr)
	}
	f.factory.failure = nil
	if f.observation(identityattempt.Selection).State() != identityattempt.AbsentNamespace {
		t.Fatal("failed factory created state")
	}
}

func TestPublicCommandActualStoreOperationIDNeverNormalizesOrCreatesContext(t *testing.T) {
	f := newCommandFixture(t, commandClerk)
	f.state = "prepared"
	exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 6 {
		t.Fatal("prepared qualifier failed", exit, out, stderr)
	}
	original := f.retained(identityattempt.Selection)
	selected, err := original.SelectionCommand()
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.requests("selection-operation"))
	for _, value := range []string{" " + string(selected.OperationID), string(selected.OperationID) + " ", "other_001"} {
		f.environment["OE_OPERATION_ID"] = value
		exit, out, stderr = f.run("identity", "operation", "status", "--kind", "selection")
		if exit == 0 || len(f.requests("selection-operation")) != before || !f.retained(identityattempt.Selection).Equal(*original) {
			t.Fatal("operation confirmation was normalized or rebased", exit, out, stderr)
		}
	}
	f.environment["OE_OPERATION_ID"] = string(selected.OperationID)
	exit, out, stderr = f.run("identity", "operation", "status", "--kind", "selection")
	if exit != 6 || len(f.requests("selection-operation")) != before+1 {
		t.Fatal("exact original confirmation refused", exit, out, stderr)
	}
}

func TestPublicCommandActualStorePreviewChangeRefusesBeforeRetain(t *testing.T) {
	for _, field := range []string{"publishable-key", "inventory", "profile", "source-generation", "native-capability"} {
		t.Run(field, func(t *testing.T) {
			f := newCommandFixture(t, commandClerk)
			f.before = func(action string) {
				if action != "preview" || len(f.requests("preview")) != 2 {
					return
				}
				switch field {
				case "publishable-key":
					f.current.Precondition.PublishableKey = "changed_public_key"
				case "inventory":
					f.current.Configuration.Inventory.HistoryCount = 1
				case "profile":
					f.current.Configuration.IdentityProfile = integrationDecode[identity.InstalledProfile](t, commandFirebase)
				case "source-generation":
					f.mu.Lock()
					epoch := identity.SafeInteger(1)
					f.current.Configuration.AdmissionReadiness.SourceGeneration.Kind = "cutover"
					f.current.Configuration.AdmissionReadiness.SourceGeneration.ReceiptEpoch = &epoch
					validationErr := f.current.Validate()
					f.mu.Unlock()
					if validationErr != nil {
						t.Error("invalid changed admission source fixture", validationErr)
					}
				case "native-capability":
					f.capabilities.Clerk = "closed"
				}
			}
			exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
			if exit == 0 || len(f.requests("preview")) != 2 || len(f.requests("select")) != 0 {
				t.Fatal("changed final preview reached dispatch", exit, out, stderr)
			}
			if f.retained(identityattempt.Selection) != nil {
				t.Fatal("changed preview retained an unapproved command")
			}
		})
	}
}

func TestPublicCommandActualStoreChangedLifecycleEvidenceRefusesBeforeEnrollment(t *testing.T) {
	for _, field := range []string{"scope", "target", "version", "state", "head", "application"} {
		t.Run(field, func(t *testing.T) {
			f := newCommandFixture(t, "")
			f.dependencies.In = strings.NewReader(commandPrivateTarget)
			f.targetChange = func(value *identity.TargetObservation) {
				if f.targetReads != 2 {
					return
				}
				switch field {
				case "scope":
					value.Scope.ProjectID = identity.TextFromUnits([]uint16{'o', 't', 'h', 'e', 'r'})
				case "target":
					value.Target.Kind = "account"
				case "version":
					value.ObservedVersion = 1
				case "state":
					value.ObservedState = "suspended"
				case "head":
					value.CurrentHead = &identity.LifecycleHead{Scope: value.Scope, Target: value.Target, OperationID: identity.TextFromUnits([]uint16{'o', 'l', 'd'}), Version: 1, State: "active"}
				case "application":
					value.Application, _ = identity.BoundLifecycleApplication("active", nil)
				}
			}
			exit, out, stderr := f.run("identity", "lifecycle", "suspend", "--target-stdin", "--confirm-state-never-used", "--confirm-slot-never-used")
			if exit == 0 || len(f.requests("target")) != 2 || len(f.requests("prepare")) != 0 || len(f.requests("apply")) != 0 {
				t.Fatal("changed target epoch reached preparation or dispatch", exit, out, stderr)
			}
			if f.factory.bootstraps != 0 || f.observation(identityattempt.Lifecycle).State() != identityattempt.AbsentNamespace {
				t.Fatal("changed target evidence caused first-use effects")
			}
		})
	}
}

func TestPublicCommandActualStoreIdentityOnlyConfigPushIsReachable(t *testing.T) {
	f := newCommandFixture(t, commandFirebase)
	exit, out, stderr := f.run("config", "push", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 0 || len(f.requests("select")) != 1 || len(f.requests("/v1/deploys")) != 0 {
		t.Fatal("identity-only config push did not reach actual executor", exit, out, stderr)
	}
	if f.retained(identityattempt.Selection) != nil || !strings.Contains(out, `"commandReceipt":"settled"`) {
		t.Fatal("config push lost exact receipt outcome")
	}
}

func TestPublicCommandActualStoreOccupiedSlotBlocksRetention(t *testing.T) {
	for _, kind := range []string{"selection", "keys-only"} {
		t.Run(kind, func(t *testing.T) {
			f := newCommandFixture(t, commandClerk)
			f.state = "prepared"
			if kind == "selection" {
				exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
				if exit != 6 {
					t.Fatal("occupied selection fixture failed", exit, out, stderr)
				}
			} else {
				path := filepath.Join(f.directory, "public-keys.json")
				if err := os.WriteFile(path, []byte("["+strings.Replace(keyWire, "key-one", "key-two", 1)+"]"), 0600); err != nil {
					t.Fatal(err)
				}
				exit, out, stderr := f.run("identity", "keys", "rotate", "--keys", path, "--confirm-state-never-used", "--confirm-slot-never-used")
				if exit != 6 {
					t.Fatal("occupied keys fixture failed", exit, out, stderr)
				}
			}
			f.retentionChanges = []control.Change{{Path: "relay.deliveryRetention", Before: "1d", After: "3d"}}
			before := len(f.requests("select")) + len(f.requests("keys-replace"))
			exit, out, stderr := f.run("config", "push")
			if exit == 0 || len(f.requests("/v1/deploys")) != 0 || len(f.requests("select"))+len(f.requests("keys-replace")) != before {
				t.Fatal("occupied identity allowed retention or replacement mutation", exit, out, stderr)
			}
		})
	}
}

func TestPublicCommandActualStoreAppliedCancellationRefusalRetainsBothIDs(t *testing.T) {
	for _, target := range []string{commandClerk, commandFirebase} {
		f := newCommandFixture(t, target)
		f.state = "prepared"
		exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
		if exit != 6 {
			t.Fatal("prepared qualifier failed", exit, out, stderr)
		}
		original := f.retained(identityattempt.Selection)
		command, err := original.SelectionCommand()
		if err != nil {
			t.Fatal(err)
		}
		f.state, f.cancelDenied = "applied", true
		exit, out, stderr = f.run("identity", "operation", "cancel", "--kind", "selection")
		retained := f.retained(identityattempt.Selection)
		if exit != 1 || retained == nil || !strings.Contains(out, "IDENTITY_CONFLICT") {
			t.Fatal("applied cancellation refusal erased original", exit, out, stderr)
		}
		selected, err := retained.SelectionCommand()
		cancellation, present := retained.CancellationID()
		if err != nil || !selected.Equal(command) || !present {
			t.Fatal("refused cancellation changed original or lost appended identity")
		}
		f.environment["OE_OPERATION_ID"] = string(cancellation)
		exit, out, stderr = f.run("identity", "operation", "cancel", "--kind", "selection")
		packets := f.requests("selection-cancel")
		if exit != 1 || len(packets) != 2 || !bytes.Equal(packets[0].body, packets[1].body) {
			t.Fatal("exact cancellation retry rekeyed or replaced command", exit, out, stderr)
		}
	}
}

func TestPublicCommandActualStoreAuthorityChangesAcrossPreDispatchAwaits(t *testing.T) {
	for _, stage := range []string{"session", "project", "current"} {
		t.Run(stage, func(t *testing.T) {
			f := newCommandFixture(t, commandClerk)
			f.before = func(action string) {
				match := stage == "session" && action == "/v1/auth/session" && len(f.requests(action)) == 2
				match = match || stage == "project" && action == "/v1/projects/sample" && len(f.requests(action)) == 2
				match = match || stage == "current" && action == "current" && len(f.requests(action)) == 2
				if match {
					f.current.Precondition.RecoveryGeneration = 2
				}
			}
			exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
			if exit == 0 || len(f.requests("select")) != 0 || f.factory.bootstraps != 0 {
				t.Fatal("changed approved authority was recaptured", exit, out, stderr)
			}
			if f.observation(identityattempt.Selection).State() != identityattempt.AbsentNamespace {
				t.Fatal("changed authority created retained state")
			}
		})
	}
}

func TestPublicCommandActualStorePostRetentionContextChangeBlocksIdentity(t *testing.T) {
	f := newCommandFixture(t, commandFirebase)
	f.retentionChanges = []control.Change{{Path: "relay.deliveryRetention", Before: "1d", After: "3d"}}
	f.before = func(action string) {
		if action == "/v1/deploys" {
			f.current.Precondition.PublishableKey = "changed_public_key"
		}
	}
	exit, out, stderr := f.run("config", "push", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit == 0 || len(f.requests("/v1/deploys")) != 1 || len(f.requests("select")) != 0 {
		t.Fatal("post-retention authority change reached identity dispatch", exit, out, stderr)
	}
	if !strings.Contains(out, `"retention":{"status":"applied"`) || !strings.Contains(out, "IDENTITY_CONTEXT_CHANGED") {
		t.Fatal("partial retention outcome was hidden", out)
	}
	if f.factory.bootstraps != 0 || f.observation(identityattempt.Selection).State() != identityattempt.AbsentNamespace {
		t.Fatal("stale approved context caused first-use effects")
	}
}

func TestPublicCommandActualStoreProductionRequiresSeparateConsent(t *testing.T) {
	f := newCommandFixture(t, commandFirebase)
	f.environmentKind = "production"
	exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 2 || !strings.Contains(out, "CONFIRMATION_REQUIRED") || f.factory.opens != 0 || f.factory.bootstraps != 0 || len(f.requests("select")) != 0 {
		t.Fatal("first-use declarations replaced Production consent", exit, out, stderr)
	}
	exit, out, stderr = f.run("identity", "select", "--yes", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 0 || len(f.requests("select")) != 1 || f.retained(identityattempt.Selection) != nil {
		t.Fatal("exact Production consent did not reach real owned store", exit, out, stderr)
	}
}

func TestPublicCommandActualStoreProductionIdentityAndRetentionConsent(t *testing.T) {
	for _, approveRetention := range []bool{false, true} {
		name := "decline-retention"
		if approveRetention {
			name = "approve-both"
		}
		t.Run(name, func(t *testing.T) {
			f := newCommandFixture(t, commandFirebase)
			f.environmentKind = "production"
			desired := config.New("sample")
			target := integrationDecode[identity.SelectionTarget](t, commandFirebase)
			desired.Environments.Production.Identity = &target
			desired.Environments.Production.Relay = &config.RelayOverride{DeliveryRetention: "3d", AttachmentRetention: "1d"}
			if err := config.Create(filepath.Join(f.directory, config.Filename), desired); err != nil {
				t.Fatal(err)
			}
			f.retentionChanges = []control.Change{{Path: "relay.deliveryRetention", Before: "1d", After: "3d"}}
			answers := "yes\nno\n"
			if approveRetention {
				answers = "yes\nyes\n"
			}
			var stdout, stderr bytes.Buffer
			dependencies := f.dependencies
			dependencies.In = iotest.OneByteReader(strings.NewReader(answers))
			dependencies.Interactive = func() bool { return true }
			dependencies.Out, dependencies.Err = &stdout, &stderr
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{"--agent", "no", "--control-url", f.server.URL, "--env", "production", "config", "push",
				"--confirm-state-never-used", "--confirm-slot-never-used"}
			exit := app.Run(ctx, args, dependencies)
			if strings.Count(stderr.String(), "Apply this exact Production identity change?") != 1 ||
				strings.Count(stderr.String(), "Apply 1 policy change(s) to Production?") != 1 {
				t.Fatal("identity approval bypassed the separate Production retention prompt", exit, stdout.String(), stderr.String())
			}
			if !approveRetention {
				if exit != 1 || !strings.Contains(stderr.String(), "error: the Production push was cancelled\n") ||
					len(f.requests("/v1/deploys")) != 0 || len(f.requests("select")) != 0 || len(f.requests("prepare")) != 0 || f.factory.bootstraps != 0 {
					t.Fatal("declined retention allowed a deploy, identity dispatch or first use", exit, stdout.String(), stderr.String())
				}
				if f.observation(identityattempt.Selection).State() != identityattempt.AbsentNamespace {
					t.Fatal("declined retention wrote identity state")
				}
				return
			}
			if exit != 0 || len(f.requests("/v1/deploys")) != 1 || len(f.requests("select")) != 1 || f.factory.bootstraps != 1 {
				t.Fatal("two explicit approvals did not complete the actual retention and identity paths", exit, stdout.String(), stderr.String())
			}
			deployAt, selectAt, postRetentionCurrent, postRetentionPreview := -1, -1, 0, 0
			f.mu.Lock()
			for index, packet := range f.packets {
				if packet.action == "/v1/deploys" {
					deployAt = index
				}
				if packet.action == "select" {
					selectAt = index
				}
				if deployAt >= 0 && selectAt < 0 && packet.action == "current" {
					postRetentionCurrent++
				}
				if deployAt >= 0 && selectAt < 0 && packet.action == "preview" {
					postRetentionPreview++
				}
			}
			f.mu.Unlock()
			if deployAt < 0 || selectAt <= deployAt || postRetentionCurrent < 2 || postRetentionPreview < 2 {
				t.Fatal("identity skipped the retention-first current and preview checks", deployAt, selectAt, postRetentionCurrent, postRetentionPreview)
			}
			if f.retained(identityattempt.Selection) != nil {
				t.Fatal("approved actual receipt did not settle the retained command")
			}
		})
	}
}

func TestPublicCommandActualStoreRefreshedAdmissionCheckTime(t *testing.T) {
	f := newCommandFixture(t, commandFirebase)
	f.before = func(action string) {
		if action == "current" || action == "preview" {
			f.mu.Lock()
			f.current.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds++
			f.mu.Unlock()
		}
	}
	exit, out, stderr := f.run("identity", "select", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != 0 || len(f.requests("select")) != 1 || f.factory.bootstraps != 1 {
		t.Fatal("independent current and preview check times blocked unchanged authority", exit, out, stderr)
	}
	f.mu.Lock()
	checkedAt := f.current.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds
	f.mu.Unlock()
	if checkedAt < 3 || f.retained(identityattempt.Selection) != nil {
		t.Fatal("timestamp fixture did not cross independent reads or settle the original command")
	}
}
