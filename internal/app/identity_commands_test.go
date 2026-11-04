package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
)

const publicClerkWire = `{"mode":"provider-bound","provider":"clerk","algorithms":["RS256"],"issuer":"https://members.clerk.accounts.dev","subjectClaim":"sub","authorizedParties":["https://chat.example"],"allowMissingAuthorizedParty":false}`
const publicFirebaseWire = `{"mode":"provider-bound","provider":"firebase","algorithms":["RS256"],"issuer":"https://securetoken.google.com/my-project","audience":"my-project","subjectClaim":"sub"}`
const publicTargetWire = `{"kind":"subject","subject":"PRIVATE_TARGET_SENTINEL","profileSource":"installed"}`
const publicObservationWire = `{"operationId":"read_one","scope":` + scopeExecutionWire + `,"target":{"kind":"subject"},"observedVersion":0,"observedState":"active","currentHead":null,"application":{"kind":"unbound-subject"}}`

// publicIdentityOperation is one server-held identity operation. The body is
// the canonical mutation body that created it.
type publicIdentityOperation struct {
	action, body, result string
}

// This loopback fixture qualifies actual Go parsing and transport only.
// Actual Console actor and native Relay effects remain separate evidence.
// It holds each identity operation as the server does: a repeated operation
// ID with the same body replays the result, and a changed body conflicts.
type publicIdentityFixture struct {
	t            *testing.T
	server       *httptest.Server
	dependencies Dependencies
	path         string
	current      identity.CurrentContext
	project      control.Project
	capabilities identity.NativeCapabilities
	mu           sync.Mutex
	calls        []string
	denyCurrent  bool
	planChanges  []control.Change
	hook         func(string, *http.Request)
	operations   map[string]publicIdentityOperation
	// state is the selection or keys-only state of a new operation, and
	// status is the lifecycle status of a new apply.
	state, status string
	// lose stores the operation of the action and then loses its reply.
	lose map[string]bool
}

func publicIdentityTestFixture(t *testing.T, desired string) *publicIdentityFixture {
	t.Helper()
	f := &publicIdentityFixture{t: t, current: executionDecode[identity.CurrentContext](t, currentExecutionWire),
		capabilities: identity.NativeCapabilities{Clerk: "available", Firebase: "available"},
		operations:   map[string]publicIdentityOperation{}, state: "applied", status: "converged", lose: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.project = control.Project{Slug: "sample", Writer: "config", Sandbox: retention(day, day), Production: retention(day, day)}
	f.project.Production.State = control.ProductionActive
	f.project.Production.CardOnFile = true
	source := config.New("sample")
	if desired != "" {
		target := executionDecode[identity.SelectionTarget](t, desired)
		source.Environments.Sandbox.Identity = &target
		production, err := target.Clone()
		if err != nil {
			t.Fatal(err)
		}
		source.Environments.Production.Identity = &production
	}
	directory := t.TempDir()
	f.path = filepath.Join(directory, config.Filename)
	if err := config.Create(f.path, source); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	profile, err := credential.Profile(f.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(profile, credential.Credential{AccessToken: "owned_public_token", Source: "keychain"}); err != nil {
		t.Fatal(err)
	}
	actual, err := control.New(f.server.URL, f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	f.dependencies = Dependencies{API: actual, Identities: actual, HTTP: f.server.Client(), Store: store,
		WorkingDir: directory, Getenv: func(string) string { return "" }}
	return f
}

func (f *publicIdentityFixture) record(action string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, action)
}

func (f *publicIdentityFixture) count(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, value := range f.calls {
		if value == action {
			count++
		}
	}
	return count
}

func (f *publicIdentityFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer owned_public_token" {
		f.t.Error("fixture bearer address changed")
		w.WriteHeader(401)
		return
	}
	action := r.URL.Query().Get("action")
	if action == "" {
		action = r.URL.Path
	}
	f.record(action)
	if f.hook != nil {
		f.hook(action, r)
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/auth/session":
		session, err := acmeSession(r.Context(), control.CredentialRequest{})
		if err != nil {
			f.t.Error(err)
		}
		_ = json.NewEncoder(w).Encode(session)
	case "/v1/projects/sample":
		_ = json.NewEncoder(w).Encode(f.project)
	case "/v1/projects/sample/deploys/plan":
		var request control.PlanRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			f.t.Error("plan body invalid")
		}
		expected := "0"
		if environment := environmentOf(f.project, request.Environment); environment != nil && environment.Revision != "" {
			expected = environment.Revision
		}
		_ = json.NewEncoder(w).Encode(control.Plan{ID: "owned_plan", ProjectSlug: "sample", Environment: request.Environment, ExpectedRevision: expected, Changes: f.planChanges})
	case "/v1/deploys":
		var request control.DeployRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			f.t.Error("deploy body invalid")
		}
		if request.Environment == "production" {
			f.project.Production.State = control.ProductionActive
			f.project.Production.Revision = "5"
		}
		_ = json.NewEncoder(w).Encode(control.Deployment{ID: "owned_deploy", Revision: "5", Status: "applied", RelayURL: "https://relay.example/signal/v1/connection/pk_public"})
	case "/v1/projects/sample/identity":
		current, err := f.current.Clone()
		if err != nil {
			f.t.Error("invalid current fixture", err)
			w.WriteHeader(500)
			return
		}
		current.Precondition.Scope.EnvironmentKind = r.URL.Query().Get("environment")
		environment := r.URL.Query().Get("environment")
		var body map[string]json.RawMessage
		if r.Method == http.MethodPost && json.NewDecoder(r.Body).Decode(&body) != nil {
			f.t.Error("identity body invalid", action)
		}
		text := func(name string) string {
			var value string
			_ = json.Unmarshal(body[name], &value)
			return value
		}
		switch action {
		case "current", "keys-read":
			if action == "keys-read" && text("selectionOperationId") != "" {
				f.replay(w, "keys-replace", text("selectionOperationId"))
				return
			}
			if f.denyCurrent {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"code":"IDENTITY_CONTROL_DENIED"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		case "preview":
			delete(body, "action")
			data, err := json.Marshal(body)
			var request identity.PreviewRequest
			if err != nil || json.Unmarshal(data, &request) != nil {
				f.t.Error("preview input did not parse")
			}
			_ = json.NewEncoder(w).Encode(identity.PreviewResult{Kind: request.Kind, ExpectedConfigurationVersion: request.ExpectedConfigurationVersion,
				Target: request.Target, Keys: request.Keys, Current: current, NativeCapabilities: f.capabilities})
		case "target":
			value := executionDecode[identity.TargetObservation](f.t, publicObservationWire)
			value.Scope.EnvironmentKind = environment
			_ = json.NewEncoder(w).Encode(value)
		case "select", "keys-replace":
			canonical, err := json.Marshal(body)
			if err != nil {
				f.t.Error("mutation body invalid", action)
			}
			id := text("operationId")
			f.mu.Lock()
			operation, held := f.operations[id]
			if !held {
				operation = publicIdentityOperation{action: action, body: string(canonical), result: selectionExecutionResult(id, f.state, action == "keys-replace")}
				f.operations[id] = operation
			}
			f.mu.Unlock()
			if held && (operation.action != action || operation.body != string(canonical)) {
				f.fail(w, 409, "IDENTITY_CONFLICT")
				return
			}
			f.reply(w, action, operation.result)
		case "selection-operation":
			f.replay(w, "select", text("selectedOperationId"))
		case "selection-cancel", "keys-cancel":
			id := text("selectionOperationId")
			kind := map[string]string{"selection-cancel": "select", "keys-cancel": "keys-replace"}[action]
			f.mu.Lock()
			operation, held := f.operations[id]
			if held && operation.action == kind {
				operation.result = selectionExecutionResult(id, "aborted", kind == "keys-replace")
				f.operations[id] = operation
			}
			f.mu.Unlock()
			if !held || operation.action != kind {
				f.fail(w, 404, "IDENTITY_OPERATION_NOT_FOUND")
				return
			}
			f.reply(w, action, operation.result)
		case "prepare":
			var version int
			_ = json.Unmarshal(body["expectedLifecycleVersion"], &version)
			_, _ = io.WriteString(w, preparationExecutionWire(environment, text("state"), version))
		case "apply":
			id := text("operationId")
			f.mu.Lock()
			operation := publicIdentityOperation{action: action, result: lifecycleExecutionResult(environment, id, text("state"), f.status)}
			f.operations[id] = operation
			f.mu.Unlock()
			f.reply(w, action, operation.result)
		case "operation":
			f.replay(w, "apply", text("lifecycleOperationId"))
		case "resume":
			id := text("operationId")
			f.mu.Lock()
			operation, held := f.operations[id]
			if held && operation.action == "apply" {
				operation.result = strings.Replace(operation.result, `"status":"`+f.status+`"`, `"status":"converged"`, 1)
				f.operations[id] = operation
			}
			f.mu.Unlock()
			if !held || operation.action != "apply" {
				f.fail(w, 404, "IDENTITY_OPERATION_NOT_FOUND")
				return
			}
			f.reply(w, action, operation.result)
		default:
			f.t.Error("unexpected identity action", action)
			w.WriteHeader(500)
		}
	default:
		f.t.Error("unexpected fixture endpoint", r.URL.Path)
		w.WriteHeader(500)
	}
}

func (f *publicIdentityFixture) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"code":"`+code+`"}`)
}

// reply sends the result, or loses it after the server stored the operation.
func (f *publicIdentityFixture) reply(w http.ResponseWriter, action, result string) {
	f.mu.Lock()
	lost := f.lose[action]
	f.mu.Unlock()
	if lost {
		f.fail(w, 503, "IDENTITY_UNAVAILABLE")
		return
	}
	_, _ = io.WriteString(w, result)
}

// replay reads the operation that the creating action stored under the ID.
func (f *publicIdentityFixture) replay(w http.ResponseWriter, action, id string) {
	f.mu.Lock()
	operation, held := f.operations[id]
	f.mu.Unlock()
	if !held || operation.action != action {
		f.fail(w, 404, "IDENTITY_OPERATION_NOT_FOUND")
		return
	}
	_, _ = io.WriteString(w, operation.result)
}

// operationCount is the number of server operations that the action created.
func (f *publicIdentityFixture) operationCount(action string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, operation := range f.operations {
		if operation.action == action {
			count++
		}
	}
	return count
}

func (f *publicIdentityFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	command := append([]string{"--json", "--control-url", f.server.URL}, args...)
	return run(t, f.dependencies, command...)
}

func (f *publicIdentityFixture) requireNoMutation(t *testing.T) {
	t.Helper()
	for _, action := range identityMutationActions {
		if f.count(action) != 0 {
			t.Fatal("read caused mutation", action)
		}
	}
}

// identityMutationActions are the fixture calls that change server state.
var identityMutationActions = []string{"select", "keys-replace", "selection-cancel", "keys-cancel", "prepare", "apply", "resume", "/v1/deploys", "/v1/projects/bootstrap"}

func TestPublicIdentityCurrentUsesActualCompleteReaderAndSafeProjection(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	exit, out, stderr := f.run(t, "identity", "current")
	if exit != 0 || stderr != "" || f.count("current") != 1 || f.count("/v1/auth/session") != 1 {
		t.Fatal("actual current did not qualify", exit, out, stderr)
	}
	result := decodeEvent(t, []byte(out))
	if result.Data["evidence"] != "installed_configuration" || result.Data["encryptedExchange"] != "unverified" || result.Data["memberBinding"] != "unverified" {
		t.Fatal("read evidence was overstated")
	}
	for _, forbidden := range []string{"verificationPolicyFingerprint", "publishableKey", "recoveryGeneration", "precondition", "scope", "owned_public_token"} {
		if strings.Contains(out+stderr, forbidden) {
			t.Fatal("current exposed internal context", forbidden)
		}
	}
	f.requireNoMutation(t)
}

func TestPublicIdentitySelectDryRunQualifiesEverySupportedVariant(t *testing.T) {
	for _, variant := range []struct{ name, wire string }{
		{"device-owned", `{"mode":"device-owned"}`},
		{"custom-token", configuredExecutionWire},
		{"configured-provider-bound", strings.Replace(configuredExecutionWire, `"custom-token"`, `"provider-bound"`, 1)},
		{"clerk", publicClerkWire}, {"firebase", publicFirebaseWire},
	} {
		t.Run(variant.name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, variant.wire)
			exit, out, stderr := f.run(t, "identity", "select", "--dry-run")
			if exit != 0 || stderr != "" || f.count("current") != 1 || f.count("preview") != 1 || !strings.Contains(out, `"status":"planned"`) {
				t.Fatal("qualified dry-run failed", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicIdentityNativeClosureIsATypedDryRunBlocker(t *testing.T) {
	for _, variant := range []struct{ name, wire string }{{"clerk", publicClerkWire}, {"firebase", publicFirebaseWire}} {
		t.Run(variant.name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, variant.wire)
			f.capabilities = identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}
			exit, out, stderr := f.run(t, "identity", "select", "--dry-run")
			if exit != exitFailure || !strings.Contains(out, `"code":"IDENTITY_CAPABILITY_CLOSED"`) {
				t.Fatal("closed capability was not reported", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicIdentitySelectUsesTheResolvedEnvironment(t *testing.T) {
	for _, source := range []string{"default", "environment-variable", "literal-before", "literal-after"} {
		t.Run(source, func(t *testing.T) {
			f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
			args := []string{"identity", "select"}
			switch source {
			case "environment-variable":
				f.dependencies.Getenv = func(key string) string {
					if key == "OE_ENV" {
						return "sandbox"
					}
					return ""
				}
			case "literal-before":
				args = append([]string{"--env", "sandbox"}, args...)
			case "literal-after":
				args = append(args, "--env", "sandbox")
			}
			exit, out, stderr := f.run(t, args...)
			// The plan and the dispatch each read a fresh preview.
			if exit != 0 || f.count("preview") != 2 || f.count("select") != 1 || f.operationCount("select") != 1 {
				t.Fatal("the resolved environment did not reach one server operation", exit, out, stderr)
			}
		})
	}
}

func TestPublicIdentityRejectsPrivateArguments(t *testing.T) {
	for _, args := range [][]string{
		{"identity", "select", "--dry-run", "--operation-id", "PRIVATE_ARGUMENT_SENTINEL"},
		{"identity", "select", "PRIVATE_ARGUMENT_SENTINEL"},
		{"identity", "lifecycle", "suspend", "--target", "PRIVATE_ARGUMENT_SENTINEL"},
		{"identity", "operation", "resume", "--kind", "lifecycle"},
	} {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		exit, out, stderr := f.run(t, args...)
		if exit != exitUsage || strings.Contains(out+stderr, "PRIVATE_ARGUMENT_SENTINEL") {
			t.Fatal("invalid input accepted or echoed", exit, out, stderr)
		}
		f.requireNoMutation(t)
	}
}

func TestPublicIdentityKeysDryRunUsesSeparateActualRead(t *testing.T) {
	f := publicIdentityTestFixture(t, configuredExecutionWire)
	// A config-writer file with ES256 keys owns rotation; this read path is the
	// console-writer one.
	f.project.Writer = "console"
	path := filepath.Join(t.TempDir(), "public-keys.json")
	if err := os.WriteFile(path, []byte("["+keyExecutionWire+"]"), 0600); err != nil {
		t.Fatal(err)
	}
	exit, out, stderr := f.run(t, "identity", "keys", "rotate", "--keys", path, "--dry-run")
	if exit != 0 || f.count("keys-read") != 1 || f.count("current") != 0 || f.count("preview") != 1 {
		t.Fatal("keys dry-run did not qualify", exit, out, stderr)
	}
	f.requireNoMutation(t)
	for _, profile := range []string{publicClerkWire, publicFirebaseWire} {
		f.current.Configuration.IdentityProfile = executionDecode[identity.InstalledProfile](t, profile)
		before := f.count("preview")
		exit, out, stderr = f.run(t, "identity", "keys", "rotate", "--keys", path, "--dry-run")
		if exit != exitFailure || f.count("preview") != before {
			t.Fatal("native keys replacement was attempted", exit, out, stderr)
		}
	}
}

func TestPublicIdentityNewInputValidationPrecedesAuthority(t *testing.T) {
	for _, bad := range []string{`[{"d":"PRIVATE_KEY_SENTINEL"}]`, `null`, `[` + strings.Replace(keyExecutionWire, `"kid":"key-one"`, `"kid":null`, 1) + `]`} {
		f := publicIdentityTestFixture(t, configuredExecutionWire)
		path := filepath.Join(t.TempDir(), "public-keys.json")
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		exit, out, stderr := f.run(t, "identity", "keys", "rotate", "--keys", path, "--dry-run")
		if exit != exitUsage || f.count("/v1/auth/session") != 0 || strings.Contains(out+stderr, "PRIVATE_KEY_SENTINEL") {
			t.Fatal("invalid keys reached authority or output", exit, out, stderr)
		}
	}
}

func TestPublicIdentityReadMissingConfigurationNamesExistingLink(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	exit, out, stderr := f.run(t, "identity", "current")
	if exit != exitFailure || !strings.Contains(out, `"next":"oe link"`) || f.count("/v1/auth/session") != 0 {
		t.Fatal("missing config suggested project creation", exit, out, stderr)
	}
}

func TestPublicIdentityMissingNodeReportsRuntimePrerequisite(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{
		{"identity", "current"},
		{"identity", "select", "--dry-run"},
		{"identity", "operation", "status", "--kind", "selection"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			exit, out, stderr := f.run(t, args...)
			refusal := decodeEvent(t, []byte(out))
			if exit != exitPersonAction || refusal.Code != "NODE_REQUIRED" || refusal.Next != "oe doctor" ||
				refusal.Action.URL != "https://nodejs.org/en/download" ||
				!strings.Contains(refusal.Error, "Node.js 22.18 or later") || stderr != "" {
				t.Fatal("missing Node did not report its prerequisite", exit, out, stderr)
			}
		})
	}
	if f.count("/v1/auth/session") != 0 {
		t.Fatal("missing Node reached authority")
	}
	f.requireNoMutation(t)
}

func TestPublicIdentityInvalidConfigurationKeepsSafeFailure(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	if err := os.WriteFile(f.path, []byte(`throw new Error("PRIVATE_CONFIG_SENTINEL");`), 0o600); err != nil {
		t.Fatal(err)
	}
	exit, out, stderr := f.run(t, "identity", "current")
	refusal := decodeEvent(t, []byte(out))
	if exit != exitUsage || refusal.Code != "CONFIG_INVALID" || refusal.Next != "oe help config" ||
		strings.Contains(out+stderr, "PRIVATE_CONFIG_SENTINEL") || f.count("/v1/auth/session") != 0 {
		t.Fatal("invalid config lost its safe failure", exit, out, stderr)
	}
	f.requireNoMutation(t)
}

func TestPublicIdentityConfigClassificationUsesExactPolicy(t *testing.T) {
	base := executionDecode[identity.CurrentContext](t, currentExecutionWire)
	desired := executionDecode[identity.SelectionTarget](t, configuredExecutionWire)
	same, err := planIdentityConfig(base, desired)
	if err != nil || !same.unchanged {
		t.Fatal("equal policy changed", err)
	}
	changed, _ := desired.Clone()
	(*changed.Keys)[0].Kid = identity.TextFromUnits([]uint16{'n', 'e', 'w'})
	rotation, err := planIdentityConfig(base, changed)
	if err != nil || rotation.kind != identity.KeysOnly || rotation.keys == nil || rotation.target != nil {
		t.Fatal("keys drift did not use keys-only", err)
	}
	for _, field := range []string{"issuer", "audience", "subjectClaim", "mode"} {
		t.Run(field, func(t *testing.T) {
			target, _ := desired.Clone()
			switch field {
			case "issuer":
				text, _ := identity.Text("https://other.example")
				target.Issuer = &text
			case "audience":
				text, _ := identity.Text("other")
				target.Audience = &text
			case "subjectClaim":
				value := "member"
				target.SubjectClaim = &value
			case "mode":
				target.Mode = "provider-bound"
			}
			installed, _ := base.Clone()
			installed.Configuration.Inventory.EverAdmitted = true
			if _, err := planIdentityConfig(installed, target); err == nil {
				t.Fatal("used policy drift became a new selection")
			}
		})
	}
	if !reflect.DeepEqual(base, executionDecode[identity.CurrentContext](t, currentExecutionWire)) {
		t.Fatal("planning changed original context")
	}
}

func TestPublicIdentityProductionPromptPrecedesMutation(t *testing.T) {
	for _, answer := range []string{"n\n", "yes\n"} {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		f.dependencies.In = strings.NewReader(answer)
		f.dependencies.Interactive = func() bool { return true }
		exit, out, stderr := run(t, f.dependencies, "--agent", "no", "--control-url", f.server.URL,
			"identity", "select", "--env", "production")
		if answer == "n\n" {
			if exit != exitUsage || f.count("select") != 0 || !strings.Contains(stderr, "not approved") {
				t.Fatal("negative Production prompt caused a mutation", exit, out, stderr)
			}
		} else if exit != 0 || f.count("select") != 1 || f.operationCount("select") != 1 {
			t.Fatal("positive prompt did not reach one server operation", exit, out, stderr)
		}
	}
}

func TestPublicNativeDraftCheckRemainsExplicitlyUnsupported(t *testing.T) {
	for _, profile := range []string{publicClerkWire, publicFirebaseWire} {
		f := publicIdentityTestFixture(t, "")
		path := filepath.Join(t.TempDir(), "public-profile.json")
		if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
			t.Fatal(err)
		}
		f.dependencies.In = unreadable{t}
		exit, out, stderr := f.run(t, "identity", "check", "--profile", path, "--assertion-stdin")
		if exit != exitUsage || !strings.Contains(out, "IDENTITY_PROFILE_UNSUPPORTED") || f.count("/v1/auth/session") != 0 {
			t.Fatal("native check invented a verifier fallback", exit, out, stderr)
		}
		f.requireNoMutation(t)
	}
}

func TestPublicIdentityKeysRotateRefusedWhenConfigOwnsKeys(t *testing.T) {
	keys := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "public-keys.json")
		if err := os.WriteFile(path, []byte("["+keyExecutionWire+"]"), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, mode := range []string{"--dry-run", "--yes"} {
		t.Run(mode, func(t *testing.T) {
			f := publicIdentityTestFixture(t, configuredExecutionWire)
			exit, out, stderr := f.run(t, "identity", "keys", "rotate", "--keys", keys(t), "--env", "sandbox", mode)
			result := decodeEvent(t, []byte(out))
			if exit != exitFailure || result.Code != "IDENTITY_CONFIG_WRITER" || result.Next != "oe config push --dry-run --env sandbox" {
				t.Fatal("config-owned keys rotation was not refused", exit, out, stderr)
			}
			if f.count("keys-read") != 0 || f.count("preview") != 0 {
				t.Fatal("refusal reached the keys read or preview")
			}
			f.requireNoMutation(t)
		})
	}
	t.Run("console-writer", func(t *testing.T) {
		f := publicIdentityTestFixture(t, configuredExecutionWire)
		f.project.Writer = "console"
		exit, out, stderr := f.run(t, "identity", "keys", "rotate", "--keys", keys(t), "--env", "sandbox", "--dry-run")
		if exit != 0 || f.count("preview") != 1 {
			t.Fatal("console-writer keys dry-run changed", exit, out, stderr)
		}
		f.requireNoMutation(t)
	})
}

func TestPublicIdentityProductionPromptShowsChange(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.dependencies.In = strings.NewReader("n\n")
	f.dependencies.Interactive = func() bool { return true }
	exit, out, stderr := run(t, f.dependencies, "--agent", "no", "--control-url", f.server.URL,
		"identity", "select", "--env", "production")
	change := strings.Index(stderr, "environments.production.identity")
	prompt := strings.Index(stderr, "Apply this exact Production identity change?")
	if exit != exitUsage || change < 0 || prompt < change || f.count("select") != 0 {
		t.Fatal("the Production prompt did not show the identity change first", exit, out, stderr)
	}
	for _, forbidden := range []string{"verificationPolicyFingerprint", "publishableKey", "recoveryGeneration", "precondition", "scope"} {
		if strings.Contains(out+stderr, forbidden) {
			t.Fatal("the prompt exposed internal context", forbidden, stderr)
		}
	}
}
