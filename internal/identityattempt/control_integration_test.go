package identityattempt_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const keyWire = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one"}`
const configuredWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + keyWire + `]}`
const fingerprintWire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const scopeWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"relay_scope"}`
const preconditionWire = `{"publishableKey":"pk_public","recoveryGeneration":1,"scope":` + scopeWire + `}`
const completeWire = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + fingerprintWire + `","identityProfile":` + configuredWire + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + fingerprintWire + `"},"reason":null},"selectionOperation":null}`
const currentWire = `{"configuration":` + completeWire + `,"precondition":` + preconditionWire + `}`
const preparedID = "lc1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func integrationDecode[T any](t *testing.T, wire string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(wire), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

type integrationRequest struct {
	method, action string
	body           map[string]json.RawMessage
}
type integrationTransport func(*http.Request) (*http.Response, error)

func (f integrationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type controlFixtureTiming struct {
	Boundary     string
	Elapsed      time.Duration
	Deadline     time.Time
	Remaining    time.Duration
	HasDeadline  bool
	Expired      bool
	ContextState string
}

type integrationFixture struct {
	started    time.Time
	timings    [64]controlFixtureTiming
	timingLen  int
	timingLost bool
	ctx        context.Context
	store      *identityattempt.Store
	lease      *identityattempt.Lease
	slot       identityattempt.Slot
	envelope   identityattempt.Envelope
	transport  control.IdentityTransport
	current    control.AddressedCurrent
	credential control.CredentialRequest
	mu         sync.Mutex
	requests   []integrationRequest
}

func (f *integrationFixture) recordTiming(boundary string) {
	// Reserve the last row for the terminal snapshot before cancellation.
	if f.timingLen >= len(f.timings)-1 && boundary != "cleanup-before-cancel" {
		f.timingLost = true
		return
	}
	now := time.Now()
	deadline, present := f.ctx.Deadline()
	state := "unknown"
	switch f.ctx.Err() {
	case nil:
		state = "none"
	case context.DeadlineExceeded:
		state = "deadline-exceeded"
	case context.Canceled:
		state = "canceled"
	}
	f.timings[f.timingLen] = controlFixtureTiming{
		Boundary:     boundary,
		Elapsed:      now.Sub(f.started),
		Deadline:     deadline.UTC(),
		Remaining:    deadline.Sub(now),
		HasDeadline:  present,
		Expired:      present && !now.Before(deadline),
		ContextState: state,
	}
	f.timingLen++
}

func (f *integrationFixture) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}
func (f *integrationFixture) last() integrationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func realIdentityFixture(t *testing.T, kind identityattempt.Kind, wrap func(http.RoundTripper) http.RoundTripper) *integrationFixture {
	t.Helper()
	f := &integrationFixture{credential: control.CredentialRequest{AccessToken: "owned_fixture_token"}}
	f.started = time.Now()
	// One complete fixture lifetime uses the existing public invocation and
	// lease limit. Setup and every later phase share this deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	f.ctx = ctx
	f.recordTiming("created")
	t.Cleanup(func() {
		// Capture terminal context state before the original cancellation.
		f.recordTiming("cleanup-before-cancel")
		cancel()
		payload := map[string]any{
			"start":    f.started.UTC(),
			"rows":     f.timings[:f.timingLen],
			"overflow": f.timingLost,
		}
		if wire, err := json.Marshal(payload); err == nil && len(wire) <= 32768 {
			t.Logf("CA8_CONTROL_FIXTURE_TIMING_V1 %s", wire)
		} else {
			t.Log("CA8_CONTROL_FIXTURE_TIMING_V1 encoding-unavailable")
		}
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error("request read failed")
			w.WriteHeader(500)
			return
		}
		body := map[string]json.RawMessage{}
		if len(data) != 0 && json.Unmarshal(data, &body) != nil {
			t.Error("request JSON failed")
			w.WriteHeader(500)
			return
		}
		action := r.URL.Query().Get("action")
		if r.URL.Path != "/api/cli/v1/projects/sample/identity" || r.URL.Query().Get("environment") != "sandbox" || r.Header.Get("Authorization") != "Bearer owned_fixture_token" || r.Header.Get("Idempotency-Key") != "" {
			t.Error("actual addressed request changed")
		}
		if action != "current" {
			var selector string
			if json.Unmarshal(body["action"], &selector) != nil || selector != action || r.Method != "POST" {
				t.Error("literal selector changed")
			}
		} else if r.Method != "GET" || len(body) != 0 {
			t.Error("current request changed")
		}
		f.mu.Lock()
		f.requests = append(f.requests, integrationRequest{r.Method, action, body})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var wire string
		switch action {
		case "current":
			wire = currentWire
		case "prepare":
			wire = `{"operationId":"read_prepare","preparedOperationId":"` + preparedID + `","scope":` + scopeWire + `,"expectedLifecycleVersion":0,"state":"suspended","target":{"kind":"subject"}}`
		case "operation", "apply", "resume":
			wire = `{"operation":{"scope":` + scopeWire + `,"target":{"kind":"subject"},"operationId":"` + preparedID + `","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"converged","supersededBy":null,"requiredMailboxes":0,"preparedMailboxes":0,"activatedMailboxes":0}`
		default:
			wire = `{"operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`
			if kind == identityattempt.KeysOnly {
				wire = strings.Replace(wire, `{"operationId"`, `{"kind":"keys-only","operationId"`, 1)
			}
		}
		if _, err := io.WriteString(w, wire); err != nil {
			t.Error("owned response write failed")
		}
	}))
	t.Cleanup(server.Close)
	base, err := identity.ParseControlBaseURL(server.URL + "/api/cli")
	if err != nil {
		t.Fatal(err)
	}
	f.slot, err = identityattempt.NewSlot(base, "org_fixture", "sample", "sandbox", kind)
	if err != nil {
		t.Fatal(err)
	}
	// The test-only export enforces the existing real native fixture policy.
	location := identityattempt.FixtureLocation(t)
	f.recordTiming("setup-bootstrap-before")
	f.store, err = identityattempt.BootstrapFirstUse(ctx, location, identityattempt.NamespaceNeverUsed)
	f.recordTiming("setup-bootstrap-after")
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("setup-enroll-before")
	f.lease, err = f.store.EnrollFirstUse(ctx, f.slot, identityattempt.SlotNeverUsed)
	f.recordTiming("setup-enroll-after")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.lease.Close(); err != nil {
			t.Error(err)
		}
	})
	f.recordTiming("setup-read-before")
	f.envelope, err = f.lease.Read(ctx)
	f.recordTiming("setup-read-after")
	if err != nil {
		t.Fatal(err)
	}
	httpClient := server.Client()
	if wrap != nil {
		httpClient.Transport = wrap(httpClient.Transport)
	}
	client, err := control.New(base.String(), httpClient)
	if err != nil {
		t.Fatal(err)
	}
	f.transport, err = client.Identity(f.slot)
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("setup-current-before")
	f.current, err = f.transport.Current(ctx, f.credential)
	f.recordTiming("setup-current-after")
	if err != nil {
		t.Fatal("actual complete-current qualifier failed", err)
	}
	return f
}

func (f *integrationFixture) retain(t *testing.T) {
	t.Helper()
	var attempt identityattempt.Attempt
	var err error
	switch f.slot.Kind() {
	case identityattempt.Selection:
		command := integrationDecode[identity.SelectionCommand](t, `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":`+preconditionWire+`}`)
		attempt, err = identityattempt.NewSelectionAttempt(command)
	case identityattempt.KeysOnly:
		command := integrationDecode[identity.KeysCommand](t, `{"operationId":"original_001","expectedConfigurationVersion":1,"keys":[`+keyWire+`],"precondition":`+preconditionWire+`}`)
		attempt, err = identityattempt.NewKeysAttempt(command)
	case identityattempt.Lifecycle:
		f.recordTiming("retain-confirm-preparation-before")
		permit, confirmErr := f.lease.ConfirmPreparation(f.ctx, f.envelope)
		f.recordTiming("retain-confirm-preparation-after")
		if confirmErr != nil {
			t.Fatal(confirmErr)
		}
		subject, _ := identity.Text("private_fixture_subject")
		profile := "installed"
		f.recordTiming("retain-http-prepare-before")
		prepared, prepareErr := f.transport.LifecyclePrepare(f.ctx, f.credential, f.current, permit, control.LifecyclePreparationInput{
			Target: identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile}, State: "suspended", Nonce: "AAAAAAAAAAAAAAAAAAAAAA"})
		f.recordTiming("retain-http-prepare-after")
		if prepareErr != nil {
			t.Fatal("actual prepare qualifier failed", prepareErr)
		}
		request := f.last()
		expected, marshalErr := json.Marshal(map[string]any{"action": "prepare", "target": identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile},
			"state": "suspended", "expectedLifecycleVersion": 0, "nonce": "AAAAAAAAAAAAAAAAAAAAAA"})
		var fields map[string]json.RawMessage
		if marshalErr != nil || json.Unmarshal(expected, &fields) != nil || !reflect.DeepEqual(fields, request.body) {
			t.Fatal("prepare changed its exact closed transient input")
		}
		command, attemptErr := prepared.Attempt()
		if attemptErr != nil {
			t.Fatal(attemptErr)
		}
		attempt, err = identityattempt.NewLifecycleAttempt(command)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("retain-store-before")
	f.envelope, err = f.lease.Retain(f.ctx, f.envelope, attempt)
	f.recordTiming("retain-store-after")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRealControlAllNineOccupiedActionsAndPreparation(t *testing.T) {
	for _, action := range []identityattempt.Action{identityattempt.SelectionApplyAction, identityattempt.SelectionStatusAction, identityattempt.SelectionCancelAction,
		identityattempt.KeysReplaceAction, identityattempt.KeysStatusAction, identityattempt.KeysCancelAction,
		identityattempt.LifecycleApplyAction, identityattempt.LifecycleStatusAction, identityattempt.LifecycleResumeAction} {
		t.Run(string(action), func(t *testing.T) {
			kind := identityattempt.Selection
			if strings.HasPrefix(string(action), "keys-") {
				kind = identityattempt.KeysOnly
			}
			if strings.HasPrefix(string(action), "lifecycle-") {
				kind = identityattempt.Lifecycle
			}
			f := realIdentityFixture(t, kind, nil)
			f.retain(t)
			var err error
			if action == identityattempt.SelectionCancelAction || action == identityattempt.KeysCancelAction {
				f.envelope, err = f.lease.AppendCancellation(f.ctx, f.envelope, "cancel_winner")
				if err != nil {
					t.Fatal(err)
				}
			}
			before := f.count()
			permit, err := f.lease.Confirm(f.ctx, f.envelope, action)
			if err != nil {
				t.Fatal(err)
			}
			var resolution identityattempt.Resolution
			switch action {
			case identityattempt.SelectionApplyAction, identityattempt.SelectionStatusAction, identityattempt.SelectionCancelAction:
				var receipt identity.SelectionReceipt
				switch action {
				case identityattempt.SelectionApplyAction:
					receipt, err = f.transport.SelectionApply(f.ctx, f.credential, permit)
				case identityattempt.SelectionStatusAction:
					receipt, err = f.transport.SelectionStatus(f.ctx, f.credential, permit)
				case identityattempt.SelectionCancelAction:
					receipt, err = f.transport.SelectionCancel(f.ctx, f.credential, permit)
				}
				if err == nil {
					resolution, err = f.lease.ResolveSelection(f.ctx, f.envelope, receipt)
				}
			case identityattempt.KeysReplaceAction, identityattempt.KeysStatusAction, identityattempt.KeysCancelAction:
				var receipt identity.KeysReceipt
				switch action {
				case identityattempt.KeysReplaceAction:
					receipt, err = f.transport.KeysReplace(f.ctx, f.credential, permit)
				case identityattempt.KeysStatusAction:
					receipt, err = f.transport.KeysStatus(f.ctx, f.credential, permit)
				case identityattempt.KeysCancelAction:
					receipt, err = f.transport.KeysCancel(f.ctx, f.credential, permit)
				}
				if err == nil {
					resolution, err = f.lease.ResolveKeys(f.ctx, f.envelope, receipt)
				}
			default:
				var reply control.LifecycleReply
				switch action {
				case identityattempt.LifecycleApplyAction:
					subject, _ := identity.Text("private_fixture_subject")
					profile := "installed"
					reply, err = f.transport.LifecycleApply(f.ctx, f.credential, f.current, permit, identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile})
				case identityattempt.LifecycleStatusAction:
					reply, err = f.transport.LifecycleOperation(f.ctx, f.credential, f.current, permit)
				case identityattempt.LifecycleResumeAction:
					reply, err = f.transport.LifecycleResume(f.ctx, f.credential, f.current, permit)
				}
				if err == nil {
					receipt, receiptErr := reply.Receipt()
					scope, scopeErr := reply.Scope()
					if receiptErr != nil || scopeErr != nil {
						t.Fatal("actual receipt provenance missing")
					}
					resolution, err = f.lease.ResolveLifecycle(f.ctx, f.envelope, scope, receipt)
				}
			}
			if err != nil || f.count() != before+1 {
				t.Fatal("one actual occupied call failed", err)
			}
			request := f.last()
			assertOccupiedBody(t, action, request)
			assertRetainedProjection(t, f.envelope, request)
			expected := identity.ReceiptSettled
			if action == identityattempt.LifecycleStatusAction {
				expected = identity.ReceiptContinuationRequired
			}
			if resolution.Disposition() != expected {
				t.Fatal("receipt settlement changed")
			}
			result, err := resolution.Envelope()
			if err != nil {
				t.Fatal(err)
			}
			retained, err := result.RetainedAttempt()
			if err != nil || (retained != nil) != (expected == identity.ReceiptContinuationRequired) {
				t.Fatal("convergence cleared the wrong local state")
			}
			if expected == identity.ReceiptContinuationRequired && !result.Equal(f.envelope) {
				t.Fatal("status changed retained identity")
			}
			if _, err := f.transport.SelectionStatus(f.ctx, f.credential, permit); err == nil || f.count() != before+1 {
				t.Fatal("used permit admitted another call")
			}
		})
	}
}

func assertOccupiedBody(t *testing.T, action identityattempt.Action, request integrationRequest) {
	t.Helper()
	expected := map[identityattempt.Action]struct {
		selector string
		fields   []string
	}{
		identityattempt.SelectionApplyAction:  {"select", []string{"action", "operationId", "expectedConfigurationVersion", "target", "precondition"}},
		identityattempt.SelectionStatusAction: {"selection-operation", []string{"action", "selectedOperationId", "precondition"}},
		identityattempt.SelectionCancelAction: {"selection-cancel", []string{"action", "operationId", "selectionOperationId", "precondition"}},
		identityattempt.KeysReplaceAction:     {"keys-replace", []string{"action", "operationId", "expectedConfigurationVersion", "keys", "precondition"}},
		identityattempt.KeysStatusAction:      {"keys-read", []string{"action", "selectionOperationId", "precondition"}},
		identityattempt.KeysCancelAction:      {"keys-cancel", []string{"action", "operationId", "selectionOperationId", "precondition"}},
		identityattempt.LifecycleApplyAction:  {"apply", []string{"action", "operationId", "target", "state", "expectedLifecycleVersion"}},
		identityattempt.LifecycleStatusAction: {"operation", []string{"action", "lifecycleOperationId"}},
		identityattempt.LifecycleResumeAction: {"resume", []string{"action", "operationId"}},
	}[action]
	if request.action != expected.selector || len(request.body) != len(expected.fields) {
		t.Fatal("occupied body was broadened")
	}
	for _, field := range expected.fields {
		if request.body[field] == nil {
			t.Fatal("occupied field missing", field)
		}
	}
	if action == identityattempt.SelectionCancelAction || action == identityattempt.KeysCancelAction {
		var cancel, original string
		if json.Unmarshal(request.body["operationId"], &cancel) != nil || json.Unmarshal(request.body["selectionOperationId"], &original) != nil || cancel != "cancel_winner" || original != "original_001" {
			t.Fatal("cancellation identity changed")
		}
	}
}

func TestRealControlCopiedPermitCannotDispatchTwice(t *testing.T) {
	f := realIdentityFixture(t, identityattempt.Selection, nil)
	f.retain(t)
	permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	copied := *permit
	before := f.count()
	if _, err := f.transport.SelectionApply(f.ctx, f.credential, permit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.transport.SelectionApply(f.ctx, f.credential, &copied); err == nil || f.count() != before+1 {
		t.Fatal("copied permit repeated dispatch")
	}
}

type integrationLossBody struct {
	io.ReadCloser
}

type integrationCloseBody struct{ io.ReadCloser }

func (b integrationCloseBody) Close() error {
	if err := b.ReadCloser.Close(); err != nil {
		return err
	}
	return errors.New("owned close failure")
}
func (b integrationLossBody) Read([]byte) (int, error) {
	return 0, errors.New("owned reply loss")
}

func TestRealControlAmbiguousRepliesKeepWholeEnrichedOriginal(t *testing.T) {
	for _, mode := range []string{"loss", "oversize", "wrong-id", "wrong-kind", "trailing", "not-found", "unknown-state", "close"} {
		t.Run(mode, func(t *testing.T) {
			f := realIdentityFixture(t, identityattempt.KeysOnly, func(actual http.RoundTripper) http.RoundTripper {
				return integrationTransport(func(r *http.Request) (*http.Response, error) {
					response, err := actual.RoundTrip(r)
					if err != nil || r.URL.Query().Get("action") == "current" {
						return response, err
					}
					if mode == "close" {
						response.Body = integrationCloseBody{response.Body}
						return response, nil
					}
					if mode == "loss" {
						response.Body = integrationLossBody{response.Body}
						return response, nil
					}
					data, readErr := io.ReadAll(response.Body)
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil {
						return nil, errors.New("owned fixture response failed")
					}
					switch mode {
					case "oversize":
						data = append(data, []byte(strings.Repeat(" ", 1_048_577))...)
					case "wrong-id":
						data = []byte(strings.Replace(string(data), "original_001", "neighbor_001", 1))
					case "wrong-kind":
						data = []byte(strings.Replace(string(data), `"kind":"keys-only",`, "", 1))
					case "not-found":
						response.StatusCode = 404
						data = []byte(`{"code":"IDENTITY_OPERATION_NOT_FOUND","message":"body_CANARY"}`)
					case "unknown-state":
						data = []byte(strings.Replace(string(data), `"state":"applied"`, `"state":"unknown"`, 1))
					case "trailing":
						data = append(data, []byte(`{}`)...)
					}
					response.Body = io.NopCloser(strings.NewReader(string(data)))
					return response, nil
				})
			})
			f.retain(t)
			var err error
			f.recordTiming("cancel-append-before")
			f.envelope, err = f.lease.AppendCancellation(f.ctx, f.envelope, "cancel_winner")
			f.recordTiming("cancel-append-after")
			if err != nil {
				t.Fatal(err)
			}
			f.recordTiming("cancel-confirm-before")
			permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.KeysCancelAction)
			f.recordTiming("cancel-confirm-after")
			if err != nil {
				t.Fatal(err)
			}
			before := f.count()
			_, err = f.transport.KeysCancel(f.ctx, f.credential, permit)
			if err == nil || f.count() != before+1 {
				t.Fatal("ambiguous reply accepted or retried")
			}
			expectedCode := "IDENTITY_RESULT_INVALID"
			switch mode {
			case "loss", "close":
				expectedCode = "IDENTITY_UNAVAILABLE"
			case "oversize":
				expectedCode = "IDENTITY_RESPONSE_TOO_LARGE"
			case "not-found":
				expectedCode = "IDENTITY_OPERATION_NOT_FOUND"
			}
			failure, ok := errors.AsType[*control.APIError](err)
			if !ok || failure.Code != expectedCode || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("ambiguous reply did not return its fixed safe classification", err)
			}
			after, err := f.lease.Read(f.ctx)
			if err != nil || !after.Equal(f.envelope) {
				t.Fatal("ambiguous reply changed original/cancellation/revision", err)
			}
		})
	}
}

func TestRealControlActiveHTTPBlocksEveryStorePhaseUntilJoin(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f := realIdentityFixture(t, identityattempt.Selection, func(actual http.RoundTripper) http.RoundTripper {
		return integrationTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("action") == "select" {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			return actual.RoundTrip(r)
		})
	})
	f.retain(t)
	permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	finished := false
	go func() {
		_, err := f.transport.SelectionApply(f.ctx, f.credential, permit)
		done <- err
	}()
	defer func() {
		once.Do(func() {
			close(release)
		})
		if !finished {
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-f.ctx.Done():
				t.Error("owned call did not join")
			}
		}
	}()
	select {
	case <-entered:
	case err := <-done:
		finished = true
		t.Fatal("call ended before gate", err)
	case <-f.ctx.Done():
		t.Fatal("call did not enter")
	}
	if _, err := f.lease.Read(f.ctx); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("read overlapped HTTP")
	}
	if _, err := f.lease.Retain(f.ctx, f.envelope, identityattempt.Attempt{}); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("retain overlapped HTTP")
	}
	if _, err := f.lease.AppendCancellation(f.ctx, f.envelope, "cancel_winner"); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("enrichment overlapped HTTP")
	}
	if _, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionStatusAction); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("confirm overlapped HTTP")
	}
	if _, err := f.lease.ResolveSelection(f.ctx, f.envelope, identity.SelectionReceipt{}); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("resolve overlapped HTTP")
	}
	if err := f.lease.Close(); !errors.Is(err, identityattempt.ErrBusy) {
		t.Fatal("close released active HTTP")
	}
	once.Do(func() {
		close(release)
	})
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-f.ctx.Done():
		t.Fatal("owned call did not complete")
	}
	if actual, err := f.lease.Read(f.ctx); err != nil || !actual.Equal(f.envelope) {
		t.Fatal("joined call left the lease blocked or changed its record", err)
	}
}

func TestRealControlLateOriginalReceiptCannotClearCancellationRevision(t *testing.T) {
	f := realIdentityFixture(t, identityattempt.Selection, nil)
	f.retain(t)
	f.recordTiming("late-confirm-apply-before")
	permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionApplyAction)
	f.recordTiming("late-confirm-apply-after")
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("late-http-apply-before")
	receipt, err := f.transport.SelectionApply(f.ctx, f.credential, permit)
	f.recordTiming("late-http-apply-after")
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("late-close-lease-before")
	if err := f.lease.Close(); err != nil {
		t.Fatal(err)
	}
	f.recordTiming("late-close-lease-after")
	f.recordTiming("late-begin-existing-before")
	f.lease, err = f.store.BeginExisting(f.ctx, f.slot)
	f.recordTiming("late-begin-existing-after")
	if err != nil {
		t.Fatal(err)
	}
	f.recordTiming("late-append-cancellation-before")
	enriched, err := f.lease.AppendCancellation(f.ctx, f.envelope, "cancel_winner")
	f.recordTiming("late-append-cancellation-after")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionCancelAction); !errors.Is(err, identityattempt.ErrChanged) {
		t.Fatal("stale full CAS confirmed")
	}
	if _, err := f.lease.ResolveSelection(f.ctx, enriched, receipt); !errors.Is(err, identityattempt.ErrReceiptMismatch) {
		t.Fatal("late original receipt cleared enriched revision")
	}
	actual, err := f.lease.Read(f.ctx)
	if err != nil || !actual.Equal(enriched) {
		t.Fatal("late receipt changed retained bytes")
	}
}

func TestRealControlLifecycleAssociationRefusalsKeepExactAttempt(t *testing.T) {
	for _, field := range []string{"scope", "kind", "state", "version"} {
		t.Run(field, func(t *testing.T) {
			f := realIdentityFixture(t, identityattempt.Lifecycle, func(actual http.RoundTripper) http.RoundTripper {
				return integrationTransport(func(request *http.Request) (*http.Response, error) {
					response, err := actual.RoundTrip(request)
					if err != nil || request.URL.Query().Get("action") != "resume" {
						return response, err
					}
					data, readErr := io.ReadAll(response.Body)
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil {
						return nil, errors.New("owned fixture reply failed")
					}
					status := integrationDecode[identity.LifecycleStatus](t, string(data))
					switch field {
					case "scope":
						status.Operation.Scope.ProjectID, _ = identity.Text("neighbor_opaque_project")
					case "kind":
						status.Operation.Target.Kind = "account"
					case "state":
						status.State = "active"
					case "version":
						status.Operation.ExpectedVersion = 1
					}
					// The perturbation is a complete valid DTO, not a parser setup fault.
					wire, err := json.Marshal(status)
					if err != nil {
						return nil, errors.New("owned association fixture invalid")
					}
					response.Body = io.NopCloser(strings.NewReader(string(wire)))
					return response, nil
				})
			})
			f.retain(t)
			f.recordTiming("lifecycle-confirm-resume-before")
			permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.LifecycleResumeAction)
			f.recordTiming("lifecycle-confirm-resume-after")
			if err != nil {
				t.Fatal(err)
			}
			before := f.count()
			_, err = f.transport.LifecycleResume(f.ctx, f.credential, f.current, permit)
			failure, ok := errors.AsType[*control.APIError](err)
			if !ok || failure.Code != "IDENTITY_RESULT_INVALID" || f.count() != before+1 {
				t.Fatal("crossed lifecycle evidence minted a receipt", err)
			}
			actual, err := f.lease.Read(f.ctx)
			if err != nil || !actual.Equal(f.envelope) {
				t.Fatal("crossed lifecycle evidence changed retained identity", err)
			}
		})
	}
}

func TestRealControlExpiredCallerAndWrongActionCannotDispatch(t *testing.T) {
	for _, mode := range []string{"expired-caller", "wrong-action"} {
		t.Run(mode, func(t *testing.T) {
			f := realIdentityFixture(t, identityattempt.Selection, nil)
			f.retain(t)
			permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.SelectionApplyAction)
			if err != nil {
				t.Fatal(err)
			}
			before := f.count()
			if mode == "expired-caller" {
				ctx, cancel := context.WithCancel(f.ctx)
				cancel()
				_, err = f.transport.SelectionApply(ctx, f.credential, permit)
			} else {
				_, err = f.transport.SelectionStatus(f.ctx, f.credential, permit)
			}
			if err == nil || f.count() != before {
				t.Fatal("expired caller or mismatched action dispatched")
			}
			actual, err := f.lease.Read(f.ctx)
			if err != nil || !actual.Equal(f.envelope) {
				t.Fatal("admission refusal changed retained identity", err)
			}
		})
	}
}

func assertRetainedProjection(t *testing.T, envelope identityattempt.Envelope, request integrationRequest) {
	t.Helper()
	attempt, err := envelope.RetainedAttempt()
	if err != nil || attempt == nil {
		t.Fatal("projection has no actual retained original")
	}
	expected := map[string]any{"action": request.action}
	switch attempt.Kind() {
	case identityattempt.Selection, identityattempt.KeysOnly:
		var id identity.SelectionOperationID
		var precondition identity.Precondition
		if attempt.Kind() == identityattempt.Selection {
			command, _ := attempt.SelectionCommand()
			id, precondition = command.OperationID, command.Precondition
			if request.action == "select" {
				expected["expectedConfigurationVersion"], expected["target"] = command.ExpectedConfigurationVersion, command.Target
			}
		} else {
			command, _ := attempt.KeysCommand()
			id, precondition = command.OperationID, command.Precondition
			if request.action == "keys-replace" {
				expected["expectedConfigurationVersion"], expected["keys"] = command.ExpectedConfigurationVersion, command.Keys
			}
		}
		expected["precondition"] = precondition
		switch request.action {
		case "select", "keys-replace":
			expected["operationId"] = id
		case "selection-operation":
			expected["selectedOperationId"] = id
		case "keys-read":
			expected["selectionOperationId"] = id
		default:
			cancel, present := attempt.CancellationID()
			if !present {
				t.Fatal("cancel projection has no retained cancellation")
			}
			expected["selectionOperationId"], expected["operationId"] = id, cancel
		}
	case identityattempt.Lifecycle:
		command, _ := attempt.LifecycleCommand()
		if request.action == "operation" {
			expected["lifecycleOperationId"] = command.OperationID
		} else {
			expected["operationId"] = command.OperationID
		}
		if request.action == "apply" {
			subject, _ := identity.Text("private_fixture_subject")
			profile := "installed"
			expected["target"] = identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile}
			expected["state"], expected["expectedLifecycleVersion"] = command.State, command.ExpectedLifecycleVersion
		}
	}
	wire, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire, &fields) != nil || !reflect.DeepEqual(fields, request.body) {
		t.Fatal("request body differs from the complete retained projection")
	}
}

func TestRealControlLifecyclePendingAndTerminalReceiptsPreserveCompleteEvidence(t *testing.T) {
	for _, state := range []string{"pending_owners", "pending_prepare", "pending_activation", "pending_service_ready", "refused", "superseded", "superseded_by_deletion"} {
		t.Run(state, func(t *testing.T) {
			f := realIdentityFixture(t, identityattempt.Lifecycle, func(actual http.RoundTripper) http.RoundTripper {
				return integrationTransport(func(request *http.Request) (*http.Response, error) {
					response, err := actual.RoundTrip(request)
					if err != nil || request.URL.Query().Get("action") != "operation" {
						return response, err
					}
					data, readErr := io.ReadAll(response.Body)
					closeErr := response.Body.Close()
					if readErr != nil || closeErr != nil {
						return nil, errors.New("owned fixture response failed")
					}
					status := integrationDecode[identity.LifecycleStatus](t, string(data))
					status.Status = state
					if state == "superseded" {
						newer, _ := identity.Text("newer_exact_operation")
						status.SupersededBy = &identity.LifecycleReference{Scope: status.Operation.Scope, Target: status.Operation.Target, OperationID: newer, Version: 2}
						status.CurrentHead = &identity.LifecycleHead{Scope: status.Operation.Scope, Target: status.Operation.Target, OperationID: newer, Version: 2, State: "active"}
					}
					status.RequiredMailboxes, status.PreparedMailboxes, status.ActivatedMailboxes = 3, 2, 1
					wire, err := json.Marshal(status)
					if err != nil {
						return nil, errors.New("owned status fixture invalid")
					}
					response.Body = io.NopCloser(strings.NewReader(string(wire)))
					return response, nil
				})
			})
			f.retain(t)
			f.recordTiming("lifecycle-confirm-status-before")
			permit, err := f.lease.Confirm(f.ctx, f.envelope, identityattempt.LifecycleStatusAction)
			f.recordTiming("lifecycle-confirm-status-after")
			if err != nil {
				t.Fatal(err)
			}
			reply, err := f.transport.LifecycleOperation(f.ctx, f.credential, f.current, permit)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := reply.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			result, err := receipt.Result()
			if err != nil || result.Status != state || result.EffectiveState != "active" || result.State != "suspended" ||
				result.RequiredMailboxes != 3 || result.PreparedMailboxes != 2 || result.ActivatedMailboxes != 1 {
				t.Fatal("transport replaced complete lifecycle evidence")
			}
			if state == "superseded" && (result.CurrentHead == nil || result.CurrentHead.Version != 2 || result.SupersededBy == nil || result.SupersededBy.Version != 2) {
				t.Fatal("historical receipt lost independently reported newer evidence")
			}
			scope, err := reply.Scope()
			if err != nil {
				t.Fatal(err)
			}
			resolution, err := f.lease.ResolveLifecycle(f.ctx, f.envelope, scope, receipt)
			if err != nil {
				t.Fatal(err)
			}
			expected := identity.ReceiptPending
			if state == "refused" || state == "superseded" || state == "superseded_by_deletion" {
				expected = identity.ReceiptSettled
			}
			if resolution.Disposition() != expected {
				t.Fatal("pending or terminal evidence changed classification")
			}
		})
	}
}
