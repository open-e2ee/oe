package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
)

const keyExecutionWire = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one"}`
const configuredExecutionWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + keyExecutionWire + `]}`
const fingerprintExecutionWire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const scopeExecutionWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"relay_scope"}`
const preconditionExecutionWire = `{"publishableKey":"pk_public","recoveryGeneration":1,"scope":` + scopeExecutionWire + `}`
const completeExecutionWire = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + fingerprintExecutionWire + `","identityProfile":` + configuredExecutionWire + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + fingerprintExecutionWire + `"},"reason":null},"selectionOperation":null}`
const currentExecutionWire = `{"configuration":` + completeExecutionWire + `,"precondition":` + preconditionExecutionWire + `}`
const preparedExecutionID = "lc1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// scopeExecutionWireFor is the fixture scope in one environment.
func scopeExecutionWireFor(environment string) string {
	return strings.Replace(scopeExecutionWire, `"environmentKind":"sandbox"`, `"environmentKind":"`+environment+`"`, 1)
}

// selectionExecutionResult is a server selection result. A keys-only result
// also names its kind.
func selectionExecutionResult(id, state string, keys bool) string {
	kind := ""
	if keys {
		kind = `,"kind":"keys-only"`
	}
	return `{"operationId":"` + id + `","state":"` + state + `","configurationVersion":2,"admissionRevision":0` + kind + `}`
}

func preparationExecutionWire(environment, state string, version int) string {
	return `{"operationId":"fresh_read_001","preparedOperationId":"` + preparedExecutionID + `","scope":` + scopeExecutionWireFor(environment) +
		`,"expectedLifecycleVersion":` + strconv.Itoa(version) + `,"state":"` + state + `","target":{"kind":"subject"}}`
}

func lifecycleExecutionResult(environment, id, state, status string) string {
	return `{"operation":{"scope":` + scopeExecutionWireFor(environment) + `,"target":{"kind":"subject"},"operationId":"` + id +
		`","expectedVersion":0},"version":1,"state":"` + state + `","currentHead":null,"effectiveState":"active","status":"` + status +
		`","supersededBy":null,"requiredMailboxes":0,"preparedMailboxes":0,"activatedMailboxes":0}`
}

func executionResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

// executionBodyID is the operation ID that a mutation body names.
func executionBodyID(t *testing.T, request *http.Request) string {
	t.Helper()
	var body struct {
		OperationID string `json:"operationId"`
	}
	if request.Body == nil || json.NewDecoder(request.Body).Decode(&body) != nil {
		t.Error("mutation body did not parse")
	}
	return body.OperationID
}

func executionDecode[T any](t *testing.T, wire string) T {
	t.Helper()
	var value T
	if json.Unmarshal([]byte(wire), &value) != nil {
		t.Fatal("invalid public execution fixture")
	}
	return value
}

type executionRoundTrip func(*http.Request) (*http.Response, error)

func (f executionRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func identityExecutionInputFor(t *testing.T, action identity.Action) identityExecutionInput {
	t.Helper()
	approved := executionDecode[identity.CurrentContext](t, currentExecutionWire)
	input := identityExecutionInput{Project: "sample", Action: action}
	switch action {
	case identity.SelectionApplyAction:
		target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
		input.Target, input.Approved = &target, &approved
	case identity.KeysReplaceAction:
		keys := executionDecode[identity.ReplacementKeys](t, `[`+keyExecutionWire+`]`)
		input.Keys, input.Approved = &keys, &approved
	case identity.LifecycleApplyAction:
		target := executionDecode[identity.LifecycleInputTarget](t, publicTargetWire)
		observed := executionDecode[identity.TargetObservation](t, publicObservationWire)
		input.LifecycleTarget, input.LifecycleState, input.Approved, input.ApprovedTarget = &target, "suspended", &approved, &observed
	case identity.LifecycleResumeAction:
		input.OperationID = preparedExecutionID
	default:
		input.OperationID = "original_001"
	}
	return input
}

func TestIdentityExecutionRefusesConsentBeforeAnyAuthority(t *testing.T) {
	for _, action := range []identity.Action{identity.SelectionApplyAction, identity.KeysReplaceAction, identity.LifecycleApplyAction, identity.LifecycleResumeAction, identity.SelectionCancelAction, identity.KeysCancelAction} {
		t.Run(string(action), func(t *testing.T) {
			r, api, factory := identityContextRunner(t)
			sessions := 0
			api.session = func(ctx context.Context, credential control.CredentialRequest) (control.Session, error) {
				sessions++
				return acmeSession(ctx, credential)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := r.executeIdentity(ctx, identityExecutionInputFor(t, action))
			if !errors.Is(err, errIdentityConsent) || sessions != 0 || len(factory.addresses) != 0 {
				t.Fatal("missing consent reached authority or transport", err)
			}
		})
	}
}

func TestIdentityExecutionInvalidInputsAndDeadlinesRefuseBeforeAuthority(t *testing.T) {
	for _, name := range []string{"unknown-action", "operation-id-on-apply", "project", "selection-keys", "keys-target", "lifecycle-private-shape", "status-target", "cancel-without-id", "resume-without-id", "unbounded", "expired"} {
		t.Run(name, func(t *testing.T) {
			r, api, factory := identityContextRunner(t)
			sessions := 0
			api.session = func(ctx context.Context, credential control.CredentialRequest) (control.Session, error) {
				sessions++
				return acmeSession(ctx, credential)
			}
			input := identityExecutionInputFor(t, identity.SelectionApplyAction)
			input.Consent = true
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
			keys := executionDecode[identity.ReplacementKeys](t, `[`+keyExecutionWire+`]`)
			switch name {
			case "unknown-action":
				input.Action = "retry-latest"
			case "operation-id-on-apply":
				input.OperationID = "original_001"
			case "project":
				input.Project = "../other"
			case "selection-keys":
				input.Keys = &keys
			case "keys-target":
				input = identityExecutionInputFor(t, identity.KeysReplaceAction)
				input.Consent, input.Target = true, &target
			case "lifecycle-private-shape":
				input = identityExecutionInputFor(t, identity.LifecycleApplyAction)
				input.Consent, input.LifecycleTarget = true, &identity.LifecycleInputTarget{Kind: "subject"}
			case "status-target":
				input = identityExecutionInputFor(t, identity.SelectionStatusAction)
				input.Target = &target
			case "cancel-without-id":
				input = identityExecutionInputFor(t, identity.SelectionCancelAction)
				input.Consent, input.OperationID = true, ""
			case "resume-without-id":
				input = identityExecutionInputFor(t, identity.LifecycleResumeAction)
				input.Consent, input.OperationID = true, ""
			case "unbounded":
				ctx = context.Background()
			case "expired":
				cancel()
			}
			_, err := r.executeIdentity(ctx, input)
			if name == "unbounded" || name == "expired" {
				if !errors.Is(err, errIdentityDeadline) {
					t.Fatal("deadline refusal changed", err)
				}
			} else if !errors.Is(err, errIdentityExecution) {
				t.Fatal("invalid execution accepted", err)
			}
			if sessions != 0 || len(factory.addresses) != 0 {
				t.Fatal("invalid input reached dependencies")
			}
		})
	}
}

func TestIdentityGeneratedIDsUseSeparateClosedContracts(t *testing.T) {
	first, err := identityNewID()
	if err != nil || first.Validate() != nil || !strings.HasPrefix(string(first), "oe_") || len(first) != 35 {
		t.Fatal("invalid fresh local operation ID")
	}
	second, err := identityNewID()
	if err != nil || first == second {
		t.Fatal("fresh generator repeated an ID")
	}
	nonce, err := identityNonce()
	if err != nil || identity.ValidatePreparationNonce(nonce) != nil {
		t.Fatal("invalid preparation nonce")
	}
}

// This controlled context keeps Err nil after an actual past deadline. It
// qualifies the logical preflight check without sleeps or a kernel timing claim.
type controlledExecutionDeadline struct {
	context.Context
	deadline time.Time
}

func (c controlledExecutionDeadline) Deadline() (time.Time, bool) {
	return c.deadline, true
}

type controlledExecutionCredentialStore struct {
	credential.Store
	reads int
}

func (s *controlledExecutionCredentialStore) Get(profile string) (credential.Credential, error) {
	s.reads++
	return s.Store.Get(profile)
}

func TestIdentityExecutionControlledLogicalDeadlinePrecedesAllAuthorityWork(t *testing.T) {
	r, api, factory := identityContextRunner(t)
	store := &controlledExecutionCredentialStore{Store: r.store}
	r.store = store
	sessions, projects := 0, 0
	api.session = func(context.Context, control.CredentialRequest) (control.Session, error) {
		sessions++
		return control.Session{}, errIdentityExecution
	}
	api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		projects++
		return control.Project{}, errIdentityExecution
	}
	ctx := controlledExecutionDeadline{Context: context.Background(), deadline: time.Now().Add(-time.Second)}
	if ctx.Err() != nil {
		t.Fatal("controlled delayed-notification fixture is invalid")
	}
	input := identityExecutionInputFor(t, identity.SelectionApplyAction)
	input.Consent = true
	_, err := r.executeIdentity(ctx, input)
	if !errors.Is(err, errIdentityDeadline) || ctx.Err() != nil {
		t.Fatal("logical expiration required a timer notification", err)
	}
	if store.reads != 0 || sessions != 0 || projects != 0 || len(factory.addresses) != 0 {
		t.Fatal("logical expiration reached credentials, authority or transport")
	}
}

func TestIdentityNewTargetRequiresApprovedContextBeforeAuthority(t *testing.T) {
	for _, action := range []identity.Action{identity.SelectionApplyAction, identity.KeysReplaceAction, identity.LifecycleApplyAction} {
		t.Run(string(action), func(t *testing.T) {
			r, _, factory := identityContextRunner(t)
			input := identityExecutionInputFor(t, action)
			input.Consent, input.Approved = true, nil
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := r.executeIdentity(ctx, input); !errors.Is(err, errIdentityExecution) {
				t.Fatal("new target recaptured consent", err)
			}
			if len(factory.addresses) != 0 {
				t.Fatal("missing approval reached authority")
			}
		})
	}
}

func TestIdentityApprovedCurrentComparesFullFreshContextBeforeMutation(t *testing.T) {
	for _, name := range []string{"same", "publishable-key", "recovery-generation", "scope-project", "configuration-version", "inventory", "refreshed-check-time", "admission-state", "admission-source-generation", "admission-evidence-state", "profile"} {
		t.Run(name, func(t *testing.T) {
			r, _, _ := identityContextRunner(t)
			approved := executionDecode[identity.CurrentContext](t, currentExecutionWire)
			observed, _ := approved.Clone()
			switch name {
			case "publishable-key":
				observed.Precondition.PublishableKey = "other_public_key"
			case "recovery-generation":
				observed.Precondition.RecoveryGeneration = 2
			case "scope-project":
				observed.Precondition.Scope.ProjectID = identity.TextFromUnits([]uint16{'o', 't', 'h', 'e', 'r'})
			case "configuration-version":
				observed.Configuration.ConfigurationVersion = 2
			case "inventory":
				observed.Configuration.Inventory.HistoryCount = 1
			case "refreshed-check-time":
				observed.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds = 1
			case "admission-state":
				reason := "not_ready"
				observed.Configuration.AdmissionReadiness.State = "unready"
				observed.Configuration.AdmissionReadiness.Reason = &reason
			case "admission-source-generation":
				epoch := identity.SafeInteger(1)
				observed.Configuration.AdmissionReadiness.SourceGeneration.Kind = "cutover"
				observed.Configuration.AdmissionReadiness.SourceGeneration.ReceiptEpoch = &epoch
			case "admission-evidence-state":
				reason := "evidence_unavailable"
				observed.Configuration.AdmissionReadiness.State = "unknown"
				observed.Configuration.AdmissionReadiness.Evidence.State = "unknown"
				observed.Configuration.AdmissionReadiness.SourceGeneration = nil
				observed.Configuration.AdmissionReadiness.Reason = &reason
			case "profile":
				observed.Configuration.IdentityProfile = executionDecode[identity.InstalledProfile](t, publicFirebaseWire)
			}
			target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
			calls := []string{}
			actual, err := control.New(defaultControlURL, &http.Client{Transport: executionRoundTrip(func(request *http.Request) (*http.Response, error) {
				action := request.URL.Query().Get("action")
				calls = append(calls, action)
				var data []byte
				var err error
				switch action {
				case "current":
					data, err = json.Marshal(observed)
				case "preview":
					data, err = json.Marshal(identity.PreviewResult{Kind: "selection", ExpectedConfigurationVersion: observed.Configuration.ConfigurationVersion,
						Target: &target, Current: observed, NativeCapabilities: identity.NativeCapabilities{Clerk: "available", Firebase: "available"}})
				case "select":
					return executionResponse(200, selectionExecutionResult(executionBodyID(t, request), "applied", false)), nil
				default:
					t.Error("unexpected identity action", action)
					return nil, errors.New("unexpected action")
				}
				if err != nil {
					t.Fatal("invalid current mutation", err)
				}
				return executionResponse(200, string(data)), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			r.identities = actual
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Action: identity.SelectionApplyAction,
				Target: &target, Approved: &approved, Consent: true})
			if name == "same" || name == "refreshed-check-time" {
				if err != nil || result.Disposition != identity.ReceiptSettled || strings.Join(calls, ",") != "current,preview,select" {
					t.Fatal("equal approved context did not reach the server mutation", err, calls)
				}
			} else if !errors.Is(err, errIdentityExecution) || len(calls) != 1 {
				t.Fatal("changed approved context reached the server mutation", err, calls)
			}
		})
	}
}

func TestIdentityApprovalContextIgnoresOnlyCheckTimeWithoutChangingInputs(t *testing.T) {
	approved := executionDecode[identity.CurrentContext](t, currentExecutionWire)
	fresh, err := approved.Clone()
	if err != nil {
		t.Fatal(err)
	}
	fresh.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds = 7
	oldApproved, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	oldFresh, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Equal(fresh) || !sameIdentityApprovalContext(approved, fresh) {
		t.Fatal("fresh check time changed approval authority")
	}
	afterApproved, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	afterFresh, err := json.Marshal(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldApproved, afterApproved) || !bytes.Equal(oldFresh, afterFresh) {
		t.Fatal("approval comparison changed original context")
	}
	fresh.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds = identity.SafeInteger(identity.MaximumSafeInteger + 1)
	if sameIdentityApprovalContext(approved, fresh) {
		t.Fatal("comparison accepted an invalid observation timestamp")
	}
}

func TestIdentityApprovedLifecycleEvidenceRefusesBeforePreparation(t *testing.T) {
	for _, name := range []string{"fresh-correlation", "scope", "version", "state", "head-presence", "application"} {
		t.Run(name, func(t *testing.T) {
			r, _, _ := identityContextRunner(t)
			approved := executionDecode[identity.CurrentContext](t, currentExecutionWire)
			target := executionDecode[identity.LifecycleInputTarget](t, publicTargetWire)
			old := executionDecode[identity.TargetObservation](t, publicObservationWire)
			fresh, _ := old.Clone()
			fresh.OperationID = identity.TextFromUnits([]uint16{'f', 'r', 'e', 's', 'h'})
			switch name {
			case "scope":
				fresh.Scope.ProjectID = identity.TextFromUnits([]uint16{'o', 't', 'h', 'e', 'r'})
			case "version":
				fresh.ObservedVersion = 1
			case "state":
				fresh.ObservedState = "suspended"
			case "head-presence":
				fresh.CurrentHead = &identity.LifecycleHead{Scope: fresh.Scope, Target: fresh.Target, OperationID: identity.TextFromUnits([]uint16{'o', 'l', 'd'}), Version: 1, State: "active"}
			case "application":
				fresh.Application, _ = identity.BoundLifecycleApplication("active", nil)
			}
			calls := []string{}
			actual, err := control.New(defaultControlURL, &http.Client{Transport: executionRoundTrip(func(request *http.Request) (*http.Response, error) {
				action := request.URL.Query().Get("action")
				calls = append(calls, action)
				var data []byte
				var err error
				switch action {
				case "current":
					data, err = json.Marshal(approved)
				case "target":
					data, err = json.Marshal(fresh)
				case "prepare":
					return executionResponse(200, preparationExecutionWire("sandbox", "suspended", 0)), nil
				case "apply":
					return executionResponse(200, lifecycleExecutionResult("sandbox", executionBodyID(t, request), "suspended", "converged")), nil
				default:
					t.Error("unexpected identity action", action)
					return nil, errors.New("unexpected action")
				}
				if err != nil {
					t.Fatal("invalid target mutation", err)
				}
				return executionResponse(200, string(data)), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			r.identities = actual
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Action: identity.LifecycleApplyAction,
				LifecycleTarget: &target, LifecycleState: "suspended", Approved: &approved, ApprovedTarget: &old, Consent: true})
			if name == "fresh-correlation" {
				if err != nil || result.Disposition != identity.ReceiptSettled || strings.Join(calls, ",") != "current,target,prepare,apply" {
					t.Fatal("fresh read ID incorrectly changed target authority", err, calls)
				}
			} else if !errors.Is(err, errIdentityExecution) || strings.Join(calls, ",") != "current,target" {
				t.Fatal("changed lifecycle evidence reached preparation", err, calls)
			}
		})
	}
}
