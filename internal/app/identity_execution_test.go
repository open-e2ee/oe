package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const keyExecutionWire = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one"}`
const configuredExecutionWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + keyExecutionWire + `]}`
const fingerprintExecutionWire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const scopeExecutionWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"relay_scope"}`
const preconditionExecutionWire = `{"publishableKey":"pk_public","recoveryGeneration":1,"scope":` + scopeExecutionWire + `}`
const completeExecutionWire = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + fingerprintExecutionWire + `","identityProfile":` + configuredExecutionWire + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + fingerprintExecutionWire + `"},"reason":null},"selectionOperation":null}`
const currentExecutionWire = `{"configuration":` + completeExecutionWire + `,"precondition":` + preconditionExecutionWire + `}`

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

func TestIdentityExecutionRefusesConsentBeforeAnyStoreFirstUse(t *testing.T) {
	for _, action := range []identityattempt.Action{identityattempt.SelectionApplyAction, identityattempt.KeysReplaceAction, identityattempt.LifecycleApplyAction, identityattempt.LifecycleResumeAction, identityattempt.SelectionCancelAction, identityattempt.KeysCancelAction} {
		t.Run(string(action), func(t *testing.T) {
			r, _, _, attempts := identityContextRunner(t)
			calls := 0
			client, err := control.New(defaultControlURL, &http.Client{Transport: executionRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Query().Get("action") != "current" || request.Method != "GET" {
					t.Error("preflight sent a mutation")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(currentExecutionWire)), Header: make(http.Header)}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			r.identities = client
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Kind: identityActionKind(action), Action: action, NamespaceFirstUse: true, SlotFirstUse: true})
			if !errors.Is(err, errIdentityConsent) || calls != 1 || attempts.opens != 0 || attempts.bootstraps != 0 {
				t.Fatal("missing consent caused store activity or mutation", err)
			}
		})
	}
}

func TestIdentityExecutionInvalidInputsAndDeadlinesRefuseBeforeAuthority(t *testing.T) {
	for _, name := range []string{"unknown-action", "crossed-kind", "project", "selection-keys", "keys-target", "lifecycle-private-shape", "status-target", "unbounded", "expired"} {
		t.Run(name, func(t *testing.T) {
			r, _, factory, attempts := identityContextRunner(t)
			input := identityExecutionInput{Project: "sample", Kind: identityattempt.Selection, Action: identityattempt.SelectionApplyAction, Consent: true}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
			keys := executionDecode[identity.ReplacementKeys](t, `[`+keyExecutionWire+`]`)
			switch name {
			case "unknown-action":
				input.Action = "retry-latest"
			case "crossed-kind":
				input.Kind = identityattempt.Lifecycle
			case "project":
				input.Project = "../other"
			case "selection-keys":
				input.Keys = &keys
			case "keys-target":
				input.Kind = identityattempt.KeysOnly
				input.Action = identityattempt.KeysReplaceAction
				input.Target = &target
			case "lifecycle-private-shape":
				input.Kind = identityattempt.Lifecycle
				input.Action = identityattempt.LifecycleApplyAction
				input.LifecycleTarget = &identity.LifecycleInputTarget{Kind: "subject"}
			case "status-target":
				input.Action = identityattempt.SelectionStatusAction
				input.Target = &target
			case "unbounded":
				ctx = context.Background()
			case "expired":
				cancel()
			}
			if _, err := r.executeIdentity(ctx, input); err == nil {
				t.Fatal("invalid execution accepted")
			}
			if len(factory.slots) != 0 || attempts.opens != 0 || attempts.bootstraps != 0 {
				t.Fatal("invalid input reached dependencies")
			}
		})
	}
}

func TestIdentityOperationEnvironmentConfirmsOnlyTheExactRetainedIdentity(t *testing.T) {
	selection := executionDecode[identity.SelectionCommand](t, `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":`+preconditionExecutionWire+`}`)
	keys := executionDecode[identity.KeysCommand](t, `{"operationId":"original_001","expectedConfigurationVersion":1,"keys":[`+keyExecutionWire+`],"precondition":`+preconditionExecutionWire+`}`)
	life := executionDecode[identity.LifecycleAttempt](t, `{"operationId":"old_exact_001","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	a, err := identityattempt.NewSelectionAttempt(selection)
	if err != nil {
		t.Fatal(err)
	}
	b, err := identityattempt.NewKeysAttempt(keys)
	if err != nil {
		t.Fatal(err)
	}
	c, err := identityattempt.NewLifecycleAttempt(life)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []identityattempt.Attempt{a, b, c} {
		original := "original_001"
		action := identityattempt.SelectionStatusAction
		if attempt.Kind() == identityattempt.KeysOnly {
			action = identityattempt.KeysStatusAction
		}
		if attempt.Kind() == identityattempt.Lifecycle {
			original = "old_exact_001"
			action = identityattempt.LifecycleStatusAction
		}
		for _, value := range []string{"", original, original + " ", " " + original, "other_001"} {
			err := confirmIdentityEnvironment(value, &attempt, action)
			if (err == nil) != (value == "" || value == original) {
				t.Fatal("operation environment was normalized or rebased")
			}
		}
	}
	if !errors.Is(confirmIdentityEnvironment("original_001", nil, identityattempt.SelectionApplyAction), identityattempt.ErrOperationIDUnretained) {
		t.Fatal("environment ID created a new context")
	}
	enriched, err := a.WithCancellation("cancel_winner")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"cancel_winner", "original_001", "cancel_loser", " cancel_winner"} {
		err := confirmIdentityEnvironment(value, &enriched, identityattempt.SelectionCancelAction)
		if (err == nil) != (value == "cancel_winner") {
			t.Fatal("cancellation confirmation changed winner")
		}
	}
	if !errors.Is(confirmIdentityEnvironment("cancel_winner", &a, identityattempt.SelectionCancelAction), identityattempt.ErrOperationIDUnretained) {
		t.Fatal("environment invented cancellation")
	}
}

func TestIdentityRetainedInputsCannotChangeSafeCommandOrInventPrivateContinuation(t *testing.T) {
	command := executionDecode[identity.SelectionCommand](t, `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":`+preconditionExecutionWire+`}`)
	attempt, err := identityattempt.NewSelectionAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	input := identityExecutionInput{Kind: identityattempt.Selection, Action: identityattempt.SelectionApplyAction}
	if retainedIdentityInput(attempt, input) != nil {
		t.Fatal("retained-only replay refused")
	}
	altered := executionDecode[identity.SelectionTarget](t, configuredExecutionWire)
	input.Target = &altered
	if !errors.Is(retainedIdentityInput(attempt, input), identityattempt.ErrChanged) {
		t.Fatal("changed selection target accepted")
	}
	lifecycle := executionDecode[identity.LifecycleAttempt](t, `{"operationId":"old_exact_001","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	life, err := identityattempt.NewLifecycleAttempt(lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	fullApply := identityExecutionInput{Kind: identityattempt.Lifecycle, Action: identityattempt.LifecycleApplyAction}
	if !errors.Is(retainedIdentityInput(life, fullApply), identityattempt.ErrContinuationUnsupported) {
		t.Fatal("full apply reconstructed a private target")
	}
	resume := identityExecutionInput{Kind: identityattempt.Lifecycle, Action: identityattempt.LifecycleResumeAction}
	if retainedIdentityInput(life, resume) != nil {
		t.Fatal("subject-free exact continuation required private context")
	}
}

func TestIdentityNonidentityRunDoesNotResolveInjectedAttemptFactory(t *testing.T) {
	attempts := &identityCountingFactory{failure: identityattempt.ErrUnsafe}
	var out, errOut bytes.Buffer
	exit := Run(context.Background(), []string{"version"}, Dependencies{API: &fakeAPI{}, Store: credential.NewMemory(), IdentityAttempts: attempts,
		Out: &out, Err: &errOut, WorkingDir: t.TempDir(), Getenv: func(string) string {
			return ""
		}})
	if exit != 0 || attempts.opens != 0 || attempts.bootstraps != 0 {
		t.Fatal("nonidentity command opened attempt state")
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
	r, api, factory, attempts := identityContextRunner(t)
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
	_, err := r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Kind: identityattempt.Selection,
		Action: identityattempt.SelectionApplyAction, Consent: true})
	if !errors.Is(err, identityattempt.ErrTimeout) || ctx.Err() != nil {
		t.Fatal("logical expiration required a timer notification", err)
	}
	if store.reads != 0 || sessions != 0 || projects != 0 || len(factory.slots) != 0 || attempts.opens != 0 || attempts.bootstraps != 0 {
		t.Fatal("logical expiration reached credentials, authority, transport or retained state")
	}
}

func TestIdentityNewTargetRequiresApprovedContextBeforeAuthority(t *testing.T) {
	for _, kind := range []identityattempt.Kind{identityattempt.Selection, identityattempt.KeysOnly, identityattempt.Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			r, _, factory, attempts := identityContextRunner(t)
			input := identityExecutionInput{Project: "sample", Kind: kind, Consent: true}
			switch kind {
			case identityattempt.Selection:
				target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
				input.Action, input.Target = identityattempt.SelectionApplyAction, &target
			case identityattempt.KeysOnly:
				keys := executionDecode[identity.ReplacementKeys](t, `[`+keyExecutionWire+`]`)
				input.Action, input.Keys = identityattempt.KeysReplaceAction, &keys
			case identityattempt.Lifecycle:
				target := executionDecode[identity.LifecycleInputTarget](t, publicTargetWire)
				input.Action, input.LifecycleTarget, input.LifecycleState = identityattempt.LifecycleApplyAction, &target, "suspended"
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := r.executeIdentity(ctx, input); !errors.Is(err, errIdentityExecution) {
				t.Fatal("new target recaptured consent", err)
			}
			if len(factory.slots) != 0 || attempts.opens != 0 || attempts.bootstraps != 0 {
				t.Fatal("missing approval reached authority or retained state")
			}
		})
	}
}

func TestIdentityApprovedCurrentComparesFullFreshContextBeforeStore(t *testing.T) {
	for _, name := range []string{"same", "publishable-key", "recovery-generation", "scope-project", "configuration-version", "inventory", "refreshed-check-time", "admission-state", "admission-source-generation", "admission-evidence-state", "profile"} {
		t.Run(name, func(t *testing.T) {
			r, _, _, attempts := identityContextRunner(t)
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
			calls := 0
			actual, err := control.New(defaultControlURL, &http.Client{Transport: executionRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.URL.Query().Get("action") != "current" {
					t.Error("approved-context refusal dispatched work")
				}
				data, err := json.Marshal(observed)
				if err != nil {
					t.Fatal("invalid current mutation", err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			r.identities = actual
			target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Kind: identityattempt.Selection, Action: identityattempt.SelectionApplyAction,
				Target: &target, Approved: &approved, Consent: true})
			if name == "same" || name == "refreshed-check-time" {
				if !errors.Is(err, identityattempt.ErrLocation) || attempts.opens != 1 {
					t.Fatal("equal approved context failed before actual owned factory", err)
				}
			} else if !errors.Is(err, errIdentityExecution) || attempts.opens != 0 {
				t.Fatal("changed approved context reached retained state", err)
			}
			if calls != 1 || attempts.bootstraps != 0 {
				t.Fatal("approved-context comparison caused extra effects")
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

func TestIdentityApprovedLifecycleEvidenceRefusesBeforeEnrollmentOrPreparation(t *testing.T) {
	for _, name := range []string{"fresh-correlation", "scope", "version", "state", "head-presence", "application"} {
		t.Run(name, func(t *testing.T) {
			r, _, _, attempts := identityContextRunner(t)
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
				if action == "current" {
					data, err = json.Marshal(approved)
				} else if action == "target" {
					data, err = json.Marshal(fresh)
				} else {
					t.Error("stale target evidence prepared or dispatched")
					return nil, errors.New("unexpected action")
				}
				if err != nil {
					t.Fatal("invalid target mutation", err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			r.identities = actual
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = r.executeIdentity(ctx, identityExecutionInput{Project: "sample", Kind: identityattempt.Lifecycle, Action: identityattempt.LifecycleApplyAction,
				LifecycleTarget: &target, LifecycleState: "suspended", Approved: &approved, ApprovedTarget: &old, Consent: true, NamespaceFirstUse: true, SlotFirstUse: true})
			if name == "fresh-correlation" {
				if !errors.Is(err, identityattempt.ErrLocation) || attempts.opens != 1 {
					t.Fatal("fresh read ID incorrectly changed target authority", err)
				}
			} else if !errors.Is(err, errIdentityExecution) || attempts.opens != 0 {
				t.Fatal("changed lifecycle evidence reached local state", err)
			}
			if len(calls) != 2 || calls[0] != "current" || calls[1] != "target" || attempts.bootstraps != 0 {
				t.Fatal("stale target caused preparation, retention or dispatch")
			}
		})
	}
}
