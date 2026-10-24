package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

func publicLifecycleResult(t *testing.T, status string) identity.LifecycleStatus {
	t.Helper()
	superseded := `null`
	if status == "superseded" {
		superseded = `{"scope":` + scopeExecutionWire + `,"target":{"kind":"subject"},"operationId":"new_exact_002","version":2}`
	}
	return executionDecode[identity.LifecycleStatus](t, `{"operation":{"scope":`+scopeExecutionWire+`,"target":{"kind":"subject"},"operationId":"old_exact_001","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"`+status+`","supersededBy":`+superseded+`,"requiredMailboxes":0,"preparedMailboxes":0,"activatedMailboxes":0}`)
}

func TestPublicExecutionErrorsKeepTheExactSafeRetainedNextStep(t *testing.T) {
	for _, kind := range []identityattempt.Kind{identityattempt.Selection, identityattempt.KeysOnly, identityattempt.Lifecycle} {
		failure := identityExecutionFailure(&control.APIError{Code: "IDENTITY_RESULT_INVALID"}, kind, "production")
		value, ok := errors.AsType[*problem](failure)
		if !ok || value.exit != exitTemporary || value.next != "oe identity operation status --kind "+string(kind)+" --env production" {
			t.Fatal("uncertain execution omitted its exact safe status step")
		}
	}
	failure := identityExecutionFailure(&control.APIError{Code: "AUTHENTICATION_REQUIRED"}, identityattempt.Selection, "sandbox")
	value, ok := errors.AsType[*problem](failure)
	if !ok || value.next != "oe auth login" {
		t.Fatal("retained status advice replaced required authentication")
	}
}

func TestPublicRetainedActionTableIsClosedAndKindSpecific(t *testing.T) {
	expected := map[identityattempt.Kind]map[string]identityattempt.Action{
		identityattempt.Selection: {"status": identityattempt.SelectionStatusAction, "retry": identityattempt.SelectionApplyAction, "cancel": identityattempt.SelectionCancelAction},
		identityattempt.KeysOnly:  {"status": identityattempt.KeysStatusAction, "retry": identityattempt.KeysReplaceAction, "cancel": identityattempt.KeysCancelAction},
		identityattempt.Lifecycle: {"status": identityattempt.LifecycleStatusAction, "resume": identityattempt.LifecycleResumeAction},
	}
	for _, kind := range []identityattempt.Kind{identityattempt.Selection, identityattempt.KeysOnly, identityattempt.Lifecycle, "unknown"} {
		for _, verb := range []string{"status", "retry", "resume", "cancel", "apply", "forget", "replace", ""} {
			if got := identityRetainedAction(verb, kind); got != expected[kind][verb] {
				t.Fatal("retained action crossed kind", kind, verb, got)
			}
		}
	}
}

func TestPublicResultProjectionKeepsActualTerminalStateAfterClear(t *testing.T) {
	for _, state := range []string{"applied", "aborted", "unchanged", "refused", "deleted"} {
		t.Run(state, func(t *testing.T) {
			received := executionDecode[identity.SelectionResult](t, `{"operationId":"original_001","state":"`+state+`","configurationVersion":2,"admissionRevision":1}`)
			result := identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &received}
			projected, err := projectIdentityExecution(identityattempt.Selection, result)
			if err != nil || projected.OperationID != "original_001" || projected.Status != state || projected.ServiceReadiness != "unverified" {
				t.Fatal("actual settled result lost its state or selected ID", err)
			}
			failure := identityResultFailure(projected)
			refused := state == "refused" || state == "deleted"
			if (failure != nil) != refused {
				t.Fatal("terminal refusal became success", state)
			}
			data, err := json.Marshal(projected)
			if err != nil || strings.Contains(string(data), "precondition") || strings.Contains(string(data), "envelope") {
				t.Fatal("projection exposed retained envelope", err)
			}
		})
	}
}

func TestPublicResultProjectionRequiresExactlyOneConsistentTypedKind(t *testing.T) {
	selection := executionDecode[identity.SelectionResult](t, `{"operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`)
	keys := executionDecode[identity.KeysResult](t, `{"kind":"keys-only","operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`)
	life := publicLifecycleResult(t, "converged")
	for _, invalid := range []struct {
		kind   identityattempt.Kind
		result identityExecutionResult
	}{
		{identityattempt.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled}},
		{identityattempt.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled, Keys: &keys}},
		{identityattempt.KeysOnly, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identityattempt.Lifecycle, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identityattempt.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection, Lifecycle: &life}},
		{"unknown", identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identityattempt.Selection, identityExecutionResult{Disposition: identity.ReceiptMismatch, Selection: &selection}},
	} {
		if _, err := projectIdentityExecution(invalid.kind, invalid.result); err == nil {
			t.Fatal("mismatched or ambiguous receipt kind was projected")
		}
	}
}

func TestPublicLifecycleStatusAndResumeHaveDifferentReceiptSemantics(t *testing.T) {
	received := publicLifecycleResult(t, "converged")
	original := executionDecode[identity.LifecycleAttempt](t, `{"operationId":"old_exact_001","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	scope := executionDecode[identity.Scope](t, scopeExecutionWire)
	for _, source := range []identity.ReceiptSource{identity.LifecycleStatusSource, identity.LifecycleApplySource, identity.LifecycleResumeSource} {
		receipt, err := identity.NewLifecycleReceipt(original, scope, source, received)
		if err != nil {
			t.Fatal("receipt fixture did not qualify", err)
		}
		disposition := identity.ClassifyLifecycleReceipt(original, scope, receipt)
		result := identityExecutionResult{Disposition: disposition, Lifecycle: &received}
		projected, err := projectIdentityExecution(identityattempt.Lifecycle, result)
		if err != nil || projected.Status != "converged" || projected.OperationID != "old_exact_001" {
			t.Fatal("actual receipt metadata lost", err)
		}
		failure := identityResultFailure(projected)
		if source == identity.LifecycleStatusSource {
			if failure == nil || failure.exit != exitTemporary || failure.code != "IDENTITY_CONTINUATION_REQUIRED" {
				t.Fatal("status-only convergence cleared uncertainty")
			}
		} else if failure != nil {
			t.Fatal("exact continuation ACK did not settle command uncertainty")
		}
		if projected.ServiceReadiness != "unverified" {
			t.Fatal("receipt became current service authority")
		}
	}
}

func TestPublicPendingAndTerminalLifecycleResultsRemainDistinct(t *testing.T) {
	for _, state := range []string{"pending_owners", "pending_prepare", "pending_activation", "pending_service_ready", "refused", "superseded", "superseded_by_deletion"} {
		t.Run(state, func(t *testing.T) {
			received := publicLifecycleResult(t, state)
			disposition := identity.ReceiptPending
			terminal := strings.HasPrefix(state, "superseded") || state == "refused"
			if terminal {
				disposition = identity.ReceiptSettled
			}
			projected, err := projectIdentityExecution(identityattempt.Lifecycle, identityExecutionResult{Disposition: disposition, Lifecycle: &received})
			if err != nil {
				t.Fatal(err)
			}
			failure := identityResultFailure(projected)
			if failure == nil || (terminal && failure.exit != exitFailure) || (!terminal && failure.exit != exitTemporary) {
				t.Fatal("lifecycle state was converted into success", state)
			}
		})
	}
}

func TestPublicRetainedParsersRejectReplacementAndFirstUseInputs(t *testing.T) {
	for _, args := range [][]string{
		{"identity", "operation", "retry", "--kind", "lifecycle"},
		{"identity", "operation", "resume", "--kind", "selection"},
		{"identity", "operation", "cancel", "--kind", "lifecycle"},
		{"identity", "operation", "status", "--kind", "selection", "--confirm-state-never-used"},
		{"identity", "operation", "retry", "--kind", "selection", "--profile", "PRIVATE_REPLACEMENT_SENTINEL"},
		{"identity", "operation", "resume", "--kind", "lifecycle", "--target-stdin"},
		{"identity", "operation", "status", "--kind", "other"},
	} {
		f := publicIdentityTestFixture(t, "")
		exit, out, stderr := f.run(t, args...)
		if exit != exitUsage || f.count("current") != 0 || strings.Contains(out+stderr, "PRIVATE_REPLACEMENT_SENTINEL") {
			t.Fatal("retained parser accepted replacement input", exit, out, stderr)
		}
	}
}

func TestPublicRetainedStatusDoesNotRequireNativeCapability(t *testing.T) {
	for _, kind := range []string{"selection", "keys-only", "lifecycle"} {
		f := publicIdentityTestFixture(t, "")
		f.capabilities = identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}
		exit, out, stderr := f.run(t, "identity", "operation", "status", "--kind", kind)
		if exit == 0 || f.count("current") != 1 || f.count("preview") != 0 {
			t.Fatal("status incorrectly required a new target capability", exit, out, stderr)
		}
		attempts := f.dependencies.IdentityAttempts.(*identityCountingFactory)
		if attempts.opens != 1 || attempts.bootstraps != 0 {
			t.Fatal("status first use was not bounded")
		}
	}
}
