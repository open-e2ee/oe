package identity

import "testing"

func TestKindAndActionTablesAreClosed(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		if kind.Validate() != nil {
			t.Fatal("known kind refused", kind)
		}
	}
	for _, kind := range []Kind{"", "keys", "Selection", "lifecycle "} {
		if kind.Validate() == nil {
			t.Fatal("unknown kind accepted", kind)
		}
	}
	table := map[Action]struct {
		kind           Kind
		status, cancel bool
	}{
		SelectionApplyAction: {Selection, false, false}, SelectionStatusAction: {Selection, true, false}, SelectionCancelAction: {Selection, false, true},
		KeysReplaceAction: {KeysOnly, false, false}, KeysStatusAction: {KeysOnly, true, false}, KeysCancelAction: {KeysOnly, false, true},
		LifecycleApplyAction: {Lifecycle, false, false}, LifecycleStatusAction: {Lifecycle, true, false}, LifecycleResumeAction: {Lifecycle, false, false},
	}
	for action, want := range table {
		if action.Kind() != want.kind || action.Status() != want.status || action.Cancel() != want.cancel {
			t.Fatal("action table changed", action)
		}
	}
	if Action("selection-retry").Kind() != "" || Action("").Status() || Action("cancel").Cancel() {
		t.Fatal("unknown action classified")
	}
}

func TestOperationResultsClassifyByTheirExactServerID(t *testing.T) {
	for _, state := range []string{"prepared", "fenced", "configuration_committed", "applied", "aborting", "aborted", "refused", "deleted", "unchanged"} {
		want := ReceiptPending
		switch state {
		case "applied", "aborted", "refused", "deleted", "unchanged":
			want = ReceiptSettled
		}
		result := mustDecode[SelectionResult](t, selectionResultWire)
		result.State = state
		keys := mustDecode[KeysResult](t, keysResultWire)
		keys.State = state
		if ClassifySelectionResult("original_001", result) != want || ClassifyKeysResult("original_001", keys) != want {
			t.Fatal("result disposition changed", state)
		}
	}
	result := mustDecode[SelectionResult](t, selectionResultWire)
	keys := mustDecode[KeysResult](t, keysResultWire)
	if ClassifySelectionResult("another_001", result) != ReceiptMismatch || ClassifyKeysResult("another_001", keys) != ReceiptMismatch {
		t.Fatal("another operation ID trusted")
	}
	if ClassifySelectionResult("short", result) != ReceiptMismatch || ClassifySelectionResult("original_001", SelectionResult{}) != ReceiptMismatch {
		t.Fatal("invalid ID or zero result trusted")
	}
	// A keys-only result is not a selection result, and the reverse.
	if ClassifySelectionResult("original_001", SelectionResult(keys)) != ReceiptMismatch || ClassifyKeysResult("original_001", KeysResult(result)) != ReceiptMismatch {
		t.Fatal("result kind crossed")
	}
}

func TestLifecycleResultsClassifyByIDAndScope(t *testing.T) {
	scope := mustDecode[Scope](t, scopeWire)
	id := mustText(t, preparedIDWire)
	for _, state := range []string{"pending_owners", "pending_prepare", "pending_activation", "pending_service_ready", "converged", "refused", "superseded", "superseded_by_deletion"} {
		for _, source := range []ReceiptSource{LifecycleStatusSource, LifecycleApplySource, LifecycleResumeSource} {
			result := mustDecode[LifecycleStatus](t, statusWire)
			result.Status = state
			if state == "superseded" {
				result.SupersededBy = &LifecycleReference{Scope: scope, Target: result.Operation.Target, OperationID: mustText(t, "newer"), Version: 2}
			}
			want := ReceiptPending
			switch state {
			case "converged":
				want = ReceiptSettled
				if source == LifecycleStatusSource {
					want = ReceiptContinuationRequired
				}
			case "refused", "superseded", "superseded_by_deletion":
				want = ReceiptSettled
			}
			if ClassifyLifecycleResult(id, scope, source, result) != want {
				t.Fatal("lifecycle result disposition changed", state, source)
			}
		}
	}
	result := mustDecode[LifecycleStatus](t, statusWire)
	other := scope
	other.EnvironmentKind = "production"
	if ClassifyLifecycleResult(mustText(t, "another"), scope, LifecycleStatusSource, result) != ReceiptMismatch ||
		ClassifyLifecycleResult(id, other, LifecycleStatusSource, result) != ReceiptMismatch ||
		ClassifyLifecycleResult(id, scope, "retry", result) != ReceiptMismatch ||
		ClassifyLifecycleResult(id, scope, LifecycleStatusSource, LifecycleStatus{}) != ReceiptMismatch {
		t.Fatal("a lifecycle result outside its ID, scope or source was trusted")
	}
}
