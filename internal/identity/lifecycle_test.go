package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

const preparedIDWire = "lc1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const statusWire = `{"operation":{"scope":` + scopeWire + `,"target":{"kind":"subject"},"operationId":"` + preparedIDWire + `","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"pending_owners","supersededBy":null,"requiredMailboxes":2,"preparedMailboxes":0,"activatedMailboxes":0}`
const attemptWire = `{"operationId":"` + preparedIDWire + `","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`
const preparationWire = `{"operationId":"fresh_read_001","preparedOperationId":"` + preparedIDWire + `","scope":` + scopeWire + `,"expectedLifecycleVersion":0,"state":"suspended","target":{"kind":"subject"}}`
const observationWire = `{"operationId":"fresh_read_002","scope":` + scopeWire + `,"target":{"kind":"subject"},"observedVersion":0,"observedState":"active","currentHead":null,"application":{"kind":"unbound-subject"}}`

func TestTransientInputsAndSafeLifecycleAssociation(t *testing.T) {
	for _, wire := range []string{`{"kind":"account","accountAddress":"a"}`, `{"kind":"subject","subject":"\ud800","profileSource":"installed"}`, `{"kind":"subject","subject":"subject","profileSource":"migration-target"}`} {
		v := mustDecode[LifecycleInputTarget](t, wire)
		roundTrip(t, v)
		assertRecursiveClosure(t, []byte(wire), func(data []byte) error { var v LifecycleInputTarget; return json.Unmarshal(data, &v) })
	}
	for _, wire := range []string{`{"kind":"subject","subject":"s","profileFingerprint":"PRIVATE_CANARY"}`, `{"kind":"account","accountAddress":"a","subject":"s"}`, `{"kind":"subject","subject":"s","profileSource":"current"}`} {
		rejectJSON[LifecycleInputTarget](t, []byte(wire))
	}
	v := mustDecode[LifecycleAttempt](t, attemptWire)
	roundTrip(t, v)
	for _, field := range []string{`"subject":"PRIVATE_CANARY"`, `"accountAddress":"PRIVATE_CANARY"`, `"profileFingerprint":"PRIVATE_CANARY"`, `"precondition":` + preconditionWire, `"privateInputDigest":"PRIVATE_CANARY"`} {
		rejectJSON[LifecycleAttempt](t, []byte(strings.Replace(attemptWire, "{", "{"+field+",", 1)))
	}
	preparation := mustDecode[Preparation](t, preparationWire)
	attempt, e := preparation.Attempt()
	if e != nil || !attempt.OperationID.Equal(preparation.PreparedOperationID) || attempt.OperationID.Equal(preparation.OperationID) {
		t.Fatal("fresh read correlation replaced prepared ID")
	}
	if !attempt.Equal(v) {
		t.Fatal("safe prepared association changed")
	}
}
func TestPreparedAndHistoricalIDsStaySeparate(t *testing.T) {
	prepared := mustText(t, preparedIDWire)
	if ValidatePreparedOperationID(prepared) != nil || ValidateResumeOperationID(prepared) != nil {
		t.Fatal("prepared positive refused")
	}
	historical := mustText(t, "01234567-89ab-4cde-8123-0123456789ab")
	if ValidateResumeOperationID(historical) != nil || ValidatePreparedOperationID(historical) == nil {
		t.Fatal("historical continuation became new prepared apply")
	}
	for _, id := range []string{strings.Replace(preparedIDWire, "lc1_", "LC1_", 1), strings.Replace(preparedIDWire, "0123456789abcdef", "0123456789abcdeF", 1), preparedIDWire[:len(preparedIDWire)-1] + "B", strings.Repeat("a", 129)} {
		if ValidatePreparedOperationID(mustText(t, id)) == nil {
			t.Fatal("noncanonical prepared ID accepted")
		}
	}
	for _, nonce := range []string{strings.Repeat("A", 22), strings.Repeat("A", 21) + "Q", strings.Repeat("A", 21) + "g", strings.Repeat("A", 21) + "w"} {
		if ValidatePreparationNonce(nonce) != nil {
			t.Fatal("canonical nonce refused")
		}
	}
	for _, nonce := range []string{strings.Repeat("A", 21), strings.Repeat("A", 21) + "B"} {
		if ValidatePreparationNonce(nonce) == nil {
			t.Fatal("noncanonical nonce accepted")
		}
	}
	read := mustDecode[LifecycleAttempt](t, strings.Replace(attemptWire, preparedIDWire, `\ud800`, 1))
	roundTrip(t, read)
	if ValidateResumeOperationID(read.OperationID) == nil {
		t.Fatal("read ID text became signed ID")
	}
}
func TestCompleteLifecyclePublicShapesAndClosure(t *testing.T) {
	status := mustDecode[LifecycleStatus](t, statusWire)
	roundTrip(t, status)
	assertRecursiveClosure(t, []byte(statusWire), func(data []byte) error { var v LifecycleStatus; return json.Unmarshal(data, &v) })
	unbound := mustDecode[TargetObservation](t, observationWire)
	roundTrip(t, unbound)
	assertRecursiveClosure(t, []byte(observationWire), func(data []byte) error { var v TargetObservation; return json.Unmarshal(data, &v) })
	bound, e := BoundLifecycleApplication("active", &status)
	if e != nil {
		t.Fatal(e)
	}
	unbound.Application = bound
	roundTrip(t, unbound)
	data, e := json.Marshal(unbound)
	if e != nil {
		t.Fatal(e)
	}
	assertRecursiveClosure(t, data, func(data []byte) error { var v TargetObservation; return json.Unmarshal(data, &v) })
	withoutOperation := strings.Replace(string(data), `"currentOperation":`+string(mustJSON(t, status)), `"PRIVATE_CANARY":null`, 1)
	rejectJSON[TargetObservation](t, []byte(withoutOperation))
	emptyBound := `{"kind":"bound-account","effectiveState":"active","currentOperation":null}`
	mustDecode[LifecycleApplication](t, emptyBound)
	rejectJSON[LifecycleApplication](t, []byte(`{"kind":"bound-account","effectiveState":"active"}`))
	reference := LifecycleReference{Scope: status.Operation.Scope, Target: status.Operation.Target, OperationID: mustText(t, "newer_operation"), Version: 2}
	head := LifecycleHead{Scope: reference.Scope, Target: reference.Target, OperationID: reference.OperationID, Version: 2, State: "active"}
	status.CurrentHead = &head
	status.SupersededBy = &reference
	status.Status = "superseded"
	roundTrip(t, status)
	copied, e := status.Clone()
	if e != nil {
		t.Fatal(e)
	}
	copied.CurrentHead.OperationID = mustText(t, "other")
	if status.Equal(copied) {
		t.Fatal("current head ignored")
	}
	for _, mutate := range []func(*LifecycleStatus){func(v *LifecycleStatus) { v.ActivatedMailboxes = 1 }, func(v *LifecycleStatus) { v.PreparedMailboxes = 3 }, func(v *LifecycleStatus) { v.Status = "superseded"; v.SupersededBy = nil }, func(v *LifecycleStatus) { v.Version = new(SafeInteger(0)) }} {
		v := mustDecode[LifecycleStatus](t, statusWire)
		mutate(&v)
		if v.Validate() == nil {
			t.Fatal("invalid count/reference/version accepted")
		}
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return data
}
func TestLifecycleReceiptExactDispositionTable(t *testing.T) {
	attempt := mustDecode[LifecycleAttempt](t, attemptWire)
	scope := mustDecode[Scope](t, scopeWire)
	for _, state := range []string{"pending_owners", "pending_prepare", "pending_activation", "pending_service_ready", "converged", "refused", "superseded", "superseded_by_deletion"} {
		for _, source := range []ReceiptSource{LifecycleStatusSource, LifecycleApplySource, LifecycleResumeSource} {
			t.Run(state+"/"+string(source), func(t *testing.T) {
				result := mustDecode[LifecycleStatus](t, statusWire)
				result.Status = state
				if state == "superseded" {
					result.SupersededBy = &LifecycleReference{Scope: scope, Target: result.Operation.Target, OperationID: mustText(t, "newer"), Version: 2}
				}
				receipt, e := NewLifecycleReceipt(attempt, scope, source, result)
				if e != nil {
					t.Fatal(e)
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
				if ClassifyLifecycleReceipt(attempt, scope, receipt) != want {
					t.Fatal("receipt disposition changed")
				}
			})
		}
	}
}
func TestLifecycleReceiptRejectsChangedOriginalAndForgedMetadata(t *testing.T) {
	attempt := mustDecode[LifecycleAttempt](t, attemptWire)
	scope := mustDecode[Scope](t, scopeWire)
	result := mustDecode[LifecycleStatus](t, statusWire)
	result.Status = "converged"
	receipt, e := NewLifecycleReceipt(attempt, scope, LifecycleApplySource, result)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*LifecycleAttempt){func(v *LifecycleAttempt) { v.OperationID = mustText(t, "other") }, func(v *LifecycleAttempt) { v.TargetKind = "account" }, func(v *LifecycleAttempt) { v.ExpectedLifecycleVersion = 1 }, func(v *LifecycleAttempt) { v.State = "active" }} {
		v, e := attempt.Clone()
		if e != nil {
			t.Fatal(e)
		}
		mutate(&v)
		if ClassifyLifecycleReceipt(v, scope, receipt) != ReceiptMismatch {
			t.Fatal("changed original settled")
		}
	}
	wrong, e := scope.Clone()
	if e != nil {
		t.Fatal(e)
	}
	wrong.ProjectID = mustText(t, "other")
	if ClassifyLifecycleReceipt(attempt, wrong, receipt) != ReceiptMismatch {
		t.Fatal("crossed scope settled")
	}
	if _, e := NewLifecycleReceipt(attempt, scope, ReceiptSource("wire_claim"), result); e == nil {
		t.Fatal("unknown source trusted")
	}
	if ClassifyLifecycleReceipt(attempt, scope, LifecycleReceipt{}) != ReceiptMismatch {
		t.Fatal("zero receipt trusted")
	}
	if _, e := json.Marshal(receipt); e == nil {
		t.Fatal("request metadata encoded")
	}
	rejectJSON[LifecycleReceipt](t, []byte(`{"source":"apply","result":`+statusWire+`}`))
	returned, e := receipt.Result()
	if e != nil {
		t.Fatal(e)
	}
	returned.Operation.Scope.ProjectID = mustText(t, "changed")
	again, e := receipt.Result()
	if e != nil || !again.Operation.Scope.ProjectID.Equal(scope.ProjectID) {
		t.Fatal("receipt result aliases caller")
	}
}
