package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

const selectionCommandWire = `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":` + preconditionWire + `}`
const keysCommandWire = `{"operationId":"original_001","expectedConfigurationVersion":1,"keys":[` + keyWire + `],"precondition":` + preconditionWire + `}`
const selectionResultWire = `{"operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`
const keysResultWire = `{"kind":"keys-only","operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`

func TestCommandsResultsAndPreviewAreClosed(t *testing.T) {
	command := mustDecode[SelectionCommand](t, selectionCommandWire)
	roundTrip(t, command)
	keys := mustDecode[KeysCommand](t, keysCommandWire)
	roundTrip(t, keys)
	result := mustDecode[SelectionResult](t, selectionResultWire)
	roundTrip(t, result)
	keyResult := mustDecode[KeysResult](t, keysResultWire)
	roundTrip(t, keyResult)
	rejectJSON[SelectionResult](t, []byte(keysResultWire))
	rejectJSON[KeysResult](t, []byte(selectionResultWire))
	for _, kind := range []string{"migration-install", "migration-retire", "keys-only"} {
		wire := strings.Replace(selectionResultWire, `{"operationId"`, `{"kind":"`+kind+`","operationId"`, 1)
		mustDecode[OperationResult](t, wire)
		rejectJSON[SelectionResult](t, []byte(wire))
	}
	for _, reason := range []string{"migration_required", "authority_in_use"} {
		wire := strings.Replace(selectionResultWire, `{"operationId"`, `{"reason":"`+reason+`","operationId"`, 1)
		mustDecode[SelectionResult](t, wire)
	}
	request := PreviewRequest{Kind: "selection", ExpectedConfigurationVersion: 1, Target: &command.Target}
	roundTrip(t, request)
	preview := PreviewResult{Kind: request.Kind, ExpectedConfigurationVersion: 1, Target: &command.Target, Current: mustDecode[CurrentContext](t, currentWire), NativeCapabilities: NativeCapabilities{Clerk: "closed", Firebase: "available"}}
	roundTrip(t, preview)
	wire, e := json.Marshal(preview)
	if e != nil {
		t.Fatal(e)
	}
	assertRecursiveClosure(t, wire, func(data []byte) error { var v PreviewResult; return json.Unmarshal(data, &v) })
	preview.ExpectedConfigurationVersion = 2
	if preview.Validate() == nil {
		t.Fatal("crossed preview version accepted")
	}
	request.Keys = &keys.Keys
	if request.Validate() == nil {
		t.Fatal("preview accepted both kinds")
	}
	for _, data := range []string{strings.Replace(selectionCommandWire, `"expectedConfigurationVersion":1`, `"expectedConfigurationVersion":0`, 1), strings.Replace(selectionCommandWire, `"operationId":"original_001"`, `"operationId":"short"`, 1), strings.Replace(selectionCommandWire, `"precondition":`+preconditionWire, `"precondition":null`, 1)} {
		rejectJSON[SelectionCommand](t, []byte(data))
	}
}
func TestIDTypesRetainTheirDifferentBounds(t *testing.T) {
	for _, n := range []int{7, 8, 96, 97} {
		id := SelectionOperationID(strings.Repeat("a", n))
		if (id.Validate() == nil) != (n >= 8 && n <= 96) {
			t.Fatal("new ID bound changed")
		}
	}
	read, e := NewSelectionReadID(TextFromUnits([]uint16{0xd800}))
	if e != nil {
		t.Fatal(e)
	}
	roundTrip(t, read)
	if _, e := NewSelectionReadID(mustText(t, strings.Repeat("a", 255))); e != nil {
		t.Fatal(e)
	}
	if _, e := NewSelectionReadID(mustText(t, strings.Repeat("a", 256))); e == nil {
		t.Fatal("read ID overflow accepted")
	}
	rejectJSON[SelectionOperationID](t, []byte(`"\ud800"`))
	rejectJSON[CancellationOperationID](t, []byte(`null`))
}
func TestSelectionAndKeysReceiptStateTables(t *testing.T) {
	command := mustDecode[SelectionCommand](t, selectionCommandWire)
	keys := mustDecode[KeysCommand](t, keysCommandWire)
	for _, state := range []string{"prepared", "fenced", "configuration_committed", "applied", "aborting", "aborted", "refused", "deleted", "unchanged"} {
		t.Run(state, func(t *testing.T) {
			result := mustDecode[SelectionResult](t, selectionResultWire)
			result.State = state
			receipt, e := NewSelectionReceipt(command, nil, SelectionApply, result)
			if e != nil {
				t.Fatal(e)
			}
			wanted := ReceiptPending
			switch state {
			case "applied", "aborted", "refused", "deleted", "unchanged":
				wanted = ReceiptSettled
			}
			if ClassifySelectionReceipt(command, nil, receipt) != wanted {
				t.Fatal("selection disposition changed")
			}
			keyResult := mustDecode[KeysResult](t, keysResultWire)
			keyResult.State = state
			keyReceipt, e := NewKeysReceipt(keys, nil, KeysReplace, keyResult)
			if e != nil || ClassifyKeysReceipt(keys, nil, keyReceipt) != wanted {
				t.Fatal("keys disposition changed")
			}
		})
	}
	wrong := mustDecode[SelectionResult](t, selectionResultWire)
	wrong.OperationID = mustText(t, "another_001")
	if _, e := NewSelectionReceipt(command, nil, SelectionApply, wrong); e == nil {
		t.Fatal("wrong selected ID accepted")
	}
	if ClassifySelectionReceipt(command, nil, SelectionReceipt{}) != ReceiptMismatch || ClassifyKeysReceipt(keys, nil, KeysReceipt{}) != ReceiptMismatch {
		t.Fatal("zero receipt trusted")
	}
}
func TestCancellationMetadataCannotRebaseOrSettleEnrichedOriginal(t *testing.T) {
	command := mustDecode[SelectionCommand](t, selectionCommandWire)
	result := mustDecode[SelectionResult](t, selectionResultWire)
	old, e := NewSelectionReceipt(command, nil, SelectionApply, result)
	if e != nil {
		t.Fatal(e)
	}
	winner := CancellationOperationID("cancel_winner")
	loser := CancellationOperationID("cancel_loser")
	if ClassifySelectionReceipt(command, &winner, old) != ReceiptMismatch {
		t.Fatal("late original ACK cleared enrichment")
	}
	cancel, e := NewSelectionReceipt(command, &winner, SelectionCancel, result)
	if e != nil {
		t.Fatal(e)
	}
	if ClassifySelectionReceipt(command, &winner, cancel) != ReceiptSettled || ClassifySelectionReceipt(command, &loser, cancel) != ReceiptMismatch {
		t.Fatal("immutable cancellation association lost")
	}
	if _, e := NewSelectionReceipt(command, nil, SelectionCancel, result); e == nil {
		t.Fatal("cancel without ID accepted")
	}
	if _, e := NewSelectionReceipt(command, &winner, SelectionApply, result); e == nil {
		t.Fatal("apply claimed cancellation metadata")
	}
	status, e := NewSelectionReceipt(command, &winner, SelectionStatus, result)
	if e != nil || ClassifySelectionReceipt(command, &winner, status) != ReceiptSettled {
		t.Fatal("exact enriched status refused")
	}
	for _, mutate := range []func(*SelectionCommand){
		func(v *SelectionCommand) { v.OperationID = "changed_001" }, func(v *SelectionCommand) { v.ExpectedConfigurationVersion++ },
		func(v *SelectionCommand) { v.Precondition.PublishableKey = "pk_changed" }, func(v *SelectionCommand) { v.Precondition.RecoveryGeneration++ },
		func(v *SelectionCommand) { v.Precondition.Scope.EnvironmentID = mustText(t, "other") }, func(v *SelectionCommand) { v.Precondition.Scope.EnvironmentKind = "production" },
		func(v *SelectionCommand) { v.Precondition.Scope.ProjectID = mustText(t, "other") }, func(v *SelectionCommand) { v.Precondition.Scope.RelayScopeID = mustText(t, "other") },
		func(v *SelectionCommand) { v.Target = mustDecode[SelectionTarget](t, configuredWire) },
	} {
		changed, e := command.Clone()
		if e != nil {
			t.Fatal(e)
		}
		mutate(&changed)
		if ClassifySelectionReceipt(changed, &winner, cancel) != ReceiptMismatch {
			t.Fatal("changed original settled")
		}
	}
	keyCommand := mustDecode[KeysCommand](t, keysCommandWire)
	keyResult := mustDecode[KeysResult](t, keysResultWire)
	keyReceipt, e := NewKeysReceipt(keyCommand, &winner, SelectionCancel, keyResult)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := keyCommand.Clone()
	if e != nil {
		t.Fatal(e)
	}
	changed.Keys[0].Kid = mustText(t, "changed")
	if ClassifyKeysReceipt(changed, &winner, keyReceipt) != ReceiptMismatch {
		t.Fatal("changed keys settled")
	}
	for _, receipt := range []any{old, cancel, status, keyReceipt} {
		if _, e := json.Marshal(receipt); e == nil {
			t.Fatal("request receipt metadata became wire JSON")
		}
	}
	rejectJSON[SelectionReceipt](t, []byte(`{"observationSource":"cancel"}`))
	rejectJSON[KeysReceipt](t, []byte(`{}`))
}
func TestReceiptFactoriesAndResultsDoNotAlias(t *testing.T) {
	command := mustDecode[KeysCommand](t, keysCommandWire)
	result := mustDecode[KeysResult](t, keysResultWire)
	receipt, e := NewKeysReceipt(command, nil, KeysReplace, result)
	if e != nil {
		t.Fatal(e)
	}
	command.Keys[0].Kid = mustText(t, "changed")
	result.State = "refused"
	expected := mustDecode[KeysCommand](t, keysCommandWire)
	if ClassifyKeysReceipt(expected, nil, receipt) != ReceiptSettled {
		t.Fatal("receipt retained caller slice")
	}
	first, e := receipt.Result()
	if e != nil {
		t.Fatal(e)
	}
	first.Kind = new("migration-install")
	second, e := receipt.Result()
	if e != nil || second.Kind == nil || *second.Kind != "keys-only" || second.State != "applied" {
		t.Fatal("result getter aliases receipt")
	}
}

func TestOrderedKeysAndWriteOptionPresenceRemainExact(t *testing.T) {
	options := strings.Replace(keyWire, `"kid":"key-one"`, `"alg":"ES256","use":"sig","key_ops":["verify"],"ext":true,"kid":"key-one"`, 1)
	desired := mustDecode[SelectionTarget](t, strings.Replace(configuredWire, keyWire, options, 1))
	roundTrip(t, desired)
	command := mustDecode[KeysCommand](t, strings.Replace(keysCommandWire, keyWire, options, 1))
	second := mustDecode[SigningPublicKey](t, strings.Replace(keyWire, "key-one", "key-two", 1))
	command.Keys = append(command.Keys, second)
	roundTrip(t, command)
	result := mustDecode[KeysResult](t, keysResultWire)
	receipt, e := NewKeysReceipt(command, nil, KeysReplace, result)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := command.Clone()
	if e != nil {
		t.Fatal(e)
	}
	changed.Keys[0], changed.Keys[1] = changed.Keys[1], changed.Keys[0]
	if ClassifyKeysReceipt(changed, nil, receipt) != ReceiptMismatch {
		t.Fatal("ordered keys collapsed")
	}
	changed, e = command.Clone()
	if e != nil {
		t.Fatal(e)
	}
	changed.Keys[0].Algorithm = nil
	if ClassifyKeysReceipt(changed, nil, receipt) != ReceiptMismatch {
		t.Fatal("optional write field presence collapsed")
	}
	for _, r := range []string{`a\u00adb`, `a\u061cb`, `a\u200db`, `a\udb40\udc01b`} {
		wire := strings.Replace(keyWire, "key-one", r, 1)
		rejectJSON[ReplacementKeys](t, []byte("["+wire+"]"))
	}
}
