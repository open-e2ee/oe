package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
)

func publicLifecycleResult(t *testing.T, status string) identity.LifecycleStatus {
	t.Helper()
	superseded := `null`
	if status == "superseded" {
		superseded = `{"scope":` + scopeExecutionWire + `,"target":{"kind":"subject"},"operationId":"new_exact_002","version":2}`
	}
	return executionDecode[identity.LifecycleStatus](t, `{"operation":{"scope":`+scopeExecutionWire+`,"target":{"kind":"subject"},"operationId":"old_exact_001","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"`+status+`","supersededBy":`+superseded+`,"requiredMailboxes":0,"preparedMailboxes":0,"activatedMailboxes":0}`)
}

func TestPublicExecutionErrorsKeepTheExactSafeNextStep(t *testing.T) {
	for _, environment := range []string{"sandbox", "production"} {
		for _, kind := range []identity.Kind{identity.Selection, identity.KeysOnly, identity.Lifecycle} {
			t.Run("unknown-"+string(kind)+"-"+environment, func(t *testing.T) {
				f := publicIdentityTestFixture(t, "")
				id := "unknown_exact_001"
				if kind == identity.Lifecycle {
					id = preparedExecutionID
				}
				exit, out, stderr := f.run(t, "--env", environment, "identity", "operation", "status", "--kind", string(kind), "--operation-id", id)
				refusal := decodeEvent(t, []byte(out))
				if exit != exitFailure || stderr != "" || refusal.Code != "IDENTITY_OPERATION_NOT_FOUND" ||
					refusal.Data["operationId"] != id || refusal.Data["kind"] != string(kind) {
					t.Fatal("an unknown operation lost its failure contract", exit, out, stderr)
				}
				if refusal.Next != "oe identity current --env "+environment {
					t.Fatal("an unknown operation loops to status by the same ID", out)
				}
				if f.count("current") != 1 || f.count("preview") != 0 {
					t.Fatal("status of an unknown operation caused other reads", f.calls)
				}
				f.requireNoMutation(t)
			})
		}
	}
	for _, kind := range []identity.Kind{identity.Selection, identity.KeysOnly, identity.Lifecycle} {
		failure := identityExecutionFailure(identityOperationError(kind, "original_001", &control.APIError{Code: "IDENTITY_RESULT_INVALID"}), "production")
		value, ok := errors.AsType[*problem](failure)
		if !ok || value.exit != exitTemporary || value.next != "oe identity operation status --kind "+string(kind)+" --operation-id original_001 --env production" ||
			value.data["operationId"] != "original_001" || value.data["kind"] != kind {
			t.Fatal("an uncertain execution omitted its exact status step")
		}
	}
	failure := identityExecutionFailure(&control.APIError{Code: "IDENTITY_RESULT_INVALID"}, "sandbox")
	if value, ok := errors.AsType[*problem](failure); !ok || value.next != "oe help identity" || value.data != nil {
		t.Fatal("a failure before dispatch invented an operation ID")
	}
	failure = identityExecutionFailure(identityOperationError(identity.Selection, "original_001", &control.APIError{Code: "AUTHENTICATION_REQUIRED"}), "sandbox")
	value, ok := errors.AsType[*problem](failure)
	if !ok || value.next != "oe auth login" || value.data["operationId"] != "original_001" {
		t.Fatal("status advice replaced required authentication")
	}
}

func TestPublicOperationActionTableIsClosedAndKindSpecific(t *testing.T) {
	expected := map[identity.Kind]map[string]identity.Action{
		identity.Selection: {"status": identity.SelectionStatusAction, "cancel": identity.SelectionCancelAction},
		identity.KeysOnly:  {"status": identity.KeysStatusAction, "cancel": identity.KeysCancelAction},
		identity.Lifecycle: {"status": identity.LifecycleStatusAction, "resume": identity.LifecycleResumeAction},
	}
	for _, kind := range []identity.Kind{identity.Selection, identity.KeysOnly, identity.Lifecycle, "unknown"} {
		for _, verb := range []string{"status", "retry", "resume", "cancel", "apply", "forget", "replace", ""} {
			if got := identityOperationAction(verb, kind); got != expected[kind][verb] {
				t.Fatal("operation action crossed kind", kind, verb, got)
			}
		}
	}
}

func TestPublicResultProjectionKeepsActualTerminalStateAfterClear(t *testing.T) {
	for _, state := range []string{"applied", "aborted", "unchanged", "refused", "deleted"} {
		t.Run(state, func(t *testing.T) {
			received := executionDecode[identity.SelectionResult](t, `{"operationId":"original_001","state":"`+state+`","configurationVersion":2,"admissionRevision":1}`)
			result := identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &received}
			projected, err := projectIdentityExecution(identity.Selection, result)
			if err != nil || projected.OperationID != "original_001" || projected.Status != state || projected.ServiceReadiness != "unverified" {
				t.Fatal("actual settled result lost its state or selected ID", err)
			}
			failure := identityResultFailure(projected, "")
			refused := state == "refused" || state == "deleted"
			if (failure != nil) != refused {
				t.Fatal("terminal refusal became success", state)
			}
			data, err := json.Marshal(projected)
			if err != nil || strings.Contains(string(data), "precondition") || strings.Contains(string(data), "envelope") {
				t.Fatal("projection exposed the command envelope", err)
			}
		})
	}
}

func TestPublicResultProjectionRequiresExactlyOneConsistentTypedKind(t *testing.T) {
	selection := executionDecode[identity.SelectionResult](t, `{"operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`)
	keys := executionDecode[identity.KeysResult](t, `{"kind":"keys-only","operationId":"original_001","state":"applied","configurationVersion":2,"admissionRevision":1}`)
	life := publicLifecycleResult(t, "converged")
	for _, invalid := range []struct {
		kind   identity.Kind
		result identityExecutionResult
	}{
		{identity.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled}},
		{identity.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled, Keys: &keys}},
		{identity.KeysOnly, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identity.Lifecycle, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identity.Selection, identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection, Lifecycle: &life}},
		{"unknown", identityExecutionResult{Disposition: identity.ReceiptSettled, Selection: &selection}},
		{identity.Selection, identityExecutionResult{Disposition: identity.ReceiptMismatch, Selection: &selection}},
	} {
		if _, err := projectIdentityExecution(invalid.kind, invalid.result); err == nil {
			t.Fatal("mismatched or ambiguous receipt kind was projected")
		}
	}
}

func TestPublicLifecycleStatusAndResumeHaveDifferentReceiptSemantics(t *testing.T) {
	received := publicLifecycleResult(t, "converged")
	id, err := identity.Text("old_exact_001")
	if err != nil {
		t.Fatal(err)
	}
	scope := executionDecode[identity.Scope](t, scopeExecutionWire)
	for _, source := range []identity.ReceiptSource{identity.LifecycleStatusSource, identity.LifecycleApplySource, identity.LifecycleResumeSource} {
		disposition := identity.ClassifyLifecycleResult(id, scope, source, received)
		result := identityExecutionResult{Disposition: disposition, Lifecycle: &received}
		projected, err := projectIdentityExecution(identity.Lifecycle, result)
		if err != nil || projected.Status != "converged" || projected.OperationID != "old_exact_001" {
			t.Fatal("actual receipt metadata lost", err)
		}
		failure := identityResultFailure(projected, "")
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
			projected, err := projectIdentityExecution(identity.Lifecycle, identityExecutionResult{Disposition: disposition, Lifecycle: &received})
			if err != nil {
				t.Fatal(err)
			}
			failure := identityResultFailure(projected, "")
			if failure == nil || (terminal && failure.exit != exitFailure) || (!terminal && failure.exit != exitTemporary) {
				t.Fatal("lifecycle state was converted into success", state)
			}
		})
	}
}

func TestPublicOperationParsersRejectReplacementInputs(t *testing.T) {
	for _, args := range [][]string{
		{"identity", "operation", "retry", "--kind", "selection", "--operation-id", "original_001"},
		{"identity", "operation", "resume", "--kind", "selection", "--operation-id", "original_001"},
		{"identity", "operation", "cancel", "--kind", "lifecycle", "--operation-id", "original_001"},
		{"identity", "operation", "cancel", "--kind", "selection"},
		{"identity", "operation", "resume", "--kind", "lifecycle"},
		{"identity", "operation", "status", "--kind", "lifecycle"},
		{"identity", "operation", "status", "--kind", "selection", "--target-stdin"},
		{"identity", "operation", "status", "--kind", "lifecycle", "--operation-id", "original_001", "--target-stdin"},
		{"identity", "operation", "status", "--kind", "selection", "--operation-id", "PRIVATE REPLACEMENT SENTINEL"},
		{"identity", "operation", "cancel", "--kind", "selection", "--operation-id", "original_001", "--profile", "PRIVATE_REPLACEMENT_SENTINEL"},
		{"identity", "operation", "resume", "--kind", "lifecycle", "--operation-id", "original_001", "--target-stdin"},
		{"identity", "operation", "status", "--kind", "other"},
	} {
		f := publicIdentityTestFixture(t, "")
		exit, out, stderr := f.run(t, args...)
		if exit != exitUsage || f.count("/v1/auth/session") != 0 || strings.Contains(out+stderr, "PRIVATE_REPLACEMENT_SENTINEL") {
			t.Fatal("operation parser accepted replacement input", args, exit, out, stderr)
		}
	}
}

func TestPublicOperationStatusDoesNotRequireNativeCapability(t *testing.T) {
	for _, kind := range []string{"selection", "keys-only", "lifecycle"} {
		f := publicIdentityTestFixture(t, "")
		f.capabilities = identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}
		id := "original_001"
		if kind == "lifecycle" {
			id = preparedExecutionID
		}
		exit, out, stderr := f.run(t, "identity", "operation", "status", "--kind", kind, "--operation-id", id)
		if exit != exitFailure || !strings.Contains(out, `"code":"IDENTITY_OPERATION_NOT_FOUND"`) || f.count("current") != 1 || f.count("preview") != 0 {
			t.Fatal("status incorrectly required a new target capability", exit, out, stderr)
		}
		f.requireNoMutation(t)
	}
}

// operationEnvironment sets OE_OPERATION_ID for every later fixture run.
func (f *publicIdentityFixture) operationEnvironment(id string) {
	f.dependencies.Getenv = func(key string) string {
		if key == "OE_OPERATION_ID" {
			return id
		}
		return ""
	}
}

// rewriteIdentity replaces the identity that both environments declare.
func (f *publicIdentityFixture) rewriteIdentity(t *testing.T, wire string) {
	t.Helper()
	source := config.New("sample")
	target := executionDecode[identity.SelectionTarget](t, wire)
	source.Environments.Sandbox.Identity = &target
	production, err := target.Clone()
	if err != nil {
		t.Fatal(err)
	}
	source.Environments.Production.Identity = &production
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if err := config.Create(f.path, source); err != nil {
		t.Fatal(err)
	}
}

func publicOperation(t *testing.T, out string) map[string]any {
	t.Helper()
	value, _ := decodeEvent(t, []byte(out)).Data["operation"].(map[string]any)
	if value == nil {
		t.Fatal("the result named no operation", out)
	}
	return value
}

func TestIdentitySelectReplaysSameOperationID(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.operationEnvironment("replay_exact_001")
	exit, first, stderr := f.run(t, "identity", "select", "--env", "sandbox")
	if exit != 0 || stderr != "" {
		t.Fatal("the first selection failed", exit, first, stderr)
	}
	exit, second, stderr := f.run(t, "identity", "select", "--env", "sandbox")
	if exit != 0 || stderr != "" {
		t.Fatal("the repeated selection failed", exit, second, stderr)
	}
	receipt := publicOperation(t, first)
	if receipt["operationId"] != "replay_exact_001" || receipt["status"] != "applied" || !reflect.DeepEqual(receipt, publicOperation(t, second)) {
		t.Fatal("the repeat did not return the same receipt", first, second)
	}
	if f.count("select") != 2 || f.operationCount("select") != 1 {
		t.Fatal("the same operation ID created a second server operation", f.calls)
	}
}

func TestIdentitySelectChangedInputSurfacesRetryConflict(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.operationEnvironment("replay_exact_001")
	if exit, out, stderr := f.run(t, "identity", "select", "--env", "sandbox"); exit != 0 {
		t.Fatal("the first selection failed", exit, out, stderr)
	}
	f.rewriteIdentity(t, publicClerkWire)
	exit, out, stderr := f.run(t, "identity", "select", "--env", "sandbox")
	refusal := decodeEvent(t, []byte(out))
	if exit != exitFailure || refusal.Code != "IDENTITY_CONFLICT" || refusal.Data["operationId"] != "replay_exact_001" || refusal.Data["kind"] != "selection" ||
		refusal.Next != "oe identity operation status --kind selection --operation-id replay_exact_001 --env sandbox" {
		t.Fatal("a changed command under one operation ID did not conflict", exit, out, stderr)
	}
	if f.count("select") != 2 || f.operationCount("select") != 1 {
		t.Fatal("the conflict replaced the server operation", f.calls)
	}
}

func TestIdentityLifecycleRefusesOperationEnvironment(t *testing.T) {
	for _, verb := range []string{"suspend", "activate"} {
		t.Run(verb, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.operationEnvironment("replay_exact_001")
			f.dependencies.In = strings.NewReader(publicTargetWire)
			exit, out, stderr := f.run(t, "identity", "lifecycle", verb, "--target-stdin", "--env", "sandbox")
			refusal := decodeEvent(t, []byte(out))
			if exit != exitUsage || refusal.Code != "IDENTITY_OPERATION_CONFLICT" ||
				refusal.Next != "oe identity operation resume --kind lifecycle --operation-id ID --env sandbox" {
				t.Fatal("a lifecycle command accepted OE_OPERATION_ID", exit, out, stderr)
			}
			if strings.Contains(out+stderr, "PRIVATE_TARGET_SENTINEL") {
				t.Fatal("the refusal echoed the private target")
			}
			f.requireNoMutation(t)
		})
	}
}

// requireNoLocalState fails when the directory holds any entry.
func requireNoLocalState(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("the command wrote local state", directory, err, entries)
	}
}

func TestIdentityOperationStatusWithoutIDReadsServerSelection(t *testing.T) {
	for _, kind := range []string{"selection", "keys-only"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "APPDATA", "LOCALAPPDATA"} {
				t.Setenv(name, home)
			}
			f := publicIdentityTestFixture(t, "")
			current := executionDecode[identity.OperationResult](t, selectionExecutionResult("server_exact_001", "applied", kind == "keys-only"))
			f.current.Configuration.Selection = &current
			before := publicConfigBytes(t, f.path)
			directory, err := os.ReadDir(filepath.Dir(f.path))
			if err != nil {
				t.Fatal(err)
			}
			exit, out, stderr := f.run(t, "identity", "operation", "status", "--kind", kind)
			operation := publicOperation(t, out)
			if exit != 0 || stderr != "" || operation["operationId"] != "server_exact_001" || operation["kind"] != kind || operation["status"] != "applied" {
				t.Fatal("status without an ID did not report the server operation", exit, out, stderr)
			}
			read := "current"
			if kind == "keys-only" {
				read = "keys-read"
			}
			if f.count(read) != 1 || f.count("selection-operation") != 0 {
				t.Fatal("status without an ID read the wrong server value", f.calls)
			}
			requireNoLocalState(t, home)
			after, err := os.ReadDir(filepath.Dir(f.path))
			if err != nil || len(after) != len(directory) || string(publicConfigBytes(t, f.path)) != string(before) {
				t.Fatal("status changed the project directory")
			}
			f.requireNoMutation(t)
		})
	}
	t.Run("other-kind", func(t *testing.T) {
		f := publicIdentityTestFixture(t, "")
		current := executionDecode[identity.OperationResult](t, selectionExecutionResult("server_exact_001", "applied", true))
		f.current.Configuration.Selection = &current
		exit, out, stderr := f.run(t, "identity", "operation", "status", "--kind", "selection")
		if exit != exitFailure || decodeEvent(t, []byte(out)).Code != "IDENTITY_OPERATION_NOT_FOUND" {
			t.Fatal("selection status reported a keys-only operation", exit, out, stderr)
		}
		f.requireNoMutation(t)
	})
}

func TestIdentityOperationStatusNeverMutates(t *testing.T) {
	reads := []string{"/v1/auth/session", "/v1/projects/sample", "current", "selection-operation", "keys-read", "operation", "target"}
	for _, args := range [][]string{
		{"--kind", "selection"},
		{"--kind", "selection", "--operation-id", "held_exact_001"},
		{"--kind", "keys-only"},
		{"--kind", "keys-only", "--operation-id", "held_keys_001"},
		{"--kind", "lifecycle", "--operation-id", preparedExecutionID},
		{"--kind", "lifecycle", "--target-stdin"},
		{"--kind", "selection", "--operation-id", "unknown_exact_001"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.operations["held_exact_001"] = publicIdentityOperation{action: "select", result: selectionExecutionResult("held_exact_001", "prepared", false)}
			f.operations["held_keys_001"] = publicIdentityOperation{action: "keys-replace", result: selectionExecutionResult("held_keys_001", "applied", true)}
			f.operations[preparedExecutionID] = publicIdentityOperation{action: "apply", result: lifecycleExecutionResult("sandbox", preparedExecutionID, "suspended", "pending_owners")}
			f.dependencies.In = strings.NewReader(publicTargetWire)
			exit, out, stderr := f.run(t, append([]string{"identity", "operation", "status"}, args...)...)
			if exit == exitUsage || strings.Contains(out+stderr, "PRIVATE_TARGET_SENTINEL") {
				t.Fatal("status was not a server read", exit, out, stderr)
			}
			f.requireNoMutation(t)
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, call := range f.calls {
				if !slices.Contains(reads, call) {
					t.Fatal("status sent a call that is not a read", call)
				}
			}
		})
	}
}

func TestIdentityLostSelectionReplyRecoversByStatusAndReplay(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.lose["select"] = true
	exit, out, stderr := f.run(t, "identity", "select", "--env", "sandbox")
	failure := decodeEvent(t, []byte(out))
	id, _ := failure.Data["operationId"].(string)
	if exit != exitTemporary || failure.Code != "IDENTITY_UNAVAILABLE" || !strings.HasPrefix(id, "oe_") ||
		failure.Next != "oe identity operation status --kind selection --operation-id "+id+" --env sandbox" {
		t.Fatal("a lost reply did not name its operation", exit, out, stderr)
	}
	f.lose["select"] = false
	exit, out, stderr = f.run(t, strings.Fields(strings.TrimPrefix(failure.Next, "oe "))...)
	if exit != 0 || publicOperation(t, out)["operationId"] != id || publicOperation(t, out)["status"] != "applied" {
		t.Fatal("status by the reported ID did not read the server operation", exit, out, stderr)
	}
	f.operationEnvironment(id)
	exit, out, stderr = f.run(t, "identity", "select", "--env", "sandbox")
	if exit != 0 || publicOperation(t, out)["operationId"] != id || f.operationCount("select") != 1 {
		t.Fatal("the repeat with the reported ID did not replay", exit, out, stderr)
	}
}

func TestIdentityPendingSelectionNamesRepeatAndCancelAborts(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.state = "prepared"
	exit, out, stderr := f.run(t, "identity", "select", "--env", "sandbox")
	pending := decodeEvent(t, []byte(out))
	operation, _ := pending.Data["operation"].(map[string]any)
	id, _ := operation["operationId"].(string)
	if exit != exitTemporary || pending.Code != "IDENTITY_PENDING" || !strings.HasPrefix(id, "oe_") ||
		!strings.Contains(pending.Error, "OE_OPERATION_ID="+id+" oe identity select --env sandbox") ||
		pending.Next != "oe identity operation status --kind selection --operation-id "+id+" --env sandbox" {
		t.Fatal("a pending selection did not name its repeat", exit, out, stderr)
	}
	exit, out, stderr = f.run(t, "identity", "operation", "cancel", "--kind", "selection", "--operation-id", id, "--env", "sandbox")
	if exit != 0 || publicOperation(t, out)["operationId"] != id || publicOperation(t, out)["status"] != "aborted" || f.count("selection-cancel") != 1 {
		t.Fatal("cancel did not abort the server operation", exit, out, stderr)
	}
	exit, out, stderr = f.run(t, "identity", "operation", "cancel", "--kind", "keys-only", "--operation-id", id, "--env", "sandbox")
	if exit != exitFailure || decodeEvent(t, []byte(out)).Code != "IDENTITY_OPERATION_NOT_FOUND" {
		t.Fatal("a keys-only cancel reached a selection operation", exit, out, stderr)
	}
}

func TestIdentityLostLifecycleReplyRecoversByStatusAndResume(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	f.lose["apply"] = true
	f.dependencies.In = strings.NewReader(publicTargetWire)
	exit, out, stderr := f.run(t, "identity", "lifecycle", "suspend", "--target-stdin", "--env", "sandbox")
	failure := decodeEvent(t, []byte(out))
	if exit != exitTemporary || failure.Code != "IDENTITY_UNAVAILABLE" || failure.Data["operationId"] != preparedExecutionID || failure.Data["kind"] != "lifecycle" ||
		failure.Next != "oe identity operation status --kind lifecycle --operation-id "+preparedExecutionID+" --env sandbox" {
		t.Fatal("a lost lifecycle reply did not name its prepared operation", exit, out, stderr)
	}
	f.lose["apply"] = false
	exit, out, stderr = f.run(t, strings.Fields(strings.TrimPrefix(failure.Next, "oe "))...)
	continuation := decodeEvent(t, []byte(out))
	if exit != exitTemporary || continuation.Code != "IDENTITY_CONTINUATION_REQUIRED" ||
		continuation.Next != "oe identity operation resume --kind lifecycle --operation-id "+preparedExecutionID+" --env sandbox" {
		t.Fatal("status did not name the resume of the same operation", exit, out, stderr)
	}
	exit, out, stderr = f.run(t, strings.Fields(strings.TrimPrefix(continuation.Next, "oe "))...)
	if exit != 0 || publicOperation(t, out)["operationId"] != preparedExecutionID || publicOperation(t, out)["status"] != "converged" ||
		f.count("resume") != 1 || f.count("prepare") != 1 || f.count("apply") != 1 {
		t.Fatal("resume did not continue the same lifecycle operation", exit, out, stderr)
	}
}

func TestIdentityProductionConsentNextIsRunnable(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	exit, out, stderr := f.run(t, "identity", "select", "--env", "production")
	refusal := decodeEvent(t, []byte(out))
	if exit != exitUsage || refusal.Code != "CONFIRMATION_REQUIRED" || f.count("select") != 0 || !strings.HasPrefix(refusal.Next, "oe identity select ") {
		t.Fatal("Production selection did not require consent", exit, out, stderr)
	}
	exit, out, stderr = f.run(t, strings.Fields(strings.TrimPrefix(refusal.Next, "oe "))...)
	if exit != 0 || f.operationCount("select") != 1 || publicOperation(t, out)["environment"] != "production" {
		t.Fatal("the consent next did not run", refusal.Next, exit, out, stderr)
	}
}

func TestIdentitySettledRefusalDoesNotBecomeSuccess(t *testing.T) {
	for _, state := range []string{"refused", "deleted"} {
		t.Run(state, func(t *testing.T) {
			f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
			f.state = state
			exit, out, stderr := f.run(t, "identity", "select", "--env", "sandbox")
			if exit != exitFailure || decodeEvent(t, []byte(out)).Code != "IDENTITY_OPERATION_REFUSED" || f.operationCount("select") != 1 {
				t.Fatal("a settled refusal became success", exit, out, stderr)
			}
		})
	}
}
