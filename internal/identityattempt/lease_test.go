package identityattempt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
)

func storeSelectionReceipt(t *testing.T, value Envelope, state string, source identity.SelectionReceiptSource) identity.SelectionReceipt {
	t.Helper()
	attempt, err := value.RetainedAttempt()
	if err != nil || attempt == nil {
		t.Fatal("receipt fixture lacks original")
	}
	command, err := attempt.SelectionCommand()
	if err != nil {
		t.Fatal(err)
	}
	result := identity.SelectionResult{OperationID: recordText(t, string(command.OperationID)), State: state, ConfigurationVersion: 2, AdmissionRevision: 0}
	receipt, err := identity.NewSelectionReceipt(command, cancellationPointer(*attempt), source, result)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func storeKeysReceipt(t *testing.T, value Envelope, state string, source identity.SelectionReceiptSource) identity.KeysReceipt {
	t.Helper()
	attempt, err := value.RetainedAttempt()
	if err != nil || attempt == nil {
		t.Fatal("receipt fixture lacks original")
	}
	command, err := attempt.KeysCommand()
	if err != nil {
		t.Fatal(err)
	}
	result := identity.KeysResult{Kind: new("keys-only"), OperationID: recordText(t, string(command.OperationID)), State: state, ConfigurationVersion: 2, AdmissionRevision: 0}
	receipt, err := identity.NewKeysReceipt(command, cancellationPointer(*attempt), source, result)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func storeLifecycleReceipt(t *testing.T, value Envelope, state string, source identity.ReceiptSource) (identity.Scope, identity.LifecycleReceipt) {
	t.Helper()
	attempt, err := value.RetainedAttempt()
	if err != nil || attempt == nil {
		t.Fatal("receipt fixture lacks original")
	}
	command, err := attempt.LifecycleCommand()
	if err != nil {
		t.Fatal(err)
	}
	scope := recordDecode[identity.Precondition](t, recordPrecondition).Scope
	scope.EnvironmentKind = value.Slot().Environment()
	result := identity.LifecycleStatus{Operation: identity.LifecycleOperation{Scope: scope, Target: identity.LifecyclePublicTarget{Kind: command.TargetKind}, OperationID: command.OperationID, ExpectedVersion: command.ExpectedLifecycleVersion}, Version: new(identity.SafeInteger(1)), State: command.State, EffectiveState: command.State, Status: state}
	receipt, err := identity.NewLifecycleReceipt(command, scope, source, result)
	if err != nil {
		t.Fatal(err)
	}
	return scope, receipt
}

func storeResolveSettled(t *testing.T, lease *Lease, value Envelope) Resolution {
	t.Helper()
	var result Resolution
	var err error
	switch value.Slot().Kind() {
	case Selection:
		result, err = lease.ResolveSelection(storeContext(t), value, storeSelectionReceipt(t, value, "applied", identity.SelectionApply))
	case KeysOnly:
		result, err = lease.ResolveKeys(storeContext(t), value, storeKeysReceipt(t, value, "applied", identity.KeysReplace))
	case Lifecycle:
		scope, receipt := storeLifecycleReceipt(t, value, "converged", identity.LifecycleApplySource)
		result, err = lease.ResolveLifecycle(storeContext(t), value, scope, receipt)
	}
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestStoreFullCASAndDetachedRead(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			_, _, lease, original := storeOccupied(t, kind)
			stale, _ := NewVacantEnvelope(original.Slot(), 1)
			_, err := lease.Retain(storeContext(t), stale, storeAttempt(t, kind))
			requireStoreError(t, err, ErrChanged)
			_, err = lease.Retain(storeContext(t), original, storeAttempt(t, kind))
			requireStoreError(t, err, ErrChanged)
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(original) || original.Revision() != 2 {
				t.Fatal("original retention changed")
			}
			attempt, err := actual.RetainedAttempt()
			if err != nil || attempt == nil {
				t.Fatal("original disappeared")
			}
			if kind == Selection {
				attempt.selection.OperationID = "changed"
			}
			if kind == KeysOnly {
				attempt.keys.OperationID = "changed"
			}
			if kind == Lifecycle {
				attempt.lifecycle.OperationID = recordText(t, "changed")
			}
			again, err := lease.Read(storeContext(t))
			if err != nil || !again.Equal(original) {
				t.Fatal("read aliases persistent original")
			}
		})
	}
}

func TestStoreCurrentNamespaceBetweenConfirmAndBegin(t *testing.T) {
	cases := []struct {
		name, fixture string
		action        Action
	}{
		{"selection-apply", "selection-original", SelectionApplyAction},
		{"selection-cancel", "selection-cancel", SelectionCancelAction},
		{"selection-status-original", "selection-original", SelectionStatusAction},
		{"selection-status-cancel", "selection-cancel", SelectionStatusAction},
		{"keys-replace", "keys-original", KeysReplaceAction},
		{"keys-cancel", "keys-cancel", KeysCancelAction},
		{"keys-status-original", "keys-original", KeysStatusAction},
		{"keys-status-cancel", "keys-cancel", KeysStatusAction},
		{"lifecycle-apply", "lifecycle-original", LifecycleApplyAction},
		{"lifecycle-resume", "lifecycle-original", LifecycleResumeAction},
		{"lifecycle-status", "lifecycle-original", LifecycleStatusAction},
		{"lifecycle-preparation", "lifecycle-preparation", ""},
	}
	for _, test := range cases {
		for _, problem := range storeCurrentNamespaceProblems() {
			t.Run(test.name+"/"+problem, func(t *testing.T) {
				fixture := storeReadyCase(t, test.fixture)
				var occupied *DispatchPermit
				var preparation *PreparationPermit
				var err error
				if fixture.preparation {
					preparation, err = fixture.lease.ConfirmPreparation(storeContext(t), fixture.expected)
				} else {
					occupied, err = fixture.lease.Confirm(storeContext(t), fixture.expected, test.action)
				}
				if err != nil || occupied == nil && preparation == nil {
					t.Fatal("positive permit fixture failed", err)
				}
				storeDamageCurrentNamespace(t, fixture, problem)
				before := storeCurrentTree(t, fixture)
				if preparation != nil {
					call, beginErr := preparation.Begin(storeContext(t))
					if call != nil {
						t.Fatal("uncertain namespace returned a preparation call")
					}
					err = beginErr
					if fixture.lease.permits[preparation.token].consumed {
						t.Fatal("refused preparation consumed its token")
					}
				} else {
					call, beginErr := occupied.Begin(storeContext(t), test.action)
					if call != nil {
						t.Fatal("uncertain namespace returned an occupied call")
					}
					err = beginErr
					if fixture.lease.permits[occupied.token].consumed || fixture.lease.occupiedCallUsed {
						t.Fatal("refused occupied call consumed dispatch authority")
					}
				}
				requireStoreError(t, err, storeCurrentNamespaceError(problem))
				storeAssertCurrentRefusal(t, fixture, before, err)
				// No call is returned. Actual HTTP dispatch remains a control-package obligation.
			})
		}
	}
}

func TestStoreCurrentNamespaceBeforeReceiptResolution(t *testing.T) {
	for _, name := range []string{"selection-original", "selection-cancel", "keys-original", "keys-cancel", "lifecycle-original"} {
		for _, problem := range storeCurrentNamespaceProblems() {
			t.Run(name+"/"+problem, func(t *testing.T) {
				fixture := storeReadyCase(t, name)
				attempt, err := fixture.expected.RetainedAttempt()
				if err != nil || attempt == nil {
					t.Fatal("resolution fixture lacks retained attempt")
				}
				var resolve func() (Resolution, error)
				switch fixture.expected.Slot().Kind() {
				case Selection:
					state, source := "applied", identity.SelectionApply
					if _, present := attempt.CancellationID(); present {
						state, source = "aborted", identity.SelectionCancel
					}
					receipt := storeSelectionReceipt(t, fixture.expected, state, source)
					command, _ := attempt.SelectionCommand()
					if identity.ClassifySelectionReceipt(command, cancellationPointer(*attempt), receipt) != identity.ReceiptSettled {
						t.Fatal("selection receipt is not a positive settlement fixture")
					}
					resolve = func() (Resolution, error) {
						return fixture.lease.ResolveSelection(storeContext(t), fixture.expected, receipt)
					}
				case KeysOnly:
					state, source := "applied", identity.KeysReplace
					if _, present := attempt.CancellationID(); present {
						state, source = "aborted", identity.SelectionCancel
					}
					receipt := storeKeysReceipt(t, fixture.expected, state, source)
					command, _ := attempt.KeysCommand()
					if identity.ClassifyKeysReceipt(command, cancellationPointer(*attempt), receipt) != identity.ReceiptSettled {
						t.Fatal("keys receipt is not a positive settlement fixture")
					}
					resolve = func() (Resolution, error) {
						return fixture.lease.ResolveKeys(storeContext(t), fixture.expected, receipt)
					}
				case Lifecycle:
					scope, receipt := storeLifecycleReceipt(t, fixture.expected, "converged", identity.LifecycleApplySource)
					command, _ := attempt.LifecycleCommand()
					if identity.ClassifyLifecycleReceipt(command, scope, receipt) != identity.ReceiptSettled {
						t.Fatal("lifecycle receipt is not a positive settlement fixture")
					}
					resolve = func() (Resolution, error) {
						return fixture.lease.ResolveLifecycle(storeContext(t), fixture.expected, scope, receipt)
					}
				default:
					t.Fatal("unknown receipt fixture kind")
				}
				storeDamageCurrentNamespace(t, fixture, problem)
				before := storeCurrentTree(t, fixture)
				result, err := resolve()
				if _, cloneErr := result.Envelope(); cloneErr == nil {
					t.Fatal("uncertain namespace returned a resolution envelope")
				}
				requireStoreError(t, err, storeCurrentNamespaceError(problem))
				storeAssertCurrentRefusal(t, fixture, before, err)
			})
		}
	}
}

func TestStoreCurrentNamespaceBeforeRetentionAndCancellationCAS(t *testing.T) {
	for _, name := range []string{"retain-selection", "retain-keys", "retain-lifecycle", "cancel-selection", "cancel-keys"} {
		for _, problem := range storeCurrentNamespaceProblems() {
			t.Run(name+"/"+problem, func(t *testing.T) {
				kind := Selection
				if name == "retain-keys" || name == "cancel-keys" {
					kind = KeysOnly
				}
				if name == "retain-lifecycle" {
					kind = Lifecycle
				}
				store, location := storeReady(t)
				lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := lease.Close(); err != nil {
						t.Error(err)
					}
				})
				value, err := lease.Read(storeContext(t))
				if err != nil {
					t.Fatal(err)
				}
				if kind == Lifecycle {
					permit, err := lease.ConfirmPreparation(storeContext(t), value)
					if err != nil {
						t.Fatal(err)
					}
					call, err := permit.Begin(storeContext(t))
					if err != nil {
						t.Fatal(err)
					}
					if err := call.Join(); err != nil {
						t.Fatal(err)
					}
				}
				attempt := storeAttempt(t, kind)
				if attempt.Validate() != nil {
					t.Fatal("retention attempt is not a valid positive fixture")
				}
				cancel := name == "cancel-selection" || name == "cancel-keys"
				if cancel {
					value, err = lease.Retain(storeContext(t), value, attempt)
					if err != nil {
						t.Fatal(err)
					}
				}
				fixture := storeReadyFixture{store: store, location: location, lease: lease, expected: value}
				storeDamageCurrentNamespace(t, fixture, problem)
				before := storeCurrentTree(t, fixture)
				if cancel {
					_, err = lease.AppendCancellation(storeContext(t), value, "cancel_001")
				} else {
					_, err = lease.Retain(storeContext(t), value, attempt)
				}
				requireStoreError(t, err, storeCurrentNamespaceError(problem))
				storeAssertCurrentRefusal(t, fixture, before, err)
			})
		}
	}
}

func TestStoreImmutableCancellationAndLateOriginalReceipt(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly} {
		t.Run(string(kind), func(t *testing.T) {
			_, _, lease, original := storeOccupied(t, kind)
			enriched, err := lease.AppendCancellation(storeContext(t), original, "cancel_001")
			if err != nil || enriched.Revision() != original.Revision()+1 {
				t.Fatal("cancellation did not append once", err)
			}
			again, err := lease.AppendCancellation(storeContext(t), enriched, "cancel_001")
			if err != nil || !again.Equal(enriched) {
				t.Fatal("same cancellation replaced winner")
			}
			_, err = lease.AppendCancellation(storeContext(t), enriched, "cancel_002")
			requireStoreError(t, err, ErrChanged)
			if kind == Selection {
				oldReceipt := storeSelectionReceipt(t, original, "applied", identity.SelectionApply)
				_, err = lease.ResolveSelection(storeContext(t), original, oldReceipt)
				requireStoreError(t, err, ErrChanged)
				_, err = lease.ResolveSelection(storeContext(t), enriched, oldReceipt)
				requireStoreError(t, err, ErrReceiptMismatch)
				pending, err := lease.ResolveSelection(storeContext(t), enriched, storeSelectionReceipt(t, enriched, "aborting", identity.SelectionCancel))
				if err != nil || pending.Disposition() != identity.ReceiptPending {
					t.Fatal("pending cancellation settled")
				}
				settled, err := lease.ResolveSelection(storeContext(t), enriched, storeSelectionReceipt(t, enriched, "aborted", identity.SelectionCancel))
				if err != nil || settled.Disposition() != identity.ReceiptSettled {
					t.Fatal("exact cancellation failed")
				}
			} else {
				oldReceipt := storeKeysReceipt(t, original, "applied", identity.KeysReplace)
				_, err = lease.ResolveKeys(storeContext(t), original, oldReceipt)
				requireStoreError(t, err, ErrChanged)
				_, err = lease.ResolveKeys(storeContext(t), enriched, oldReceipt)
				requireStoreError(t, err, ErrReceiptMismatch)
				settled, err := lease.ResolveKeys(storeContext(t), enriched, storeKeysReceipt(t, enriched, "aborted", identity.SelectionCancel))
				if err != nil || settled.Disposition() != identity.ReceiptSettled {
					t.Fatal("exact cancellation failed")
				}
			}
		})
	}
}

func TestStoreLifecycleDispositionAndActualScope(t *testing.T) {
	_, _, lease, original := storeOccupied(t, Lifecycle)
	for _, source := range []identity.ReceiptSource{identity.LifecycleStatusSource, identity.LifecycleApplySource} {
		scope, receipt := storeLifecycleReceipt(t, original, "converged", source)
		if source == identity.LifecycleStatusSource {
			wrong, _ := scope.Clone()
			wrong.ProjectID = recordText(t, "other")
			_, err := lease.ResolveLifecycle(storeContext(t), original, wrong, receipt)
			requireStoreError(t, err, ErrReceiptMismatch)
			result, err := lease.ResolveLifecycle(storeContext(t), original, scope, receipt)
			if err != nil || result.Disposition() != identity.ReceiptContinuationRequired {
				t.Fatal("status cleared uncertainty")
			}
			current, err := lease.Read(storeContext(t))
			if err != nil || !current.Equal(original) {
				t.Fatal("status changed retained original")
			}
		} else {
			result, err := lease.ResolveLifecycle(storeContext(t), original, scope, receipt)
			if err != nil || result.Disposition() != identity.ReceiptSettled {
				t.Fatal("apply ACK did not settle")
			}
			vacant, err := result.Envelope()
			if err != nil || vacant.Revision() != original.Revision()+1 {
				t.Fatal("settlement revision changed")
			}
			attempt, _ := vacant.RetainedAttempt()
			if attempt != nil {
				t.Fatal("settled attempt remained occupied")
			}
		}
	}
}

func TestStoreNineOccupiedPermitActionsAndCopySafety(t *testing.T) {
	for _, action := range []Action{SelectionApplyAction, KeysReplaceAction, SelectionCancelAction, KeysCancelAction, LifecycleApplyAction, LifecycleResumeAction, SelectionStatusAction, KeysStatusAction, LifecycleStatusAction} {
		t.Run(string(action), func(t *testing.T) {
			kind := Selection
			if action == KeysReplaceAction || action == KeysCancelAction || action == KeysStatusAction {
				kind = KeysOnly
			}
			if action == LifecycleApplyAction || action == LifecycleResumeAction || action == LifecycleStatusAction {
				kind = Lifecycle
			}
			_, _, lease, original := storeOccupied(t, kind)
			if action == SelectionCancelAction || action == KeysCancelAction {
				var err error
				original, err = lease.AppendCancellation(storeContext(t), original, "cancel_001")
				if err != nil {
					t.Fatal(err)
				}
			}
			permit, err := lease.Confirm(storeContext(t), original, action)
			if err != nil {
				t.Fatal(err)
			}
			copy := *permit
			if _, err := permit.Begin(storeContext(t), Action("wrong")); err == nil {
				t.Fatal("wrong action consumed token")
			}
			call, err := copy.Begin(storeContext(t), action)
			if err != nil || call.Action() != action || !call.Slot().Equal(original.Slot()) {
				t.Fatal("exact call failed", err)
			}
			if _, err := permit.Begin(storeContext(t), action); err == nil {
				t.Fatal("copied permit dispatched twice")
			}
			if _, err := lease.Read(storeContext(t)); !errors.Is(err, ErrBusy) {
				t.Fatal("state phase overlapped call")
			}
			requireStoreError(t, lease.Close(), ErrBusy)
			deadline, bounded := call.Context().Deadline()
			if !bounded || time.Until(deadline) > callLimit || deadline.After(lease.deadline) {
				t.Fatal("call budget escaped lease")
			}
			retained, err := call.Attempt()
			want, _ := original.RetainedAttempt()
			if err != nil || want == nil || !retained.Equal(*want) {
				t.Fatal("call changed retained fields")
			}
			if _, err := json.Marshal(call); err == nil {
				t.Fatal("call serialized")
			}
			if err := call.Join(); err != nil {
				t.Fatal(err)
			}
			if err := call.Join(); err != nil {
				t.Fatal("join not idempotent")
			}
			if call.Context().Err() == nil {
				t.Fatal("joined call context still dispatchable")
			}
			if _, err := lease.Confirm(storeContext(t), original, action); err == nil {
				t.Fatal("invocation admitted another occupied call")
			}
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(original) {
				t.Fatal("join resolved or changed original")
			}
		})
	}
}

func TestStorePreparationTracksOneJoinedRead(t *testing.T) {
	store, _ := storeReady(t)
	lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, Lifecycle), SlotNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	vacant, err := lease.Read(storeContext(t))
	if err != nil {
		t.Fatal(err)
	}
	permit, err := lease.ConfirmPreparation(storeContext(t), vacant)
	if err != nil {
		t.Fatal(err)
	}
	call, err := permit.Begin(storeContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Retain(storeContext(t), vacant, storeAttempt(t, Lifecycle)); !errors.Is(err, ErrBusy) {
		t.Fatal("retention overlapped preparation")
	}
	if err := lease.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("active preparation closed")
	}
	if err := call.Join(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.ConfirmPreparation(storeContext(t), vacant); err == nil {
		t.Fatal("second preparation admitted")
	}
	occupied, err := lease.Retain(storeContext(t), vacant, storeAttempt(t, Lifecycle))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Confirm(storeContext(t), occupied, LifecycleApplyAction); err != nil {
		t.Fatal(err)
	}
	// No HTTP handler exists in these module tests. This proves tracking, not preparation provenance.
}

func TestStoreJoinAndCleanupRemainPossibleAfterExpiry(t *testing.T) {
	_, _, lease, original := storeOccupied(t, Selection)
	permit, err := lease.Confirm(storeContext(t), original, SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), callLimit+time.Second)
	defer cancel()
	call, err := permit.Begin(ctx, SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-call.Context().Done():
	case <-time.After(callLimit + time.Second):
		t.Fatal("bounded call did not expire")
	}
	requireStoreError(t, lease.Close(), ErrBusy)
	requireStoreError(t, call.Join(), ErrTimeout)
	if err := call.Join(); err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	lease.deadline = time.Now().Add(-time.Second)
	lease.mu.Unlock()
	if _, err := lease.Read(storeContext(t)); !errors.Is(err, ErrTimeout) {
		t.Fatal("phase admitted after logical expiry")
	}
	if err := lease.Close(); err != nil {
		t.Fatal("expired lease could not release", err)
	}
	if _, err := permit.Begin(storeContext(t), SelectionApplyAction); !errors.Is(err, ErrChanged) {
		t.Fatal("closed permit remained usable")
	}
}

func TestStoreIdentityEnvironmentExactConfirmation(t *testing.T) {
	for _, value := range []string{"wrong", " original_001", "original_001 "} {
		t.Run(value, func(t *testing.T) {
			_, _, lease, original := storeOccupied(t, Selection)
			t.Setenv("OE_OPERATION_ID", value)
			_, err := lease.Confirm(storeContext(t), original, SelectionApplyAction)
			requireStoreError(t, err, ErrOperationIDMismatch)
		})
	}
	_, _, lease, original := storeOccupied(t, Selection)
	t.Setenv("OE_OPERATION_ID", "original_001")
	if _, err := lease.Confirm(storeContext(t), original, SelectionApplyAction); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OE_OPERATION_ID", "")
	enriched, err := lease.AppendCancellation(storeContext(t), original, "cancel_001")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OE_OPERATION_ID", "cancel_001")
	if _, err := lease.Confirm(storeContext(t), enriched, SelectionCancelAction); err != nil {
		t.Fatal(err)
	}
	_, err = lease.Confirm(storeContext(t), enriched, SelectionStatusAction)
	requireStoreError(t, err, ErrOperationIDMismatch)
}

func TestStoreEnvironmentCannotInitializeContext(t *testing.T) {
	location := storeFixtureLocation(t)
	t.Setenv("OE_OPERATION_ID", "original_001")
	_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
	requireStoreError(t, err, ErrOperationIDUnretained)
	if _, err := os.Stat(location.path()); !os.IsNotExist(err) {
		t.Fatal("environment ID initialized store")
	}
	t.Setenv("OE_OPERATION_ID", "")
	store, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OE_OPERATION_ID", "original_001")
	_, err = store.EnrollFirstUse(storeContext(t), recordSlot(t, Selection), SlotNeverUsed)
	requireStoreError(t, err, ErrOperationIDUnretained)
	lock, record := storePaths(t, location, recordSlot(t, Selection))
	for _, path := range []string{lock, record} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("environment ID created context")
		}
	}
}

func TestStoreRevisionExhaustionNeverErases(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		for _, occupied := range []bool{false, true} {
			t.Run(string(kind)+"/"+map[bool]string{false: "vacant", true: "occupied"}[occupied], func(t *testing.T) {
				store, location, lease, original := storeOccupied(t, kind)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				var value Envelope
				var err error
				maximum := identity.SafeInteger(identity.MaximumSafeInteger)
				if occupied {
					attempt, _ := original.RetainedAttempt()
					value, err = NewOccupiedEnvelope(original.Slot(), maximum, *attempt)
				} else {
					value, err = NewVacantEnvelope(original.Slot(), maximum)
				}
				if err != nil {
					t.Fatal(err)
				}
				storeReplaceRecord(t, location, value, recordEncoded(t, value))
				lease, err = store.BeginExisting(storeContext(t), value.Slot())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := lease.Close(); err != nil {
						t.Error(err)
					}
				}()
				if !occupied {
					if kind == Lifecycle {
						permit, err := lease.ConfirmPreparation(storeContext(t), value)
						if err != nil {
							t.Fatal(err)
						}
						call, err := permit.Begin(storeContext(t))
						if err != nil || call.Join() != nil {
							t.Fatal("preparation tracking fixture failed")
						}
					}
					_, err = lease.Retain(storeContext(t), value, storeAttempt(t, kind))
				} else {
					if kind != Lifecycle {
						_, err = lease.AppendCancellation(storeContext(t), value, "cancel_001")
						requireStoreError(t, err, ErrRevisionExhausted)
					}
					switch kind {
					case Selection:
						_, err = lease.ResolveSelection(storeContext(t), value, storeSelectionReceipt(t, value, "applied", identity.SelectionApply))
					case KeysOnly:
						_, err = lease.ResolveKeys(storeContext(t), value, storeKeysReceipt(t, value, "applied", identity.KeysReplace))
					case Lifecycle:
						scope, receipt := storeLifecycleReceipt(t, value, "converged", identity.LifecycleApplySource)
						_, err = lease.ResolveLifecycle(storeContext(t), value, scope, receipt)
					}
				}
				requireStoreError(t, err, ErrRevisionExhausted)
				actual, err := lease.Read(storeContext(t))
				if err != nil || !actual.Equal(value) {
					t.Fatal("revision exhaustion erased or advanced state")
				}
			})
		}
	}
}

func TestStoreBoundedContextsClosedAndExpiredPermits(t *testing.T) {
	store, _, lease, original := storeOccupied(t, Selection)
	_, err := lease.Read(context.Background())
	requireStoreError(t, err, ErrTimeout)
	_, err = store.BeginExisting(context.Background(), original.Slot())
	requireStoreError(t, err, ErrTimeout)
	permit, err := lease.Confirm(storeContext(t), original, SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = permit.Begin(storeContext(t), SelectionApplyAction)
	requireStoreError(t, err, ErrChanged)
	lease, err = store.BeginExisting(storeContext(t), original.Slot())
	if err != nil {
		t.Fatal(err)
	}
	permit, err = lease.Confirm(storeContext(t), original, SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	lease.deadline = time.Now().Add(-time.Second)
	_, err = permit.Begin(storeContext(t), SelectionApplyAction)
	requireStoreError(t, err, ErrTimeout)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	// Logical expiry cannot force a stalled kernel call to return. No timed unlock exists.
}

func TestStoreUnconsumedPermitFullCASAndStaleJoin(t *testing.T) {
	_, _, lease, original := storeOccupied(t, Selection)
	permit, err := lease.Confirm(storeContext(t), original, SelectionApplyAction)
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := lease.AppendCancellation(storeContext(t), original, "cancel_001")
	if err != nil {
		t.Fatal(err)
	}
	_, err = permit.Begin(storeContext(t), SelectionApplyAction)
	requireStoreError(t, err, ErrChanged)
	cancelPermit, err := lease.Confirm(storeContext(t), enriched, SelectionCancelAction)
	if err != nil {
		t.Fatal(err)
	}
	call, err := cancelPermit.Begin(storeContext(t), SelectionCancelAction)
	if err != nil {
		t.Fatal(err)
	}
	stale := &DispatchCall{lease: lease, token: permit.token}
	requireStoreError(t, stale.Join(), ErrChanged)
	requireStoreError(t, lease.Close(), ErrBusy)
	if err := call.Join(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreConfirmationComparesEveryRetainedContext(t *testing.T) {
	store, _ := storeReady(t)
	lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, Selection), SlotNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	vacant, err := lease.Read(storeContext(t))
	if err != nil {
		t.Fatal(err)
	}
	command := recordDecode[identity.SelectionCommand](t, recordSelectionWire)
	command.Target = recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
	keys := *command.Target.Keys
	second, err := keys[0].Clone()
	if err != nil {
		t.Fatal(err)
	}
	second.Kid = recordText(t, "key_2")
	keys[0].Extractable = new(false)
	keys = append(keys, second)
	command.Target.Keys = &keys
	if _, err := NewSelectionAttempt(command); !errors.Is(err, ErrEnvelope) {
		t.Fatal("non-extractable public selection fixture was accepted")
	}
	keys[0].Extractable = new(true)
	attempt, err := NewSelectionAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	original, err := lease.Retain(storeContext(t), vacant, attempt)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range []string{"operation", "expected-version", "precondition", "optional-presence", "key-order", "cancellation", "slot", "revision"} {
		t.Run(vector, func(t *testing.T) {
			copy, err := attempt.SelectionCommand()
			if err != nil {
				t.Fatal(err)
			}
			slot, revision := original.Slot(), original.Revision()
			switch vector {
			case "operation":
				copy.OperationID = "other_original"
			case "expected-version":
				copy.ExpectedConfigurationVersion++
			case "precondition":
				copy.Precondition.RecoveryGeneration++
			case "optional-presence":
				(*copy.Target.Keys)[0].Extractable = nil
			case "key-order":
				(*copy.Target.Keys)[0], (*copy.Target.Keys)[1] = (*copy.Target.Keys)[1], (*copy.Target.Keys)[0]
			case "slot":
				slot.organization = "org_other"
			case "revision":
				revision++
			}
			changed, err := NewSelectionAttempt(copy)
			if err != nil {
				t.Fatal("changed context fixture invalid", err)
			}
			if vector == "cancellation" {
				changed, err = changed.WithCancellation("cancel_001")
				if err != nil {
					t.Fatal(err)
				}
			}
			expected, err := NewOccupiedEnvelope(slot, revision, changed)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := lease.Confirm(storeContext(t), expected, SelectionApplyAction)
			requireStoreError(t, err, ErrChanged)
			if permit != nil {
				t.Fatal("changed context returned permit")
			}
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(original) {
				t.Fatal("changed re-entry replaced original")
			}
		})
	}
}

// This context models delayed timer notification. It does not model native I/O.
type storeDelayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (v storeDelayedDeadlineContext) Deadline() (time.Time, bool) { return v.deadline, true }

func TestStoreJoinChecksLogicalDeadlineBeforeTimerNotification(t *testing.T) {
	for _, name := range []string{"selection-original", "lifecycle-preparation"} {
		t.Run(name, func(t *testing.T) {
			fixture := storeReadyCase(t, name)
			var token uint64
			var join func() error
			if fixture.preparation {
				permit, err := fixture.lease.ConfirmPreparation(storeContext(t), fixture.expected)
				if err != nil {
					t.Fatal(err)
				}
				call, err := permit.Begin(storeContext(t))
				if err != nil {
					t.Fatal(err)
				}
				token, join = call.token, call.Join
			} else {
				permit, err := fixture.lease.Confirm(storeContext(t), fixture.expected, SelectionApplyAction)
				if err != nil {
					t.Fatal(err)
				}
				call, err := permit.Begin(storeContext(t), SelectionApplyAction)
				if err != nil {
					t.Fatal(err)
				}
				token, join = call.token, call.Join
			}
			state := fixture.lease.permits[token]
			originalContext := state.callContext
			if originalContext.Err() != nil {
				t.Fatal("positive call context already expired")
			}
			state.callContext = storeDelayedDeadlineContext{Context: originalContext, deadline: time.Now().Add(-time.Second)}
			if state.callContext.Err() != nil {
				t.Fatal("controlled timer notification was not delayed")
			}
			fixture.lease.permits[token] = state
			requireStoreError(t, join(), ErrTimeout)
			if fixture.lease.active || !fixture.lease.permits[token].joined || originalContext.Err() == nil {
				t.Fatal("expired call was not joined and canceled")
			}
			if fixture.lease.preparationJoined {
				t.Fatal("expired preparation gained retention authority")
			}
			if err := join(); err != nil {
				t.Fatal("repeat join after expiry failed", err)
			}
			actual, err := fixture.lease.Read(storeContext(t))
			if err != nil || !actual.Equal(fixture.expected) {
				t.Fatal("expired join changed full retained envelope")
			}
			if fixture.preparation {
				_, err := fixture.lease.Retain(storeContext(t), fixture.expected, storeAttempt(t, Lifecycle))
				requireStoreError(t, err, ErrContinuationUnsupported)
			} else if !fixture.lease.occupiedCallUsed {
				t.Fatal("expired occupied call became reusable")
			}
			if err := fixture.lease.Close(); err != nil {
				t.Fatal("joined expired call blocked checked cleanup", err)
			}
		})
	}
}
