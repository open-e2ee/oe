package identityattempt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

type storeStageFailure struct {
	stage string
	hits  int
}

func (o *storeStageFailure) Observe(stage string) error {
	if stage == o.stage {
		o.hits++
		return ErrPersistence
	}
	return nil
}

type storeStageRecorder struct{ stages []string }

func (o *storeStageRecorder) Observe(stage string) error {
	o.stages = append(o.stages, stage)
	return nil
}

type storeStageAction struct {
	stage  string
	action func() error
}

func (o *storeStageAction) Observe(stage string) error {
	if stage == o.stage {
		return o.action()
	}
	return nil
}

type storeCommitFixture struct {
	store         *Store
	location      Location
	lease         *Lease
	before, after Envelope
	operation     func() error
}

func storeCommitCase(t *testing.T, name string) storeCommitFixture {
	t.Helper()
	store, location := storeReady(t)
	kind := Selection
	if strings.HasSuffix(name, "keys") {
		kind = KeysOnly
	}
	if strings.HasSuffix(name, "lifecycle") {
		kind = Lifecycle
	}
	slot := recordSlot(t, kind)
	fixture := storeCommitFixture{store: store, location: location}
	if strings.HasPrefix(name, "initial-") {
		fixture.after, _ = NewVacantEnvelope(slot, 1)
		fixture.operation = func() error {
			lease, err := store.EnrollFirstUse(storeContext(t), slot, SlotNeverUsed)
			if err != nil {
				return err
			}
			return lease.Close()
		}
		return fixture
	}
	lease, err := store.EnrollFirstUse(storeContext(t), slot, SlotNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	fixture.lease = lease
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	fixture.before, err = lease.Read(storeContext(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(name, "retain-") {
		if kind == Lifecycle {
			permit, err := lease.ConfirmPreparation(storeContext(t), fixture.before)
			if err != nil {
				t.Fatal(err)
			}
			call, err := permit.Begin(storeContext(t))
			if err != nil || call.Join() != nil {
				t.Fatal("preparation tracking fixture failed")
			}
		}
		attempt := storeAttempt(t, kind)
		fixture.after, _ = NewOccupiedEnvelope(slot, fixture.before.Revision()+1, attempt)
		fixture.operation = func() error { _, err := lease.Retain(storeContext(t), fixture.before, attempt); return err }
	} else {
		fixture.before = storeRetain(t, lease)
		if strings.HasPrefix(name, "cancel-") {
			attempt, _ := fixture.before.RetainedAttempt()
			enriched, err := attempt.WithCancellation("cancel_001")
			if err != nil {
				t.Fatal(err)
			}
			fixture.after, _ = NewOccupiedEnvelope(slot, fixture.before.Revision()+1, enriched)
			fixture.operation = func() error {
				_, err := lease.AppendCancellation(storeContext(t), fixture.before, "cancel_001")
				return err
			}
		} else {
			fixture.after, _ = NewVacantEnvelope(slot, fixture.before.Revision()+1)
			fixture.operation = func() error {
				var err error
				switch kind {
				case Selection:
					_, err = lease.ResolveSelection(storeContext(t), fixture.before, storeSelectionReceipt(t, fixture.before, "applied", identity.SelectionApply))
				case KeysOnly:
					_, err = lease.ResolveKeys(storeContext(t), fixture.before, storeKeysReceipt(t, fixture.before, "applied", identity.KeysReplace))
				case Lifecycle:
					scope, receipt := storeLifecycleReceipt(t, fixture.before, "converged", identity.LifecycleApplySource)
					_, err = lease.ResolveLifecycle(storeContext(t), fixture.before, scope, receipt)
				}
				return err
			}
		}
	}
	return fixture
}

func storeCommitContexts() []string {
	return []string{"initial-vacant-selection", "initial-vacant-keys", "initial-vacant-lifecycle", "retain-selection", "retain-keys", "retain-lifecycle", "cancel-selection", "cancel-keys", "settle-selection", "settle-keys", "settle-lifecycle"}
}

// These99 rows inject a controlled phase refusal. They do not claim a native syscall error.
func TestStoreControlledCommitFailures(t *testing.T) {
	stages := []struct {
		name, point string
		installed   bool
	}{
		{"temp-create", "before-temp-create", false}, {"write", "before-write", false},
		{"file-flush", "before-file-flush", false}, {"file-close", "before-file-close", false},
		{"replace", "before-replace", false}, {"platform-barrier", "before-platform-barrier", true},
		{"post-open-security", "before-post-open-security", true}, {"readback", "before-readback", true},
		{"canonical-compare", "before-canonical-compare", true},
	}
	for _, name := range storeCommitContexts() {
		for _, stage := range stages {
			if !t.Run(name+"/"+stage.name, func(t *testing.T) {
				fixture := storeCommitCase(t, name)
				observer := &storeStageFailure{stage: stage.point}
				fixture.store.location.observer = observer
				if fixture.lease != nil {
					fixture.lease.observer = observer
				}
				err := fixture.operation()
				requireStoreError(t, err, ErrPersistence)
				if observer.hits != 1 {
					t.Fatal("controlled failure point was not reached exactly once")
				}
				_, path := storePaths(t, fixture.location, fixture.after.Slot())
				actual, readErr := os.ReadFile(path)
				if stage.installed {
					if readErr != nil || !bytes.Equal(actual, recordEncoded(t, fixture.after)) {
						t.Fatal("installed next state was rolled back or altered")
					}
				} else if fixture.before.Validate() == nil {
					if readErr != nil || !bytes.Equal(actual, recordEncoded(t, fixture.before)) {
						t.Fatal("original state changed before replace")
					}
				} else if !os.IsNotExist(readErr) {
					t.Fatal("initial record appeared before replace")
				}
				if fixture.lease != nil {
					if err := fixture.lease.Close(); err != nil {
						t.Fatal(err)
					}
				}
				// No permit or transport exists in this operation. Orphan evidence is retained.
			}) {
				return
			}
		}
	}
}

func TestStoreCommitOrderAndStableLock(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			_, location, lease, original := storeOccupied(t, kind)
			lockPath, _ := storePaths(t, location, original.Slot())
			before, err := os.Stat(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &storeStageRecorder{}
			lease.observer = recorder
			action := SelectionApplyAction
			if kind == KeysOnly {
				action = KeysReplaceAction
			}
			if kind == Lifecycle {
				action = LifecycleApplyAction
			}
			permit, err := lease.Confirm(storeContext(t), original, action)
			if err != nil || permit == nil {
				t.Fatal("complete confirmation failed", err)
			}
			expected := []string{"before-temp-create", "temporary-created", "before-write", "partial-write-observed", "complete-write-returned", "before-file-flush", "file-flush-returned", "before-file-close", "checked-close-returned", "before-replace", nativeReplacePhase(), "before-platform-barrier"}
			if phase := nativeDirectoryBarrierPhase(); phase != "" {
				expected = append(expected, phase)
			}
			expected = append(expected, "before-post-open-security", "before-readback", "before-canonical-compare", "canonical-readback-returned")
			ready := []string{"ready-before-structure", "ready-before-open", "ready-opened", "ready-canonical-read-returned", "ready-before-file-flush", "ready-file-flush-returned", "ready-before-file-close", "ready-checked-close-returned", "ready-before-parent-barrier", storeReadyParentPoint(), "ready-before-readback", "ready-canonical-readback-returned"}
			expected = append(ready, expected...)
			if strings.Join(expected, ",") != strings.Join(recorder.stages, ",") {
				t.Fatal("native phase order changed")
			}
			after, err := os.Stat(lockPath)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("record replacement changed stable lock identity")
			}
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(original) {
				t.Fatal("confirmation advanced revision or changed a field")
			}
		})
	}
}

func TestStoreReadbackMismatchNeverReturnsPermit(t *testing.T) {
	_, location, lease, original := storeOccupied(t, Selection)
	_, path := storePaths(t, location, original.Slot())
	lease.observer = &storeStageAction{stage: "before-readback", action: func() error {
		data, err := os.ReadFile(path)
		if err != nil {
			return ErrPersistence
		}
		data = bytes.Replace(data, []byte(`"revision":2`), []byte(`"revision":3`), 1)
		if os.WriteFile(path, data, 0o600) != nil {
			return ErrPersistence
		}
		return nil
	}}
	permit, err := lease.Confirm(storeContext(t), original, SelectionApplyAction)
	requireStoreError(t, err, ErrPersistence)
	if permit != nil {
		t.Fatal("mismatched actual readback returned a permit")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte(`"revision":3`)) {
		t.Fatal("mismatched installed bytes were rolled back")
	}
}

type storeFailedCloser struct{ calls int }

func (c *storeFailedCloser) Close() error { c.calls++; return errors.New("controlled close failure") }

func TestStoreSoleAbsenceAndCheckedReleaseComposition(t *testing.T) {
	closer := &storeFailedCloser{}
	release := releaseFile(closer)
	if closer.calls != 1 || release != ErrRelease {
		t.Fatal("checked close failure disappeared")
	}
	for _, primary := range []error{errMissing, errExists, ErrUnsafe, ErrChanged, ErrPersistence} {
		joined := combine(primary, release)
		if !errors.Is(joined, primary) || !errors.Is(joined, ErrRelease) {
			t.Fatal("primary or release error disappeared")
		}
		if soleMissing(joined) {
			t.Fatal("joined failure became an absence observation or first use")
		}
	}
	if !soleMissing(combine(errMissing, nil)) || soleMissing(nil) || soleMissing(ErrChanged) {
		t.Fatal("sole absence classification changed")
	}
	if combine(nil, ErrRelease) != ErrRelease || combine(nil, nil) != nil {
		t.Fatal("release-only result changed")
	}
	// This is a controlled composition test. It is not a native close-error claim.
}

func TestStoreNoPhaseBeginsAfterContextExpiry(t *testing.T) {
	fixture := storeCommitCase(t, "retain-selection")
	ctx, cancel := context.WithCancel(storeContext(t))
	cancel()
	_, err := fixture.lease.Retain(ctx, fixture.before, storeAttempt(t, Selection))
	requireStoreError(t, err, ErrTimeout)
	entries, err := os.ReadDir(filepath.Join(fixture.location.path(), "v1"))
	if err != nil || len(entries) != 1 {
		t.Fatal("expired phase created temporary state")
	}
}

func TestStoreActualClosedLockReleaseFailureRemainsVisible(t *testing.T) {
	_, location, lease, original := storeOccupied(t, Selection)
	if err := lease.lock.Close(); err != nil {
		t.Fatal("owned lock close fixture failed")
	}
	err := lease.Close()
	requireStoreError(t, err, ErrRelease)
	_, path := storePaths(t, location, original.Slot())
	data, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(data, recordEncoded(t, original)) {
		t.Fatal("release failure rewrote retained record")
	}
	if err := lease.Close(); err != nil {
		t.Fatal("idempotent close repeated release after failure")
	}
	// The fixture deliberately closes its own descriptor. It tests real invalid-handle
	// release paths, not arbitrary kernel failure or delayed resource release.
}

func TestStoreCancellationAtMutationBoundaries(t *testing.T) {
	for _, point := range []string{"before-temp-create", "before-write", "before-file-flush", "before-replace", nativeReplacePhase()} {
		t.Run(point, func(t *testing.T) {
			fixture := storeCommitCase(t, "retain-selection")
			ctx, cancel := context.WithCancel(storeContext(t))
			defer cancel()
			seen := false
			fixture.lease.observer = &storeStageAction{stage: point, action: func() error { seen = true; cancel(); return nil }}
			_, err := fixture.lease.Retain(ctx, fixture.before, storeAttempt(t, Selection))
			requireStoreError(t, err, ErrTimeout)
			if !seen {
				t.Fatal("cancellation fixture did not reach its exact native phase")
			}
			_, path := storePaths(t, fixture.location, fixture.before.Slot())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if point == nativeReplacePhase() {
				if !bytes.Equal(data, recordEncoded(t, fixture.after)) {
					t.Fatal("post-timeout installed bytes were rolled back or treated as vacant")
				}
			} else if !bytes.Equal(data, recordEncoded(t, fixture.before)) {
				t.Fatal("pre-replace cancellation changed original")
			}
			entries, err := os.ReadDir(filepath.Join(fixture.location.path(), "v1"))
			if err != nil {
				t.Fatal(err)
			}
			if point == "before-temp-create" && len(entries) != 1 {
				t.Fatal("cancellation before creation created a temporary")
			}
			if point == "before-write" {
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".") {
						info, err := entry.Info()
						if err != nil || info.Size() != 0 {
							t.Fatal("write began after logical cancellation")
						}
					}
				}
			}
			if err := fixture.lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreCancellationNeverMintsEitherPermit(t *testing.T) {
	for _, preparation := range []bool{false, true} {
		t.Run(map[bool]string{false: "occupied", true: "preparation"}[preparation], func(t *testing.T) {
			kind := Selection
			if preparation {
				kind = Lifecycle
			}
			store, _ := storeReady(t)
			lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			}()
			value, err := lease.Read(storeContext(t))
			if err != nil {
				t.Fatal(err)
			}
			if !preparation {
				value = storeRetain(t, lease)
			}
			ctx, cancel := context.WithCancel(storeContext(t))
			defer cancel()
			lease.observer = &storeStageAction{stage: nativeReplacePhase(), action: func() error { cancel(); return nil }}
			if preparation {
				permit, err := lease.ConfirmPreparation(ctx, value)
				if permit != nil {
					t.Fatal("canceled preparation returned permit")
				}
				requireStoreError(t, err, ErrTimeout)
			} else {
				permit, err := lease.Confirm(ctx, value, SelectionApplyAction)
				if permit != nil {
					t.Fatal("canceled occupied confirmation returned permit")
				}
				requireStoreError(t, err, ErrTimeout)
			}
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(value) {
				t.Fatal("post-timeout identical install altered current retained state")
			}
		})
	}
}

func storeReadyContexts() []string {
	return []string{"selection-original", "selection-cancel", "keys-original", "keys-cancel", "lifecycle-original", "lifecycle-preparation"}
}

type storeReadyFixture struct {
	store       *Store
	location    Location
	lease       *Lease
	expected    Envelope
	preparation bool
	action      Action
}

func storeReadyCase(t *testing.T, name string) storeReadyFixture {
	t.Helper()
	kind := Selection
	if strings.HasPrefix(name, "keys-") {
		kind = KeysOnly
	}
	if strings.HasPrefix(name, "lifecycle-") {
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
	preparation := name == "lifecycle-preparation"
	if !preparation {
		value = storeRetain(t, lease)
	}
	action := SelectionApplyAction
	if kind == KeysOnly {
		action = KeysReplaceAction
	}
	if kind == Lifecycle {
		action = LifecycleApplyAction
	}
	if strings.HasSuffix(name, "-cancel") {
		value, err = lease.AppendCancellation(storeContext(t), value, "cancel_001")
		if err != nil {
			t.Fatal(err)
		}
		if kind == Selection {
			action = SelectionCancelAction
		} else {
			action = KeysCancelAction
		}
	}
	return storeReadyFixture{store, location, lease, value, preparation, action}
}

func (f storeReadyFixture) confirm(ctx context.Context) (bool, error) {
	if f.preparation {
		permit, err := f.lease.ConfirmPreparation(ctx, f.expected)
		return permit != nil, err
	}
	permit, err := f.lease.Confirm(ctx, f.expected, f.action)
	return permit != nil, err
}

func storeReadyParentPoint() string {
	if nativeDirectoryBarrierPhase() == "" {
		return "ready-parent-check-returned"
	}
	return "ready-parent-fsync-returned"
}

func TestStoreReadyRepeatBothPermitsAndExactOriginals(t *testing.T) {
	for _, name := range storeReadyContexts() {
		t.Run(name, func(t *testing.T) {
			fixture := storeReadyCase(t, name)
			path := filepath.Join(fixture.location.path(), "store.json")
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &storeStageRecorder{}
			fixture.lease.observer = recorder
			minted, err := fixture.confirm(storeContext(t))
			if err != nil || !minted {
				t.Fatal("current ready qualification failed", err)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("ready repeat replaced manifest object")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != readyManifest {
				t.Fatal("ready repeat rewrote manifest bytes")
			}
			actual, err := fixture.lease.Read(storeContext(t))
			if err != nil || !actual.Equal(fixture.expected) {
				t.Fatal("ready repeat changed full original/cancellation context")
			}
			joined := strings.Join(recorder.stages, ",")
			if !strings.Contains(joined, "ready-file-flush-returned,ready-before-file-close,ready-checked-close-returned,ready-before-parent-barrier,"+storeReadyParentPoint()+",ready-before-readback,ready-canonical-readback-returned,before-temp-create") {
				t.Fatal("ready boundaries did not precede fresh attempt commit")
			}
			// No permit is consumed here. No actual control dispatch follows from this test.
		})
	}
}

func TestStoreReadyRepeatControlledRefusals(t *testing.T) {
	for _, name := range storeReadyContexts() {
		for _, point := range []string{"ready-before-open", "ready-canonical-read-returned", "ready-before-file-flush", "ready-before-file-close", "ready-before-parent-barrier", "ready-before-readback"} {
			t.Run(name+"/"+point, func(t *testing.T) {
				fixture := storeReadyCase(t, name)
				failure := &storeStageFailure{stage: point}
				fixture.lease.observer = failure
				minted, err := fixture.confirm(storeContext(t))
				requireStoreError(t, err, ErrPersistence)
				if minted || failure.hits != 1 {
					t.Fatal("failed ready qualification minted permit or missed boundary")
				}
				actual, err := fixture.lease.Read(storeContext(t))
				if err != nil || !actual.Equal(fixture.expected) {
					t.Fatal("ready refusal changed full original/cancellation context")
				}
				// This is a controlled boundary refusal, not a native syscall failure.
			})
		}
	}
}

func TestStoreReadyRepeatCancellationAtActualBoundaries(t *testing.T) {
	for _, name := range storeReadyContexts() {
		for _, point := range []string{"ready-before-file-flush", "ready-file-flush-returned", "ready-before-parent-barrier", "ready-canonical-readback-returned"} {
			t.Run(name+"/"+point, func(t *testing.T) {
				fixture := storeReadyCase(t, name)
				ctx, cancel := context.WithCancel(storeContext(t))
				defer cancel()
				seen := false
				fixture.lease.observer = &storeStageAction{stage: point, action: func() error { seen = true; cancel(); return nil }}
				minted, err := fixture.confirm(ctx)
				requireStoreError(t, err, ErrTimeout)
				if minted || !seen {
					t.Fatal("canceled ready qualification minted permit or missed boundary")
				}
				actual, err := fixture.lease.Read(storeContext(t))
				if err != nil || !actual.Equal(fixture.expected) {
					t.Fatal("ready timeout settled or rolled back retained context")
				}
			})
		}
	}
}

func TestStoreReadyRepeatRefusesCurrentEvidenceWithoutRepair(t *testing.T) {
	for _, name := range storeReadyContexts() {
		for _, problem := range []string{"missing", "unsafe-object", "malformed", "orphan"} {
			t.Run(name+"/"+problem, func(t *testing.T) {
				fixture := storeReadyCase(t, name)
				path := filepath.Join(fixture.location.path(), "store.json")
				switch problem {
				case "missing":
					if os.Remove(path) != nil {
						t.Fatal("manifest loss fixture failed")
					}
				case "unsafe-object":
					if os.Remove(path) != nil || os.Mkdir(path, 0o700) != nil {
						t.Fatal("unsafe manifest fixture failed")
					}
				case "malformed":
					if os.WriteFile(path, []byte("{}\n"), 0o600) != nil {
						t.Fatal("malformed manifest fixture failed")
					}
				case "orphan":
					if os.WriteFile(filepath.Join(fixture.location.path(), ".manifest.orphan.tmp"), []byte("partial"), 0o600) != nil {
						t.Fatal("orphan manifest fixture failed")
					}
				}
				minted, err := fixture.confirm(storeContext(t))
				if err == nil || minted {
					t.Fatal("uncertain current namespace minted permit")
				}
				if problem == "missing" {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatal("missing manifest was repaired")
					}
				}
				if problem == "malformed" {
					data, err := os.ReadFile(path)
					if err != nil || string(data) != "{}\n" {
						t.Fatal("malformed manifest was repaired")
					}
				}
				_, record := storePaths(t, fixture.location, fixture.expected.Slot())
				data, err := os.ReadFile(record)
				if err != nil || !bytes.Equal(data, recordEncoded(t, fixture.expected)) {
					t.Fatal("namespace refusal changed full original/cancellation context")
				}
			})
		}
	}
}

func TestStoreReadyRepeatChangedManifestIdentityRefuses(t *testing.T) {
	for _, name := range storeReadyContexts() {
		t.Run(name, func(t *testing.T) {
			fixture := storeReadyCase(t, name)
			path := filepath.Join(fixture.location.path(), "store.json")
			fixture.lease.observer = &storeStageAction{stage: "ready-before-readback", action: func() error {
				if err := os.Rename(path, filepath.Join(fixture.location.anchor, "held-ready-original")); err != nil {
					return err
				}
				file, err := fixture.lease.namespace.root.openFile(storeContext(t), "store.json", true)
				if err != nil {
					return err
				}
				_, writeErr := file.WriteString(readyManifest)
				return combine(writeErr, releaseFile(file))
			}}
			minted, err := fixture.confirm(storeContext(t))
			requireStoreError(t, err, ErrChanged)
			if minted {
				t.Fatal("different manifest object minted permit despite identical bytes")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != readyManifest {
				t.Fatal("changed manifest fixture was rolled back")
			}
		})
	}
}
