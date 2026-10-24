package identityattempt

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
)

// Qualification supplies a fresh owned0700 root with a safe native ancestor chain.
// A missing fixture prerequisite is a failure, never a skip or a user-root fallback.
func storeFixtureLocation(t *testing.T) Location {
	t.Helper()
	t.Setenv("OE_OPERATION_ID", "")
	base := os.Getenv("OE_IDENTITY_STORE_FIXTURE_ROOT")
	if !filepath.IsAbs(base) || !strings.HasPrefix(filepath.Base(base), "ca8-store-fixtures-") {
		t.Fatal("an explicitly owned identity store fixture root is required")
	}
	canonical, err := filepath.EvalSymlinks(base)
	if err != nil || canonical != filepath.Clean(base) {
		t.Fatal("the fixture root must be an existing canonical directory")
	}
	if selected, err := DefaultLocation(); err == nil && (base == selected.anchor || strings.HasPrefix(base, selected.path())) {
		t.Fatal("the fixture root cannot name the selected user store")
	}
	root, err := os.MkdirTemp(base, "case-")
	if err != nil {
		t.Fatal("fixture creation failed")
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("failed owned fixture retained:", root)
			return
		}
		if os.RemoveAll(root) != nil {
			t.Error("owned fixture cleanup failed")
		}
	})
	return Location{anchor: root, managed: managedDirectoryNames()}
}

func storeCurrentNamespaceError(problem string) error {
	switch problem {
	case "malformed":
		return ErrFormat
	case "unsafe-object":
		return ErrUnsafe
	case "canonical-replacement":
		return ErrChanged
	default:
		return ErrUncertain
	}
}

func storeCurrentNamespaceProblems() []string {
	return []string{"missing", "malformed", "unsafe-object", "canonical-replacement", "root-orphan", "root-lock-content", "slot-lock-content", "record-orphan"}
}

// These mutations act only on this test's explicit owned fixture.
func storeDamageCurrentNamespace(t *testing.T, fixture storeReadyFixture, problem string) {
	t.Helper()
	manifest := filepath.Join(fixture.location.path(), "store.json")
	lock, _ := storePaths(t, fixture.location, fixture.expected.Slot())
	switch problem {
	case "missing":
		if os.Remove(manifest) != nil {
			t.Fatal("manifest loss fixture failed")
		}
	case "malformed":
		if os.WriteFile(manifest, []byte("{}\n"), 0o600) != nil {
			t.Fatal("malformed manifest fixture failed")
		}
	case "unsafe-object":
		if os.Remove(manifest) != nil || os.Mkdir(manifest, 0o700) != nil {
			t.Fatal("nonregular manifest fixture failed")
		}
	case "canonical-replacement":
		before, err := os.Stat(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if os.Rename(manifest, filepath.Join(fixture.location.anchor, "former-ready-marker")) != nil {
			t.Fatal("manifest displacement fixture failed")
		}
		file, err := fixture.lease.namespace.root.openFile(storeContext(t), "store.json", true)
		if err != nil {
			t.Fatal(err)
		}
		n, writeErr := file.WriteString(readyManifest)
		closeErr := file.Close()
		if writeErr != nil || n != len(readyManifest) || closeErr != nil {
			t.Fatal("canonical replacement fixture failed")
		}
		after, err := os.Stat(manifest)
		if err != nil || os.SameFile(before, after) {
			t.Fatal("replacement fixture did not change the actual object")
		}
	case "root-orphan":
		if os.WriteFile(filepath.Join(fixture.location.path(), ".manifest.unexpected.tmp"), []byte("partial"), 0o600) != nil {
			t.Fatal("root orphan fixture failed")
		}
	case "root-lock-content":
		if os.WriteFile(filepath.Join(fixture.location.path(), "root.lock"), []byte("changed"), 0o600) != nil {
			t.Fatal("root lock fixture failed")
		}
	case "slot-lock-content":
		if os.WriteFile(lock, []byte("changed"), 0o600) != nil {
			t.Fatal("slot lock fixture failed")
		}
	case "record-orphan":
		if os.WriteFile(filepath.Join(fixture.location.path(), "v1", "."+fixture.lease.stem+".uncertain.tmp"), []byte("partial"), 0o600) != nil {
			t.Fatal("record orphan fixture failed")
		}
	default:
		t.Fatal("unknown current namespace fixture")
	}
}

func storeCurrentTree(t *testing.T, location Location) string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(location.path(), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(location.path(), path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := relative + "\x00" + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += "\x00" + string(data)
		}
		entries = append(entries, value)
		return nil
	})
	if err != nil {
		t.Fatal("owned current namespace snapshot failed", err)
	}
	return strings.Join(entries, "\n")
}

func storeAssertCurrentRefusal(t *testing.T, fixture storeReadyFixture, before string, err error) {
	t.Helper()
	if err == nil || errors.Is(err, ErrRelease) {
		t.Fatal("current namespace refusal was absent or hid a release failure", err)
	}
	if fixture.lease.active {
		t.Fatal("refused namespace created an active call")
	}
	if storeCurrentTree(t, fixture.location) != before {
		t.Fatal("current namespace refusal changed visible fixture evidence")
	}
	_, record := storePaths(t, fixture.location, fixture.expected.Slot())
	data, readErr := os.ReadFile(record)
	if readErr != nil || string(data) != string(recordEncoded(t, fixture.expected)) {
		t.Fatal("refusal changed original, cancellation or revision")
	}
	if _, readErr := fixture.lease.Read(storeContext(t)); readErr == nil {
		t.Fatal("common lease read accepted uncertain current namespace")
	}
}

func storeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func storeReady(t *testing.T) (*Store, Location) {
	t.Helper()
	location := storeFixtureLocation(t)
	store, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	return store, location
}

func storeAttempt(t *testing.T, kind Kind) Attempt {
	t.Helper()
	if kind != Lifecycle {
		return recordAttempt(t, kind)
	}
	command := recordDecode[identity.LifecycleAttempt](t, recordLifecycleWire)
	command.OperationID = recordText(t, "lc1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	value, err := NewLifecycleAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func storeRetain(t *testing.T, lease *Lease) Envelope {
	t.Helper()
	ctx := storeContext(t)
	vacant, err := lease.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lease.slot.Kind() == Lifecycle {
		permit, err := lease.ConfirmPreparation(ctx, vacant)
		if err != nil {
			t.Fatal(err)
		}
		call, err := permit.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if call.Slot().Kind() != Lifecycle {
			t.Fatal("preparation lost exact slot")
		}
		if err := call.Join(); err != nil {
			t.Fatal(err)
		}
	}
	value, err := lease.Retain(ctx, vacant, storeAttempt(t, lease.slot.Kind()))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func storeOccupied(t *testing.T, kind Kind) (*Store, Location, *Lease, Envelope) {
	t.Helper()
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
	value := storeRetain(t, lease)
	return store, location, lease, value
}

func storePaths(t *testing.T, location Location, slot Slot) (string, string) {
	t.Helper()
	stem, err := slot.FilenameStem()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(location.path(), "locks", stem+".lock"), filepath.Join(location.path(), "v1", stem+".json")
}

func requireStoreError(t *testing.T, err, expected error) {
	t.Helper()
	if !errors.Is(err, expected) {
		t.Fatalf("store error = %v; expected fixed error %v", err, expected)
	}
}

func TestStoreExistingAbsenceCreatesNothing(t *testing.T) {
	location := storeFixtureLocation(t)
	store, err := Open(location)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := store.Inspect(storeContext(t), recordSlot(t, Selection))
	if err != nil || observation.State() != AbsentNamespace {
		t.Fatal("absent namespace observation changed")
	}
	if _, ready := observation.Envelope(); ready {
		t.Fatal("absence returned an envelope")
	}
	if _, err := store.BeginExisting(storeContext(t), recordSlot(t, Selection)); !errors.Is(err, ErrFirstUseRequired) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(location.anchor)
	if err != nil || len(entries) != 0 {
		t.Fatal("ordinary absence initialized state")
	}
}

func TestStoreExplicitFirstUseDeclarations(t *testing.T) {
	for _, declaration := range []FirstUse{0, SlotNeverUsed, 255} {
		t.Run(string(rune(declaration+65)), func(t *testing.T) {
			location := storeFixtureLocation(t)
			_, err := BootstrapFirstUse(storeContext(t), location, declaration)
			requireStoreError(t, err, ErrFirstUseRequired)
			if _, err := os.Stat(location.path()); !os.IsNotExist(err) {
				t.Fatal("invalid declaration created namespace")
			}
		})
	}
	store, location := storeReady(t)
	_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
	requireStoreError(t, err, ErrAlreadyInitialized)
	_, err = store.EnrollFirstUse(storeContext(t), recordSlot(t, Selection), NamespaceNeverUsed)
	requireStoreError(t, err, ErrFirstUseRequired)
}

func TestStoreNamespaceWitnessLossRefuses(t *testing.T) {
	for _, target := range []string{"root.lock", "store.json", "locks", "v1"} {
		t.Run(target, func(t *testing.T) {
			_, location := storeReady(t)
			path := filepath.Join(location.path(), target)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			_, err := Open(location)
			requireStoreError(t, err, ErrUncertain)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("lost witness recreated")
			}
		})
	}
}

func TestStoreIncompleteBootstrapNeverCompletes(t *testing.T) {
	for _, stage := range []string{"root-directory-created", "root-lock-created", "directories-created"} {
		t.Run(stage, func(t *testing.T) {
			location := storeFixtureLocation(t)
			location.observer = &storeStageFailure{stage: stage}
			_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
			requireStoreError(t, err, ErrPersistence)
			location.observer = nil
			_, err = Open(location)
			requireStoreError(t, err, ErrUncertain)
			_, err = BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
			requireStoreError(t, err, ErrAlreadyInitialized)
		})
	}
}

func TestStoreCanonicalManifestAndUnknownEvidence(t *testing.T) {
	for _, data := range []string{"", "{}\n", "{\"schemaVersion\":2,\"storeVersion\":1}\n", readyManifest + "\n"} {
		t.Run(data, func(t *testing.T) {
			_, location := storeReady(t)
			if os.WriteFile(filepath.Join(location.path(), "store.json"), []byte(data), 0o600) != nil {
				t.Fatal("fixture write failed")
			}
			_, err := Open(location)
			if err == nil {
				t.Fatal("noncanonical manifest accepted")
			}
		})
	}
	_, location := storeReady(t)
	if os.WriteFile(filepath.Join(location.path(), ".manifest.orphan.tmp"), []byte("partial"), 0o600) != nil {
		t.Fatal("fixture creation failed")
	}
	_, err := Open(location)
	requireStoreError(t, err, ErrUncertain)
}

func TestStoreSlotLossAndEnrollmentCrashRefuse(t *testing.T) {
	for _, missing := range []string{"lock", "record"} {
		t.Run(missing, func(t *testing.T) {
			store, location, lease, value := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			lockPath, recordPath := storePaths(t, location, value.Slot())
			path := recordPath
			if missing == "lock" {
				path = lockPath
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			_, err := store.BeginExisting(storeContext(t), value.Slot())
			requireStoreError(t, err, ErrUncertain)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("missing object recreated")
			}
		})
	}
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			store, location := storeReady(t)
			store.location.observer = &storeStageFailure{stage: "slot-lock-created"}
			_, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
			requireStoreError(t, err, ErrPersistence)
			store.location.observer = nil
			_, err = store.BeginExisting(storeContext(t), recordSlot(t, kind))
			requireStoreError(t, err, ErrUncertain)
			lockPath, recordPath := storePaths(t, location, recordSlot(t, kind))
			if _, err := os.Stat(lockPath); err != nil {
				t.Fatal("stable lock lost")
			}
			if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
				t.Fatal("initial vacancy invented")
			}
		})
	}
}

func TestStoreAllWitnessLossHasNoFreshnessInference(t *testing.T) {
	store, location, lease, value := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(location.path()); err != nil {
		t.Fatal("fixture loss failed")
	}
	observation, err := store.Inspect(storeContext(t), value.Slot())
	if err != nil || observation.State() != AbsentNamespace {
		t.Fatal("loss became recovery authority")
	}
	_, err = store.BeginExisting(storeContext(t), value.Slot())
	requireStoreError(t, err, ErrFirstUseRequired)
	if _, err := os.Stat(location.path()); !os.IsNotExist(err) {
		t.Fatal("ordinary call recreated lost namespace")
	}
	// No test claims that local bytes can distinguish this loss from true first use.
}

func TestStoreLostSlotWitnessesNeverInferEnrollment(t *testing.T) {
	store, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	lock, record := storePaths(t, location, original.Slot())
	if os.Remove(lock) != nil || os.Remove(record) != nil {
		t.Fatal("owned complete slot loss fixture failed")
	}
	observation, err := store.Inspect(storeContext(t), original.Slot())
	if err != nil || observation.State() != AbsentSlot {
		t.Fatal("unwitnessed slot loss gained recovery authority")
	}
	_, err = store.BeginExisting(storeContext(t), original.Slot())
	requireStoreError(t, err, ErrFirstUseRequired)
	// No ordinary operation can distinguish true unused state from loss of all witnesses.
}

func TestStoreKnownTemporaryBlocksMissingAssociation(t *testing.T) {
	store, location := storeReady(t)
	slot := recordSlot(t, Selection)
	stem, _ := slot.FilenameStem()
	path := filepath.Join(location.path(), "v1", "."+stem+".orphan.tmp")
	if os.WriteFile(path, []byte("partial"), 0o600) != nil {
		t.Fatal("owned orphan fixture failed")
	}
	_, err := store.EnrollFirstUse(storeContext(t), slot, SlotNeverUsed)
	requireStoreError(t, err, ErrUncertain)
	observation, err := store.Inspect(storeContext(t), slot)
	requireStoreError(t, err, ErrUncertain)
	if observation.State() != 0 {
		t.Fatal("an error returned an absence observation")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "partial" {
		t.Fatal("uncertain temporary was removed or repaired")
	}
}

func TestStoreValidStaleBackupCannotProveFreshness(t *testing.T) {
	store, location, lease, old := storeOccupied(t, Selection)
	backup := recordEncoded(t, old)
	storeResolveSettled(t, lease, old)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	// This fixture models an external stale copy. The runtime offers no restore API.
	storeReplaceRecord(t, location, old, backup)
	lease, err := store.BeginExisting(storeContext(t), old.Slot())
	if err != nil {
		t.Fatal("canonical old bytes cannot prove their age", err)
	}
	actual, err := lease.Read(storeContext(t))
	if err != nil || !actual.Equal(old) {
		t.Fatal("stale backup fixture changed")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	// Acceptance here is the explicit local detection limit, not freshness or recovery evidence.
}

func TestStoreCancellationBeforeNativeDirectoryCreates(t *testing.T) {
	for _, point := range []string{"before-selected-anchor-create", "before-managed-directory-create", "between-managed-directory-creates", "root-directory-created"} {
		t.Run(point, func(t *testing.T) {
			location := storeFixtureLocation(t)
			if point == "before-selected-anchor-create" {
				location.anchor = filepath.Join(location.anchor, "selected-config")
			}
			ctx, cancel := context.WithCancel(storeContext(t))
			defer cancel()
			seen, calls := false, 0
			selected := point
			if point == "between-managed-directory-creates" {
				selected = "before-managed-directory-create"
			}
			location.observer = &storeStageAction{stage: selected, action: func() error {
				calls++
				if point == "between-managed-directory-creates" && calls == 1 {
					return nil
				}
				seen = true
				cancel()
				return nil
			}}
			_, err := BootstrapFirstUse(ctx, location, NamespaceNeverUsed)
			requireStoreError(t, err, ErrTimeout)
			if !seen {
				t.Fatal("native create cancellation phase not reached")
			}
			if point == "before-selected-anchor-create" {
				if _, err := os.Stat(location.anchor); !os.IsNotExist(err) {
					t.Fatal("selected-anchor create began after cancellation")
				}
			} else if point == "before-managed-directory-create" {
				if _, err := os.Stat(filepath.Join(location.anchor, location.managed[0])); !os.IsNotExist(err) {
					t.Fatal("managed-directory create began after cancellation")
				}
			} else if point == "between-managed-directory-creates" {
				first := filepath.Join(location.anchor, location.managed[0])
				if _, err := os.Stat(first); err != nil {
					t.Fatal("first native create did not precede cancellation")
				}
				if _, err := os.Stat(filepath.Join(first, location.managed[1])); !os.IsNotExist(err) {
					t.Fatal("second native create began after cancellation")
				}
			} else {
				if _, err := os.Stat(filepath.Join(location.path(), "root.lock")); !os.IsNotExist(err) {
					t.Fatal("root-lock create began after cancellation")
				}
			}
		})
	}
}
