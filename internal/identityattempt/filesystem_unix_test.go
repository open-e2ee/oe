//go:build darwin || linux

package identityattempt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
	"golang.org/x/sys/unix"
)

type unixStoreActorGroup struct {
	command             *exec.Cmd
	mu                  sync.Mutex
	pid                 int
	pending             bool
	terminationComplete bool
	waiting             bool
	sealed              bool
	waitComplete        bool
	releaseErr          error
}

func storeDamageStableLock(t *testing.T, path string, _ *os.File) {
	t.Helper()
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal("stable lock content fixture failed", err)
	}
}

func newStoreActorGroup(command *exec.Cmd) (storeActorGroup, error) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return &unixStoreActorGroup{command: command}, nil
}
func (g *unixStoreActorGroup) Attach(process *os.Process) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if process == nil || process.Pid <= 0 || g.pid != 0 || g.sealed {
		return ErrUnsafe
	}
	g.pid = process.Pid
	if g.pending {
		return g.terminateLocked()
	}
	return nil
}
func (g *unixStoreActorGroup) terminateLocked() error {
	if g.sealed {
		return os.ErrProcessDone
	}
	if g.pid == 0 {
		g.pending = true
		return nil
	}
	if g.terminationComplete {
		return nil
	}
	needed, err := storeActorGroupNeedsSignal(g.pid)
	if err == nil && needed {
		err = unix.Kill(-g.pid, unix.SIGKILL)
	}
	if err != nil {
		g.releaseErr = combine(g.releaseErr, fmt.Errorf("actor group termination: %w", err))
	} else {
		g.terminationComplete = true
	}
	return err
}
func (g *unixStoreActorGroup) Terminate() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.terminateLocked()
}
func (g *unixStoreActorGroup) Wait(ctx context.Context) (error, error) {
	g.mu.Lock()
	if g.pid == 0 || g.waiting || g.sealed {
		g.releaseErr = combine(g.releaseErr, ErrRelease)
		g.mu.Unlock()
		return nil, ErrRelease
	}
	g.waiting = true
	pid := g.pid
	g.mu.Unlock()
	deadline, bounded := ctx.Deadline()
	deadline = deadline.Add(g.command.WaitDelay)
	terminal := false
	var observationErr error
	if bounded {
		for time.Now().Before(deadline) {
			var err error
			terminal, err = storeActorTerminal(pid)
			if err != nil {
				observationErr = err
				break
			}
			if terminal {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	g.mu.Lock()
	// A successful terminal observation has not reaped the owned leader.
	// On observation failure, refuse any further group mutation.
	if terminal {
		_ = g.terminateLocked() // The error is retained in releaseErr.
	}
	g.sealed = true
	if !terminal {
		g.releaseErr = combine(g.releaseErr, combine(ErrRelease, observationErr))
		result := g.releaseErr
		g.mu.Unlock()
		// No unbounded reap after an unavailable or incomplete terminal observation.
		return nil, result
	}
	g.mu.Unlock()
	waitErr := g.command.Wait()
	g.mu.Lock()
	g.waitComplete = g.command.ProcessState != nil
	if !g.waitComplete {
		g.releaseErr = combine(g.releaseErr, combine(ErrRelease, waitErr))
	}
	result := g.releaseErr
	g.mu.Unlock()
	return waitErr, result
}
func (g *unixStoreActorGroup) Close() error {
	g.mu.Lock()
	pid, sealed, waited, result := g.pid, g.sealed, g.waitComplete, g.releaseErr
	g.mu.Unlock()
	if pid == 0 {
		return result
	}
	if !sealed || !waited {
		return combine(result, ErrRelease)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		empty, err := storeActorGroupEmpty(pid)
		if err != nil {
			return combine(result, fmt.Errorf("actor group closure census: %w", err))
		}
		if empty {
			return result
		}
		time.Sleep(10 * time.Millisecond)
	}
	return combine(result, ErrRelease)
}
func storeActorAlive(pid int) bool { return unix.Kill(pid, 0) == nil }

func TestStoreUnixManagedSecurityAndStableObjects(t *testing.T) {
	_, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{location.path(), filepath.Join(location.path(), "locks"), filepath.Join(location.path(), "v1")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatal("managed directory was not private")
		}
	}
	lock, record := storePaths(t, location, original.Slot())
	for _, path := range []string{lock, record, filepath.Join(location.path(), "root.lock"), filepath.Join(location.path(), "store.json")} {
		file, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nativeFileStamp(file, false, true); err != nil {
			t.Fatal(err)
		}
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if file.Close() != nil {
			t.Fatal("fixture close failed")
		}
		// Native production opens are checked separately; os.OpenFile also uses close-on-exec.
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("fixture descriptor inherits across exec")
		}
	}
	store, err := Open(location)
	if err != nil {
		t.Fatal(err)
	}
	lease, err = store.BeginExisting(storeContext(t), original.Slot())
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(lease.lock.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("native stable lock descriptor is inheritable")
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStoreUnixUnsafeModesNeverRepair(t *testing.T) {
	for _, target := range []string{"root", "record", "lock"} {
		for _, mode := range []os.FileMode{0o755, 0o644, os.ModeSetuid | 0o600, os.ModeSetgid | 0o600, os.ModeSticky | 0o600} {
			t.Run(fmt.Sprintf("%s/%o", target, mode), func(t *testing.T) {
				store, location, lease, original := storeOccupied(t, Selection)
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				lock, record := storePaths(t, location, original.Slot())
				path := location.path()
				if target == "record" {
					path = record
				}
				if target == "lock" {
					path = lock
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal("mode fixture setup failed", err)
				}
				before, err := os.Stat(path)
				if err != nil || before.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != mode {
					t.Fatal("requested native mode fixture was not established")
				}
				_, err = store.BeginExisting(storeContext(t), original.Slot())
				requireStoreError(t, err, ErrUnsafe)
				after, err := os.Stat(path)
				if err != nil || after.Mode() != before.Mode() {
					t.Fatal("unsafe mode was repaired")
				}
				// Fixture cleanup needs traversal only; product never repairs this object.
				if target == "root" && os.Chmod(path, 0o700) != nil {
					t.Fatal("owned fixture cleanup preparation failed")
				}
			})
		}
	}
}

func TestStoreUnixUnsafeAncestorAndLinkedComponents(t *testing.T) {
	for _, index := range []int{-1, 0, 1, 2} {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			location := storeFixtureLocation(t)
			if index == -1 {
				if err := os.Chmod(location.anchor, 0o777); err != nil {
					t.Fatal(err)
				}
				_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
				requireStoreError(t, err, ErrUnsafe)
				if os.Chmod(location.anchor, 0o700) != nil {
					t.Fatal("owned fixture cleanup preparation failed")
				}
				return
			}
			parent := location.anchor
			for before := 0; before < index; before++ {
				parent = filepath.Join(parent, location.managed[before])
				if os.Mkdir(parent, 0o700) != nil {
					t.Fatal("component fixture failed")
				}
			}
			target := filepath.Join(location.anchor, "linked-target")
			if os.Mkdir(target, 0o700) != nil || os.Symlink(target, filepath.Join(parent, location.managed[index])) != nil {
				t.Fatal("native link fixture failed")
			}
			_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
			requireStoreError(t, err, ErrUnsafe)
		})
	}
}

func TestStoreUnixNonregularAndHardlinkedRecords(t *testing.T) {
	for _, kind := range []string{"directory", "fifo", "socket", "device", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			store, location, lease, original := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_, path := storePaths(t, location, original.Slot())
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var fd int = -1
			switch kind {
			case "directory":
				if os.Mkdir(path, 0o700) != nil {
					t.Fatal("directory fixture failed")
				}
			case "fifo":
				if unix.Mkfifo(path, 0o600) != nil {
					t.Fatal("FIFO fixture failed")
				}
			case "socket":
				var err error
				fd, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
				if err != nil {
					t.Fatal("socket fixture setup failed")
				}
				defer func() {
					if unix.Close(fd) != nil {
						t.Error("socket fixture close failed")
					}
				}()
				socketPath := filepath.Join(location.anchor, "s")
				if len(socketPath) >= 104 {
					t.Fatal("native socket fixture requires an explicitly owned shorter fixture root")
				}
				if unix.Bind(fd, &unix.SockaddrUnix{Name: socketPath}) != nil || os.Rename(socketPath, path) != nil {
					t.Fatal("actual socket fixture bind/rename failed")
				}
			case "device":
				// Requires a separately granted native privileged fixture, never a symlink substitute.
				if os.Getenv("OE_IDENTITY_STORE_PRIVILEGED_FIXTURES") != "1" {
					t.Fatal("native device fixture privilege has not been granted")
				}
				if unix.Mknod(path, unix.S_IFCHR|0o600, 0) != nil {
					t.Fatal("native device fixture was not established")
				}
			case "symlink":
				source := filepath.Join(location.anchor, "symlink-record")
				if os.WriteFile(source, recordEncoded(t, original), 0o600) != nil || os.Symlink(source, path) != nil {
					t.Fatal("record symlink fixture failed")
				}
			case "hardlink":
				source := filepath.Join(location.anchor, "linked-record")
				if os.WriteFile(source, recordEncoded(t, original), 0o600) != nil || os.Link(source, path) != nil {
					t.Fatal("hardlink fixture failed")
				}
			}
			_, err := store.BeginExisting(storeContext(t), original.Slot())
			requireStoreError(t, err, ErrUnsafe)
		})
	}
}

func TestStoreUnixForeignOwnerPrerequisite(t *testing.T) {
	if os.Getenv("OE_IDENTITY_STORE_PRIVILEGED_FIXTURES") != "1" {
		t.Fatal("native foreign-owner fixture privilege has not been granted")
	}
	uid, err := strconv.Atoi(os.Getenv("OE_IDENTITY_STORE_FOREIGN_UID"))
	if err != nil || uid < 0 || uid == os.Geteuid() {
		t.Fatal("an explicit different fixture UID is required")
	}
	store, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	_, path := storePaths(t, location, original.Slot())
	if os.Chown(path, uid, -1) != nil {
		t.Fatal("foreign-owner fixture was not established")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("foreign-owner fixture stat failed")
	}
	actual, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(actual.Uid) != uid {
		t.Fatal("actual foreign owner was not established")
	}
	_, err = store.BeginExisting(storeContext(t), original.Slot())
	requireStoreError(t, err, ErrUnsafe)
}

func TestStoreUnixPinnedParentNeverBecomesMissingLeaf(t *testing.T) {
	_, location := storeReady(t)
	root, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal(err)
	}
	old := location.path() + "-moved"
	if os.Rename(location.path(), old) != nil {
		t.Fatal("native directory rename fixture failed")
	}
	defer func() {
		if root.Close() != nil {
			t.Error("pinned directory close failed")
		}
		if os.Rename(old, location.path()) != nil {
			t.Error("owned fixture path restoration failed")
		}
	}()
	_, err = root.openFile(storeContext(t), "missing.lock", false)
	if !errors.Is(err, ErrChanged) || soleMissing(err) {
		t.Fatal("changed parent became absent file")
	}
	_, err = root.subdirectory(storeContext(t), "missing", false)
	if !errors.Is(err, ErrChanged) || soleMissing(err) {
		t.Fatal("changed parent became absent directory")
	}
}

func TestStoreUnixFinalAnchorSecurity(t *testing.T) {
	location := storeFixtureLocation(t)
	location.anchor = filepath.Join(location.anchor, "selected-config")
	store, err := Open(location)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inspect(storeContext(t), recordSlot(t, Selection)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(location.anchor); !os.IsNotExist(err) {
		t.Fatal("ordinary read created selected anchor")
	}
	if _, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(location.anchor)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("created selected anchor is not private")
	}
	file, err := os.Open(location.anchor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nativeFileStamp(file, true, true); err != nil {
		t.Fatal(err)
	}
	if file.Close() != nil {
		t.Fatal("anchor fixture close failed")
	}
	missing := storeFixtureLocation(t)
	missing.anchor = filepath.Join(missing.anchor, "missing-parent", "selected-config")
	_, err = BootstrapFirstUse(storeContext(t), missing, NamespaceNeverUsed)
	requireStoreError(t, err, ErrLocation)
	if _, err := os.Stat(filepath.Dir(missing.anchor)); !os.IsNotExist(err) {
		t.Fatal("an earlier parent was created")
	}
}

func TestStoreUnixExistingAnchorPermissionsRemainExact(t *testing.T) {
	location := storeFixtureLocation(t)
	if os.Chmod(location.anchor, 0o755) != nil {
		t.Fatal("safe existing anchor setup failed")
	}
	if _, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(location.anchor)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatal("existing safe anchor was narrowed or repaired")
	}
}

func TestStoreUnixKnownRemoteMountRefusalBoundary(t *testing.T) {
	// A real remote mount needs a separate fixture grant. This only tests branch propagation.
	location := storeFixtureLocation(t)
	original := unixMountReceiver
	unixMountReceiver = func(*os.File) error { return ErrUnsafe }
	defer func() { unixMountReceiver = original }()
	_, err := Open(location)
	requireStoreError(t, err, ErrUnsafe)
}

func TestStoreUnixSelectedAnchorReplacementRefuses(t *testing.T) {
	for _, vector := range []string{"linked-before-create", "unsafe-after-create", "moved-after-create"} {
		t.Run(vector, func(t *testing.T) {
			location := storeFixtureLocation(t)
			parent := location.anchor
			location.anchor = filepath.Join(parent, "selected-config")
			if vector == "linked-before-create" {
				target := filepath.Join(parent, "linked-config-target")
				if os.Mkdir(target, 0o700) != nil || os.Symlink(target, location.anchor) != nil {
					t.Fatal("selected anchor link fixture failed")
				}
			} else {
				location.observer = &storeStageAction{stage: "selected-anchor-created", action: func() error {
					if vector == "unsafe-after-create" {
						return os.Chmod(location.anchor, 0o777)
					}
					return os.Rename(location.anchor, location.anchor+"-moved")
				}}
			}
			_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
			if vector == "moved-after-create" {
				requireStoreError(t, err, ErrChanged)
			} else {
				requireStoreError(t, err, ErrUnsafe)
			}
			if _, err := os.Stat(location.path()); !os.IsNotExist(err) {
				t.Fatal("unsafe selected anchor gained managed namespace")
			}
		})
	}
}

func TestStoreUnixHardlinkedStableLockAndTemporary(t *testing.T) {
	t.Run("stable-lock", func(t *testing.T) {
		store, location, lease, value := storeOccupied(t, Selection)
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
		lock, _ := storePaths(t, location, value.Slot())
		if os.Link(lock, filepath.Join(location.anchor, "linked-lock")) != nil {
			t.Fatal("native lock link fixture failed")
		}
		_, err := store.BeginExisting(storeContext(t), value.Slot())
		requireStoreError(t, err, ErrUnsafe)
	})
	t.Run("temporary", func(t *testing.T) {
		fixture := storeCommitCase(t, "retain-selection")
		directory := filepath.Join(fixture.location.path(), "v1")
		fixture.lease.observer = &storeStageAction{stage: "temporary-created", action: func() error {
			entries, err := os.ReadDir(directory)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if entry.Name()[0] == '.' {
					return os.Link(filepath.Join(directory, entry.Name()), filepath.Join(fixture.location.anchor, "linked-temporary"))
				}
			}
			return ErrPersistence
		}}
		err := fixture.operation()
		requireStoreError(t, err, ErrUnsafe)
		_, path := storePaths(t, fixture.location, fixture.before.Slot())
		data, err := os.ReadFile(path)
		if err != nil || string(data) != string(recordEncoded(t, fixture.before)) {
			t.Fatal("unsafe temporary changed original")
		}
	})
}

func TestStoreUnixCancellationBeforeCreatedParentFlush(t *testing.T) {
	location := storeFixtureLocation(t)
	ctx, cancel := context.WithCancel(storeContext(t))
	defer cancel()
	seen := false
	location.observer = &storeStageAction{stage: "before-created-directory-parent-flush", action: func() error { seen = true; cancel(); return nil }}
	_, err := BootstrapFirstUse(ctx, location, NamespaceNeverUsed)
	requireStoreError(t, err, ErrTimeout)
	if !seen {
		t.Fatal("native parent flush cancellation point was not reached")
	}
	first := filepath.Join(location.anchor, location.managed[0])
	if _, err := os.Stat(first); err != nil {
		t.Fatal("created prefix was rolled back after timeout")
	}
	if _, err := os.Stat(filepath.Join(first, location.managed[1])); !os.IsNotExist(err) {
		t.Fatal("another directory create began after cancellation")
	}
}

func TestStoreUnixHeldLockMustKeepItsManagedLeaf(t *testing.T) {
	for _, rootLock := range []bool{false, true} {
		t.Run(map[bool]string{false: "slot", true: "root"}[rootLock], func(t *testing.T) {
			_, location, lease, value := storeOccupied(t, Selection)
			path, _ := storePaths(t, location, value.Slot())
			if rootLock {
				path = filepath.Join(location.path(), "root.lock")
			}
			if os.Rename(path, filepath.Join(location.anchor, "old-held-lock")) != nil {
				t.Fatal("native stable-leaf rename fixture failed")
			}
			if os.WriteFile(path, nil, 0o600) != nil {
				t.Fatal("native replacement lock fixture failed")
			}
			_, err := lease.Read(storeContext(t))
			requireStoreError(t, err, ErrChanged)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreUnixCurrentDirectoriesBeforeBegin(t *testing.T) {
	for _, component := range []string{"root", "locks", "v1"} {
		t.Run(component, func(t *testing.T) {
			fixture := storeReadyCase(t, "selection-cancel")
			permit, err := fixture.lease.Confirm(storeContext(t), fixture.expected, SelectionCancelAction)
			if err != nil {
				t.Fatal(err)
			}
			path := fixture.location.path()
			if component != "root" {
				path = filepath.Join(path, component)
			}
			if os.Chmod(path, 0o777) != nil {
				t.Fatal("owned directory security fixture failed")
			}
			before := storeCurrentTree(t, fixture)
			call, err := permit.Begin(storeContext(t), SelectionCancelAction)
			if call != nil {
				t.Fatal("unsafe managed directory returned a call")
			}
			storeAssertCurrentRefusal(t, fixture, before, err)
		})
	}
}

func TestStoreUnixCurrentDirectoryAssociationBeforeResolve(t *testing.T) {
	for _, component := range []string{"locks", "v1"} {
		t.Run(component, func(t *testing.T) {
			fixture := storeReadyCase(t, "selection-cancel")
			receipt := storeSelectionReceipt(t, fixture.expected, "aborted", identity.SelectionCancel)
			path := filepath.Join(fixture.location.path(), component)
			former := filepath.Join(fixture.location.anchor, "former-"+component)
			if os.Rename(path, former) != nil || os.Mkdir(path, 0o700) != nil {
				t.Fatal("owned directory association fixture failed")
			}
			before := storeCurrentTree(t, fixture)
			result, err := fixture.lease.ResolveSelection(storeContext(t), fixture.expected, receipt)
			if err == nil || errors.Is(err, ErrRelease) {
				t.Fatal("changed directory association was accepted or hid release failure", err)
			}
			if _, cloneErr := result.Envelope(); cloneErr == nil {
				t.Fatal("changed directory returned a resolution envelope")
			}
			if storeCurrentTree(t, fixture) != before {
				t.Fatal("changed directory was repaired")
			}
			_, record := storePaths(t, fixture.location, fixture.expected.Slot())
			if component == "v1" {
				record = filepath.Join(former, filepath.Base(record))
			}
			data, err := os.ReadFile(record)
			if err != nil || string(data) != string(recordEncoded(t, fixture.expected)) {
				t.Fatal("changed association erased exact retained original")
			}
		})
	}
}
