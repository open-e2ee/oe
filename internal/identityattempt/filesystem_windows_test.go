package identityattempt

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"github.com/open-e2ee/oe/internal/identity"
	"golang.org/x/sys/windows"
)

type windowsStoreActorGroup struct {
	job     windows.Handle
	command *exec.Cmd
}
type storeJobAccounting struct {
	times                             [4]int64
	faults, total, active, terminated uint32
}

func newStoreActorGroup(command *exec.Cmd) (storeActorGroup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, ErrUnsafe
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		if windows.CloseHandle(job) != nil {
			return nil, combine(ErrUnsafe, ErrRelease)
		}
		return nil, ErrUnsafe
	}
	return &windowsStoreActorGroup{job: job, command: command}, nil
}
func (g *windowsStoreActorGroup) Attach(process *os.Process) error {
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(process.Pid))
	if err != nil {
		return ErrUnsafe
	}
	var result error
	if windows.AssignProcessToJobObject(g.job, handle) != nil {
		result = ErrUnsafe
	}
	if windows.CloseHandle(handle) != nil {
		result = combine(result, ErrRelease)
	}
	return result
}
func (g *windowsStoreActorGroup) Terminate() error {
	if g.job == 0 {
		return nil
	}
	if windows.TerminateJobObject(g.job, 137) != nil {
		return ErrRelease
	}
	return nil
}
func (g *windowsStoreActorGroup) Wait(_ context.Context) (error, error) {
	return g.command.Wait(), nil
}
func (g *windowsStoreActorGroup) Close() error {
	if g.job == 0 {
		return nil
	}
	result := g.Terminate()
	deadline := time.Now().Add(time.Second)
	zero := false
	for time.Now().Before(deadline) {
		var accounting storeJobAccounting
		var length uint32
		if windows.QueryInformationJobObject(g.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), &length) != nil || length != uint32(unsafe.Sizeof(accounting)) {
			result = combine(result, ErrRelease)
			break
		}
		if accounting.active == 0 {
			zero = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !zero {
		result = combine(result, ErrRelease)
	}
	if windows.CloseHandle(g.job) != nil {
		result = combine(result, ErrRelease)
	}
	g.job = 0
	return result
}
func storeActorAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	var code uint32
	query := windows.GetExitCodeProcess(handle, &code)
	closed := windows.CloseHandle(handle)
	return query == nil && closed == nil && code == 259
}

func storeDamageStableLock(t *testing.T, path string, held *os.File) {
	t.Helper()
	before, err := nativeFileStamp(held, false, true)
	if err != nil || before.size != 0 {
		t.Fatal("stable lock mutation lacks its empty held object", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("stable lock mutation open failed", err)
	}
	closed := false
	defer func() {
		if !closed && file.Close() != nil {
			t.Error("stable lock mutation cleanup failed")
		}
	}()
	opened, err := nativeFileStamp(file, false, true)
	if err != nil || opened != before {
		t.Fatal("stable lock mutation opened another object", err)
	}
	count, blocked := file.WriteAt([]byte("changed"), 0)
	after, err := nativeFileStamp(held, false, true)
	if count != 0 || !errors.Is(blocked, windows.ERROR_LOCK_VIOLATION) || err != nil || after != before {
		t.Fatal("native stable lock did not prevent the protected-range write", blocked, err)
	}
	t.Log("native protected-range write refusal:", blocked)
	// Offset one lies outside the live [0,1) lock. No lock is released.
	count, writeErr := file.WriteAt([]byte("changed"), 1)
	closeErr := file.Close()
	closed = true
	if writeErr != nil || count != len("changed") || closeErr != nil {
		t.Fatal("nonempty stable lock corruption was not established", writeErr, closeErr)
	}
	after, err = nativeFileStamp(held, false, true)
	if err != nil || after.device != before.device || after.object != before.object || after.size != 8 {
		t.Fatal("stable lock corruption changed its object or missed its size", err)
	}
	data := make([]byte, 8)
	if count, err := held.ReadAt(data, 0); err != nil || count != len(data) || string(data) != "\x00changed" {
		t.Fatal("stable lock corruption bytes differ", err)
	}
	t.Logf("owned stable lock device=%d object=%d size=%d", after.device, after.object, after.size)
}

func storeWindowsApplyDescriptor(t *testing.T, path, value string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(value)
	if err != nil {
		t.Fatal("native descriptor fixture did not parse")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal("descriptor owner fixture failed")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("descriptor DACL fixture failed")
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("descriptor fixture path failed")
	}
	handle, err := windows.CreateFile(wide, windows.WRITE_DAC|windows.WRITE_OWNER|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("native descriptor fixture handle failed")
	}
	var flags windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	if protected {
		flags |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		flags |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	changed := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, flags, owner, nil, dacl, nil)
	closed := windows.CloseHandle(handle)
	if changed != nil || closed != nil {
		t.Fatal("native descriptor fixture was not established or closed")
	}
}

func TestStoreWindowsProtectedObjectsAndNoInheritedHandle(t *testing.T) {
	_, location, lease, value := storeOccupied(t, Selection)
	for _, directory := range []*nativeDirectory{lease.namespace.root, lease.namespace.locks, lease.namespace.records} {
		if err := windowsCheckSecurity(windows.Handle(directory.file.Fd()), true); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []*os.File{lease.lock, lease.namespace.rootLock} {
		if _, err := nativeFileStamp(file, false, true); err != nil {
			t.Fatal(err)
		}
		// The real grandchild/owner-death test proves handle noninheritance across exec.
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	lock, record := storePaths(t, location, value.Slot())
	for _, path := range []string{lock, record} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		check := windowsCheckSecurity(windows.Handle(file.Fd()), true)
		closed := file.Close()
		if check != nil || closed != nil {
			t.Fatal("protected record/lock fixture failed")
		}
	}
}

func TestStoreWindowsUnsafeDACLRefusal(t *testing.T) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	owner := principals.user.String()
	for _, vector := range []struct {
		name, dacl string
		protected  bool
	}{
		{"null", "D:NO_ACCESS_CONTROL", true},
		{"unprotected", "D:(A;;FA;;;" + owner + ")(A;;FA;;;SY)", false},
		{"extra-everyone-grant", "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FR;;;WD)", true},
		{"missing-system", "D:P(A;;FA;;;" + owner + ")", true},
		{"wrong-mask", "D:P(A;;FR;;;" + owner + ")(A;;FA;;;SY)", true},
		{"inherited-owner", "D:P(A;ID;FA;;;" + owner + ")(A;;FA;;;SY)", true},
	} {
		t.Run(vector.name, func(t *testing.T) {
			store, location, lease, value := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_, path := storePaths(t, location, value.Slot())
			if vector.name == "inherited-owner" {
				storeWindowsInheritedOwnerRecord(t, location, path, owner)
			} else {
				storeWindowsApplyDescriptor(t, path, "O:"+owner+vector.dacl, vector.protected)
			}
			before := storeWindowsAncestorDescriptor(t, path)
			_, err := store.BeginExisting(storeContext(t), value.Slot())
			requireStoreError(t, err, ErrUnsafe)
			if storeWindowsAncestorDescriptor(t, path) != before {
				t.Fatal("unsafe DACL refusal repaired its fixture")
			}
			// Only the owned fixture restores access for cleanup after the refusal.
			storeWindowsApplyDescriptor(t, path, "O:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)", true)
		})
	}
}

func TestStoreWindowsForeignOwnerPrerequisite(t *testing.T) {
	if os.Getenv("OE_IDENTITY_STORE_PRIVILEGED_FIXTURES") != "1" {
		t.Fatal("native foreign-owner fixture privilege has not been granted")
	}
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	store, location, lease, value := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	_, path := storePaths(t, location, value.Slot())
	storeWindowsApplyDescriptor(t, path, "O:SYD:P(A;;FA;;;"+principals.user.String()+")(A;;FA;;;SY)", true)
	_, err = store.BeginExisting(storeContext(t), value.Slot())
	requireStoreError(t, err, ErrUnsafe)
}

func TestStoreWindowsPinnedDirectoryDeniesRename(t *testing.T) {
	_, location := storeReady(t)
	root, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal(err)
	}
	moved := location.path() + "-moved"
	renameErr := os.Rename(location.path(), moved)
	if renameErr == nil {
		cleanup := root.Close()
		t.Fatal("pinned directory unexpectedly allowed rename; checked close:", cleanup)
	}
	t.Log("actual pinned rename refusal:", renameErr)
	if err := root.revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if os.Rename(location.path(), moved) != nil || os.Rename(moved, location.path()) != nil {
		t.Fatal("unpinned owned directory rename fixture failed")
	}
}

func TestStoreWindowsHardlinkAndReparsePrerequisites(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			store, location, lease, value := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_, path := storePaths(t, location, value.Slot())
			if os.Remove(path) != nil {
				t.Fatal("record fixture removal failed")
			}
			target := filepath.Join(location.anchor, "record-target")
			if os.WriteFile(target, recordEncoded(t, value), 0o600) != nil {
				t.Fatal("record target fixture failed")
			}
			var err error
			if kind == "hardlink" {
				err = os.Link(target, path)
			} else {
				err = os.Symlink(target, path)
			}
			if err != nil {
				t.Fatal("native link prerequisite was not established", err)
			}
			_, err = store.BeginExisting(storeContext(t), value.Slot())
			requireStoreError(t, err, ErrUnsafe)
		})
	}
}

func TestStoreWindowsReplacementWithOpenReadHandleRefuses(t *testing.T) {
	_, location, lease, value := storeOccupied(t, Selection)
	_, path := storePaths(t, location, value.Slot())
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := lease.Confirm(storeContext(t), value, SelectionApplyAction)
	if reader.Close() != nil {
		t.Fatal("owned reader close failed")
	}
	if permit != nil || !errors.Is(err, ErrPersistence) {
		t.Fatal("sharing-denied replacement returned a permit")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(recordEncoded(t, value)) {
		t.Fatal("sharing-denied replacement changed original")
	}
	// Its temporary is uncertain evidence. No retry or cleanup bypass is permitted.
}

func TestStoreWindowsFinalSelectedAnchor(t *testing.T) {
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
	file, err := windowsOpenDirectory(location.anchor, true)
	if err != nil {
		t.Fatal("created anchor lacks strict native security", err)
	}
	if file.Close() != nil {
		t.Fatal("selected anchor close failed")
	}
	missing := storeFixtureLocation(t)
	missing.anchor = filepath.Join(missing.anchor, "absent-parent", "selected-config")
	_, err = BootstrapFirstUse(storeContext(t), missing, NamespaceNeverUsed)
	requireStoreError(t, err, ErrLocation)
	if _, err := os.Stat(filepath.Dir(missing.anchor)); !os.IsNotExist(err) {
		t.Fatal("an earlier anchor parent was created")
	}
}

func TestStoreWindowsUnavailableKnownFolderPolicy(t *testing.T) {
	// This is controlled selector-error propagation, not a native known-folder failure.
	original := defaultConfigRoot
	defer func() { defaultConfigRoot = original }()
	for _, result := range []error{errors.New("controlled known-folder failure"), nil} {
		defaultConfigRoot = func() (string, error) { return "", result }
		location, err := DefaultLocation()
		if !errors.Is(err, ErrLocation) || location.validate() == nil {
			t.Fatal("unavailable selected location gained fallback")
		}
	}
}

func TestStoreWindowsSelectedAnchorUnsafeChangeRefuses(t *testing.T) {
	location := storeFixtureLocation(t)
	location.anchor = filepath.Join(location.anchor, "selected-config")
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	location.observer = &storeStageAction{stage: "selected-anchor-created", action: func() error {
		storeWindowsApplyDescriptor(t, location.anchor, "O:"+principals.user.String()+"D:P(A;;FA;;;"+principals.user.String()+")(A;;FA;;;SY)(A;;FA;;;WD)", true)
		return nil
	}}
	_, err = BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
	requireStoreError(t, err, ErrUnsafe)
	if _, err := os.Stat(location.path()); !os.IsNotExist(err) {
		t.Fatal("unsafe selected anchor gained managed namespace")
	}
}

func TestStoreWindowsNonDiskHandleRefuses(t *testing.T) {
	var read, write windows.Handle
	if windows.CreatePipe(&read, &write, nil, 0) != nil {
		t.Fatal("native pipe fixture prerequisite failed")
	}
	file := os.NewFile(uintptr(read), "owned-pipe")
	if file == nil {
		if windows.CloseHandle(read) != nil {
			t.Error("pipe read handle close failed")
		}
		if windows.CloseHandle(write) != nil {
			t.Error("pipe write handle close failed")
		}
		t.Fatal("owned pipe wrapper failed")
	}
	_, err := nativeFileStamp(file, false, true)
	requireStoreError(t, err, ErrUnsafe)
	if file.Close() != nil || windows.CloseHandle(write) != nil {
		t.Fatal("native pipe fixture close failed")
	}
}

func storeWindowsSetReparse(t *testing.T, path string, data []byte) {
	t.Helper()
	if os.Getenv("OE_IDENTITY_STORE_PRIVILEGED_FIXTURES") != "1" {
		t.Fatal("native reparse fixture privilege has not been granted")
	}
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("reparse fixture path failed")
	}
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("reparse fixture handle failed")
	}
	var returned uint32
	setErr := windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &returned, nil)
	var readback [16384]byte
	getErr := windows.DeviceIoControl(handle, windows.FSCTL_GET_REPARSE_POINT, nil, 0, &readback[0], uint32(len(readback)), &returned, nil)
	closeErr := windows.CloseHandle(handle)
	if setErr != nil || getErr != nil || closeErr != nil || returned < 8 || binary.LittleEndian.Uint32(readback[:4]) != binary.LittleEndian.Uint32(data[:4]) {
		t.Fatal("actual native reparse fixture was not established and closed")
	}
}

func TestStoreWindowsJunctionAndOtherNativeReparseTag(t *testing.T) {
	for _, kind := range []string{"junction", "private-guid-tag"} {
		t.Run(kind, func(t *testing.T) {
			store, location, lease, original := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_, path := storePaths(t, location, original.Slot())
			if os.Remove(path) != nil {
				t.Fatal("native reparse record fixture removal failed")
			}
			var data []byte
			if kind == "junction" {
				if os.Mkdir(path, 0o700) != nil {
					t.Fatal("junction directory fixture failed")
				}
				target := filepath.Join(location.anchor, "junction-target")
				if os.Mkdir(target, 0o700) != nil {
					t.Fatal("junction target fixture failed")
				}
				substitute, err := windows.UTF16FromString(`\??\` + target)
				if err != nil {
					t.Fatal("junction substitute fixture failed")
				}
				printName, err := windows.UTF16FromString(target)
				if err != nil {
					t.Fatal("junction print fixture failed")
				}
				data = make([]byte, 16+2*(len(substitute)+len(printName)))
				binary.LittleEndian.PutUint32(data[:4], windows.IO_REPARSE_TAG_MOUNT_POINT)
				binary.LittleEndian.PutUint16(data[4:6], uint16(len(data)-8))
				binary.LittleEndian.PutUint16(data[10:12], uint16(2*(len(substitute)-1)))
				binary.LittleEndian.PutUint16(data[12:14], uint16(2*len(substitute)))
				binary.LittleEndian.PutUint16(data[14:16], uint16(2*(len(printName)-1)))
				for index, value := range append(substitute, printName...) {
					binary.LittleEndian.PutUint16(data[16+2*index:], value)
				}
			} else {
				if os.WriteFile(path, []byte("owned"), 0o600) != nil {
					t.Fatal("private reparse file fixture failed")
				}
				// Microsoft requires a GUID buffer for a non-Microsoft tag.
				data = make([]byte, 28)
				binary.LittleEndian.PutUint32(data[:4], 0x00000042)
				binary.LittleEndian.PutUint16(data[4:6], 4)
				copy(data[8:24], []byte{0x14, 0x28, 0x35, 0x46, 0x57, 0x68, 0x49, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8})
				copy(data[24:], []byte("test"))
			}
			storeWindowsSetReparse(t, path, data)
			_, err := store.BeginExisting(storeContext(t), original.Slot())
			requireStoreError(t, err, ErrUnsafe)
		})
	}
}

func TestStoreWindowsCurrentDirectorySecurityAtCallAndResolve(t *testing.T) {
	for _, operation := range []string{"begin", "resolve"} {
		for _, component := range []string{"root", "locks", "v1"} {
			t.Run(operation+"/"+component, func(t *testing.T) {
				fixture := storeReadyCase(t, "selection-cancel")
				permit, err := fixture.lease.Confirm(storeContext(t), fixture.expected, SelectionCancelAction)
				if err != nil {
					t.Fatal(err)
				}
				principals, err := currentWindowsPrincipals()
				if err != nil {
					t.Fatal(err)
				}
				path := fixture.location.path()
				directory := fixture.lease.namespace.root
				if component != "root" {
					path = filepath.Join(path, component)
				}
				if component == "locks" {
					directory = fixture.lease.namespace.locks
				}
				if component == "v1" {
					directory = fixture.lease.namespace.records
				}
				owner := principals.user.String()
				storeWindowsApplyDescriptor(t, path, "O:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)(A;;FR;;;WD)", true)
				before := storeCurrentTree(t, fixture)
				if operation == "begin" {
					call, beginErr := permit.Begin(storeContext(t), SelectionCancelAction)
					if call != nil {
						t.Fatal("unsafe current directory returned a call")
					}
					err = beginErr
				} else {
					result, resolveErr := fixture.lease.ResolveSelection(storeContext(t), fixture.expected, storeSelectionReceipt(t, fixture.expected, "aborted", identity.SelectionCancel))
					if _, cloneErr := result.Envelope(); cloneErr == nil {
						t.Fatal("unsafe directory returned a resolution envelope")
					}
					err = resolveErr
				}
				storeAssertCurrentRefusal(t, fixture, before, err)
				if !errors.Is(windowsCheckSecurity(windows.Handle(directory.file.Fd()), true), ErrUnsafe) {
					t.Fatal("unsafe fixture DACL was repaired")
				}
			})
		}
	}
}
