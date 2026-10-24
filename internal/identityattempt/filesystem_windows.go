package identityattempt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileAllAccess uint32 = 0x001f01ff
const windowsAncestorRead uint32 = windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.FILE_READ_ATTRIBUTES | windows.FILE_EXECUTE

type windowsPrincipals struct{ user, system, administrators *windows.SID }

var currentWindowsPrincipals = sync.OnceValues(func() (windowsPrincipals, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return windowsPrincipals{}, ErrUnsafe
	}
	owner, err := user.User.Sid.Copy()
	if err != nil {
		return windowsPrincipals{}, ErrUnsafe
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return windowsPrincipals{}, ErrUnsafe
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil || owner.Equals(system) {
		return windowsPrincipals{}, ErrUnsafe
	}
	return windowsPrincipals{owner, system, administrators}, nil
})

var defaultConfigRoot = func() (string, error) { return windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0) }

func managedDirectoryNames() [3]string    { return [3]string{"OpenE2EE", "oe", "identity-attempts"} }
func nativeReplacePhase() string          { return "move-with-write-through-returned" }
func nativeDirectoryBarrierPhase() string { return "" }

func windowsProtectedDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		return nil, err
	}
	owner := principals.user.String()
	if owner == "" {
		return nil, ErrUnsafe
	}
	value, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)")
	if err != nil {
		return nil, ErrUnsafe
	}
	return value, nil
}

func windowsCheckSecurity(handle windows.Handle, managed bool) error {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		return ErrUnsafe
	}
	owner, defaulted, err := sd.Owner()
	if err != nil || defaulted || owner == nil || !owner.IsValid() {
		return ErrUnsafe
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(principals.user) || sid.Equals(principals.system) || sid.Equals(principals.administrators)
	}
	if managed && !owner.Equals(principals.user) || !managed && !trusted(owner) {
		return ErrUnsafe
	}
	dacl, defaulted, err := sd.DACL()
	if err != nil || defaulted || dacl == nil {
		return ErrUnsafe
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PRESENT == 0 {
		return ErrUnsafe
	}
	if managed && (control&windows.SE_DACL_PROTECTED == 0 || dacl.AceCount != 2) {
		return ErrUnsafe
	}
	seenUser, seenSystem := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil || ace.Header.AceSize < 12 {
			return ErrUnsafe
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			return ErrUnsafe
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 != int(ace.Header.AceSize) {
			return ErrUnsafe
		}
		if managed {
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || uint32(ace.Mask) != windowsFileAllAccess {
				return ErrUnsafe
			}
			switch {
			case sid.Equals(principals.user):
				if seenUser {
					return ErrUnsafe
				}
				seenUser = true
			case sid.Equals(principals.system):
				if seenSystem {
					return ErrUnsafe
				}
				seenSystem = true
			default:
				return ErrUnsafe
			}
		} else {
			// Unknown ACE flag semantics refuse. Broad mutation grants are never inferred safe.
			if ace.Header.AceFlags & ^uint8(0x1f) != 0 {
				return ErrUnsafe
			}
			if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && uint32(ace.Mask)&^windowsAncestorRead != 0 && !trusted(sid) {
				return ErrUnsafe
			}
		}
	}
	runtime.KeepAlive(sd)
	if managed && (!seenUser || !seenSystem) {
		return ErrUnsafe
	}
	return nil
}

func nativeFileStamp(file *os.File, directory, managed bool) (fileStamp, error) {
	if file == nil {
		return fileStamp{}, ErrUnsafe
	}
	handle := windows.Handle(file.Fd())
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return fileStamp{}, ErrUnsafe
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil {
		return fileStamp{}, ErrUnsafe
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fileStamp{}, ErrUnsafe
	}
	actualDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if actualDirectory != directory || !directory && info.NumberOfLinks != 1 {
		return fileStamp{}, ErrUnsafe
	}
	if err := windowsCheckSecurity(handle, managed); err != nil {
		return fileStamp{}, err
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size > 1<<63-1 {
		return fileStamp{}, ErrTooLarge
	}
	return fileStamp{uint64(info.VolumeSerialNumber), uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), int64(size)}, nil
}

func windowsOpenDirectory(path string, managed bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrLocation
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, errMissing
		}
		return nil, ErrUnsafe
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		if windows.CloseHandle(handle) != nil {
			return nil, combine(ErrUnsafe, ErrRelease)
		}
		return nil, ErrUnsafe
	}
	if _, err := nativeFileStamp(file, true, managed); err != nil {
		return nil, combine(err, releaseFile(file))
	}
	return file, nil
}

func windowsMakeDirectory(ctx context.Context, path string) (bool, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, ErrLocation
	}
	sd, err := windowsProtectedDescriptor()
	if err != nil {
		return false, err
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := phase(ctx); err != nil {
		return false, err
	}
	err = windows.CreateDirectory(name, &security)
	runtime.KeepAlive(sd)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false, nil
	}
	if err != nil {
		return false, ErrPersistence
	}
	return true, nil
}

func nativeOpenLocation(ctx context.Context, location Location, create bool) (*nativeDirectory, bool, error) {
	if err := phase(ctx); err != nil {
		return nil, false, err
	}
	if location.validate() != nil {
		return nil, false, ErrLocation
	}
	volume := filepath.VolumeName(location.anchor)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(location.anchor, `\\`) {
		return nil, false, ErrLocation
	}
	rootPath := volume + string(filepath.Separator)
	rootName, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return nil, false, ErrLocation
	}
	switch windows.GetDriveType(rootName) {
	case windows.DRIVE_UNKNOWN, windows.DRIVE_NO_ROOT_DIR, windows.DRIVE_REMOTE:
		return nil, false, ErrUnsafe
	}
	root, err := windowsOpenDirectory(rootPath, false)
	if err != nil {
		return nil, false, err
	}
	pins := []*os.File{root}
	fail := func(err error) (*nativeDirectory, bool, error) {
		for index := len(pins) - 1; index >= 0; index-- {
			err = combine(err, releaseFile(pins[index]))
		}
		return nil, false, err
	}
	currentPath := rootPath
	parts := strings.Split(strings.TrimPrefix(location.anchor, rootPath), string(filepath.Separator))
	if location.anchor == rootPath {
		parts = nil
	}
	for index, part := range parts {
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		if !validLeaf(part) {
			return fail(ErrLocation)
		}
		currentPath = filepath.Join(currentPath, part)
		file, err := windowsOpenDirectory(currentPath, false)
		createdAnchor := false
		if soleMissing(err) && index != len(parts)-1 {
			return fail(ErrLocation)
		}
		if soleMissing(err) && create {
			if err := phase(ctx); err != nil {
				return fail(err)
			}
			if err := observe(ctx, location.observer, "before-selected-anchor-create"); err != nil {
				return fail(err)
			}
			createdAnchor, err = windowsMakeDirectory(ctx, currentPath)
			if err != nil {
				return fail(err)
			}
			if err := phase(ctx); err != nil {
				return fail(err)
			}
			file, err = windowsOpenDirectory(currentPath, createdAnchor)
		}
		if err != nil {
			return fail(err)
		}
		pins = append(pins, file)
		if createdAnchor {
			// Windows uses checked native security/readback, not a POSIX directory flush.
			if err := observe(ctx, location.observer, "selected-anchor-created"); err != nil {
				return fail(err)
			}
		}
	}
	createdFinal := false
	for index, part := range location.managed {
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		if _, err := nativeFileStamp(pins[len(pins)-1], true, index > 0); err != nil {
			return fail(err)
		}
		currentPath = filepath.Join(currentPath, part)
		if create {
			if err := observe(ctx, location.observer, "before-managed-directory-create"); err != nil {
				return fail(err)
			}
			created, err := windowsMakeDirectory(ctx, currentPath)
			if err != nil {
				return fail(err)
			}
			if index == len(location.managed)-1 {
				createdFinal = created
			}
		}
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		file, err := windowsOpenDirectory(currentPath, true)
		if err != nil {
			return fail(err)
		}
		pins = append(pins, file)
	}
	return &nativeDirectory{file: pins[len(pins)-1], path: currentPath, pins: pins[:len(pins)-1]}, createdFinal, nil
}

func (d *nativeDirectory) revalidate() error {
	before, err := nativeFileStamp(d.file, true, true)
	if err != nil {
		return err
	}
	current, err := windowsOpenDirectory(d.path, true)
	if soleMissing(err) {
		return ErrChanged
	}
	if err != nil {
		return err
	}
	after, check := nativeFileStamp(current, true, true)
	if check == nil && (before.device != after.device || before.object != after.object) {
		check = ErrChanged
	}
	return combine(check, releaseFile(current))
}

func (d *nativeDirectory) subdirectory(ctx context.Context, name string, create bool) (*nativeDirectory, error) {
	if err := phase(ctx); err != nil {
		return nil, err
	}
	if !validLeaf(name) {
		return nil, ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	path := filepath.Join(d.path, name)
	if create {
		created, err := windowsMakeDirectory(ctx, path)
		if err != nil {
			return nil, err
		}
		if !created {
			return nil, ErrUncertain
		}
	}
	file, err := windowsOpenDirectory(path, true)
	if check := d.revalidate(); check != nil {
		if file != nil {
			check = combine(check, releaseFile(file))
		}
		return nil, combine(err, check)
	}
	if err != nil {
		return nil, err
	}
	return &nativeDirectory{file: file, path: path}, nil
}

func (d *nativeDirectory) openFile(ctx context.Context, name string, create bool) (*os.File, error) {
	if err := phase(ctx); err != nil {
		return nil, err
	}
	if !validLeaf(name) {
		return nil, ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	path := filepath.Join(d.path, name)
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrFormat
	}
	disposition := uint32(windows.OPEN_EXISTING)
	var security *windows.SecurityAttributes
	var sd *windows.SECURITY_DESCRIPTOR
	if create {
		disposition = windows.CREATE_NEW
		sd, err = windowsProtectedDescriptor()
		if err != nil {
			return nil, err
		}
		security = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(wide, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, security, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		if check := d.revalidate(); check != nil {
			return nil, check
		}
		if errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, ErrChanged
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, errMissing
		}
		if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, errExists
		}
		return nil, ErrUnsafe
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		if windows.CloseHandle(handle) != nil {
			return nil, combine(ErrUnsafe, ErrRelease)
		}
		return nil, ErrUnsafe
	}
	if _, err := nativeFileStamp(file, false, true); err != nil {
		return nil, combine(err, releaseFile(file))
	}
	return file, nil
}

func (d *nativeDirectory) names() ([]string, error) {
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	file, err := windowsOpenDirectory(d.path, true)
	if err != nil {
		return nil, err
	}
	names, readErr := file.Readdirnames(-1)
	if readErr != nil {
		readErr = ErrPersistence
	}
	return names, combine(readErr, releaseFile(file))
}

func (d *nativeDirectory) replace(ctx context.Context, source, destination string) error {
	if err := phase(ctx); err != nil {
		return err
	}
	if !validLeaf(source) || !validLeaf(destination) {
		return ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(filepath.Join(d.path, source))
	if err != nil {
		return ErrFormat
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(d.path, destination))
	if err != nil {
		return ErrFormat
	}
	if err := phase(ctx); err != nil {
		return err
	}
	if windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH) != nil {
		return ErrPersistence
	}
	return nil
}

// Windows has no POSIX directory barrier here. The checked move is one phase.
func (d *nativeDirectory) sync(ctx context.Context) error {
	if err := phase(ctx); err != nil {
		return err
	}
	if err := d.revalidate(); err != nil {
		return err
	}
	return phase(ctx)
}

func nativeLock(ctx context.Context, file *os.File, exclusive bool) error {
	if err := boundedContext(ctx); err != nil {
		return err
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	for {
		if err := phase(ctx); err != nil {
			return ErrBusy
		}
		var position windows.Overlapped
		err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &position)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return ErrUnsafe
		}
		timer := time.NewTimer(acquisitionPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrBusy
		case <-timer.C:
		}
	}
}

func nativeUnlock(file *os.File) error {
	if file == nil {
		return ErrRelease
	}
	var position windows.Overlapped
	if windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &position) != nil {
		return ErrRelease
	}
	return nil
}
