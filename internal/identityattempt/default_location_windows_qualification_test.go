//go:build windows && identity_default_root_qualification

package identityattempt

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

type storeWindowsDefaultMetadata struct {
	device     uint32
	object     uint64
	attributes uint32
	descriptor [32]byte
	missing    bool
}

// This qualifier reads the real caller's Known Folder without an injected root.
// Its build tag keeps ordinary-user acceptance separate from privileged fixtures.
func TestStoreWindowsOrdinaryDefaultLocationReadOnly(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal("ordinary caller token user unavailable")
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil || user.User.Sid.Equals(system) {
		t.Fatal("ordinary qualifier refuses SYSTEM")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal("ordinary caller token groups unavailable")
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.Equals(administrators) {
			t.Fatal("ordinary qualifier refuses administrator membership, including a filtered token")
		}
	}
	var elevation, returned uint32
	if windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returned) != nil ||
		returned != uint32(unsafe.Sizeof(elevation)) || elevation != 0 {
		t.Fatal("ordinary qualifier requires a verified unelevated token")
	}
	storeWindowsOrdinaryPrivileges(t, token)
	expected, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil {
		t.Fatal("actual Known Folder prerequisite unavailable")
	}
	location, err := DefaultLocation()
	if err != nil || location.anchor != expected {
		t.Fatal("production selection did not use the actual Known Folder")
	}
	before := storeWindowsDefaultTreeMetadata(t, location)
	directory, created, err := nativeOpenLocation(storeContext(t), location, false)
	if created || err != nil && !soleMissing(err) {
		t.Fatal("actual ordinary default-root chain was refused", err)
	}
	if directory != nil && directory.Close() != nil {
		t.Fatal("ordinary read-only qualifier handle close failed")
	}
	after := storeWindowsDefaultTreeMetadata(t, location)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("ordinary qualification changed directory identity, attributes, owner or DACL")
	}
	t.Log("actual ordinary Known Folder ancestor chain qualified without namespace creation or ACL repair")
}

func storeWindowsOrdinaryPrivileges(t *testing.T, token windows.Token) {
	t.Helper()
	var required, returned uint32
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &required); !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || required < 4 || required > 65536 {
		t.Fatal("ordinary token privilege size prerequisite failed")
	}
	buffer := make([]byte, required)
	if windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], required, &returned) != nil || returned != required {
		t.Fatal("ordinary token privilege readback failed")
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	offset := uint32(unsafe.Offsetof(privileges.Privileges))
	entrySize := uint32(unsafe.Sizeof(windows.LUIDAndAttributes{}))
	if returned < offset || privileges.PrivilegeCount > (returned-offset)/entrySize {
		t.Fatal("ordinary token privilege count is invalid")
	}
	name, err := windows.UTF16PtrFromString("SeChangeNotifyPrivilege")
	var traverse windows.LUID
	if err != nil || windows.LookupPrivilegeValue(nil, name, &traverse) != nil {
		t.Fatal("ordinary traverse privilege prerequisite failed")
	}
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 && privilege.Luid != traverse {
			t.Fatal("ordinary qualifier refuses enabled privileges beyond default traverse checking")
		}
	}
	runtime.KeepAlive(buffer)
}

func storeWindowsDefaultTreeMetadata(t *testing.T, location Location) []storeWindowsDefaultMetadata {
	t.Helper()
	volume := filepath.VolumeName(location.anchor)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatal("actual default-root qualifier requires a local drive")
	}
	path := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(location.anchor, path), string(filepath.Separator))
	if location.anchor == path {
		parts = nil
	}
	paths := []string{path}
	for _, part := range append(parts, location.managed[:]...) {
		if !validLeaf(part) {
			t.Fatal("actual default-root component is invalid")
		}
		path = filepath.Join(path, part)
		paths = append(paths, path)
	}
	var result []storeWindowsDefaultMetadata
	for _, path := range paths {
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal("metadata qualifier path unavailable")
		}
		handle, err := windows.CreateFile(wide, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return append(result, storeWindowsDefaultMetadata{missing: true})
		}
		if err != nil {
			t.Fatal("actual directory metadata open failed")
		}
		var info windows.ByHandleFileInformation
		informationErr := windows.GetFileInformationByHandle(handle, &info)
		sd, securityErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		closeErr := windows.CloseHandle(handle)
		if informationErr != nil || securityErr != nil || closeErr != nil || sd == nil || !sd.IsValid() || sd.String() == "" {
			t.Fatal("actual directory metadata readback or close failed")
		}
		result = append(result, storeWindowsDefaultMetadata{device: info.VolumeSerialNumber,
			object: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), attributes: info.FileAttributes,
			descriptor: sha256.Sum256([]byte(sd.String()))})
	}
	return result
}
