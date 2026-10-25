//go:build windows && (identity_default_root_qualification || identity_default_qualification)

package identityattempt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
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
	storeWindowsDefaultPrincipal(t)
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

func storeWindowsDefaultPrincipal(t *testing.T) map[string]any {
	t.Helper()
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
	return map[string]any{"identity": user.User.Sid.String(), "administrator": false, "elevated": false,
		"onlyEnabledPrivilege": "SeChangeNotifyPrivilege", "os": runtime.GOOS, "architecture": runtime.GOARCH}
}

func defaultQualificationPlatform(t *testing.T, location Location) map[string]any {
	t.Helper()
	result := storeWindowsDefaultPrincipal(t)
	expected, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if err != nil || expected != location.anchor {
		t.Fatal("production default does not match the actual standard user's Known Folder")
	}
	result["defaultAnchor"] = expected
	var ancestors []map[string]any
	for _, row := range storeWindowsDefaultTreeMetadata(t, location) {
		ancestors = append(ancestors, map[string]any{"device": row.device, "object": row.object,
			"attributes": row.attributes, "descriptorSHA256": hex.EncodeToString(row.descriptor[:]), "missing": row.missing})
	}
	result["nativeAncestors"] = ancestors
	return result
}

func defaultQualificationEvidenceStamp(t *testing.T, file *os.File) fileStamp {
	t.Helper()
	handle := windows.Handle(file.Fd())
	kind, kindErr := windows.GetFileType(handle)
	var info windows.ByHandleFileInformation
	if kindErr != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		t.Fatal("ordinary handoff native file identity unavailable")
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size > 2097152 {
		t.Fatal("ordinary handoff file exceeds its bound")
	}
	return fileStamp{uint64(info.VolumeSerialNumber), uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), int64(size)}
}

var storeWindowsLoaderNonce = flag.String("identity-loader-gui-nonce", "", "explicit disposable loader observation nonce")
var storeWindowsLoaderSID = flag.String("identity-loader-gui-sid", "", "expected disposable loader observation SID")

func storeWindowsLoaderReport(t *testing.T, stage, code string, detail map[string]any, err error) {
	t.Helper()
	if detail == nil {
		detail = make(map[string]any)
	}
	detail["stage"], detail["code"] = stage, code
	if err != nil {
		detail["errorType"] = fmt.Sprintf("%T", err)
		var native windows.Errno
		if errors.As(err, &native) {
			detail["win32Code"] = uint64(native)
		}
	}
	data, encodeErr := json.Marshal(detail)
	if encodeErr != nil || len(data) > 4096 {
		t.Fatal("loader observation exceeds its fixed record bound")
	}
	t.Logf("loader-gui-observation %s", data)
	switch code {
	case "LOAD_FAILED", "RESOLVE_FAILED", "NULL_HANDLE", "QUERY_FAILED", "INVALID_RETURNED_SPAN", "INVALID_RETURNED_NAME":
		t.Fail()
	}
}

// This changes DLL load order. Its observations cannot qualify any D case.
func TestStoreWindowsLoaderGUIObservation(t *testing.T) {
	if len(*storeWindowsLoaderNonce) != 32 || strings.Trim(*storeWindowsLoaderNonce, "0123456789abcdef") != "" || *storeWindowsLoaderSID == "" {
		t.Fatal("explicit disposable loader observation identity is required")
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		t.Fatal("loader observation refuses an operation ID")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	principal := storeWindowsDefaultPrincipal(t)
	if principal["identity"] != *storeWindowsLoaderSID {
		t.Fatal("loader observation caller differs from the disposable SID")
	}
	threadID := windows.GetCurrentThreadId()
	started := time.Now()
	before := func(stage string) {
		if time.Since(started) >= 5*time.Second {
			t.Fatal("loader observation exceeded its five-second logical budget")
		}
		storeWindowsLoaderReport(t, stage, "STARTED", nil, nil)
	}
	storeWindowsLoaderReport(t, "context", "DIAGNOSTIC_ONLY", map[string]any{
		"pid": os.Getpid(), "threadID": threadID, "nonce": *storeWindowsLoaderNonce,
		"principal": principal, "dCredit": false, "dllReferences": "retained until process exit",
	}, nil)
	user32 := windows.NewLazySystemDLL("user32.dll")
	before("user32-load")
	userErr := user32.Load()
	if userErr != nil {
		storeWindowsLoaderReport(t, "user32-load", "LOAD_FAILED", nil, userErr)
		storeWindowsLoaderReport(t, "gui-readbacks", "NOT_ATTEMPTED_USER32_UNAVAILABLE", nil, nil)
	} else {
		storeWindowsLoaderReport(t, "user32-load", "AVAILABLE", nil, nil)
		resolve := func(name string) *windows.LazyProc {
			before(name + "-resolve")
			proc := user32.NewProc(name)
			if err := proc.Find(); err != nil {
				storeWindowsLoaderReport(t, name+"-resolve", "RESOLVE_FAILED", nil, err)
				return nil
			}
			storeWindowsLoaderReport(t, name+"-resolve", "AVAILABLE", nil, nil)
			return proc
		}
		station := resolve("GetProcessWindowStation")
		desktop := resolve("GetThreadDesktop")
		information := resolve("GetUserObjectInformationW")
		objects := []struct {
			name, expected string
			proc           *windows.LazyProc
			args           []uintptr
		}{
			{"station", "ca8_station_" + *storeWindowsLoaderNonce, station, nil},
			{"desktop", "ca8_desktop_" + *storeWindowsLoaderNonce, desktop, []uintptr{uintptr(threadID)}},
		}
		for _, object := range objects {
			if object.proc == nil {
				storeWindowsLoaderReport(t, object.name, "NOT_ATTEMPTED_PROCEDURE_UNAVAILABLE", nil, nil)
				continue
			}
			before(object.name + "-handle")
			handle, _, callErr := object.proc.Call(object.args...)
			if handle == 0 {
				storeWindowsLoaderReport(t, object.name, "NULL_HANDLE", map[string]any{"null": true}, callErr)
				continue
			}
			// These association handles are borrowed. Never close or replace them.
			storeWindowsLoaderReport(t, object.name+"-handle", "AVAILABLE", map[string]any{"null": false}, nil)
			if information == nil {
				storeWindowsLoaderReport(t, object.name+"-name", "NOT_ATTEMPTED_PROCEDURE_UNAVAILABLE", nil, nil)
				continue
			}
			var buffer [256]uint16
			var needed uint32
			before(object.name + "-name")
			ok, _, nameErr := information.Call(handle, 2, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Sizeof(buffer)), uintptr(unsafe.Pointer(&needed)))
			runtime.KeepAlive(buffer)
			if ok == 0 {
				storeWindowsLoaderReport(t, object.name+"-name", "QUERY_FAILED", map[string]any{"neededBytes": needed}, nameErr)
				continue
			}
			if needed < 2 || needed > uint32(unsafe.Sizeof(buffer)) || needed%2 != 0 || buffer[needed/2-1] != 0 {
				storeWindowsLoaderReport(t, object.name+"-name", "INVALID_RETURNED_SPAN", map[string]any{"neededBytes": needed}, nil)
				continue
			}
			units := buffer[:needed/2-1]
			if len(units) == 0 || slices.Contains(units, uint16(0)) {
				storeWindowsLoaderReport(t, object.name+"-name", "INVALID_RETURNED_NAME", map[string]any{"neededBytes": needed}, nil)
				continue
			}
			name := windows.UTF16ToString(units)
			storeWindowsLoaderReport(t, object.name+"-name", "AVAILABLE", map[string]any{
				"name": name, "neededBytes": needed, "matchesRequested": name == object.expected,
			}, nil)
			if name != object.expected {
				t.Fail()
			}
		}
	}
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	before("shell32-load")
	if err := shell32.Load(); err != nil {
		storeWindowsLoaderReport(t, "shell32-load", "LOAD_FAILED", nil, err)
		storeWindowsLoaderReport(t, "SHGetKnownFolderPath-resolve", "NOT_ATTEMPTED_SHELL32_UNAVAILABLE", nil, nil)
	} else {
		storeWindowsLoaderReport(t, "shell32-load", "AVAILABLE", nil, nil)
		before("SHGetKnownFolderPath-resolve")
		if err := shell32.NewProc("SHGetKnownFolderPath").Find(); err != nil {
			storeWindowsLoaderReport(t, "SHGetKnownFolderPath-resolve", "RESOLVE_FAILED", nil, err)
		} else {
			storeWindowsLoaderReport(t, "SHGetKnownFolderPath-resolve", "AVAILABLE_NOT_CALLED", nil, nil)
		}
	}
	runtime.KeepAlive(user32)
	runtime.KeepAlive(shell32)
	before("sequence-returned")
	storeWindowsLoaderReport(t, "sequence-returned", "DIAGNOSTIC_ONLY", map[string]any{
		"elapsedMilliseconds": time.Since(started).Milliseconds(), "dCredit": false,
	}, nil)
}
