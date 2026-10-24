//go:build windows

package identityattempt

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func storeWindowsAncestorDescriptor(t *testing.T, path string) [32]byte {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() || sd.String() == "" {
		t.Fatal("owned ancestor security readback failed")
	}
	return sha256.Sum256([]byte(sd.String()))
}

func storeWindowsReadFixtureDescriptor(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() {
		t.Fatal("native fixture descriptor readback failed", err)
	}
	owner, defaulted, ownerErr := sd.Owner()
	control, _, controlErr := sd.Control()
	acl, _, aclErr := sd.DACL()
	if ownerErr != nil || controlErr != nil || aclErr != nil || owner == nil || !owner.IsValid() || acl == nil || acl.AceCount > 16 {
		t.Fatal("native fixture descriptor readback is not bounded")
	}
	t.Logf("native owned descriptor owner=%s ownerDefaulted=%t control=%#x aces=%d", owner.String(), defaulted, control, acl.AceCount)
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil || ace.Header.AceSize < 12 ||
			ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
			t.Fatal("native fixture ACE readback is not a bounded allow/deny ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 != int(ace.Header.AceSize) {
			t.Fatal("native fixture ACE SID readback failed")
		}
		t.Logf("native owned ACE index=%d type=%#x flags=%#x mask=%#x sid=%s", index, ace.Header.AceType, ace.Header.AceFlags, ace.Mask, sid.String())
	}
	runtime.KeepAlive(sd)
	return sd
}

func storeWindowsAncestorACEEstablished(t *testing.T, path, descriptor string) {
	t.Helper()
	// Read and report the actual native shape before checking the ACE roster.
	actual := storeWindowsReadFixtureDescriptor(t, path)
	expected, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		t.Fatal("expected ancestor ACE did not parse")
	}
	expectedACL, _, err := expected.DACL()
	if err != nil || expectedACL == nil || expectedACL.AceCount < 2 || expectedACL.AceCount > 3 {
		t.Fatal("expected ancestor ACE roster invalid")
	}
	actualACL, _, err := actual.DACL()
	if err != nil || actualACL == nil || actualACL.AceCount != expectedACL.AceCount {
		t.Fatal("actual ancestor ACE roster unavailable or changed")
	}
	wantOwner, _, ownerErr := expected.Owner()
	owner, _, actualOwnerErr := actual.Owner()
	wantControl, _, controlErr := expected.Control()
	control, _, actualControlErr := actual.Control()
	if ownerErr != nil || actualOwnerErr != nil || controlErr != nil || actualControlErr != nil ||
		!owner.Equals(wantOwner) || (control^wantControl)&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("native fixture owner or protection differs")
	}
	for wanted := uint32(0); wanted < uint32(expectedACL.AceCount); wanted++ {
		var want *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(expectedACL, wanted, &want) != nil || want == nil {
			t.Fatal("expected ancestor ACE unavailable")
		}
		wantSID := (*windows.SID)(unsafe.Pointer(&want.SidStart))
		mapped := uint32(want.Mask) &^ (windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE)
		for _, entry := range []struct{ generic, specific uint32 }{
			{windows.GENERIC_ALL, windowsFileAllAccess}, {windows.GENERIC_READ, windows.FILE_GENERIC_READ},
			{windows.GENERIC_WRITE, windows.FILE_GENERIC_WRITE}, {windows.GENERIC_EXECUTE, windows.FILE_GENERIC_EXECUTE},
		} {
			if uint32(want.Mask)&entry.generic != 0 {
				mapped |= entry.specific
			}
		}
		matched := false
		for index := uint32(0); index < uint32(actualACL.AceCount); index++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(actualACL, index, &ace) != nil || ace == nil {
				t.Fatal("actual ancestor ACE unavailable")
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(wantSID) && ace.Header.AceType == want.Header.AceType && ace.Header.AceFlags == want.Header.AceFlags &&
				(uint32(ace.Mask) == uint32(want.Mask) || uint32(ace.Mask) == mapped) {
				matched = true
			}
		}
		if !matched {
			t.Fatal("native ACL did not retain the intended effective/inherit-only fixture grant")
		}
	}
	runtime.KeepAlive(expected)
	runtime.KeepAlive(actual)
}

func storeWindowsInheritFixtureACL(t *testing.T, path, parentACE, childACEs string) {
	t.Helper()
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	owner := principals.user.String()
	base := "O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)"
	// Keep access to the owned child until its explicit inheritance transition.
	storeWindowsApplyDescriptor(t, path, base, true)
	storeWindowsApplyDescriptor(t, filepath.Dir(path), base+parentACE, true)
	storeWindowsApplyDescriptor(t, path, "O:"+owner+"D:"+childACEs, false)
}

func storeWindowsInheritedOwnerRecord(t *testing.T, location Location, path, owner string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("inherited owner record read failed", err)
	}
	parent := filepath.Join(location.anchor, "native-inherited-owner")
	source := filepath.Join(parent, "record.json")
	if os.Mkdir(parent, 0o700) != nil || os.WriteFile(source, data, 0o600) != nil {
		t.Fatal("inherited owner record creation failed")
	}
	storeWindowsInheritFixtureACL(t, source, "(A;OINP;FA;;;"+owner+")", "(A;;FA;;;SY)")
	descriptor := "O:" + owner + "D:(A;;FA;;;SY)(A;ID;FA;;;" + owner + ")"
	storeWindowsAncestorACEEstablished(t, source, descriptor)
	before := storeFixtureObjectStamp(t, source, false)
	security := storeWindowsAncestorDescriptor(t, source)
	if os.Rename(source, path) != nil {
		t.Fatal("same-volume inherited record move failed")
	}
	storeWindowsAncestorACEEstablished(t, path, descriptor)
	if after := storeFixtureObjectStamp(t, path, false); after != before || storeWindowsAncestorDescriptor(t, path) != security {
		t.Fatal("inherited record move changed its object or descriptor")
	}
	if actual, err := os.ReadFile(path); err != nil || string(actual) != string(data) {
		t.Fatal("inherited record move changed retained bytes", err)
	}
	t.Log("managed record fixture has genuine inherited owner access and an unprotected DACL; protected parent directories remain unchanged")
}

func TestStoreWindowsAncestorEffectiveAndInheritOnlyGrants(t *testing.T) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	base := "O:" + principals.user.String() + "D:P(A;;FA;;;" + principals.user.String() + ")(A;;FA;;;SY)"
	for _, vector := range []struct {
		name, ace string
		accept    bool
	}{
		{"read-only", "(A;;FR;;;WD)", true},
		{"create-subdirectory", "(A;;0x00000004;;;AU)", true},
		{"creator-owner-inherit-only", "(A;OICIIO;GA;;;CO)", true},
		{"everyone-inherit-only-full", "(A;OICIIO;FA;;;WD)", true},
		{"inherited-inherit-only-full", "(A;OICIIDIO;FA;;;WD)", true},
		{"effective-creator-owner", "(A;;GA;;;CO)", false},
		{"effective-inheritable-full", "(A;OICI;FA;;;WD)", false},
		{"effective-inherited-full", "(A;ID;FA;;;WD)", false},
		{"create-file-is-write-data", "(A;;0x00000002;;;WD)", false},
		{"delete-object", "(A;;0x00010000;;;WD)", false},
		{"delete-child", "(A;;0x00000040;;;WD)", false},
		{"write-attributes", "(A;;0x00000100;;;WD)", false},
		{"write-extended-attributes", "(A;;0x00000010;;;WD)", false},
		{"change-dacl", "(A;;0x00040000;;;WD)", false},
		{"change-owner", "(A;;0x00080000;;;WD)", false},
		{"generic-write", "(A;;GW;;;WD)", false},
		{"generic-all", "(A;;GA;;;WD)", false},
	} {
		t.Run(vector.name, func(t *testing.T) {
			location := storeFixtureLocation(t)
			descriptor := base + vector.ace
			if vector.name == "inherited-inherit-only-full" || vector.name == "effective-inherited-full" {
				child := filepath.Join(location.anchor, "native-inherited-child")
				if os.Mkdir(child, 0o700) != nil {
					t.Fatal("native inherited child creation failed")
				}
				parentACE, childACE := "(A;CINP;FA;;;WD)", "(A;ID;FA;;;WD)"
				if vector.name == "inherited-inherit-only-full" {
					// OI produces a genuine inherited, inherit-only ACE on a directory.
					parentACE, childACE = "(A;OI;FA;;;WD)", "(A;OIIDIO;FA;;;WD)"
				}
				storeWindowsInheritFixtureACL(t, child, parentACE, "(A;;FA;;;"+principals.user.String()+")(A;;FA;;;SY)")
				location.anchor = child
				descriptor = "O:" + principals.user.String() + "D:(A;;FA;;;" + principals.user.String() + ")(A;;FA;;;SY)" + childACE
			} else if vector.name == "effective-creator-owner" {
				storeWindowsApplyDescriptor(t, location.anchor, base, true)
				storeWindowsAncestorACEEstablished(t, location.anchor, base)
				sd, err := windows.SecurityDescriptorFromString(descriptor)
				if err != nil || sd == nil || !sd.IsValid() {
					t.Fatal("raw Creator Owner descriptor fixture did not parse", err)
				}
				wide, err := windows.UTF16PtrFromString(location.anchor)
				if err != nil {
					t.Fatal("raw Creator Owner fixture path failed", err)
				}
				setFileSecurity := windows.NewLazySystemDLL("advapi32.dll").NewProc("SetFileSecurityW")
				if err := setFileSecurity.Find(); err != nil {
					t.Fatal("native file security fixture API unavailable", err)
				}
				changed, _, callErr := setFileSecurity.Call(uintptr(unsafe.Pointer(wide)),
					uintptr(windows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(sd)))
				runtime.KeepAlive(sd)
				runtime.KeepAlive(wide)
				if changed == 0 {
					t.Fatal("raw Creator Owner DACL fixture update failed", callErr)
				}
			} else {
				storeWindowsApplyDescriptor(t, location.anchor, descriptor, true)
			}
			storeWindowsAncestorACEEstablished(t, location.anchor, descriptor)
			before := storeWindowsAncestorDescriptor(t, location.anchor)
			file, err := windowsOpenDirectory(location.anchor, false)
			if file != nil && file.Close() != nil {
				t.Fatal("ancestor qualification handle close failed")
			}
			if vector.accept && err != nil || !vector.accept && !errors.Is(err, ErrUnsafe) {
				t.Fatal("effective ancestor permission classification failed", err)
			}
			if after := storeWindowsAncestorDescriptor(t, location.anchor); after != before {
				t.Fatal("ancestor qualification changed its security descriptor")
			}
		})
	}
}

func TestStoreWindowsAncestorInheritanceNeverWeakensManagedSecurity(t *testing.T) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	location := storeFixtureLocation(t)
	owner := principals.user.String()
	storeWindowsApplyDescriptor(t, location.anchor, "O:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)(A;;0x00000004;;;AU)(A;OICIIO;FA;;;WD)(A;OICIIO;GA;;;CO)", true)
	if _, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed); err != nil {
		t.Fatal("safe ancestor creation/inheritance shape was refused", err)
	}
	directory, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := windowsCheckSecurity(windows.Handle(directory.file.Fd()), true); err != nil {
		t.Fatal("managed directory inherited a parent grant", err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	for _, ace := range []string{"(A;;0x00000004;;;AU)", "(A;OICIIO;FA;;;WD)", "(A;OICIIO;GA;;;CO)"} {
		storeWindowsApplyDescriptor(t, location.path(), "O:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)"+ace, true)
		before := storeWindowsAncestorDescriptor(t, location.path())
		file, err := windowsOpenDirectory(location.path(), true)
		if file != nil && file.Close() != nil {
			t.Fatal("managed refusal handle close failed")
		}
		if !errors.Is(err, ErrUnsafe) || storeWindowsAncestorDescriptor(t, location.path()) != before {
			t.Fatal("managed exact two-entry security was weakened or repaired", err)
		}
	}
}

func storeWindowsDeleteHandle(path string) (windows.Handle, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(wide, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func TestStoreWindowsCreateSiblingCannotReplacePinnedExistingChild(t *testing.T) {
	_, location := storeReady(t)
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	owner := principals.user.String()
	storeWindowsApplyDescriptor(t, location.anchor, "O:"+owner+"D:P(A;;FA;;;"+owner+")(A;;FA;;;SY)(A;;0x00000004;;;AU)(A;OICIIO;GA;;;CO)", true)
	directory, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed && directory.Close() != nil {
			t.Error("pinned directory cleanup failed")
		}
	}()
	created, err := windowsMakeDirectory(storeContext(t), filepath.Join(location.anchor, "new-sibling"))
	if err != nil || !created {
		t.Fatal("pinned ancestor refused unrelated child creation", err)
	}
	paths := []string{location.anchor}
	path := location.anchor
	for _, component := range location.managed {
		path = filepath.Join(path, component)
		paths = append(paths, path)
	}
	for _, path := range paths {
		handle, err := storeWindowsDeleteHandle(path)
		if err == nil {
			if windows.CloseHandle(handle) != nil {
				t.Error("unexpected delete handle close failed")
			}
			t.Fatal("existing pinned child allowed delete or replacement access")
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatal("pinned refusal did not establish the sharing invariant", err)
		}
		if os.Rename(path, path+"-moved") == nil {
			t.Fatal("existing pinned child allowed rename")
		}
	}
	if err := directory.revalidate(); err != nil {
		t.Fatal("sibling creation displaced the qualified child", err)
	}
	if err := directory.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	for _, path := range paths {
		handle, err := storeWindowsDeleteHandle(path)
		if err != nil || windows.CloseHandle(handle) != nil {
			t.Fatal("unpinned positive delete-access control failed", err)
		}
		if os.Rename(path, path+"-moved") != nil || os.Rename(path+"-moved", path) != nil {
			t.Fatal("unpinned positive rename control failed")
		}
	}
}
