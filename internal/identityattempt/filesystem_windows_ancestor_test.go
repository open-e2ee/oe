//go:build windows

package identityattempt

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
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

func storeWindowsAncestorACEEstablished(t *testing.T, path, descriptor string) {
	t.Helper()
	expected, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		t.Fatal("expected ancestor ACE did not parse")
	}
	expectedACL, _, err := expected.DACL()
	if err != nil || expectedACL == nil || expectedACL.AceCount != 3 {
		t.Fatal("expected ancestor ACE roster invalid")
	}
	var want *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(expectedACL, 2, &want) != nil || want == nil {
		t.Fatal("expected ancestor ACE unavailable")
	}
	wantSID := (*windows.SID)(unsafe.Pointer(&want.SidStart))
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || actual == nil {
		t.Fatal("actual ancestor ACE readback failed")
	}
	actualACL, _, err := actual.DACL()
	if err != nil || actualACL == nil {
		t.Fatal("actual ancestor ACE roster unavailable")
	}
	mapped := uint32(want.Mask) &^ (windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE)
	for _, entry := range []struct{ generic, specific uint32 }{
		{windows.GENERIC_ALL, windowsFileAllAccess}, {windows.GENERIC_READ, windows.FILE_GENERIC_READ},
		{windows.GENERIC_WRITE, windows.FILE_GENERIC_WRITE}, {windows.GENERIC_EXECUTE, windows.FILE_GENERIC_EXECUTE},
	} {
		if uint32(want.Mask)&entry.generic != 0 {
			mapped |= entry.specific
		}
	}
	for index := uint32(0); index < uint32(actualACL.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(actualACL, index, &ace) != nil || ace == nil {
			t.Fatal("actual ancestor ACE unavailable")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.Equals(wantSID) && ace.Header.AceType == want.Header.AceType && ace.Header.AceFlags == want.Header.AceFlags &&
			(uint32(ace.Mask) == uint32(want.Mask) || uint32(ace.Mask) == mapped) {
			return
		}
	}
	t.Fatal("native ACL did not retain the intended effective/inherit-only fixture grant")
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
			storeWindowsApplyDescriptor(t, location.anchor, base+vector.ace, true)
			storeWindowsAncestorACEEstablished(t, location.anchor, base+vector.ace)
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
