//go:build windows

package identityattempt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func storeWindowsCapturedPolicyDescriptor(t *testing.T, encoded, wantHash string) (*windows.SECURITY_DESCRIPTOR, []byte) {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) != 224 {
		t.Fatal("captured root descriptor bytes differ", err)
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != wantHash {
		t.Fatal("captured root descriptor hash differs")
	}
	// Match x/sys's pointer alignment for a Go-owned self-relative descriptor.
	wordBytes := int(unsafe.Sizeof(uintptr(0)))
	words := make([]uintptr, (len(data)+wordBytes-1)/wordBytes)
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(data))
	copy(raw, data)
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&words[0]))
	if !sd.IsValid() || int(sd.Length()) != len(data) {
		t.Fatal("Windows rejected the captured root descriptor")
	}
	return sd, raw
}

func TestStoreWindowsTrustedInstallerNativeIdentity(t *testing.T) {
	actual, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil {
		t.Fatal("native TrustedInstaller identity lookup failed", err)
	}
	installer, err := windowsInstallerOwner()
	if err != nil || !actual.Equals(installer) || actual.String() != windowsTrustedInstallerSID {
		t.Fatal("native TrustedInstaller identity differs from the owner policy", err)
	}
}

func TestStoreWindowsCapturedTrustedInstallerRootPolicy(t *testing.T) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	installer, err := windowsInstallerOwner()
	if err != nil {
		t.Fatal(err)
	}
	// Exact GetKernelObjectSecurity snapshots from run 40152333192, component 0.
	for _, vector := range []struct{ name, encoded, sha256 string }{
		{
			name:    "windows-amd64",
			encoded: "AQAEhBQAAAAAAAAAAAAAADQAAAABBgAAAAAABVAAAAC1ifs4GYTCy1xsI21XAHduwAJkhwIArAAGAAAAAAA4AKEAEAABCgAAAAAADwMAAAAAAAEAZSiXcFehGiyGem1jRNAhk6bqsPzdyE1NmNYxFViDuikAABQABAAAAAEBAAAAAAAFCwAAAAALFAAAAAHgAQEAAAAAAAULAAAAAAMUAP8BHwABAQAAAAAABRIAAAAAAxgA/wEfAAECAAAAAAAFIAAAACACAAAAAxgAqQASAAECAAAAAAAFIAAAACECAAA=",
			sha256:  "3b4c9221f5bdfb7473c959c9a07688f70960620a4c6991884118620b76ac4602",
		},
		{
			name:    "windows-arm64",
			encoded: "AQAEgBQAAAAAAAAAAAAAADQAAAABBgAAAAAABVAAAAC1ifs4GYTCy1xsI21XAHduwAJkhwIArAAGAAAAAAA4AKEAEAABCgAAAAAADwMAAAAAAAEAZSiXcFehGiyGem1jRNAhk6bqsPzdyE1NmNYxFViDuikAABQABAAAAAEBAAAAAAAFCwAAAAALFAAAAAHgAQEAAAAAAAULAAAAAAMUAP8BHwABAQAAAAAABRIAAAAAAxgA/wEfAAECAAAAAAAFIAAAACACAAAAAxgAqQASAAECAAAAAAAFIAAAACECAAA=",
			sha256:  "fd47a617de2717e297dbca005d82d45bdb3dfd87dddbefacd85b5e4503f86956",
		},
	} {
		t.Run(vector.name, func(t *testing.T) {
			sd, raw := storeWindowsCapturedPolicyDescriptor(t, vector.encoded, vector.sha256)
			owner, defaulted, err := sd.Owner()
			if err != nil || defaulted || owner == nil || !owner.Equals(installer) {
				t.Fatal("captured root owner is not TrustedInstaller", err)
			}
			// The published owner predicate refuses this exact native descriptor.
			if owner.Equals(principals.user) || owner.Equals(principals.system) || owner.Equals(principals.administrators) {
				t.Fatal("captured owner no longer reproduces the published refusal")
			}
			before := sha256.Sum256(raw)
			if err := windowsCheckDescriptor(sd, false, principals); err != nil {
				t.Fatal("captured TrustedInstaller ancestor descriptor was refused", err)
			}
			if err := windowsCheckDescriptor(sd, true, principals); !errors.Is(err, ErrUnsafe) {
				t.Fatal("captured root descriptor gained managed-object acceptance", err)
			}
			if sha256.Sum256(raw) != before {
				t.Fatal("descriptor qualification changed captured bytes")
			}
			runtime.KeepAlive(sd)
		})
	}
}

func TestStoreWindowsTrustedInstallerOwnerScope(t *testing.T) {
	principals, err := currentWindowsPrincipals()
	if err != nil {
		t.Fatal(err)
	}
	user := principals.user.String()
	const installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	const otherService = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478465"
	const foreignUser = "S-1-5-21-1-2-3-424242"
	for _, vector := range []struct {
		name, owner, extra string
		managed, accept    bool
	}{
		{name: "user-owner", owner: user, accept: true},
		{name: "system-owner", owner: "SY", accept: true},
		{name: "administrators-owner", owner: "BA", accept: true},
		{name: "installer-ancestor-owner", owner: installer, accept: true},
		{name: "other-service-owner", owner: otherService},
		{name: "foreign-owner", owner: foreignUser},
		{name: "managed-user-owner", owner: user, managed: true, accept: true},
		{name: "managed-installer-owner", owner: installer, managed: true},
		{name: "managed-system-owner", owner: "SY", managed: true},
		{name: "managed-administrators-owner", owner: "BA", managed: true},
		{name: "installer-owner-admin-mutation", owner: installer, extra: "(A;;FA;;;BA)", accept: true},
		{name: "installer-owner-installer-read", owner: installer, extra: "(A;;0x001200ad;;;" + installer + ")", accept: true},
		{name: "installer-owner-inherit-only-installer", owner: installer, extra: "(A;OICIIO;FA;;;" + installer + ")", accept: true},
		{name: "installer-owner-installer-mutation", owner: installer, extra: "(A;;FA;;;" + installer + ")"},
		{name: "user-owner-installer-mutation", owner: user, extra: "(A;;FA;;;" + installer + ")"},
		{name: "installer-owner-everyone-mutation", owner: installer, extra: "(A;;FA;;;WD)"},
		{name: "installer-owner-create-file", owner: installer, extra: "(A;;0x00000002;;;WD)"},
		{name: "installer-owner-write-ea", owner: installer, extra: "(A;;0x00000010;;;WD)"},
		{name: "installer-owner-delete-child", owner: installer, extra: "(A;;0x00000040;;;WD)"},
		{name: "installer-owner-write-attributes", owner: installer, extra: "(A;;0x00000100;;;WD)"},
		{name: "installer-owner-delete-object", owner: installer, extra: "(A;;0x00010000;;;WD)"},
		{name: "installer-owner-change-dacl", owner: installer, extra: "(A;;0x00040000;;;WD)"},
		{name: "installer-owner-change-owner", owner: installer, extra: "(A;;0x00080000;;;WD)"},
		{name: "installer-owner-generic-write", owner: installer, extra: "(A;;GW;;;WD)"},
		{name: "installer-owner-generic-all", owner: installer, extra: "(A;;GA;;;WD)"},
	} {
		t.Run(vector.name, func(t *testing.T) {
			sddl := "O:" + vector.owner + "D:P(A;;FA;;;" + user + ")(A;;FA;;;SY)" + vector.extra
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil || sd == nil || !sd.IsValid() {
				t.Fatal("native owner-policy descriptor did not parse", err)
			}
			result := windowsCheckDescriptor(sd, vector.managed, principals)
			if vector.accept && result != nil || !vector.accept && !errors.Is(result, ErrUnsafe) {
				t.Fatal("native owner-policy classification differs", result)
			}
			runtime.KeepAlive(sd)
		})
	}
}
