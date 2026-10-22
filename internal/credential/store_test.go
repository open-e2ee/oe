package credential

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestResolvePrefersScopedCICredentialWithoutStoringIt(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "ci-token")
	t.Setenv("OE_ACCESS_TOKEN_SCOPES", "project:read,deploy:write")
	store := NewMemory()
	value, err := Resolve(store, "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	if value.AccessToken != "ci-token" || value.Source != "environment" {
		t.Fatalf("unexpected credential: %#v", value)
	}
	if _, err := store.Get("https://control.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CI credential was stored: %v", err)
	}
	if err := RequireScope(value, "deploy:write"); err != nil {
		t.Fatal(err)
	}
	if err := RequireScope(value, "secret:write"); err == nil {
		t.Fatal("accepted missing scope")
	}
}

func TestProfileDropsPathsAndNormalizesHost(t *testing.T) {
	profile, err := Profile("https://CONTROL.EXAMPLE/v1")
	if err != nil {
		t.Fatal(err)
	}
	if profile != "https://control.example" {
		t.Fatalf("unexpected profile %q", profile)
	}
}

func TestMemoryStoreLifecycle(t *testing.T) {
	store := NewMemory()
	if err := store.Set("profile", Credential{AccessToken: "token"}); err != nil {
		t.Fatal(err)
	}
	value, err := store.Get("profile")
	if err != nil || value.AccessToken != "token" {
		t.Fatalf("get: %#v, %v", value, err)
	}
	if err := store.Delete("profile"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get("profile"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete did not remove credential: %v", err)
	}
}

func TestLocationNamesTheStoreOfEachSystem(t *testing.T) {
	for _, test := range []struct {
		goos, source string
		want         Location
	}{
		{"darwin", "keychain", Location{Key: "keychain", Label: "macOS Keychain"}},
		{"linux", "keychain", Location{Key: "secret-service", Label: "Secret Service"}},
		{"windows", "keychain", Location{Key: "wincred", Label: "Windows Credential Manager"}},
		{"darwin", "environment", Location{Key: "environment", Label: "OE_ACCESS_TOKEN"}},
		{"linux", "memory", Location{Key: "memory"}},
	} {
		if got := locationOf(test.goos, test.source); got != test.want {
			t.Fatalf("%s %s: %#v, want %#v", test.goos, test.source, got, test.want)
		}
	}
}

func TestProtectionBypassRoundTrip(t *testing.T) {
	original := Credential{AccessToken: "access", RefreshToken: "refresh", ProtectionBypass: "control-bypass"}
	store := NewMemory()
	if err := store.Set("profile", original); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get("profile")
	if err != nil || stored.ProtectionBypass != original.ProtectionBypass {
		t.Fatal("memory store did not preserve the protection bypass")
	}
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Credential
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProtectionBypass != original.ProtectionBypass {
		t.Fatal("JSON did not preserve the protection bypass")
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil || fields["protectionBypass"] != original.ProtectionBypass {
		t.Fatal("JSON protectionBypass field is missing")
	}
}

func TestCredentialJSONWithoutProtectionBypass(t *testing.T) {
	var value Credential
	if err := json.Unmarshal([]byte(`{"accessToken":"access","refreshToken":"refresh","scopes":[]}`), &value); err != nil {
		t.Fatal(err)
	}
	if value.AccessToken != "access" || value.RefreshToken != "refresh" || value.ProtectionBypass != "" {
		t.Fatal("old credential JSON no longer decodes")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["protectionBypass"]; exists {
		t.Fatal("empty protection bypass is not optional in JSON")
	}
}
