package credential

import (
	"errors"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestKeychainProtectionOnlyIsNotASession(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	keyring.MockInit()
	store := Keychain{}
	if err := store.Set("profile", Credential{ProtectionBypass: "bypass"}); err != nil {
		t.Fatal(err)
	}
	if value, err := store.Get("profile"); err != nil || value.ProtectionBypass != "bypass" {
		t.Fatal("client prerequisite is unavailable")
	}
	if _, err := Resolve(store, "profile"); !errors.Is(err, ErrNotFound) {
		t.Fatal("bypass-only entry resolved as a session")
	}
	for _, value := range []Credential{{}, {ProtectionBypass: " \n"}, {RefreshToken: "orphaned"}} {
		if err := store.Set("empty", value); err == nil {
			t.Fatal("accepted an empty credential")
		}
	}
}

type sessionFailureStore struct {
	*Memory
	boundary string
	failure  error
}

func (s sessionFailureStore) Get(profile string) (Credential, error) {
	if s.boundary == "get" {
		return Credential{}, s.failure
	}
	return s.Memory.Get(profile)
}

func (s sessionFailureStore) Set(profile string, value Credential) error {
	if s.boundary == "set" {
		return s.failure
	}
	return s.Memory.Set(profile, value)
}

func (s sessionFailureStore) Delete(profile string) error {
	if s.boundary == "delete" {
		return s.failure
	}
	return s.Memory.Delete(profile)
}

func TestDeleteSessionReportsStorageFailures(t *testing.T) {
	for _, boundary := range []string{"get", "set", "delete"} {
		t.Run(boundary, func(t *testing.T) {
			failure := errors.New("injected storage failure")
			store := sessionFailureStore{Memory: NewMemory(), boundary: boundary, failure: failure}
			value := Credential{AccessToken: "expired"}
			if boundary != "delete" {
				value.ProtectionBypass = "bypass"
			}
			if err := store.Memory.Set("profile", value); err != nil {
				t.Fatal(err)
			}
			if err := DeleteSession(store, "profile"); !errors.Is(err, failure) {
				t.Fatalf("storage failure was hidden: %v", err)
			}
			stored, err := store.Memory.Get("profile")
			if err != nil || stored.AccessToken != value.AccessToken || stored.ProtectionBypass != value.ProtectionBypass {
				t.Fatal("failed cleanup changed the credential")
			}
		})
	}
	if err := DeleteSession(NewMemory(), "absent"); err != nil {
		t.Fatal(err)
	}
}
