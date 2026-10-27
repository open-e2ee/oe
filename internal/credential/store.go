package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"

	keyring "github.com/zalando/go-keyring"
)

const service = "dev.open-e2ee.cli"

var ErrNotFound = errors.New("credential not found")

type Credential struct {
	AccessToken      string   `json:"accessToken"`
	ExpiresAt        string   `json:"expiresAt,omitempty"`
	RefreshToken     string   `json:"refreshToken,omitempty"`
	ProtectionBypass string   `json:"protectionBypass,omitempty"`
	Scopes           []string `json:"scopes"`
	Source           string   `json:"-"`
}

type Store interface {
	Get(profile string) (Credential, error)
	Set(profile string, value Credential) error
	Delete(profile string) error
}

type Keychain struct{}

func (Keychain) Get(profile string) (Credential, error) {
	encoded, err := keyring.Get(service, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("read OS keychain: %w", err)
	}
	var value Credential
	if err := json.Unmarshal([]byte(encoded), &value); err != nil {
		return Credential{}, fmt.Errorf("decode OS keychain credential: %w", err)
	}
	if value.AccessToken == "" && strings.TrimSpace(value.ProtectionBypass) == "" {
		return Credential{}, errors.New("OS keychain credential is empty")
	}
	value.Source = "keychain"
	return value, nil
}

func (Keychain) Set(profile string, value Credential) error {
	if value.AccessToken == "" && strings.TrimSpace(value.ProtectionBypass) == "" {
		return errors.New("refuse to store an empty credential")
	}
	copyValue := value
	copyValue.Source = ""
	sort.Strings(copyValue.Scopes)
	encoded, err := json.Marshal(copyValue)
	if err != nil {
		return err
	}
	if err := keyring.Set(service, profile, string(encoded)); err != nil {
		return fmt.Errorf("write OS keychain: %w", err)
	}
	return nil
}

func (Keychain) Delete(profile string) error {
	err := keyring.Delete(service, profile)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete OS keychain credential: %w", err)
	}
	return nil
}

func Resolve(store Store, profile string) (Credential, error) {
	if token := strings.TrimSpace(os.Getenv("OE_ACCESS_TOKEN")); token != "" {
		return Credential{
			AccessToken: token,
			Scopes:      splitScopes(os.Getenv("OE_ACCESS_TOKEN_SCOPES")),
			Source:      "environment",
		}, nil
	}
	value, err := store.Get(profile)
	if err == nil && value.AccessToken == "" {
		return Credential{}, ErrNotFound
	}
	return value, err
}

// DeleteSession removes session credentials but keeps the independent bypass
// needed to reach the control API for a new login. Explicit logout uses Delete.
func DeleteSession(store Store, profile string) error {
	value, err := store.Get(profile)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(value.ProtectionBypass) != "" {
		return store.Set(profile, Credential{ProtectionBypass: value.ProtectionBypass})
	}
	return store.Delete(profile)
}

// Location names where a credential comes from. Key is stable for a program
// to read, and Label is the name that a person knows.
type Location struct {
	Key   string
	Label string
}

// LocationOf names the location of a credential with source on this system.
func LocationOf(source string) Location {
	return locationOf(runtime.GOOS, source)
}

// locationOf names the store that go-keyring uses on goos for a stored
// session. A source with no known store keeps its name as the key and has no
// label.
func locationOf(goos, source string) Location {
	switch source {
	case "environment":
		return Location{Key: "environment", Label: "OE_ACCESS_TOKEN"}
	case "keychain":
		switch goos {
		case "darwin":
			return Location{Key: "keychain", Label: "macOS Keychain"}
		case "windows":
			return Location{Key: "wincred", Label: "Windows Credential Manager"}
		default:
			return Location{Key: "secret-service", Label: "Secret Service"}
		}
	}
	return Location{Key: source}
}

func Profile(controlURL string) (string, error) {
	parsed, err := url.Parse(controlURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid control URL %q", controlURL)
	}
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host), nil
}

func RequireScope(value Credential, scope string) error {
	if len(value.Scopes) == 0 {
		// The control API remains authoritative. Interactive WorkOS credentials do
		// not carry local scope metadata and are still checked by the server.
		return nil
	}
	for _, candidate := range value.Scopes {
		if candidate == scope || candidate == "*" {
			return nil
		}
	}
	return fmt.Errorf("credential does not include required scope %q", scope)
}

func splitScopes(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' })
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != "" {
			result = append(result, field)
		}
	}
	sort.Strings(result)
	return result
}
