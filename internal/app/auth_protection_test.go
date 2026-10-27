package app

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/credential"
	keyring "github.com/zalando/go-keyring"
)

func TestExpiredSessionRetainsProtectionForNextLogin(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	// Exercise the credential encoding and validation without the OS keychain.
	keyring.MockInit()
	for _, bypass := range []string{"stored-bypass", ""} {
		t.Run("bypass="+bypass, func(t *testing.T) {
			server := newConsole(t, "accepted", true)
			server.protectionBypass = new(bypass)
			server.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/user_management/authenticate" {
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if r.PostForm.Get("grant_type") == "refresh_token" {
						server.answer(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
						return
					}
				}
				server.serve(w, r)
			})
			store := credential.Keychain{}
			profile, _ := credential.Profile(server.controlURL())
			if err := store.Set(profile, credential.Credential{
				AccessToken: "expired", RefreshToken: "expired-refresh", ExpiresAt: "2000-01-01T00:00:00Z",
				ProtectionBypass: bypass, Scopes: []string{"project:read"},
			}); err != nil {
				t.Fatal(err)
			}
			other := "https://other.example"
			if err := store.Set(other, credential.Credential{AccessToken: "other-token", ProtectionBypass: "other-bypass"}); err != nil {
				t.Fatal(err)
			}
			deps := server.dependencies(store, environment(nil))
			exit, stdout, _ := run(t, deps, "--control-url", server.controlURL(), "--agent=yes", "auth", "status")
			if result := decodeEvent(t, []byte(stdout)); exit != 4 || result.Code != "SESSION_EXPIRED" {
				t.Fatalf("expired session: exit=%d %s", exit, stdout)
			}
			stored, err := store.Get(profile)
			if bypass == "" {
				if !errors.Is(err, credential.ErrNotFound) {
					t.Errorf("empty origin was not removed: %v", err)
				}
			} else if err != nil || stored.ProtectionBypass != bypass || stored.AccessToken != "" || stored.RefreshToken != "" || stored.ExpiresAt != "" || len(stored.Scopes) != 0 {
				t.Errorf("expired session cleanup did not retain only protection: %v", err)
			}
			if _, err := credential.Resolve(store, profile); !errors.Is(err, credential.ErrNotFound) {
				t.Errorf("expired session still resolves: %v", err)
			}
			// A new invocation must recover the bypass from storage before its
			// first configuration request, then store a new session with it.
			exit, stdout, stderr := run(t, server.dependencies(store, environment(nil)), "--control-url", server.controlURL(), "--agent=yes", "auth", "login")
			if exit != 0 {
				t.Fatalf("next login: exit=%d %s", exit, stdout)
			}
			if strings.Contains(stdout+stderr, "stored-bypass") || strings.Contains(stdout+stderr, "expired-refresh") {
				t.Fatal("output exposed a credential")
			}
			stored, err = store.Get(profile)
			if err != nil || stored.RefreshToken != "refresh" || stored.ProtectionBypass != bypass {
				t.Fatal("new login did not retain protection with the new session")
			}
			exit, _, _ = run(t, server.dependencies(store, environment(nil)), "--control-url", server.controlURL(), "auth", "logout")
			if _, err := store.Get(profile); exit != 0 || !errors.Is(err, credential.ErrNotFound) {
				t.Fatal("intentional logout did not remove the whole origin")
			}
			if value, err := store.Get(other); err != nil || value.AccessToken != "other-token" || value.ProtectionBypass != "other-bypass" {
				t.Fatal("another origin changed")
			}
		})
	}
}

func TestDeploymentProtectionDoesNotSendLoginBackToLogin(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	for _, test := range []struct {
		name string
		body map[string]any
	}{
		{"legacy", map[string]any{"error": "Protected by Vercel Authentication"}},
		{"structured envelope", map[string]any{
			"error":   map[string]any{"code": "401", "message": "Protected deployment"},
			"message": "Protected by Vercel Authentication",
			"access":  "vendor-access-instruction",
			"mcp":     "vendor-mcp-instruction",
			"protection": map[string]any{
				"vercel_auth_enabled": true, "password_enabled": false, "auto_vercel_auth_redirect": true,
				"vercel_auth_callback": "https://vercel.com/sso-api?nonce=vendor-callback-nonce",
			},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newConsole(t, "accepted", true)
			server.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/cli/v1/auth/configuration" {
					t.Error("login passed the deployment protection boundary")
				}
				server.answer(w, http.StatusUnauthorized, test.body)
			})
			exit, stdout, stderr := run(t, server.dependencies(credential.NewMemory(), environment(nil)), "--control-url", server.controlURL(), "--agent=yes", "auth", "login")
			result := decodeEvent(t, []byte(stdout))
			if exit != 5 || result.Code != "DEPLOYMENT_PROTECTION_REQUIRED" || result.Next != "" || !strings.Contains(result.Error, "OE_PROTECTION_BYPASS") {
				t.Fatalf("deployment protection gave no actionable diagnosis: exit=%d %s", exit, stdout)
			}
			for _, private := range []string{"vendor-access-instruction", "vendor-mcp-instruction", "vendor-callback-nonce", "Protected deployment"} {
				if strings.Contains(stdout+stderr, private) {
					t.Fatal("deployment protection reflected the vendor envelope")
				}
			}
		})
	}
}
