package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
)

type unreadIdentityInput struct{ reads int }

func (in *unreadIdentityInput) Read([]byte) (int, error) {
	in.reads++
	return 0, errors.New("assertion stdin must remain unread")
}

const identityPublicProfile = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://ISSUER_CANARY.example","audience":"AUDIENCE_CANARY","subjectClaim":"sub","keys":[{"kid":"KEY_CANARY","kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`

func identityFixture(t *testing.T, profile string) (string, string, credential.Store) {
	t.Helper()
	t.Setenv("OE_ACCESS_TOKEN", "")
	directory := initializedProject(t, "identity-check")
	file := filepath.Join(directory, "public-profile.json")
	if err := os.WriteFile(file, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	return directory, file, store
}

func acceptedIdentity(environment string) identity.Check {
	return identity.Check{State: "accepted_at_check", ProfileMode: "custom-token", Environment: environment, Configuration: "draft", InstalledConfiguration: "unverified", DeviceAdmission: "unverified", MemberBinding: "unverified", EncryptedExchange: "unverified", Lifecycle: "unverified", ExpiresAt: new(int64(100))}
}

func TestIdentityExternalCheckIsTransientHistoricalAndReadOnly(t *testing.T) {
	for _, output := range [][]string{{"--json"}, {"--json-stream"}, {"--agent", "no"}} {
		t.Run(strings.Join(output, " "), func(t *testing.T) {
			t.Setenv("OE_ENV", "production")
			directory, profile, store := identityFixture(t, identityPublicProfile)
			before := mustRead(t, filepath.Join(directory, "open-e2ee.config.ts"))
			calls := 0
			api := &fakeAPI{checkIdentity: func(_ context.Context, credential control.CredentialRequest, project, environment string, draft identity.Draft) (identity.Check, error) {
				calls++
				if credential.AccessToken != "test-token" || credential.OperationID != "" || project != "identity-check" || environment != "production" || draft.Assertion != "ASSERTION_CANARY" || draft.Target.Issuer != "https://ISSUER_CANARY.example" {
					t.Error("wrong draft, scope or authority")
				}
				return acceptedIdentity(environment), nil
			}}
			args := append(output, "identity", "check", "--profile", profile, "--assertion-stdin")
			exit, out, stderr := run(t, Dependencies{API: api, Store: store, WorkingDir: directory, In: strings.NewReader("  ASSERTION_CANARY\n")}, args...)
			if exit != 0 || calls != 1 || stderr != "" || !strings.Contains(strings.ToLower(out), "check") || !strings.Contains(out, "100") {
				t.Fatalf("historical check failed: exit=%d out=%s err=%s", exit, out, stderr)
			}
			for _, secret := range []string{"ASSERTION_CANARY", "ISSUER_CANARY", "AUDIENCE_CANARY", "KEY_CANARY", "test-token"} {
				if strings.Contains(out+stderr, secret) {
					t.Error("output exposed input")
				}
			}
			if string(before) != string(mustRead(t, filepath.Join(directory, "open-e2ee.config.ts"))) {
				t.Fatal("check changed configuration")
			}
			entries, _ := os.ReadDir(directory)
			if len(entries) != 2 {
				t.Fatal("check persisted additional input or state")
			}
		})
	}
}

func TestIdentityInvalidInputDoesNotCallAPIOrReadUnrelatedStdin(t *testing.T) {
	for _, tc := range []struct {
		name, profile string
		args          []string
	}{
		{"device stdin", `{"mode":"device-owned"}`, []string{"--assertion-stdin"}},
		{"missing external stdin", identityPublicProfile, nil},
		{"private key", strings.Replace(identityPublicProfile, `"kid"`, `"d":"PRIVATE_CANARY","kid"`, 1), []string{"--assertion-stdin"}},
		{"native provider", `{"mode":"provider-bound","provider":"firebase"}`, nil},
		{"positional assertion", identityPublicProfile, []string{"ASSERTION_CANARY"}},
		{"assertion flag", identityPublicProfile, []string{"--assertion=ASSERTION_CANARY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory, profile, store := identityFixture(t, tc.profile)
			in := &unreadIdentityInput{}
			calls := 0
			api := &fakeAPI{checkIdentity: func(context.Context, control.CredentialRequest, string, string, identity.Draft) (identity.Check, error) {
				calls++
				return identity.Check{}, nil
			}}
			args := append([]string{"--json", "identity", "check", "--profile", profile}, tc.args...)
			exit, out, stderr := run(t, Dependencies{API: api, Store: store, WorkingDir: directory, In: in}, args...)
			if exit != exitUsage || calls != 0 || in.reads != 0 || strings.Contains(out+stderr, "CANARY") {
				t.Fatalf("invalid input escaped: exit=%d calls=%d reads=%d out=%s err=%s", exit, calls, in.reads, out, stderr)
			}
		})
	}
}

func TestIdentityRequiresAuthorityBeforeReadingAssertion(t *testing.T) {
	directory, profile, _ := identityFixture(t, identityPublicProfile)
	in := &unreadIdentityInput{}
	exit, out, stderr := run(t, Dependencies{API: &fakeAPI{}, Store: credential.NewMemory(), WorkingDir: directory, In: in}, "--json", "identity", "check", "--profile", profile, "--assertion-stdin")
	if exit != exitAuthentication || in.reads != 0 || strings.Contains(out+stderr, "CANARY") {
		t.Fatalf("authentication did not precede stdin: exit=%d reads=%d output=%s", exit, in.reads, out)
	}
}

func TestIdentityBoundsStdinAndRejectsContradictoryOrUnsafeResponses(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		result      identity.Check
		err         error
	}{
		{"empty", "  ", acceptedIdentity("production"), nil},
		{"oversize", strings.Repeat("X", 65_537), acceptedIdentity("production"), nil},
		{"wrong environment", "ASSERTION_CANARY", acceptedIdentity("sandbox"), nil},
		{"arbitrary failure", "ASSERTION_CANARY", identity.Check{}, errors.New("PRIVATE_CANARY")},
		{"fixed failure", "ASSERTION_CANARY", identity.Check{}, &control.APIError{Code: "IDENTITY_ASSERTION_INVALID", Message: "PRIVATE_CANARY"}},
		{"invalid session", "ASSERTION_CANARY", identity.Check{}, &control.APIError{Code: "INVALID_SESSION", Message: "PRIVATE_CANARY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory, profile, store := identityFixture(t, identityPublicProfile)
			calls := 0
			api := &fakeAPI{checkIdentity: func(context.Context, control.CredentialRequest, string, string, identity.Draft) (identity.Check, error) {
				calls++
				return tc.result, tc.err
			}}
			exit, out, stderr := run(t, Dependencies{API: api, Store: store, WorkingDir: directory, In: strings.NewReader(tc.input)}, "--json", "identity", "check", "--env", "production", "--profile", profile, "--assertion-stdin")
			if exit == 0 || calls > 1 || strings.Contains(out+stderr, "CANARY") {
				t.Fatalf("unsafe result escaped: exit=%d out=%s err=%s", exit, out, stderr)
			}
			var event map[string]any
			if json.Unmarshal([]byte(out), &event) != nil || event["status"] != "error" {
				t.Fatal("failure has no safe JSON result")
			}
			if (tc.name == "empty" || tc.name == "oversize") && calls != 0 {
				t.Fatal("invalid stdin reached API")
			}
		})
	}
}

func TestIdentityCheckDeviceOwnedUsesTheAddressedReadAndNoAssertion(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/identity-check/identity/check" || r.URL.RawQuery != "environment=sandbox" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("identity check used the wrong method, scope or authority")
		}
		fmt.Fprint(w, `{"state":"not_applicable","profileMode":"device-owned","reason":"device_owned_identity","environment":"sandbox","configuration":"draft","installedConfiguration":"unverified","deviceAdmission":"unverified","memberBinding":"unverified","encryptedExchange":"unverified","lifecycle":"unverified"}`)
	}))
	defer server.Close()
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	directory := initializedProject(t, "identity-check")
	profile := filepath.Join(directory, "identity-profile.json")
	if err := os.WriteFile(profile, []byte(`{"mode":"device-owned"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	in := &unreadIdentityInput{}
	exit, out, stderr := run(t, Dependencies{API: api, Store: store, WorkingDir: directory, In: in}, "--json", "identity", "check", "--profile", profile)
	if exit != 0 || !strings.Contains(out, `"state":"not_applicable"`) || !strings.Contains(out, `"installedConfiguration":"unverified"`) || stderr != "" || calls != 1 || in.reads != 0 {
		t.Fatalf("device-owned identity check: exit=%d requests=%d stdinReads=%d output=%s stderr=%s", exit, calls, in.reads, out, stderr)
	}
}

func TestIdentityCheckUsesStoredOrEnvironmentProtection(t *testing.T) {
	for _, test := range []struct {
		name, stored, environment string
		wantExit                  int
	}{
		{"stored", "BYPASS_CANARY", "", 0},
		{"environment overrides stored", "OLD_BYPASS_CANARY", "BYPASS_CANARY", 0},
		{"missing", "", "", exitPersonAction},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, profile, _ := identityFixture(t, `{"mode":"device-owned"}`)
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/api/cli/v1/projects/identity-check/identity/check" || r.URL.RawQuery != "environment=sandbox" || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("Idempotency-Key") != "" {
					t.Error("check used the wrong request or authority")
				}
				if r.Header.Get("x-vercel-protection-bypass") != "BYPASS_CANARY" {
					w.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(w, `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true},"access":"VENDOR_CANARY"}`)
					return
				}
				fmt.Fprint(w, `{"state":"not_applicable","profileMode":"device-owned","reason":"device_owned_identity","environment":"sandbox","configuration":"draft","installedConfiguration":"unverified","deviceAdmission":"unverified","memberBinding":"unverified","encryptedExchange":"unverified","lifecycle":"unverified"}`)
			}))
			defer server.Close()
			api, err := control.New(server.URL+"/api/cli", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			store := credential.NewMemory()
			origin, _ := credential.Profile(server.URL + "/api/cli")
			if err := store.Set(origin, credential.Credential{AccessToken: "test-token", Scopes: []string{"project:read"}, ProtectionBypass: test.stored}); err != nil {
				t.Fatal(err)
			}
			in := &unreadIdentityInput{}
			exit, out, stderr := run(t, Dependencies{API: api, Store: store, WorkingDir: directory, In: in, Getenv: environment(map[string]string{"OE_PROTECTION_BYPASS": test.environment})}, "--json", "--agent=yes", "--control-url", server.URL+"/api/cli", "--env", "sandbox", "identity", "check", "--profile", profile)
			if exit != test.wantExit || stderr != "" || calls != 1 || in.reads != 0 {
				t.Fatalf("check: exit=%d calls=%d reads=%d out=%s stderr=%s", exit, calls, in.reads, out, stderr)
			}
			if test.wantExit == 0 && !strings.Contains(out, `"state":"not_applicable"`) {
				t.Fatal("check lost the device-owned evidence level")
			}
			if test.wantExit != 0 {
				result := decodeEvent(t, []byte(out))
				if result.Code != "DEPLOYMENT_PROTECTION_REQUIRED" || result.Next == "oe auth login" || !strings.Contains(result.Error, "OE_PROTECTION_BYPASS") {
					t.Fatal("protection refusal lost its corrective action")
				}
			}
			for _, secret := range []string{"BYPASS_CANARY", "VENDOR_CANARY", "test-token"} {
				if strings.Contains(out+stderr, secret) {
					t.Fatal("check exposed credentials or vendor text")
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 2 {
				t.Fatal("check created local state")
			}
		})
	}
}
