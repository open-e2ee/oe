package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

const deviceCheckResult = `{"state":"not_applicable","profileMode":"device-owned","reason":"device_owned_identity","environment":"production","configuration":"draft","installedConfiguration":"unverified","deviceAdmission":"unverified","memberBinding":"unverified","encryptedExchange":"unverified","lifecycle":"unverified"}`

func TestIdentityTransportUsesExactScopeWithoutOperationOrRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/cli/v1/projects/identity-fixture/identity/check" || r.URL.RawQuery != "environment=production" || r.Header.Get("Authorization") != "Bearer CLI_CANARY" || r.Header.Get("Idempotency-Key") != "" {
			t.Error("wrong request authority or route")
		}
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["target"] == nil {
			t.Error("device-owned check sent assertion or extra authority")
		}
		fmt.Fprint(w, deviceCheckResult)
	}))
	defer server.Close()
	client, err := New(server.URL+"/api/cli", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.CheckIdentity(t.Context(), CredentialRequest{AccessToken: "CLI_CANARY", OperationID: "must-not-send"}, "identity-fixture", "production", identity.Draft{Target: identity.Profile{Mode: "device-owned"}})
	if err != nil || result.State != "not_applicable" || calls != 1 {
		t.Fatalf("historical transport failed: %v requests=%d", err, calls)
	}
}

func TestIdentityTransportRefusesMalformedUnknownAndCrossedResults(t *testing.T) {
	for _, body := range []string{
		`{`, deviceCheckResult + `{}`,
		strings.Replace(deviceCheckResult, `"production"`, `"sandbox"`, 1),
		strings.Replace(deviceCheckResult, `"unverified"`, `"verified"`, 1),
		strings.Replace(deviceCheckResult, `"state":"not_applicable"`, `"private":"ASSERTION_CANARY","state":"not_applicable"`, 1),
		strings.Repeat("ASSERTION_CANARY", 2000),
	} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			client, _ := New(server.URL, server.Client())
			_, err := client.CheckIdentity(t.Context(), CredentialRequest{}, "fixture", "production", identity.Draft{Target: identity.Profile{Mode: "device-owned"}})
			if err == nil || strings.Contains(err.Error(), "CANARY") {
				t.Fatal("invalid identity response accepted or exposed")
			}
		})
	}
}

func TestIdentityTransportSanitizesRefusalAndDoesNotRetry(t *testing.T) {
	for _, status := range []int{400, 401, 429, 503} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(status)
			fmt.Fprint(w, `{"code":"PRIVATE_CANARY","message":"ASSERTION_CANARY"}`)
		}))
		client, _ := New(server.URL, server.Client())
		_, err := client.CheckIdentity(t.Context(), CredentialRequest{AccessToken: "CLI_CANARY"}, "fixture", "production", identity.Draft{Target: identity.Profile{Mode: "device-owned"}})
		server.Close()
		if err == nil || strings.Contains(err.Error(), "CANARY") || calls != 1 {
			t.Fatalf("unsafe failure or retry: requests=%d", calls)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"code":"IDENTITY_ASSERTION_INVALID","message":"ASSERTION_CANARY"}`)
	}))
	defer server.Close()
	client, _ := New(server.URL, server.Client())
	_, err := client.CheckIdentity(t.Context(), CredentialRequest{}, "fixture", "production", identity.Draft{Target: identity.Profile{Mode: "device-owned"}})
	failure, ok := errors.AsType[*APIError](err)
	if !ok || failure.Code != "IDENTITY_ASSERTION_INVALID" || strings.Contains(failure.Message, "CANARY") {
		t.Fatal("safe fixed code lost or raw message exposed")
	}
}

func TestIdentityTransportNeverForwardsAssertionsThroughRedirects(t *testing.T) {
	forwarded := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded++; fmt.Fprint(w, deviceCheckResult) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	client, _ := New(origin.URL, origin.Client())
	_, err := client.CheckIdentity(t.Context(), CredentialRequest{}, "fixture", "production", identity.Draft{Target: identity.Profile{Mode: "custom-token"}, Assertion: "ASSERTION_CANARY"})
	if err == nil || forwarded != 0 {
		t.Fatal("identity input followed a redirect")
	}
}
