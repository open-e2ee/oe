package control

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeploymentProtectionClassificationIsSpecific(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		protected  bool
	}{
		{"vendor error", `{"error":"Protected by Vercel Authentication"}`, 401, true},
		{"vendor message", `{"message":"Protected by Vercel Authentication"}`, 401, true},
		{"vendor envelope", `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 401, true},
		{"envelope without protection", `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication"}`, 401, false},
		{"envelope with protection false", `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":false}}`, 401, false},
		{"envelope with string protection", `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":"true"}}`, 401, false},
		{"envelope with different nested code", `{"error":{"code":"INVALID_SESSION","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 401, false},
		{"envelope with different nested message", `{"error":{"code":"401","message":"Authentication required"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 401, false},
		{"envelope with different top message", `{"error":{"code":"401","message":"Protected deployment"},"message":"Authentication required","protection":{"vercel_auth_enabled":true}}`, 401, false},
		{"envelope with API code", `{"code":"INVALID_SESSION","error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 401, false},
		{"envelope with different status", `{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 403, false},
		{"unrelated object", `{"error":{"code":"401","message":"Protected deployment"}}`, 401, false},
		{"numeric error", `{"error":401,"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`, 401, false},
		{"ordinary session", `{"code":"AUTHENTICATION_REQUIRED","message":"Run oe auth login first."}`, 401, false},
		{"coded API refusal", `{"code":"INVALID_SESSION","message":"Protected by Vercel Authentication"}`, 401, false},
		{"generic text", `Protected by Vercel Authentication`, 401, false},
		{"HTML", `<html><body>Protected by Vercel Authentication</body></html>`, 401, false},
		{"substring", `{"error":"unrelated Protected by Vercel Authentication text"}`, 401, false},
		{"incomplete JSON", `{"error":"Protected by Vercel Authentication",`, 401, false},
		{"different status", `{"error":"Protected by Vercel Authentication"}`, 403, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := decodeResponse(&http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body))}, nil)
			failure, ok := errors.AsType[*APIError](err)
			if !ok || (failure.Code == "DEPLOYMENT_PROTECTION_REQUIRED") != test.protected {
				t.Fatalf("unexpected classification: %v", err)
			}
		})
	}
}

func TestControlErrorPreservesStringAndCodedMessages(t *testing.T) {
	for _, test := range []struct {
		body, code, message string
	}{
		{`{"error":"legacy refusal"}`, "", "legacy refusal"},
		{`{"code":"INVALID_SESSION","message":"session refusal","error":{"code":"401"}}`, "INVALID_SESSION", "session refusal"},
		{`{"error":{"code":"401","message":"nested vendor text"}}`, "", "Unauthorized"},
	} {
		err := decodeResponse(&http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader(test.body))}, nil)
		failure, ok := errors.AsType[*APIError](err)
		if !ok || failure.Code != test.code || failure.Message != test.message {
			t.Fatalf("control error behavior changed: %v", err)
		}
	}
}

func TestWorkOSUnauthorizedIsNotDeploymentProtection(t *testing.T) {
	for _, body := range []string{
		`{"error":"Protected by Vercel Authentication"}`,
		`{"error":{"code":"401","message":"Protected deployment"},"message":"Protected by Vercel Authentication","protection":{"vercel_auth_enabled":true}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(server.Close)
		client, err := New(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		// WorkOS form replies have a separate decoder. Even the vendor phrase
		// there must not produce a control deployment-protection classification.
		err = client.doForm(t.Context(), server.URL, nil, nil)
		if failure, ok := errors.AsType[*APIError](err); ok && failure.Code == "DEPLOYMENT_PROTECTION_REQUIRED" {
			t.Fatal("WorkOS failure was classified as control deployment protection")
		}
		if err == nil {
			t.Fatal("WorkOS unauthorized response succeeded")
		}
	}
}
