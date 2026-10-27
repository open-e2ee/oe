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
		{"ordinary session", `{"code":"AUTHENTICATION_REQUIRED","message":"Run oe auth login first."}`, 401, false},
		{"coded API refusal", `{"code":"INVALID_SESSION","message":"Protected by Vercel Authentication"}`, 401, false},
		{"generic text", `Protected by Vercel Authentication`, 401, false},
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

func TestWorkOSUnauthorizedIsNotDeploymentProtection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"Protected by Vercel Authentication"}`)
	}))
	defer server.Close()
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
