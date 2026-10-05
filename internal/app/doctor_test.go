package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
)

// TestDoctorWaitSeesTheFirstAcknowledgedMessage decodes the activation body
// that the console sends, so it proves the wire field name and not only the
// wait loop.
func TestDoctorWaitSeesTheFirstAcknowledgedMessage(t *testing.T) {
	var activations atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	relayURL := server.URL + "/signal/v1/connection/pk_sandbox_public"
	mux.HandleFunc("GET /v1/health", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"status":"ok"}`)
	})
	mux.HandleFunc("GET /v1/projects/wait-chat", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(response, `{"slug":"wait-chat","writer":"config","sandbox":{"relayUrl":%q,"revision":"1"}}`, relayURL)
	})
	mux.HandleFunc("GET /v1/projects/wait-chat/activation", func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(response, `{"code":"AUTHENTICATION_REQUIRED"}`, http.StatusUnauthorized)
			return
		}
		acknowledged := activations.Add(1) > 1
		fmt.Fprintf(response, `{"firstDevice":true,"firstAcknowledged":%t}`, acknowledged)
	})
	mux.HandleFunc("GET /signal/v1/connection/pk_sandbox_public", func(response http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(response, `{"schemaVersion":1}`)
	})
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	directory := initializedProject(t, "wait-chat")
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, relayURL); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	// The wait ends after a few polls, so a CLI that never sees the
	// acknowledgement fails at once and does not wait for the timeout.
	sleeps := 0
	sleep := func(context.Context, time.Duration) error {
		if sleeps++; sleeps > 3 {
			return context.DeadlineExceeded
		}
		return nil
	}

	exit, stdout, _ := run(t, Dependencies{
		API: api, HTTP: server.Client(), Store: store, WorkingDir: directory, Sleep: sleep,
	}, "--json-stream", "doctor", "--wait", "--timeout", "1m")
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	result := decodeEvent(t, []byte(lines[len(lines)-1]))
	if exit != 0 || result.Status != "ok" || result.Data["firstAcknowledged"] != true || result.Data["firstDevice"] != true {
		t.Fatalf("doctor --wait did not see the first acknowledged message: exit=%d %s", exit, stdout)
	}
	if calls := activations.Load(); calls != 2 {
		t.Fatalf("doctor --wait read the activation %d times, want 2", calls)
	}
	if progress := decodeEvent(t, []byte(lines[0])); progress.Status != "progress" || progress.Data["relayOrigin"] != server.URL {
		t.Fatalf("doctor --wait did not report the checks before the wait: %s", stdout)
	}
}

func TestDoctorWaitRefusesAnInvalidRequestBeforeAnyRead(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "doctor", "--timeout", "1m"},
		{"--json", "doctor", "--wait", "--timeout", "0s"},
		{"--json", "doctor", "--wait", "--env", "production"},
	} {
		exit, stdout, _ := run(t, Dependencies{WorkingDir: initializedProject(t, "wait-chat")}, args...)
		if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" || failure.Next != "oe help doctor" {
			t.Fatalf("%v exited %d: %s", args, exit, stdout)
		}
	}
}

func TestDoctorWaitRefreshesASessionThatExpires(t *testing.T) {
	directory := initializedProject(t, "refresh-wait")
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, sandboxRelayURL); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	if err := store.Set(profile, credential.Credential{
		AccessToken: "first-token", RefreshToken: "refresh-1", ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	var tokens []string
	api := &fakeAPI{
		getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{Slug: "refresh-wait", Sandbox: projectEnvironment(sandboxRelayURL, "1")}, nil
		},
		refreshAuthorization: func(_ context.Context, refreshToken string) (control.Token, error) {
			if refreshToken != "refresh-1" {
				return control.Token{}, errors.New("unexpected refresh token " + refreshToken)
			}
			return control.Token{AccessToken: "second-token", RefreshToken: "refresh-2", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}, nil
		},
		activation: func(_ context.Context, request control.CredentialRequest, _ string) (control.Activation, error) {
			tokens = append(tokens, request.AccessToken)
			return control.Activation{FirstDevice: true, FirstAcknowledged: len(tokens) > 1}, nil
		},
	}
	relay := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{Body: http.NoBody, Header: make(http.Header), StatusCode: http.StatusOK}, nil
	})}
	// Each poll moves the clock past the session expiry.
	sleep := func(context.Context, time.Duration) error {
		now = now.Add(10 * time.Minute)
		return nil
	}
	exit, stdout, _ := run(t, Dependencies{
		API: api, HTTP: relay, Store: store, WorkingDir: directory, Sleep: sleep, Now: func() time.Time { return now },
	}, "--json", "doctor", "--wait")
	if exit != 0 || strings.Join(tokens, ",") != "first-token,second-token" {
		t.Fatalf("the wait did not refresh the session: exit=%d tokens=%v %s", exit, tokens, stdout)
	}
}

// TestDoctorNamesLinkForAMissingConnection proves that a configured clone
// with no env file is sent to oe link, not to oe new, which refuses it.
func TestDoctorNamesLinkForAMissingConnection(t *testing.T) {
	directory := initializedProject(t, "clone-chat")
	for _, test := range []struct{ environment, next string }{
		{"sandbox", "oe link"},
		{"production", "oe config push"},
	} {
		exit, stdout, _ := run(t, Dependencies{WorkingDir: directory}, "--json", "--env", test.environment, "doctor")
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitFailure || failure.Code != "RELAY_CONNECTION_MISSING" || failure.Next != test.next {
			t.Fatalf("%s doctor in a clone gave exit=%d %s", test.environment, exit, stdout)
		}
	}
}
