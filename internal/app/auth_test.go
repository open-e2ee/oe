package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
)

// relayTerms is the terms document list of the console route tests.
var relayTerms = []map[string]any{{
	"name": "Relay service terms", "url": "https://open-e2ee.dev/legal/relay-terms/2026-08-26",
	"version": "relay-2026-08-26",
}}

// personSession is the session route answer for a person with a name.
func personSession() map[string]any {
	return map[string]any{
		"schemaVersion": 1, "user": map[string]any{"id": "user_example", "email": "jane@example.com", "name": "Jane Doe"},
		"organization": map[string]any{"id": "org_example", "name": "Acme Inc."}, "role": "admin", "agent": nil,
	}
}

// console is a loopback control API with the WorkOS device flow, the session
// route, the organization list, and the terms routes. The CLI reaches it
// through the real control client, so each body is the JSON that the console
// route answers. session is the answer of the session route. organizations is
// the answer of the organization list; when it is nil, the list answers 404,
// as a console older than the organization commands does. A refresh with an
// organization_id moves the session and the list to that organization, or
// answers the WorkOS error signIn when it is set. routes serves any other
// authorized route that a test adds.
type console struct {
	t             *testing.T
	server        *httptest.Server
	routes        *http.ServeMux
	mu            sync.Mutex
	state         string
	canAccept     bool
	session       map[string]any
	organizations map[string]any
	signIn        string
	requests      []string
	accepts       []map[string]any
	refreshes     []url.Values
}

func newConsole(t *testing.T, state string, canAccept bool) *console {
	t.Helper()
	c := &console{t: t, routes: http.NewServeMux(), state: state, canAccept: canAccept, session: personSession()}
	c.server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

// controlURL is the value of --control-url for this console.
func (c *console) controlURL() string { return c.server.URL + "/api/cli" }

// requested reports each "METHOD path" that the console answered.
func (c *console) requested() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

// accepted reports each acceptance body that the console recorded.
func (c *console) accepted() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.accepts)
}

func (c *console) serve(response http.ResponseWriter, request *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request.Method+" "+request.URL.Path)
	switch request.URL.Path {
	case "/api/cli/v1/auth/configuration":
		c.answer(response, http.StatusOK, map[string]any{
			"schemaVersion": 1, "clientId": "client_cli_test",
			"deviceAuthorizationEndpoint": c.server.URL + "/user_management/authorize/device",
			"tokenEndpoint":               c.server.URL + "/user_management/authenticate",
		})
		return
	case "/user_management/authorize/device":
		c.answer(response, http.StatusOK, map[string]any{
			"device_code": "device", "user_code": "ABCD-EFGH", "expires_in": 900, "interval": 1,
			"verification_uri":          "https://login.example/device",
			"verification_uri_complete": "https://login.example/device?user_code=ABCD-EFGH",
		})
		return
	case "/user_management/authenticate":
		if err := request.ParseForm(); err != nil {
			c.t.Errorf("parse the token form: %v", err)
		}
		if request.PostForm.Get("grant_type") == "refresh_token" {
			c.refreshes = append(c.refreshes, request.PostForm)
		}
		if target := request.PostForm.Get("organization_id"); target != "" {
			if c.signIn != "" {
				c.answer(response, http.StatusBadRequest, map[string]any{"error": c.signIn, "error_description": "Sign in again."})
				return
			}
			c.moveTo(target)
			c.answer(response, http.StatusOK, map[string]any{
				"access_token": sessionTokenIn(target), "refresh_token": "refresh-" + target,
			})
			return
		}
		c.answer(response, http.StatusOK, map[string]any{
			"access_token": sessionToken(), "refresh_token": "refresh",
		})
		return
	}
	if request.Header.Get("Authorization") == "" {
		c.answer(response, http.StatusUnauthorized, map[string]any{
			"code": "AUTHENTICATION_REQUIRED", "message": "Run oe auth login first.",
		})
		return
	}
	switch request.Method + " " + request.URL.Path {
	case "GET /api/cli/v1/auth/session":
		c.answer(response, http.StatusOK, c.session)
	case "GET /api/cli/v1/organizations":
		if c.organizations == nil {
			c.answer(response, http.StatusNotFound, map[string]any{"code": "NOT_FOUND", "message": "Not found."})
			return
		}
		c.answer(response, http.StatusOK, c.organizations)
	case "GET /api/cli/v1/terms":
		c.answer(response, http.StatusOK, c.terms())
	case "POST /api/cli/v1/terms/acceptance":
		if !c.canAccept {
			c.answer(response, http.StatusForbidden, map[string]any{
				"code":    "TERMS_PERMISSION_REQUIRED",
				"message": "Your Organization role does not permit accepting the Relay service terms. An administrator of your Organization must accept them.",
			})
			return
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			c.t.Errorf("decode the acceptance body: %v", err)
		}
		c.accepts = append(c.accepts, body)
		changed := c.state == "required"
		c.state = "accepted"
		answer := c.terms()
		answer["changed"] = changed
		c.answer(response, http.StatusOK, answer)
	default:
		if handler, pattern := c.routes.Handler(request); pattern != "" {
			handler.ServeHTTP(response, request)
			return
		}
		c.t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		response.WriteHeader(http.StatusNotFound)
	}
}

// moveTo moves the session and the organization list to target, as a
// WorkOS refresh with organization_id does.
func (c *console) moveTo(target string) {
	session := maps.Clone(c.session)
	for _, entry := range c.organizations["organizations"].([]map[string]any) {
		if entry["id"] == target {
			session["organization"] = map[string]any{"id": target, "name": entry["name"]}
			session["role"] = entry["role"]
		}
	}
	c.session = session
	organizations := maps.Clone(c.organizations)
	organizations["current"] = target
	c.organizations = organizations
}

// twoOrganizations is the organization list of a person in Acme Inc., the
// organization of the session, and in Beta LLC.
func twoOrganizations() map[string]any {
	return map[string]any{"schemaVersion": 1, "current": "org_example", "organizations": []map[string]any{
		{"id": "org_example", "name": "Acme Inc.", "role": "admin"},
		{"id": "org_beta", "name": "Beta LLC", "role": "member"},
	}}
}

// refreshed reports the form of each refresh grant that the console answered.
func (c *console) refreshed() []url.Values {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.refreshes)
}

func (c *console) terms() map[string]any {
	var acceptedAt any
	if c.state == "accepted" {
		acceptedAt = "2026-09-01T09:30:00.000Z"
	}
	return map[string]any{
		"acceptedAt": acceptedAt, "canAccept": c.canAccept, "documents": relayTerms, "state": c.state,
	}
}

func (c *console) answer(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "private, no-store")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(body); err != nil {
		c.t.Errorf("encode the console answer: %v", err)
	}
}

// sessionToken is an unsigned access token with the claims of a WorkOS
// session in the console route tests.
func sessionToken() string { return sessionTokenIn("org_example") }

// sessionTokenIn is a session token in organization.
func sessionTokenIn(organization string) string {
	claims, _ := json.Marshal(map[string]any{
		"client_id": "client_cli_test", "sub": "user_example", "org_id": organization,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

// storeSession stores a valid session for the console.
func (c *console) storeSession(t *testing.T, store credential.Store) {
	t.Helper()
	profile, err := credential.Profile(c.controlURL())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(profile, credential.Credential{
		AccessToken: sessionToken(), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		RefreshToken: "refresh",
	}); err != nil {
		t.Fatal(err)
	}
}

// dependencies reaches the console through the real control client.
func (c *console) dependencies(store credential.Store, getenv func(string) string) Dependencies {
	api, err := control.New(c.controlURL(), c.server.Client())
	if err != nil {
		c.t.Fatal(err)
	}
	return Dependencies{
		API: api, Store: store, Getenv: getenv,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
}

// decodeEvents decodes each JSON document on stdout.
func decodeEvents(t *testing.T, stdout string) []event {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var events []event
	for {
		var value event
		if err := decoder.Decode(&value); errors.Is(err, io.EOF) {
			return events
		} else if err != nil {
			t.Fatalf("decode JSON output: %v\n%s", err, stdout)
		}
		events = append(events, value)
	}
}

var underClaudeCode = environment(map[string]string{"CLAUDECODE": "1"})

func TestAuthLoginUnderAnAgentWritesPendingThenResult(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "accepted", true)
	store := credential.NewMemory()
	browser := &opener{}
	dependencies := server.dependencies(store, underClaudeCode)
	dependencies.Interactive, dependencies.OpenURL, dependencies.In = terminal, browser.open, unreadable{t}
	exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	events := decodeEvents(t, stdout)
	if exit != 0 || len(events) != 2 || stderr != "" {
		t.Fatalf("an agent login did not write two JSON documents: exit=%d stdout=%s stderr=%q", exit, stdout, stderr)
	}
	pending, result := events[0], events[1]
	if pending.Status != "pending" || pending.Command != "auth login" || pending.Message != "A person must approve this device." ||
		pending.Action.Kind != "browser" || pending.Action.URL != "https://login.example/device?user_code=ABCD-EFGH" || pending.Action.Reason != "login" ||
		pending.Data["userCode"] != "ABCD-EFGH" || pending.Data["expiresInSeconds"] != float64(900) ||
		pending.Data["bareVerificationUrl"] != "https://login.example/device" {
		t.Fatalf("the pending event does not hand the device to a person: %s", stdout)
	}
	organization, _ := result.Data["organization"].(map[string]any)
	if result.Status != "ok" || result.Command != "auth login" || result.Next != "" || organization["id"] != "org_example" ||
		result.Data["user"] != "user_example" || result.Data["email"] != "jane@example.com" || result.Data["userName"] != "Jane Doe" ||
		result.Data["organizationName"] != "Acme Inc." || result.Data["role"] != "admin" ||
		result.Data["terms"] != "accepted" || result.Data["source"] != "keychain" || result.Data["store"] != credential.LocationOf("keychain").Key ||
		result.Message != "Signed in as Jane Doe (jane@example.com) in Acme Inc. Acme Inc. has accepted the OpenE2EE terms." {
		t.Fatalf("the login result is incomplete: %s", stdout)
	}
	if len(browser.opened) != 0 || strings.Contains(stdout, sessionToken()[:20]) {
		t.Fatalf("an agent login opened a browser or printed the token: %v %s", browser.opened, stdout)
	}
	profile, _ := credential.Profile(server.controlURL())
	if _, err := store.Get(profile); err != nil {
		t.Fatalf("the session was not stored: %v", err)
	}
}

func TestAuthLoginTermsRequiredUnderAnAgentExitsZeroWithNext(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "required", true)
	dependencies := server.dependencies(credential.NewMemory(), underClaudeCode)
	dependencies.Interactive, dependencies.In = terminal, unreadable{t}
	exit, stdout, _ := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	events := decodeEvents(t, stdout)
	if exit != 0 || len(events) != 2 {
		t.Fatalf("required terms under an agent failed the login: exit=%d %s", exit, stdout)
	}
	result := events[1]
	documents, _ := result.Data["documents"].([]any)
	if result.Status != "ok" || result.Data["terms"] != "required" || result.Data["canAccept"] != true ||
		len(documents) != 1 || result.Next != "oe auth login --accept-terms" {
		t.Fatalf("required terms did not name the acceptance: %s", stdout)
	}
	if slices.Contains(server.requested(), "POST /api/cli/v1/terms/acceptance") {
		t.Fatal("a login without --accept-terms accepted the terms")
	}
}

func TestAuthLoginAcceptTermsSendsTheDetectedAgent(t *testing.T) {
	for _, test := range []struct {
		name   string
		getenv func(string) string
		want   map[string]any
	}{
		{"agent", underClaudeCode, map[string]any{"actor": "agent", "agentName": "claude-code"}},
		{"person", environment(nil), map[string]any{"actor": "person"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("OE_ACCESS_TOKEN", "")
			server := newConsole(t, "required", true)
			store := credential.NewMemory()
			server.storeSession(t, store)
			dependencies := server.dependencies(store, test.getenv)
			exit, stdout, _ := run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "login", "--accept-terms")
			result := decodeEvent(t, []byte(stdout))
			if exit != 0 || result.Data["terms"] != "accepted" || result.Data["changed"] != true || result.Next != "" {
				t.Fatalf("--accept-terms did not accept: exit=%d %s", exit, stdout)
			}
			if accepts := server.accepted(); len(accepts) != 1 || !maps.Equal(accepts[0], test.want) {
				t.Fatalf("acceptance body %v, want %v", accepts, test.want)
			}
			if slices.Contains(server.requested(), "POST /user_management/authorize/device") {
				t.Fatal("--accept-terms with a valid session started a device flow")
			}

			// The organization has accepted, so a second run records nothing.
			exit, stdout, _ = run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "login", "--accept-terms")
			if again := decodeEvent(t, []byte(stdout)); exit != 0 || again.Data["changed"] != false || len(server.accepted()) != 1 {
				t.Fatalf("a second --accept-terms was not a no-op: exit=%d %s", exit, stdout)
			}
		})
	}
}

func TestAuthLoginAsksAPersonAtATerminal(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	for _, test := range []struct {
		answer string
		terms  string
	}{{"y\n", "accepted"}, {"n\n", "required"}} {
		server := newConsole(t, "required", true)
		store := credential.NewMemory()
		dependencies := server.dependencies(store, environment(nil))
		dependencies.Interactive, dependencies.OpenURL = terminal, (&opener{}).open
		dependencies.In = strings.NewReader(test.answer)
		exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
		if exit != 0 || !strings.Contains(stderr, "Relay service terms: https://open-e2ee.dev/legal/relay-terms/2026-08-26") ||
			!strings.Contains(stderr, "Accept these terms for Acme Inc.? [y/N]") {
			t.Fatalf("a person was not asked once with the documents: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
		}
		server.mu.Lock()
		state := server.state
		server.mu.Unlock()
		if state != test.terms {
			t.Fatalf("answer %q left the terms %s", test.answer, state)
		}
		profile, _ := credential.Profile(server.controlURL())
		if _, err := store.Get(profile); err != nil {
			t.Fatalf("answer %q removed the session: %v", test.answer, err)
		}
	}
}

func TestAcceptTermsWithoutPermissionExitsFiveAndKeepsTheSession(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "required", false)
	store := credential.NewMemory()
	server.storeSession(t, store)
	dependencies := server.dependencies(store, underClaudeCode)
	exit, stdout, _ := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	events := decodeEvents(t, stdout)
	if result := events[len(events)-1]; exit != 0 || result.Data["canAccept"] != false || result.Next != "" ||
		!strings.Contains(result.Message, "An administrator of Acme Inc. must accept them") {
		t.Fatalf("a member login did not name the administrator: exit=%d %s", exit, stdout)
	}

	exit, stdout, _ = run(t, dependencies, "--control-url", server.controlURL(), "auth", "login", "--accept-terms")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || failure.Command != "auth login" || failure.Code != "TERMS_PERMISSION_REQUIRED" || failure.Next != "" ||
		!strings.HasPrefix(failure.Error, "Your Organization role does not permit") {
		t.Fatalf("acceptance without permission: exit=%d %s", exit, stdout)
	}
	profile, _ := credential.Profile(server.controlURL())
	if _, err := store.Get(profile); err != nil {
		t.Fatalf("a refused acceptance removed the session: %v", err)
	}
}

func TestAuthStatusExitsFourWithoutASession(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	exit, stdout, _ := run(t, Dependencies{}, "--json", "auth", "status")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitAuthentication || failure.Command != "auth status" || failure.Code != "AUTHENTICATION_REQUIRED" || failure.Next != "oe auth login" {
		t.Fatalf("auth status without a session: exit=%d %s", exit, stdout)
	}
}

func TestAuthStatusReportsTermsAndTokenSource(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "required", false)
	store := credential.NewMemory()
	server.storeSession(t, store)
	exit, stdout, _ := run(t, server.dependencies(store, nil), "--json", "--control-url", server.controlURL(), "auth", "status")
	status := decodeEvent(t, []byte(stdout))
	organization, _ := status.Data["organization"].(map[string]any)
	// The memory store stands in for the OS keychain and names itself.
	if exit != 0 || status.Command != "auth status" || status.Data["user"] != "user_example" || organization["id"] != "org_example" ||
		status.Data["email"] != "jane@example.com" || status.Data["userName"] != "Jane Doe" || status.Data["organizationName"] != "Acme Inc." ||
		status.Data["role"] != "admin" || status.Data["terms"] != "required" || status.Data["canAccept"] != false ||
		status.Data["source"] != "memory" || status.Data["store"] != "memory" {
		t.Fatalf("auth status is incomplete: exit=%d %s", exit, stdout)
	}
	if strings.Contains(stdout, sessionToken()[:20]) || strings.Contains(stdout, "refresh") {
		t.Fatalf("auth status printed a token: %s", stdout)
	}
}

// The text of auth status leads with the person and ends the line with the
// store. It names no user, organization, or registration ID.
func TestAuthStatusTextNamesThePersonNotAnID(t *testing.T) {
	agent := personSession()
	agent["agent"] = map[string]any{"registrationId": "agent_reg_example"}
	unnamed := personSession()
	unnamed["user"] = map[string]any{"id": "user_example", "email": "jane@example.com", "name": nil}
	unnamed["role"] = nil
	plain := personSession()
	plain["organization"] = map[string]any{"id": "org_example", "name": "Acme"}
	keychain := credential.LocationOf("keychain").Label
	for _, test := range []struct {
		name        string
		session     map[string]any
		environment bool
		terms       string
		want        string
	}{
		{"person with a name", personSession(), false, "accepted",
			"Signed in as Jane Doe (jane@example.com) in Acme Inc. (" + keychain + ")\nAcme Inc. has accepted the OpenE2EE terms.\n"},
		{"person without a name", unnamed, false, "required",
			"Signed in as jane@example.com in Acme Inc. (" + keychain + ")\nAcme Inc. has not accepted the OpenE2EE terms.\n"},
		{"organization name without a period", plain, false, "accepted",
			"Signed in as Jane Doe (jane@example.com) in Acme. (" + keychain + ")\nAcme has accepted the OpenE2EE terms.\n"},
		{"agent", agent, false, "accepted",
			"Signed in as an agent for Jane Doe (jane@example.com) in Acme Inc. (" + keychain + ")\nAcme Inc. has accepted the OpenE2EE terms.\n"},
		{"environment credential", personSession(), true, "accepted",
			"Signed in as Jane Doe (jane@example.com) in Acme Inc. (OE_ACCESS_TOKEN)\nAcme Inc. has accepted the OpenE2EE terms.\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("OE_ACCESS_TOKEN", "")
			server := newConsole(t, test.terms, true)
			server.session = test.session
			store := credential.NewMemory()
			if test.environment {
				t.Setenv("OE_ACCESS_TOKEN", sessionToken())
			} else {
				// A stored session reads as the OS keychain, as Keychain.Get sets it.
				server.storeSession(t, keychainStore{store})
			}
			dependencies := server.dependencies(keychainStore{store}, nil)
			exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "status")
			if exit != 0 || stdout != test.want {
				t.Fatalf("auth status: exit=%d stdout=%q stderr=%q, want %q", exit, stdout, stderr, test.want)
			}
			for _, id := range []string{"user_", "org_", "agent_reg_"} {
				if strings.Contains(stdout, id) {
					t.Fatalf("auth status text names an ID %q: %q", id, stdout)
				}
			}
			exit, stdout, _ = run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "status")
			status := decodeEvent(t, []byte(stdout))
			registration, _ := status.Data["agent"].(map[string]any)
			if exit != 0 || (test.name == "agent") != (registration["registrationId"] == "agent_reg_example") {
				t.Fatalf("auth status JSON agent: exit=%d %s", exit, stdout)
			}
			if test.name == "person without a name" && (status.Data["userName"] != nil || status.Data["role"] != nil) {
				t.Fatalf("a missing name or role is not null: %s", stdout)
			}
		})
	}
}

// keychainStore reads a memory session as the OS keychain does.
type keychainStore struct{ *credential.Memory }

func (s keychainStore) Get(profile string) (credential.Credential, error) {
	value, err := s.Memory.Get(profile)
	value.Source = "keychain"
	return value, err
}

func TestAuthStatusWithoutTheSessionRouteFails(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "accepted", true)
	server.session = map[string]any{"schemaVersion": 1, "user": map[string]any{"id": "user_example"}}
	store := credential.NewMemory()
	server.storeSession(t, store)
	exit, stdout, _ := run(t, server.dependencies(store, nil), "--json", "--control-url", server.controlURL(), "auth", "status")
	if failure := decodeEvent(t, []byte(stdout)); exit == 0 || failure.Status != "error" ||
		!strings.Contains(failure.Error, "incomplete session") {
		t.Fatalf("an incomplete session answer passed: exit=%d %s", exit, stdout)
	}
}

func TestTopLevelLoginIsAUsageError(t *testing.T) {
	for verb, next := range map[string]string{"login": "oe auth login", "logout": "oe auth logout", "whoami": "oe auth status"} {
		exit, stdout, _ := run(t, Dependencies{}, "--json", verb)
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitUsage || failure.Code != "USAGE_ERROR" || failure.Next != next || !strings.Contains(failure.Error, next) {
			t.Fatalf("oe %s is still a command, or does not name %s: exit=%d %s", verb, next, exit, stdout)
		}
	}
	exit, stdout, _ := run(t, Dependencies{}, "--json", "help")
	var help struct {
		Data struct {
			Commands []struct {
				Name string `json:"name"`
			} `json:"commands"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &help); exit != 0 || err != nil {
		t.Fatalf("help failed: exit=%d %v", exit, err)
	}
	var names []string
	for _, command := range help.Data.Commands {
		names = append(names, command.Name)
	}
	if !slices.Contains(names, "auth") || slices.Contains(names, "login") || slices.Contains(names, "logout") {
		t.Fatalf("help lists %v", names)
	}
	var stderr bytes.Buffer
	if exit := Run(t.Context(), []string{"auth", "bogus"}, Dependencies{Out: io.Discard, Err: &stderr, WorkingDir: t.TempDir()}); exit != exitUsage ||
		!strings.HasSuffix(stderr.String(), "next: oe help auth\n") {
		t.Fatalf("an unknown auth command: exit=%d %q", exit, stderr.String())
	}
}

func TestTermsRefusalNamesTheCommandToRetry(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{}, &control.APIError{
			Status: 409, Code: "TERMS_REQUIRED", Message: "Accept the OpenE2EE terms first.", CanAccept: true,
			Documents: []control.TermsDocument{{Name: "Relay service terms", URL: "https://open-e2ee.dev/legal/relay-terms/2026-08-26", Version: "relay-2026-08-26"}},
		}
	}}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", "show", "any-chat")
	failure := decodeEvent(t, []byte(stdout))
	documents, _ := failure.Data["documents"].([]any)
	if exit != exitPersonAction || failure.Next != "oe auth login --accept-terms" || failure.Data["retry"] != "oe --json project show any-chat" ||
		failure.Data["canAccept"] != true || len(documents) != 1 {
		t.Fatalf("a terms refusal did not name the acceptance and the retry: exit=%d %s", exit, stdout)
	}
}

// setupPrompt is the first line of the post-login prompt.
const setupPrompt = "What do you want to do in this directory?"

// appDirectory is a new directory named name that holds the package.json of
// an app and no config.
func appDirectory(t *testing.T, name string) string {
	t.Helper()
	directory := emptyDirectory(t, name)
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"name":"`+name+`"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory
}

// personLogin runs the CLI for a person at a terminal, with no agent, in
// directory. answers are the lines that the person types.
func personLogin(server *console, store credential.Store, directory, answers string) Dependencies {
	dependencies := server.dependencies(store, environment(nil))
	dependencies.Interactive, dependencies.OpenURL = terminal, (&opener{}).open
	dependencies.WorkingDir, dependencies.In = directory, strings.NewReader(answers)
	return dependencies
}

// projectRoutes adds the project create, list, and read routes to the
// console. The account can read one project, chat-demo.
func projectRoutes(t *testing.T, server *console) {
	t.Helper()
	answer := func(response http.ResponseWriter, body string) {
		response.Header().Set("Content-Type", "application/json")
		io.WriteString(response, body)
	}
	server.routes.HandleFunc("POST /api/cli/v1/projects/bootstrap", func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode the bootstrap body: %v", err)
		}
		_, created := created(1, body)
		answer(response, created)
	})
	server.routes.HandleFunc("GET /api/cli/v1/projects", func(response http.ResponseWriter, _ *http.Request) {
		answer(response, `[{"name":"Chat demo","product":"signal-relay","production":{"state":"active"},"slug":"chat-demo"}]`)
	})
	server.routes.HandleFunc("GET /api/cli/v1/projects/chat-demo", func(response http.ResponseWriter, _ *http.Request) {
		answer(response, fmt.Sprintf(linkedProject, "chat-demo"))
	})
}

func TestLoginOffersCreateLinkSkipInAnAppDirectory(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	for _, test := range []struct {
		name    string
		terms   string
		answers string
		// project is the project of the config after the run, or "" for no
		// config.
		project string
		output  string
	}{
		{"create", "accepted", "1\n", "prompt-chat", "Created project prompt-chat with its Sandbox environment"},
		{"link", "accepted", "2\n1\n", "chat-demo", "Linked chat-demo."},
		{"skip", "accepted", "3\n", "", "next: oe new"},
		{"no answer", "accepted", "", "", "next: oe new"},
		// The terms prompt and the setup prompt read one line each.
		{"after the terms", "required", "y\n2\n1\n", "chat-demo", "Linked chat-demo."},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newConsole(t, test.terms, true)
			projectRoutes(t, server)
			store := credential.NewMemory()
			directory := appDirectory(t, "prompt-chat")
			exit, stdout, stderr := run(t, personLogin(server, store, directory, test.answers), "--control-url", server.controlURL(), "auth", "login")
			if exit != 0 || !strings.Contains(stdout, "Signed in as Jane Doe (jane@example.com) in Acme Inc.") || !strings.Contains(stdout, test.output) {
				t.Fatalf("answer %q: exit=%d stdout=%q stderr=%q", test.answers, exit, stdout, stderr)
			}
			for _, line := range []string{setupPrompt, "1. Create a new signal-relay project (oe new)", "2. Link an existing project (oe link)", "3. Skip"} {
				if !strings.Contains(stderr, line) {
					t.Fatalf("the prompt has no %q: %q", line, stderr)
				}
			}
			// The prompt names only the setup commands.
			if prompt := stderr[strings.Index(stderr, setupPrompt):]; strings.Count(prompt, "oe ") != 2 {
				t.Fatalf("the prompt names a command other than oe new and oe link: %q", prompt)
			}
			path := filepath.Join(directory, config.Filename)
			if test.project == "" {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("a skip wrote %s: %v", config.Filename, err)
				}
				if slices.ContainsFunc(server.requested(), func(request string) bool { return strings.Contains(request, "/v1/projects") }) {
					t.Fatalf("a skip called a project route: %q", server.requested())
				}
			} else if linked, err := config.Load(path); err != nil || linked.Project != test.project {
				t.Fatalf("the config holds %#v (%v), want project %s", linked, err, test.project)
			}
			profile, _ := credential.Profile(server.controlURL())
			if _, err := store.Get(profile); err != nil {
				t.Fatalf("the session was not kept: %v", err)
			}
		})
	}
}

func TestLoginOutsideAnAppDirectoryOffersNothing(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	// A package.json in a parent does not make an app directory.
	child := filepath.Join(appDirectory(t, "parent-chat"), "notes")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{emptyDirectory(t, "plain"), child} {
		server := newConsole(t, "accepted", true)
		dependencies := personLogin(server, credential.NewMemory(), directory, "")
		dependencies.In = unreadable{t}
		exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
		if exit != 0 || !strings.Contains(stdout, "Signed in as Jane Doe (jane@example.com) in Acme Inc.") || strings.Contains(stdout, "next:") || strings.Contains(stderr, setupPrompt) {
			t.Fatalf("a login in %s offered a setup or a next command: exit=%d stdout=%q stderr=%q", directory, exit, stdout, stderr)
		}
		if names := entries(t, directory); len(names) != 0 {
			t.Fatalf("a login in %s wrote %v", directory, names)
		}
	}
}

func TestLoginInASetUpDirectoryOffersNothing(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	root := initializedProject(t, "set-chat")
	web := filepath.Join(root, "web")
	if err := os.Mkdir(web, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{root, web} {
		if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"name":"set-chat"}`+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	source := mustRead(t, filepath.Join(root, config.Filename))
	for _, directory := range []string{root, web} {
		server := newConsole(t, "accepted", true)
		dependencies := personLogin(server, credential.NewMemory(), directory, "")
		dependencies.In = unreadable{t}
		exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
		if exit != 0 || !strings.HasSuffix(stdout, "\nnext: oe link\n") || strings.Contains(stderr, setupPrompt) {
			t.Fatalf("a login in the set-up %s: exit=%d stdout=%q stderr=%q", directory, exit, stdout, stderr)
		}
	}
	if after := mustRead(t, filepath.Join(root, config.Filename)); !bytes.Equal(after, source) {
		t.Fatalf("a login changed the config:\n%s", after)
	}
}

// TestTermsInALinkedDirectoryNameDoctor proves that the terms step in a
// directory whose setup is done names oe doctor, not oe link: the config sets
// the directory up, and .env.local holds the Sandbox Relay connection.
func TestTermsInALinkedDirectoryNameDoctor(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	directory := initializedProject(t, "linked-chat")
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, sandboxRelayURL); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"auth", "login", "--accept-terms"}, {"auth", "login"}} {
		server := newConsole(t, "required", true)
		store := credential.NewMemory()
		server.storeSession(t, store)
		dependencies := server.dependencies(store, environment(nil))
		dependencies.WorkingDir, dependencies.In = directory, unreadable{t}
		exit, stdout, _ := run(t, dependencies, append([]string{"--json", "--control-url", server.controlURL()}, args...)...)
		result := decodeEvents(t, stdout)
		if args[len(args)-1] == "login" {
			// Without --accept-terms, the terms step comes first.
			if exit != 0 || result[len(result)-1].Next != "oe auth login --accept-terms" {
				t.Fatalf("%v: exit=%d %s", args, exit, stdout)
			}
			continue
		}
		if exit != 0 || result[len(result)-1].Next != "oe doctor" {
			t.Fatalf("%v in a linked directory: exit=%d %s", args, exit, stdout)
		}
	}
}

func TestLoginUnderAnAgentNamesNewInNext(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	directory := appDirectory(t, "agent-chat")
	server := newConsole(t, "accepted", true)
	dependencies := server.dependencies(credential.NewMemory(), underClaudeCode)
	dependencies.Interactive, dependencies.In, dependencies.WorkingDir = terminal, unreadable{t}, directory
	exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	if events := decodeEvents(t, stdout); exit != 0 || len(events) != 2 || stderr != "" || events[1].Next != "oe new" {
		t.Fatalf("an agent login in an app directory did not name oe new: exit=%d stdout=%s stderr=%q", exit, stdout, stderr)
	}

	// A person without a terminal gets the same next and no prompt.
	dependencies = personLogin(server, credential.NewMemory(), directory, "")
	dependencies.Interactive, dependencies.In = func() bool { return false }, unreadable{t}
	exit, stdout, stderr = run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	if exit != 0 || !strings.HasSuffix(stdout, "\nnext: oe new\n") || strings.Contains(stderr, setupPrompt) {
		t.Fatalf("a login without a terminal: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}

	// Terms that stay required keep the terms next. After --accept-terms,
	// next is oe new.
	server = newConsole(t, "required", true)
	store := credential.NewMemory()
	server.storeSession(t, store)
	dependencies = server.dependencies(store, underClaudeCode)
	dependencies.Interactive, dependencies.In, dependencies.WorkingDir = terminal, unreadable{t}, directory
	exit, stdout, _ = run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
	if events := decodeEvents(t, stdout); exit != 0 || events[len(events)-1].Next != "oe auth login --accept-terms" {
		t.Fatalf("required terms did not keep the terms next: exit=%d %s", exit, stdout)
	}
	exit, stdout, _ = run(t, dependencies, "--control-url", server.controlURL(), "auth", "login", "--accept-terms")
	if result := decodeEvent(t, []byte(stdout)); exit != 0 || result.Data["terms"] != "accepted" || result.Next != "oe new" {
		t.Fatalf("an accepted login in an app directory did not name oe new: exit=%d %s", exit, stdout)
	}
	if _, err := os.Stat(filepath.Join(directory, config.Filename)); !os.IsNotExist(err) {
		t.Fatalf("a login under an agent wrote %s: %v", config.Filename, err)
	}
}

func TestRefusedAccessTokenNamesTheVariableAndNoLogin(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "refused-ci-token")
	refused := &control.APIError{Status: 401, Code: "INVALID_SESSION", Message: "Run oe auth login again."}
	api := &fakeAPI{
		session: func(context.Context, control.CredentialRequest) (control.Session, error) {
			return control.Session{}, refused
		},
		getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{}, refused
		},
	}
	for _, args := range [][]string{
		{"--json", "auth", "login"},
		{"--json", "auth", "login", "--accept-terms"},
		{"--json", "project", "show", "any-chat"},
	} {
		exit, stdout, stderr := run(t, Dependencies{API: api}, args...)
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitAuthentication || failure.Code != "ACCESS_TOKEN_INVALID" || failure.Next != "" ||
			!strings.Contains(failure.Error, "OE_ACCESS_TOKEN") || !strings.Contains(failure.Error, "unset OE_ACCESS_TOKEN") {
			t.Fatalf("%v with a refused OE_ACCESS_TOKEN: exit=%d %s", args, exit, stdout)
		}
		if strings.Contains(stdout+stderr, "refused-ci-token") {
			t.Fatalf("%v printed the access token", args)
		}
	}
}

func TestStoredSessionRefusalStillNamesLogin(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{}, &control.APIError{Status: 401, Code: "INVALID_SESSION", Message: "Run oe auth login again."}
	}}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", "show", "any-chat")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitAuthentication || failure.Code != "INVALID_SESSION" || failure.Next != "oe auth login" {
		t.Fatalf("a refused stored session lost its login next: exit=%d %s", exit, stdout)
	}
}

func TestAccessTokenFailureThatNamesLoginLosesTheNext(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "ci-token")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{}, &control.APIError{Status: 403, Code: "ORGANIZATION_REQUIRED", Message: "Sign in to an organization."}
	}}
	exit, stdout, _ := run(t, Dependencies{API: api}, "--json", "project", "show", "any-chat")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || failure.Code != "ORGANIZATION_REQUIRED" || failure.Next != "" || !strings.Contains(failure.Error, "OE_ACCESS_TOKEN") {
		t.Fatalf("ORGANIZATION_REQUIRED under OE_ACCESS_TOKEN named a login: exit=%d %s", exit, stdout)
	}
}

func TestLoginThatNoPersonApprovesTimesOut(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	start := func(context.Context, control.AuthorizationRequest) (control.Authorization, error) {
		return control.Authorization{DeviceCode: "device", VerificationURL: "https://login.example/device", UserCode: "ABCD", IntervalSeconds: 1}, nil
	}
	waitForDeadline := func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	for name, poll := range map[string]func(context.Context, control.Authorization) (control.Token, error){
		"local timeout": func(context.Context, control.Authorization) (control.Token, error) {
			return control.Token{Pending: true}, nil
		},
		"expired device code": func(context.Context, control.Authorization) (control.Token, error) {
			return control.Token{}, control.ErrAuthorizationExpired
		},
	} {
		api := &fakeAPI{startAuthorization: start, pollAuthorization: poll}
		args := []string{"--json", "auth", "login", "--timeout", "10ms"}
		exit, stdout, _ := run(t, Dependencies{API: api, Sleep: waitForDeadline, Getenv: environment(nil), OpenURL: (&opener{}).open}, args...)
		events := decodeEvents(t, stdout)
		failure := events[len(events)-1]
		if exit != exitTemporary || failure.Code != "LOGIN_TIMED_OUT" || failure.Next != "oe --json auth login --timeout 10ms" {
			t.Fatalf("%s: exit=%d %s", name, exit, stdout)
		}
	}
}

// TestEndedParentKeepsTheLoginError proves that only the login deadline
// gives LOGIN_TIMED_OUT. A parent context that was cancelled, or whose own
// deadline passed, keeps the error.
func TestEndedParentKeepsTheLoginError(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for name, ctx := range map[string]context.Context{"cancelled": cancelled, "expired": expired} {
		loginCtx, stopLogin := context.WithTimeout(ctx, time.Minute)
		cause := fmt.Errorf("login did not complete: %w", loginCtx.Err())
		if err := loginFailure(ctx, loginCtx, time.Minute, cause); err != cause {
			t.Errorf("a %s parent made the login error %v", name, err)
		}
		stopLogin()
	}
}

func TestLoginNeedsAPositiveTimeout(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	for _, timeout := range []string{"0s", "-1s"} {
		exit, stdout, _ := run(t, Dependencies{API: &fakeAPI{}, Getenv: environment(nil)}, "--json", "auth", "login", "--timeout="+timeout)
		if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" || failure.Next != "oe help auth" {
			t.Fatalf("auth login --timeout=%s gave exit=%d %s", timeout, exit, stdout)
		}
	}
}

// TestRefusedAccessTokenKeepsTheData proves that ACCESS_TOKEN_INVALID keeps
// the data of the failure, such as the state of each environment of a push.
func TestRefusedAccessTokenKeepsTheData(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "ci-token")
	t.Setenv("OE_ACCESS_TOKEN_SCOPES", "")
	directory := initializedProject(t, "push-chat")
	api := &fakeAPI{
		getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{Slug: "push-chat", Writer: "config", Sandbox: &control.ProjectEnvironment{RelayURL: "https://relay.example/signal/v1/connection/pk_sandbox"}}, nil
		},
		plan: func(context.Context, control.CredentialRequest, control.PlanRequest) (control.Plan, error) {
			return control.Plan{}, &control.APIError{Status: 401, Code: "INVALID_SESSION", Message: "Run oe auth login again."}
		},
	}
	exit, stdout, _ := run(t, Dependencies{API: api, WorkingDir: directory}, "--json", "config", "push", "--dry-run")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitAuthentication || failure.Code != "ACCESS_TOKEN_INVALID" || failure.Data["environments"] == nil {
		t.Fatalf("a refused OE_ACCESS_TOKEN lost the push data: exit=%d %s", exit, stdout)
	}
}

// A login with --organization runs the device flow, then moves the session
// to the organization with one refresh, and stores the rotated pair.
func TestAuthLoginOrganizationSwitchesAfterTheDeviceFlow(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "accepted", true)
	server.organizations = twoOrganizations()
	store := credential.NewMemory()
	dependencies := server.dependencies(store, underClaudeCode)
	dependencies.Interactive, dependencies.OpenURL, dependencies.In = terminal, (&opener{}).open, unreadable{t}
	exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login", "--organization", "beta llc")
	events := decodeEvents(t, stdout)
	if exit != 0 || len(events) != 2 || stderr != "" {
		t.Fatalf("login --organization: exit=%d stdout=%s stderr=%q", exit, stdout, stderr)
	}
	result := events[1]
	organization, _ := result.Data["organization"].(map[string]any)
	organizations, _ := result.Data["organizations"].([]any)
	if organization["id"] != "org_beta" || result.Data["organizationName"] != "Beta LLC" || len(organizations) != 2 ||
		result.Message != "Signed in as Jane Doe (jane@example.com) in Beta LLC. You belong to 2 organizations; run oe org switch to change. Beta LLC has accepted the OpenE2EE terms." {
		t.Fatalf("the login did not end in Beta LLC: %s", stdout)
	}
	if current, _ := organizations[1].(map[string]any); current["id"] != "org_beta" || current["current"] != true {
		t.Fatalf("data.organizations does not mark Beta LLC current: %s", stdout)
	}
	refreshes := server.refreshed()
	if len(refreshes) != 1 || refreshes[0].Get("organization_id") != "org_beta" || refreshes[0].Get("refresh_token") != "refresh" {
		t.Fatalf("the switch refreshed %v", refreshes)
	}
	profile, _ := credential.Profile(server.controlURL())
	if stored, err := store.Get(profile); err != nil || stored.RefreshToken != "refresh-org_beta" || sessionClaimsOf(stored.AccessToken).Organization != "org_beta" {
		t.Fatalf("the store does not hold the switched session: %v", err)
	}
}

// A login whose organization needs its own sign-in exits 5. The session of
// the device flow stays stored, and the message says to choose the
// organization on the sign-in page.
func TestAuthLoginOrganizationNeedsItsOwnSignIn(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "accepted", true)
	server.organizations, server.signIn = twoOrganizations(), "sso_required"
	store := credential.NewMemory()
	dependencies := server.dependencies(store, underClaudeCode)
	dependencies.Interactive, dependencies.OpenURL, dependencies.In = terminal, (&opener{}).open, unreadable{t}
	exit, stdout, _ := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login", "--organization", "Beta LLC")
	events := decodeEvents(t, stdout)
	failure := events[len(events)-1]
	if exit != exitPersonAction || failure.Code != "ORGANIZATION_SIGN_IN_REQUIRED" || failure.Next != "oe auth login --organization 'Beta LLC'" ||
		!strings.Contains(failure.Error, "choose Beta LLC on the sign-in page") || failure.Data["reason"] != "sso_required" {
		t.Fatalf("a sign-in refusal: exit=%d %s", exit, stdout)
	}
	profile, _ := credential.Profile(server.controlURL())
	if stored, err := store.Get(profile); err != nil || stored.RefreshToken != "refresh" {
		t.Fatalf("the refusal changed the stored session: %v %#v", err, stored)
	}
}

func TestAuthLoginOrganizationRefusesAnEnvironmentToken(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", sessionToken())
	server := newConsole(t, "accepted", true)
	dependencies := server.dependencies(credential.NewMemory(), environment(map[string]string{"OE_ACCESS_TOKEN": sessionToken()}))
	exit, stdout, _ := run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "login", "--organization", "org_beta")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" || !strings.Contains(failure.Error, "unset OE_ACCESS_TOKEN") {
		t.Fatalf("login --organization under OE_ACCESS_TOKEN: exit=%d %s", exit, stdout)
	}
	if len(server.requested()) != 0 {
		t.Fatalf("the refusal reached the console: %q", server.requested())
	}
}

// --json and an agent never get the organization chooser, even at a
// terminal. The result still lists the organizations.
func TestAuthLoginNeverPromptsForTheOrganizationUnderJSONOrAnAgent(t *testing.T) {
	for name, global := range map[string]struct {
		args   []string
		getenv func(string) string
	}{
		"json":  {[]string{"--json"}, nil},
		"agent": {nil, underClaudeCode},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OE_ACCESS_TOKEN", "")
			server := newConsole(t, "accepted", true)
			server.organizations = twoOrganizations()
			dependencies := server.dependencies(credential.NewMemory(), global.getenv)
			dependencies.Interactive, dependencies.OpenURL, dependencies.In = terminal, (&opener{}).open, unreadable{t}
			exit, stdout, stderr := run(t, dependencies, append(global.args, "--control-url", server.controlURL(), "auth", "login")...)
			events := decodeEvents(t, stdout)
			result := events[len(events)-1]
			organizations, _ := result.Data["organizations"].([]any)
			if exit != 0 || strings.Contains(stderr, "Switch to which organization") || len(organizations) != 2 ||
				!strings.Contains(result.Message, "You belong to 2 organizations; run oe org switch to change.") {
				t.Fatalf("login: exit=%d stdout=%s stderr=%q", exit, stdout, stderr)
			}
			if refreshes := server.refreshed(); len(refreshes) != 0 {
				t.Fatalf("a login without a person switched the organization: %v", refreshes)
			}
		})
	}
}

// A person at a terminal with more than one organization chooses one after
// the login. Enter keeps the organization of the session.
func TestAuthLoginLetsAPersonChooseTheOrganization(t *testing.T) {
	for _, test := range []struct {
		answer, organization string
		refreshes            int
	}{
		{"2\n", "Beta LLC", 1},
		{"\n", "Acme Inc.", 0},
	} {
		t.Run(test.organization, func(t *testing.T) {
			t.Setenv("OE_ACCESS_TOKEN", "")
			server := newConsole(t, "accepted", true)
			server.organizations = twoOrganizations()
			dependencies := server.dependencies(credential.NewMemory(), nil)
			dependencies.Interactive, dependencies.OpenURL, dependencies.In = terminal, (&opener{}).open, strings.NewReader(test.answer)
			exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "login")
			if exit != 0 || !strings.Contains(stderr, "  1. Acme Inc. (current)\n  2. Beta LLC\nSwitch to which organization? [1-2, Enter keeps Acme Inc.] ") ||
				!strings.Contains(stdout, "\nSigned in as Jane Doe (jane@example.com) in "+strings.TrimSuffix(test.organization, ".")+". You belong to 2 organizations; run oe org switch to change.") {
				t.Fatalf("the chooser: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
			}
			if refreshes := server.refreshed(); len(refreshes) != test.refreshes {
				t.Fatalf("the chooser refreshed %v", refreshes)
			}
		})
	}
}

// auth status names each organization with its role. A console without the
// list keeps the output of TestAuthStatusTextNamesThePersonNotAnID.
func TestAuthStatusListsTheOrganizations(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := newConsole(t, "accepted", true)
	server.organizations = twoOrganizations()
	store := credential.NewMemory()
	server.storeSession(t, keychainStore{store})
	dependencies := server.dependencies(keychainStore{store}, nil)
	exit, stdout, stderr := run(t, dependencies, "--control-url", server.controlURL(), "auth", "status")
	if exit != 0 || !strings.HasSuffix(stdout, "\nAcme Inc. has accepted the OpenE2EE terms.\nOrganizations: Acme Inc. (admin, current), Beta LLC (member)\n") {
		t.Fatalf("auth status: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
	exit, stdout, _ = run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "status")
	organizations, _ := decodeEvent(t, []byte(stdout)).Data["organizations"].([]any)
	if exit != 0 || len(organizations) != 2 {
		t.Fatalf("auth status --json: exit=%d %s", exit, stdout)
	}

	server.organizations = nil
	exit, stdout, _ = run(t, dependencies, "--json", "--control-url", server.controlURL(), "auth", "status")
	if status := decodeEvent(t, []byte(stdout)); exit != 0 || status.Data["organizations"] != nil {
		t.Fatalf("auth status on a console without the list: exit=%d %s", exit, stdout)
	}
}
