package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/agent"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

// TestMain removes the variables that coding agents set, and OE_ENV, so a
// test that runs under an agent or in a configured shell sees the same
// defaults as CI. A test that needs a variable passes Getenv.
func TestMain(m *testing.M) {
	for _, name := range agent.Variables() {
		os.Unsetenv(name)
	}
	os.Unsetenv("OE_ENV")
	m.Run()
}

type event struct {
	Status  string `json:"status"`
	Command string `json:"command"`
	Message string `json:"message"`
	Error   string `json:"error"`
	Code    string `json:"code"`
	Next    string `json:"next"`
	Action  struct {
		Kind   string `json:"kind"`
		URL    string `json:"url"`
		Reason string `json:"reason"`
	} `json:"action"`
	Data map[string]any `json:"data"`
}

// decodeEvent decodes the one JSON document that --json writes and fails when
// stdout holds another.
func decodeEvent(t *testing.T, stdout []byte) event {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	var value event
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode JSON output: %v\n%s", err, stdout)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("JSON mode wrote more than one document: %s", stdout)
	}
	return value
}

func run(t *testing.T, dependencies Dependencies, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	dependencies.Out, dependencies.Err = &stdout, &stderr
	if dependencies.WorkingDir == "" {
		dependencies.WorkingDir = t.TempDir()
	}
	if dependencies.API == nil {
		dependencies.API = &fakeAPI{}
	}
	if dependencies.Store == nil {
		dependencies.Store = credential.NewMemory()
	}
	exit := Run(t.Context(), args, dependencies)
	return exit, stdout.String(), stderr.String()
}

func TestUsageErrorsExitTwoInTheRequestedMode(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown command":           {"--json", "bogus"},
		"unknown global flag":       {"--bogus", "--json"},
		"unknown command flag":      {"config", "push", "--bogus", "--json"},
		"unexpected argument":       {"--json", "doctor", "extra"},
		"missing global flag value": {"--json", "doctor", "--env"},
		"invalid environment":       {"--json", "--env=stage", "doctor"},
		"missing subcommand":        {"--json", "project"},
		"unknown help topic":        {"--json", "help", "bogus"},
		"new with production":       {"--json", "--env", "production", "new"},
		"invalid agent mode":        {"--json", "--agent=maybe", "doctor"},
		"missing agent mode":        {"doctor", "--json", "--agent"},
	} {
		t.Run(name, func(t *testing.T) {
			exit, stdout, stderr := run(t, Dependencies{}, args...)
			if exit != exitUsage {
				t.Fatalf("exit %d, want %d: %s %s", exit, exitUsage, stdout, stderr)
			}
			failure := decodeEvent(t, []byte(stdout))
			if failure.Status != "error" || failure.Code != "USAGE_ERROR" || !strings.HasPrefix(failure.Next, "oe ") {
				t.Fatalf("usage error has no code or next command: %s", stdout)
			}
			if strings.Contains(failure.Error, "flag provided but not defined") && !strings.Contains(failure.Error, "oe config push") {
				t.Fatalf("flag error does not name the command: %s", failure.Error)
			}
		})
	}
}

func TestTextFailureNamesTheNextCommandOnStandardError(t *testing.T) {
	exit, stdout, stderr := run(t, Dependencies{}, "config", "push")
	if exit != exitFailure || stdout != "" {
		t.Fatalf("text failure wrote to stdout or exited %d: %q", exit, stdout)
	}
	if !strings.Contains(stderr, "error: open-e2ee.config.ts was not found") || !strings.HasSuffix(stderr, "next: oe new\n") {
		t.Fatalf("text failure did not name oe new: %q", stderr)
	}
}

func TestGlobalFlagsAreAcceptedAfterTheCommand(t *testing.T) {
	for _, args := range [][]string{
		{"version", "--json"},
		{"--json", "version"},
		{"version", "--", "--json"},
	} {
		exit, stdout, _ := run(t, Dependencies{}, args...)
		if slices.Contains(args, "--") {
			if exit != exitUsage {
				t.Fatalf("arguments after -- reached the global parser: %v exit=%d %s", args, exit, stdout)
			}
			continue
		}
		if exit != 0 || decodeEvent(t, []byte(stdout)).Data["version"] != Version {
			t.Fatalf("global flag position changed the result: %v %s", args, stdout)
		}
	}
}

func TestHelpDescribesEachCommand(t *testing.T) {
	exit, stdout, _ := run(t, Dependencies{}, "-h")
	if exit != 0 || !strings.Contains(stdout, "Exit codes:") || !strings.Contains(stdout, "oe help <command>") {
		t.Fatalf("-h did not show the command surface: %s", stdout)
	}
	for _, flag := range []string{"--help", "-h"} {
		exit, stdout, _ := run(t, Dependencies{}, "--json", "help", flag)
		if spec := decodeEvent(t, []byte(stdout)); exit != 0 || spec.Command != "help" {
			t.Fatalf("oe help %s did not describe help: exit=%d %s", flag, exit, stdout)
		}
	}
	for _, args := range [][]string{{"--json", "help", "project"}, {"--json", "project", "--help"}} {
		exit, stdout, _ := run(t, Dependencies{}, args...)
		spec := decodeEvent(t, []byte(stdout))
		usage, _ := spec.Data["usage"].([]any)
		if exit != 0 || spec.Command != "project" || !slices.Contains(usage, any("oe project connection [PROJECT] [--env sandbox|production]")) {
			t.Fatalf("%v did not describe project: %s", args, stdout)
		}
	}
}

func TestMissingSessionExitsFourAndNamesLogin(t *testing.T) {
	exit, stdout, _ := run(t, Dependencies{}, "--json", "project", "show", "any-chat")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitAuthentication || failure.Code != "AUTHENTICATION_REQUIRED" || failure.Next != "oe auth login" {
		t.Fatalf("missing session was not an authentication failure: exit=%d %s", exit, stdout)
	}
}

// TestControlRefusalKeepsTheConsoleCode covers the refusals that the project
// read passes through. TestProjectReadNamesTheProjectList covers the refusals
// that it maps.
func TestControlRefusalKeepsTheConsoleCode(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	for _, test := range []struct {
		refusal *control.APIError
		exit    int
		next    string
	}{
		{&control.APIError{Status: 401, Code: "INVALID_SESSION", Message: "Run oe auth login again."}, exitAuthentication, "oe auth login"},
		{&control.APIError{Status: 409, Code: "TERMS_REQUIRED", Message: "Accept the OpenE2EE terms first.", CanAccept: true}, exitPersonAction, "oe auth login --accept-terms"},
		{&control.APIError{Status: 409, Code: "TERMS_REQUIRED", Message: "An administrator must accept the OpenE2EE terms."}, exitPersonAction, ""},
		{&control.APIError{Status: 403, Code: "TERMS_PERMISSION_REQUIRED", Message: "An administrator of your Organization must accept them."}, exitPersonAction, ""},
		{&control.APIError{Status: 500, Message: "Internal Server Error"}, exitFailure, ""},
	} {
		api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{}, test.refusal
		}}
		exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", "show", "any-chat")
		failure := decodeEvent(t, []byte(stdout))
		wantCode := test.refusal.Code
		if wantCode == "" {
			wantCode = "CONTROL_ERROR"
		}
		if exit != test.exit || failure.Code != wantCode || failure.Next != test.next || failure.Error != test.refusal.Message {
			t.Fatalf("refusal %#v became exit=%d %s", test.refusal, exit, stdout)
		}
	}
}

func TestProjectConnectionPrintsTheServerRelayURL(t *testing.T) {
	directory := initializedProject(t, "connection-chat")
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	var requested []string
	api := &fakeAPI{getProject: func(_ context.Context, _ control.CredentialRequest, slug string) (control.Project, error) {
		requested = append(requested, slug)
		return control.Project{Slug: slug, Writer: "config", Sandbox: projectEnvironment(sandboxRelayURL, "3")}, nil
	}}
	dependencies := Dependencies{API: api, Store: store, WorkingDir: directory}

	exit, stdout, _ := run(t, dependencies, "project", "connection")
	if exit != 0 || stdout != sandboxRelayURL+"\n" {
		t.Fatalf("text connection is not the bare URL: exit=%d %q", exit, stdout)
	}
	exit, stdout, _ = run(t, dependencies, "project", "connection", "other-chat", "--json", "--env=sandbox")
	connection := decodeEvent(t, []byte(stdout))
	if exit != 0 || connection.Data["relayUrl"] != sandboxRelayURL || connection.Data["project"] != "other-chat" || connection.Data["variable"] != "OPEN_E2EE_RELAY_URL" {
		t.Fatalf("JSON connection is incomplete: %s", stdout)
	}
	exit, stdout, _ = run(t, dependencies, "--json", "project", "connection", "--env", "production")
	inactive := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || inactive.Code != "ENVIRONMENT_NOT_ACTIVE" || inactive.Next != "oe config push" {
		t.Fatalf("inactive Production did not name oe config push: %s", stdout)
	}
	if !slices.Equal(requested, []string{"connection-chat", "other-chat", "connection-chat"}) {
		t.Fatalf("connection read the wrong projects: %v", requested)
	}
}

func TestProjectShowNeedsNoConfigAndOmitsTheConnection(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(_ context.Context, _ control.CredentialRequest, slug string) (control.Project, error) {
		return control.Project{Slug: slug, Writer: "config", Sandbox: projectEnvironment(sandboxRelayURL, "3")}, nil
	}}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", "show", "show-chat")
	shown := decodeEvent(t, []byte(stdout))
	project, _ := shown.Data["project"].(map[string]any)
	environments, _ := project["environments"].(map[string]any)
	sandbox, _ := environments["sandbox"].(map[string]any)
	production, _ := environments["production"].(map[string]any)
	if exit != 0 || sandbox["active"] != true || sandbox["revision"] != "3" || production["active"] != false {
		t.Fatalf("project show lost the environments: %s", stdout)
	}
	// The CLI names the retention as the config does, not with the wire name
	// of the control API.
	if sandbox["deliveryRetentionSeconds"] != float64(86_400) || sandbox["attachmentRetentionSeconds"] != float64(86_400) ||
		strings.Contains(stdout, "deliveryTtlSeconds") {
		t.Fatalf("project show named the retention fields wrong: %s", stdout)
	}
	if strings.Contains(stdout, "pk_sandbox_public") {
		t.Fatalf("project show printed a Relay connection URL: %s", stdout)
	}
}

// productionActivation answers a project whose Production can activate, and
// needs a card first when card is true.
func productionActivation(t *testing.T, project string, card bool) *pushConsole {
	console := newPushConsole(t, project)
	if card {
		console.blockProduction(control.BlockedByCard)
	}
	return console
}

// deviceLogin answers a browser authorization that a person approves at once,
// for an organization that has accepted the terms.
func deviceLogin() *fakeAPI {
	return &fakeAPI{
		startAuthorization: func(context.Context, control.AuthorizationRequest) (control.Authorization, error) {
			return control.Authorization{DeviceCode: "device", VerificationURL: "https://login.example/device", UserCode: "ABCD", IntervalSeconds: 1}, nil
		},
		pollAuthorization: func(context.Context, control.Authorization) (control.Token, error) {
			return control.Token{AccessToken: "token"}, nil
		},
		terms: func(context.Context, control.CredentialRequest) (control.Terms, error) {
			return control.Terms{State: control.TermsAccepted, CanAccept: true}, nil
		},
		session: acmeSession,
	}
}

// acmeSession answers the session read for a person without a name.
func acmeSession(context.Context, control.CredentialRequest) (control.Session, error) {
	return control.Session{
		SchemaVersion: 1, User: control.SessionUser{ID: "user_example", Email: "jane@example.com"},
		Organization: control.SessionOrganization{ID: "org_example", Name: "Acme Inc."},
	}, nil
}

// unreadable is standard input that fails the test when a command reads it.
type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("the command read standard input")
	return 0, io.EOF
}

// opener is a fake browser that records each URL that it opens.
type opener struct{ opened []string }

func (o *opener) open(target string) error {
	o.opened = append(o.opened, target)
	return nil
}

func terminal() bool { return true }

func TestAgentFlagOverridesDetection(t *testing.T) {
	claudeCode := environment(map[string]string{"CLAUDECODE": "1"})
	exit, stdout, _ := run(t, Dependencies{Getenv: claudeCode}, "--agent", "no", "version")
	if exit != 0 || stdout != Version+"\n" {
		t.Fatalf("--agent no did not restore text: exit=%d %q", exit, stdout)
	}
	exit, stdout, _ = run(t, Dependencies{}, "version", "--agent=yes")
	if exit != 0 || decodeEvent(t, []byte(stdout)).Data["version"] != Version {
		t.Fatalf("--agent yes did not select JSON: exit=%d %q", exit, stdout)
	}
	for _, test := range []struct {
		args   []string
		getenv func(string) string
		opened int
	}{
		{[]string{"--agent", "no", "auth", "login"}, claudeCode, 1},
		{[]string{"--agent", "yes", "auth", "login"}, environment(nil), 0},
		{[]string{"--agent", "auto", "auth", "login"}, claudeCode, 0},
	} {
		browser := &opener{}
		exit, stdout, _ := run(t, Dependencies{
			API: deviceLogin(), Getenv: test.getenv, Interactive: terminal, OpenURL: browser.open,
		}, test.args...)
		if exit != 0 || len(browser.opened) != test.opened {
			t.Fatalf("%v opened %d browsers, want %d: exit=%d %s", test.args, len(browser.opened), test.opened, exit, stdout)
		}
	}
}

func TestAgentNeverOpensABrowser(t *testing.T) {
	codex := environment(map[string]string{"CODEX_THREAD_ID": "codex-thread"})
	browser := &opener{}
	exit, stdout, _ := run(t, Dependencies{
		API: deviceLogin(), Getenv: codex, Interactive: terminal, OpenURL: browser.open,
	}, "auth", "login")
	pending, _, _ := strings.Cut(stdout, "\n")
	if first := decodeEvent(t, []byte(pending)); exit != 0 || first.Status != "pending" || first.Action.URL != "https://login.example/device" || first.Data["userCode"] != "ABCD" {
		t.Fatalf("an agent login hid the URL from the person who approves it: exit=%d stdout=%s", exit, stdout)
	}

	directory := initializedProject(t, "agent-chat")
	store := credential.NewMemory()
	storeCredential(t, store, "deploy:write")
	exit, stdout, _ = run(t, Dependencies{
		API: productionActivation(t, "agent-chat", true), Store: store, WorkingDir: directory,
		Getenv: codex, Interactive: terminal, OpenURL: browser.open,
	}, "config", "push", "--yes")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || failure.Code != "CARD_REQUIRED" || failure.Action.URL != cardSetupURL {
		t.Fatalf("an agent did not get the setup page in action.url: exit=%d %s", exit, stdout)
	}
	if len(browser.opened) != 0 {
		t.Fatalf("an agent opened a browser: %v", browser.opened)
	}
}

func TestNoTTYAndNoAgentNeverPrompts(t *testing.T) {
	directory := initializedProject(t, "headless-chat")
	store := credential.NewMemory()
	storeCredential(t, store, "deploy:write")
	browser := &opener{}
	script := Dependencies{
		Store: store, WorkingDir: directory, In: unreadable{t},
		Interactive: func() bool { return false }, OpenURL: browser.open,
	}

	script.API = productionActivation(t, "headless-chat", false)
	exit, stdout, stderr := run(t, script, "config", "push")
	if exit != exitUsage || stdout != "" || strings.Contains(stderr, "[y/N]") || !strings.HasSuffix(stderr, "next: oe config push --yes\n") {
		t.Fatalf("a script got a prompt in place of a text refusal: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}

	script.API = productionActivation(t, "headless-chat", true)
	exit, _, stderr = run(t, script, "config", "push", "--yes")
	if exit != exitPersonAction || !strings.Contains(stderr, cardSetupURL) {
		t.Fatalf("a script did not get the setup page: exit=%d stderr=%q", exit, stderr)
	}

	script.API = deviceLogin()
	exit, stdout, _ = run(t, script, "auth", "login")
	if exit != 0 || !strings.Contains(stdout, "https://login.example/device") {
		t.Fatalf("a script login hid the URL: exit=%d %q", exit, stdout)
	}
	if len(browser.opened) != 0 {
		t.Fatalf("a script opened a browser: %v", browser.opened)
	}
}

func TestAgentAtATerminalNeverPrompts(t *testing.T) {
	directory := initializedProject(t, "terminal-chat")
	store := credential.NewMemory()
	storeCredential(t, store, "deploy:write")
	exit, stdout, _ := run(t, Dependencies{
		API: productionActivation(t, "terminal-chat", false), Store: store, WorkingDir: directory, In: unreadable{t},
		Getenv: environment(map[string]string{"OPENCODE": "1"}), Interactive: terminal,
	}, "config", "push")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "CONFIRMATION_REQUIRED" || failure.Next != "oe config push --yes" {
		t.Fatalf("an agent at a terminal was not refused without a prompt: exit=%d %s", exit, stdout)
	}
}

func TestLogoutRemovesTheStoredSession(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	exit, stdout, _ := run(t, Dependencies{Store: store, Getenv: func(string) string { return "" }}, "--json", "auth", "logout")
	if exit != 0 || decodeEvent(t, []byte(stdout)).Data["environmentCredential"] != false {
		t.Fatalf("logout failed: %s", stdout)
	}
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(profile); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("logout left the session stored: %v", err)
	}
	if exit, _, _ := run(t, Dependencies{Store: store}, "auth", "logout"); exit != 0 {
		t.Fatal("a second logout failed")
	}
}

// environment returns a Getenv that reads only values.
func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestAgentDefaultsToJSON(t *testing.T) {
	claudeCode := environment(map[string]string{"CLAUDECODE": "1"})
	exit, stdout, _ := run(t, Dependencies{Getenv: claudeCode}, "version")
	if exit != 0 || decodeEvent(t, []byte(stdout)).Data["version"] != Version {
		t.Fatalf("an agent did not get JSON by default: exit=%d %q", exit, stdout)
	}
	exit, stdout, stderr := run(t, Dependencies{Getenv: claudeCode}, "config", "push")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitFailure || stderr != "" || failure.Code != "CONFIG_NOT_FOUND" {
		t.Fatalf("an agent did not get the failure as JSON on stdout: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
	exit, stdout, _ = run(t, Dependencies{API: deviceLogin(), Getenv: claudeCode}, "--json-stream", "auth", "login")
	first, _, _ := strings.Cut(stdout, "\n")
	if exit != 0 || decodeEvent(t, []byte(first)).Status != "pending" {
		t.Fatalf("--json-stream under an agent wrote no pending event: exit=%d %q", exit, stdout)
	}
}

// TestProjectReadNamesTheProjectList proves that every read of a project that
// does not exist, or that the session cannot read, names oe project list. The
// control API refuses a slug that it cannot read with CONTROL_CONFLICT, so the
// project list decides between a project that is not found and a listed
// project that the service cannot read. That refusal keeps the code of the
// server and names the page that reports it. The code alone does not prove an
// inconsistent record, so the message makes that claim only for a refusal
// that a retry gets again.
func TestProjectReadNamesTheProjectList(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	conflict := &control.APIError{Status: 409, Code: "CONTROL_CONFLICT", Message: "The managed Relay project does not exist."}
	notFound := &control.APIError{Status: 404, Code: "PROJECT_NOT_FOUND", Message: "Relay project not found."}
	for _, test := range []struct {
		name, slug string
		refusal    *control.APIError
		listed     []string
		code       string
		exit       int
		next       string
	}{
		{"refused", "gone-chat", notFound, nil, "PROJECT_NOT_FOUND", exitFailure, "oe project list"},
		{"unknown", "gone-chat", conflict, []string{"other-chat"}, "PROJECT_NOT_FOUND", exitFailure, "oe project list"},
		{"invalid", "Bad_Slug", nil, nil, "PROJECT_INVALID", exitUsage, "oe project list"},
		{"too long", strings.Repeat("a", 64), nil, nil, "PROJECT_INVALID", exitUsage, "oe project list"},
		{"listed but unreadable", "broken-chat", conflict, []string{"broken-chat"}, "CONTROL_CONFLICT", exitFailure, ""},
	} {
		reads := 0
		api := &fakeAPI{
			getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
				reads++
				return control.Project{}, test.refusal
			},
			listProjects: func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error) {
				var projects []control.ProjectSummary
				for _, slug := range test.listed {
					projects = append(projects, control.ProjectSummary{Slug: slug})
				}
				return projects, nil
			},
		}
		for _, command := range []string{"show", "connection"} {
			exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", command, test.slug)
			failure := decodeEvent(t, []byte(stdout))
			if exit != test.exit || failure.Code != test.code || failure.Next != test.next || failure.Data["project"] != test.slug {
				t.Fatalf("%s project %s: exit=%d %s", test.name, command, exit, stdout)
			}
			if test.code == "CONTROL_CONFLICT" && (failure.Action.URL != reportURL || failure.Action.Reason != "report" ||
				failure.Data["listed"] != true || !strings.Contains(failure.Error, "The managed Relay project does not exist") ||
				!strings.Contains(failure.Error, "when a retry gets the same refusal, the service holds an inconsistent record")) {
				t.Fatalf("a listed project that the read refuses did not name the report page: %s", stdout)
			}
		}
		if test.code == "PROJECT_INVALID" && reads != 0 {
			t.Fatalf("%s: an invalid slug reached the control API", test.name)
		}
	}
}

// TestCommandFieldIsTheCommandPath proves that the command field of every
// result is the command path of the surface, for a success and for a failure
// of the same command, in every command group.
func TestCommandFieldIsTheCommandPath(t *testing.T) {
	var paths []string
	for _, spec := range commandSurface {
		for _, usage := range spec.Usage {
			path := commandPath(usage)
			words := strings.Fields(path)
			if got := envelopeCommand(words[0], append(words[1:], "--json", "extra")); got != path {
				t.Fatalf("a failure of %q names %q", usage, got)
			}
			paths = append(paths, path)
		}
	}
	want := []string{
		"new", "auth login", "auth status", "auth logout", "doctor", "link",
		"project list", "project show", "project connection", "config push", "config pull",
		"notifications status", "notifications setup ios", "notifications add-nse", "notifications verify ios",
		"notifications apple-filtering-request", "agent setup", "version", "help",
	}
	if !slices.Equal(paths, want) {
		t.Fatalf("the command paths are %q, want %q", paths, want)
	}

	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{
		getProject: func(_ context.Context, _ control.CredentialRequest, slug string) (control.Project, error) {
			return control.Project{Slug: slug, Writer: "config", Sandbox: projectEnvironment(sandboxRelayURL, "3")}, nil
		},
		listProjects: func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error) {
			return []control.ProjectSummary{{Slug: "path-chat"}}, nil
		},
		notifications: func(_ context.Context, _ control.CredentialRequest, _, environment string) (control.NotificationConfiguration, error) {
			return control.NotificationConfiguration{Environment: environment, ConfigurationVersion: 1}, nil
		},
	}
	directory := initializedProject(t, "path-chat")
	for _, test := range []struct {
		path    string
		success []string
		failure []string
	}{
		{"project list", []string{"project", "list"}, []string{"project", "list", "extra"}},
		{"project show", []string{"project", "show"}, []string{"project", "show", "Bad_Slug"}},
		{"project connection", []string{"project", "connection"}, []string{"project", "connection", "Bad_Slug"}},
		{"notifications status", []string{"notifications", "status"}, []string{"notifications", "status", "extra"}},
		{"notifications apple-filtering-request", []string{"notifications", "apple-filtering-request"}, []string{"notifications", "apple-filtering-request", "extra"}},
	} {
		exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, append([]string{"--json"}, test.success...)...)
		if result := decodeEvent(t, []byte(stdout)); exit != 0 || result.Command != test.path {
			t.Fatalf("a success of %s: exit=%d %s", test.path, exit, stdout)
		}
		exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, append([]string{"--json"}, test.failure...)...)
		if result := decodeEvent(t, []byte(stdout)); exit == 0 || result.Command != test.path {
			t.Fatalf("a failure of %s: exit=%d %s", test.path, exit, stdout)
		}
	}
}
