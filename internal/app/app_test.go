package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
)

const (
	sandboxRelayURL    = "https://sandbox.relay.open-e2ee.dev/signal/v1/connection/pk_sandbox_public"
	productionRelayURL = "https://relay.open-e2ee.dev/signal/v1/connection/pk_prod_public"
)

func TestAuthLoginStoresBrowserCredentialWithoutPrintingToken(t *testing.T) {
	store := credential.NewMemory()
	api := &fakeAPI{
		startAuthorization: func(context.Context, control.AuthorizationRequest) (control.Authorization, error) {
			return control.Authorization{DeviceCode: "authorization", VerificationURL: "https://login.example/device", UserCode: "ABCD", IntervalSeconds: 1}, nil
		},
		pollAuthorization: func(context.Context, control.Authorization) (control.Token, error) {
			return control.Token{AccessToken: "browser-secret"}, nil
		},
		terms: func(context.Context, control.CredentialRequest) (control.Terms, error) {
			return control.Terms{State: control.TermsAccepted, CanAccept: true}, nil
		},
		session: acmeSession,
	}
	var stdout, stderr bytes.Buffer
	var opened string
	exit := Run(context.Background(), []string{"--json", "auth", "login"}, Dependencies{
		API: api, Store: store, Out: &stdout, Err: &stderr, WorkingDir: t.TempDir(),
		Interactive: func() bool { return true },
		OpenURL:     func(target string) error { opened = target; return nil },
		Sleep:       func(context.Context, time.Duration) error { return nil },
	})
	if exit != 0 {
		t.Fatalf("login failed: %s", stdout.String())
	}
	if opened != "https://login.example/device" {
		t.Fatalf("browser did not open: %q", opened)
	}
	if strings.Contains(stdout.String(), "browser-secret") || strings.Contains(stderr.String(), "browser-secret") {
		t.Fatal("login output exposed the access token")
	}
	pending, result, _ := strings.Cut(stdout.String(), "\n")
	if event := decodeEvent(t, []byte(pending)); event.Status != "pending" || event.Action.URL != "https://login.example/device" || event.Data["userCode"] != "ABCD" {
		t.Fatalf("JSON login hid the prompt from the person who approves it: %s", stdout.String())
	}
	if event := decodeEvent(t, []byte(result)); event.Status != "ok" {
		t.Fatalf("JSON login did not end in one success document: %s", stdout.String())
	}
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(profile)
	if err != nil || stored.AccessToken != "browser-secret" {
		t.Fatalf("credential was not stored: %#v, %v", stored, err)
	}
}

func TestNewWritesTheNextJSVariable(t *testing.T) {
	directory := emptyDirectory(t, "next-chat")
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":{"next":"16.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:write")
	api := &fakeAPI{bootstrapSandbox: func(context.Context, control.CredentialRequest, control.BootstrapRequest) (control.Bootstrap, error) {
		return control.Bootstrap{Created: true, ProjectSlug: "next-chat", Writer: "config", Environment: "sandbox", SandboxRelayURL: sandboxRelayURL}, nil
	}}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "new")
	connection, _ := decodeEvent(t, []byte(stdout)).Data["connection"].(map[string]any)
	if exit != 0 || connection["variable"] != "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL" || connection["framework"] != "Next.js" {
		t.Fatalf("new did not name the Next.js variable: %s", stdout)
	}
	environment, err := os.ReadFile(filepath.Join(directory, ".env.local"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(environment), "\nNEXT_PUBLIC_OPEN_E2EE_RELAY_URL="+sandboxRelayURL+"\n") || strings.Contains(string(environment), "\nOPEN_E2EE_RELAY_URL=") {
		t.Fatalf("a Next.js client cannot read the Sandbox connection: %q", environment)
	}
}

func TestPushAndConnectionNameTheExpoVariable(t *testing.T) {
	directory := initializedProject(t, "expo-chat")
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":{"expo":"55.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	console := newPushConsole(t, "expo-chat")
	console.activeProduction(86_400)
	dependencies := pushDependencies(t, console, directory)
	exit, stdout, _ := run(t, dependencies, "--json", "config", "push", "--yes")
	pushed := decodeEvent(t, []byte(stdout))
	connection, _ := pushed.Data["connection"].(map[string]any)
	if exit != 0 || connection["variable"] != "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL" || !strings.Contains(pushed.Message, "Wrote .env.production.local: EXPO_PUBLIC_OPEN_E2EE_RELAY_URL.") {
		t.Fatalf("push did not name the Expo variable: %s", stdout)
	}
	environment, err := os.ReadFile(filepath.Join(directory, ".env.production.local"))
	if err != nil || !strings.Contains(string(environment), "\nEXPO_PUBLIC_OPEN_E2EE_RELAY_URL="+productionRelayURL+"\n") {
		t.Fatalf("production environment has no Expo variable: %q %v", environment, err)
	}
	exit, stdout, _ = run(t, dependencies, "--json", "project", "connection", "--env", "production")
	if connection := decodeEvent(t, []byte(stdout)); exit != 0 || connection.Data["variable"] != "EXPO_PUBLIC_OPEN_E2EE_RELAY_URL" {
		t.Fatalf("connection did not name the Expo variable: %s", stdout)
	}
}

func TestUnreadablePackageJSONFailsBeforeRemoteMutation(t *testing.T) {
	directory := emptyDirectory(t, "broken-chat")
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":`), 0o644); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:write")
	api := &fakeAPI{bootstrapSandbox: func(context.Context, control.CredentialRequest, control.BootstrapRequest) (control.Bootstrap, error) {
		t.Fatal("new changed the server before it could choose the variable")
		return control.Bootstrap{}, nil
	}}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "new")
	if exit == 0 || !strings.Contains(stdout, "package.json") {
		t.Fatalf("an unreadable package.json did not stop oe new: %s", stdout)
	}
	for _, file := range []string{".env.local", config.Filename} {
		if _, err := os.Stat(filepath.Join(directory, file)); !os.IsNotExist(err) {
			t.Fatalf("new wrote %s: %v", file, err)
		}
	}
}

func TestDoctorReportsSafeConnectionOriginAndRefusesProjectDrift(t *testing.T) {
	directory := initializedProject(t, "doctor-chat")
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, sandboxRelayURL); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "doctor-chat", Sandbox: projectEnvironment(sandboxRelayURL, "1")}, nil
	}}
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != sandboxRelayURL {
			t.Fatalf("doctor requested an unexpected URL: %s", request.URL)
		}
		return &http.Response{Body: io.NopCloser(strings.NewReader(`{"schemaVersion":1}`)), Header: make(http.Header), StatusCode: http.StatusOK}, nil
	})}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--env", "sandbox", "--json", "doctor"}, Dependencies{API: api, HTTP: httpClient, Store: store, Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: directory})
	if exit != 0 || !strings.Contains(stdout.String(), `"relayOrigin":"https://sandbox.relay.open-e2ee.dev"`) || strings.Contains(stdout.String(), "pk_sandbox_public") {
		t.Fatalf("doctor did not report only the safe origin: %s", stdout.String())
	}
	api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "doctor-chat", Sandbox: projectEnvironment("https://sandbox.relay.open-e2ee.dev/signal/v1/connection/another-project", "1")}, nil
	}
	stdout.Reset()
	exit = Run(context.Background(), []string{"--env", "sandbox", "--json", "doctor"}, Dependencies{API: api, HTTP: httpClient, Store: store, Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: directory})
	if exit == 0 || !strings.Contains(stdout.String(), "stale or belongs to another project") || strings.Contains(stdout.String(), "pk_sandbox_public") {
		t.Fatalf("doctor did not refuse project drift safely: %s", stdout.String())
	}
}

func TestNotificationsSetupStagesLocalAndRemoteProfile(t *testing.T) {
	directory := initializedProject(t, "notification-chat")
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":{"expo":"55.0.0","expo-notifications":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "app.json"), []byte(`{"expo":{"ios":{"bundleIdentifier":"dev.open_e2ee.chat"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:write")
	wrote := false
	api := &fakeAPI{
		notifications: func(_ context.Context, request control.CredentialRequest, project, environment string) (control.NotificationConfiguration, error) {
			if request.AccessToken == "" || project != "notification-chat" || environment != "sandbox" {
				t.Fatalf("notification read lost authority: %#v %s %s", request, project, environment)
			}
			return control.NotificationConfiguration{
				AllowedProfiles:      []control.NotificationProfile{control.NotificationBackgroundOnly},
				ConfigurationVersion: 2, Environment: "sandbox", Providers: []string{"apns"},
			}, nil
		},
		configureNotifications: func(_ context.Context, request control.CredentialRequest, project string, input control.NotificationConfigurationRequest) (control.NotificationConfiguration, error) {
			wrote = true
			if request.OperationID == "" || project != "notification-chat" || input.Environment != "sandbox" || input.ExpectedConfigurationVersion != 2 || !hasNotificationProfile(input.AllowedProfiles, control.NotificationVisibleAlert) {
				t.Fatalf("notification write lost concurrency contract: %#v %#v", request, input)
			}
			return control.NotificationConfiguration{AllowedProfiles: input.AllowedProfiles, ConfigurationVersion: 3, Environment: "sandbox", Providers: []string{"apns"}}, nil
		},
	}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "notifications", "setup", "ios", "--profile", "visible-alert"}, Dependencies{
		API: api, Store: store, Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: directory,
	})
	if exit != 0 || !wrote || !strings.Contains(stdout.String(), "best-effort wake") {
		t.Fatalf("notification setup failed: wrote=%v output=%s", wrote, stdout.String())
	}
	configured, err := os.ReadFile(filepath.Join(directory, "app.json"))
	if err != nil || !strings.Contains(string(configured), "remote-notification") || !strings.Contains(string(configured), "expo-notifications") {
		t.Fatalf("local Expo configuration was not staged: %s %v", configured, err)
	}
}

func TestNotificationsFilteringRequestDoesNotClaimActivation(t *testing.T) {
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "notifications", "apple-filtering-request"}, Dependencies{
		API: &fakeAPI{}, Store: credential.NewMemory(), Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: t.TempDir(),
	})
	if exit != 0 || !strings.Contains(stdout.String(), "does not improve APNs delivery") || !strings.Contains(stdout.String(), "physical-device suppression evidence") {
		t.Fatalf("filtering guidance is unsafe or incomplete: %s", stdout.String())
	}
}

func TestConsoleWriterFailsBeforeRemoteMutation(t *testing.T) {
	directory := initializedProject(t, "console-chat")
	store := credential.NewMemory()
	storeCredential(t, store, "deploy:write")
	api := &fakeAPI{
		getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{Slug: "console-chat", Writer: "console", Production: projectEnvironment(productionRelayURL, "7")}, nil
		},
		plan: func(context.Context, control.CredentialRequest, control.PlanRequest) (control.Plan, error) {
			t.Fatal("console-first project reached the plan")
			return control.Plan{}, nil
		},
		deploy: func(context.Context, control.CredentialRequest, control.DeployRequest) (control.Deployment, error) {
			t.Fatal("console-first project reached deploy mutation")
			return control.Deployment{}, nil
		},
	}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "config", "push", "--yes"}, Dependencies{API: api, Store: store, Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: directory})
	if exit == 0 || decodeEvent(t, stdout.Bytes()).Code != "CONSOLE_WRITER" {
		t.Fatalf("console writer was not rejected: %s", stdout.String())
	}
}

func TestConfigRefusalsKeepTheirCodes(t *testing.T) {
	directory := initializedProject(t, "refusal-chat")
	path := filepath.Join(directory, config.Filename)
	if err := os.WriteFile(path, []byte("export const relay = {};\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	exit, stdout, _ := run(t, Dependencies{WorkingDir: directory}, "--json", "doctor")
	if refusal := decodeEvent(t, []byte(stdout)); exit != exitFailure || refusal.Code != "CONFIG_INVALID" || refusal.Next != "" || !strings.Contains(refusal.Error, "has no default export") {
		t.Fatalf("a config with no default export was not CONFIG_INVALID: exit=%d %s", exit, stdout)
	}

	source := strings.Replace(string(mustRead(t, filepath.Join(initializedProject(t, "old-chat"), config.Filename))), `project: "old-chat"`, `project: ["old", "chat"].join("-")`, 1)
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "new-chat", Writer: "config"}, nil
	}}
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "new-chat", "--yes")
	refusal := decodeEvent(t, []byte(stdout))
	edits, _ := refusal.Data["edits"].([]any)
	var edit map[string]any
	if len(edits) == 1 {
		edit, _ = edits[0].(map[string]any)
	}
	if exit != exitPersonAction || refusal.Code != "CONFIG_EDIT_REQUIRED" || edit["path"] != "project" || edit["currentExpression"] != `["old", "chat"].join("-")` || edit["newValue"] != "new-chat" {
		t.Fatalf("a computed project was not CONFIG_EDIT_REQUIRED with the edit: exit=%d %s", exit, stdout)
	}
	if after := mustRead(t, path); string(after) != source {
		t.Fatalf("CONFIG_EDIT_REQUIRED changed the file: %q", after)
	}

	t.Setenv("PATH", t.TempDir())
	exit, stdout, _ = run(t, Dependencies{WorkingDir: directory}, "--json", "doctor")
	if refusal := decodeEvent(t, []byte(stdout)); exit != exitPersonAction || refusal.Code != "NODE_REQUIRED" || refusal.Next != "oe --json doctor" || refusal.Action.URL != "https://nodejs.org/en/download" {
		t.Fatalf("a missing node was not NODE_REQUIRED: exit=%d %s", exit, stdout)
	}
}

func TestPushToProductionRefusesAConfigWithoutProduction(t *testing.T) {
	directory := t.TempDir()
	value := config.New("sandbox-chat")
	value.Environments.Production = nil
	if err := config.Create(filepath.Join(directory, config.Filename), value); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "deploy:write")
	api := &fakeAPI{
		getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
			return control.Project{Slug: "sandbox-chat", Writer: "config"}, nil
		},
		plan: func(context.Context, control.CredentialRequest, control.PlanRequest) (control.Plan, error) {
			t.Fatal("a config without Production reached the plan")
			return control.Plan{}, nil
		},
	}
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "--env", "production", "config", "push", "--yes")
	if refusal := decodeEvent(t, []byte(stdout)); exit != exitUsage || refusal.Code != "USAGE_ERROR" || !strings.Contains(refusal.Error, "has no Production section") {
		t.Fatalf("a Production push without a Production section was not refused: exit=%d %s", exit, stdout)
	}
}

func TestRelayEnvironmentRemovalCannotLeaveAnotherProjectConnection(t *testing.T) {
	directory := t.TempDir()
	filename := ".env.production.local"
	if err := writeRelayEnvironment(directory, filename, envfile.DefaultVariable, productionRelayURL); err != nil {
		t.Fatal(err)
	}
	if err := writeRelayEnvironment(directory, filename, envfile.DefaultVariable, ""); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, filename))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "OPEN_E2EE_RELAY_URL=") || strings.Contains(string(contents), productionRelayURL) {
		t.Fatalf("removed environment retained a Relay connection: %q", contents)
	}
	if !strings.Contains(string(contents), "not configured for this environment") {
		t.Fatalf("removed environment has no exact handoff: %q", contents)
	}
}

func TestValidatePlanRejectsCrossBoundaryResponses(t *testing.T) {
	project := control.Project{Slug: "project-one", Production: projectEnvironment(productionRelayURL, "1")}
	valid := control.Plan{ID: "plan-1", ProjectSlug: "project-one", Environment: "production", ExpectedRevision: "1"}
	if err := validatePlan(valid, project, "production"); err != nil {
		t.Fatal(err)
	}
	for name, changed := range map[string]control.Plan{
		"missing id":        {ProjectSlug: "project-one", Environment: "production", ExpectedRevision: "1"},
		"wrong project":     {ID: "plan-1", ProjectSlug: "project-two", Environment: "production", ExpectedRevision: "1"},
		"wrong environment": {ID: "plan-1", ProjectSlug: "project-one", Environment: "sandbox", ExpectedRevision: "1"},
		"stale revision":    {ID: "plan-1", ProjectSlug: "project-one", Environment: "production", ExpectedRevision: "0"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePlan(changed, project, "production"); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestJSONOutputIsOneDocumentAfterAutomaticLogin(t *testing.T) {
	directory := emptyDirectory(t, "login-dev")
	api := &fakeAPI{
		startAuthorization: func(context.Context, control.AuthorizationRequest) (control.Authorization, error) {
			return control.Authorization{DeviceCode: "auth", VerificationURL: "https://login.example", UserCode: "CODE"}, nil
		},
		pollAuthorization: func(context.Context, control.Authorization) (control.Token, error) {
			return control.Token{AccessToken: "token"}, nil
		},
		bootstrapSandbox: func(context.Context, control.CredentialRequest, control.BootstrapRequest) (control.Bootstrap, error) {
			return control.Bootstrap{Created: true, ProjectSlug: "login-dev", Writer: "config", Environment: "sandbox", SandboxRelayURL: sandboxRelayURL}, nil
		},
	}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "new"}, Dependencies{
		API: api, Store: credential.NewMemory(), Out: &stdout, Err: &bytes.Buffer{}, WorkingDir: directory,
		Interactive: terminal, Getenv: environment(nil),
		OpenURL: func(string) error { return nil }, Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if exit != 0 {
		t.Fatalf("automatic login failed: %s", stdout.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var first map[string]any
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	var second map[string]any
	if err := decoder.Decode(&second); !errors.Is(err, io.EOF) {
		t.Fatalf("JSON mode emitted multiple documents: %s", stdout.String())
	}
}

func TestTransientRefreshKeepsAStillValidSession(t *testing.T) {
	directory := initializedProject(t, "refresh-chat")
	store := credential.NewMemory()
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := store.Set(profile, credential.Credential{
		AccessToken: "still-valid-token", ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
		RefreshToken: "refresh-token",
	}); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{
		refreshAuthorization: func(context.Context, string) (control.Token, error) {
			return control.Token{}, errors.New("temporary WorkOS failure")
		},
		getProject: func(_ context.Context, request control.CredentialRequest, _ string) (control.Project, error) {
			if request.AccessToken != "still-valid-token" {
				t.Fatalf("request did not retain the current session: %#v", request)
			}
			return control.Project{Slug: "refresh-chat", Writer: "config"}, nil
		},
	}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "project", "show"}, Dependencies{
		API: api, Store: store, Out: &stdout, Err: &bytes.Buffer{},
		WorkingDir: directory, Now: func() time.Time { return now },
	})
	if exit != 0 {
		t.Fatalf("transient refresh rejected a valid session: %s", stdout.String())
	}
}

func TestTerminalRefreshRemovesTheExpiredSession(t *testing.T) {
	directory := initializedProject(t, "expired-chat")
	store := credential.NewMemory()
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := store.Set(profile, credential.Credential{
		AccessToken: "expired-token", ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339),
		RefreshToken: "expired-refresh",
	}); err != nil {
		t.Fatal(err)
	}
	api := &fakeAPI{refreshAuthorization: func(context.Context, string) (control.Token, error) {
		return control.Token{}, control.ErrSessionExpired
	}}
	var stdout bytes.Buffer
	exit := Run(context.Background(), []string{"--json", "project", "show"}, Dependencies{
		API: api, Store: store, Out: &stdout, Err: &bytes.Buffer{},
		WorkingDir: directory, Now: func() time.Time { return now },
	})
	if event := decodeEvent(t, stdout.Bytes()); exit != exitAuthentication || event.Code != "SESSION_EXPIRED" || event.Next != "oe auth login" {
		t.Fatalf("terminal refresh did not require login: exit=%d output=%s", exit, stdout.String())
	}
	if _, err := store.Get(profile); !errors.Is(err, credential.ErrNotFound) {
		t.Fatalf("terminal session remained stored: %v", err)
	}
}

func projectEnvironment(relayURL, revision string) *control.ProjectEnvironment {
	return &control.ProjectEnvironment{
		AttachmentRetentionSeconds: 86_400,
		DeliveryRetentionSeconds:   86_400,
		RelayReceipts:              new(true),
		RelayURL:                   relayURL,
		Revision:                   revision,
	}
}

func initializedProject(t *testing.T, project string) string {
	t.Helper()
	directory := t.TempDir()
	if err := config.Create(filepath.Join(directory, config.Filename), config.New(project)); err != nil {
		t.Fatal(err)
	}
	return directory
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func storeCredential(t *testing.T, store credential.Store, scopes ...string) {
	t.Helper()
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(profile, credential.Credential{AccessToken: "test-token", Scopes: scopes}); err != nil {
		t.Fatal(err)
	}
}

type fakeAPI struct {
	startAuthorization     func(context.Context, control.AuthorizationRequest) (control.Authorization, error)
	pollAuthorization      func(context.Context, control.Authorization) (control.Token, error)
	refreshAuthorization   func(context.Context, string) (control.Token, error)
	bootstrapSandbox       func(context.Context, control.CredentialRequest, control.BootstrapRequest) (control.Bootstrap, error)
	activation             func(context.Context, control.CredentialRequest, string) (control.Activation, error)
	plan                   func(context.Context, control.CredentialRequest, control.PlanRequest) (control.Plan, error)
	deploy                 func(context.Context, control.CredentialRequest, control.DeployRequest) (control.Deployment, error)
	getProject             func(context.Context, control.CredentialRequest, string) (control.Project, error)
	listProjects           func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error)
	notifications          func(context.Context, control.CredentialRequest, string, string) (control.NotificationConfiguration, error)
	configureNotifications func(context.Context, control.CredentialRequest, string, control.NotificationConfigurationRequest) (control.NotificationConfiguration, error)
	terms                  func(context.Context, control.CredentialRequest) (control.Terms, error)
	acceptTerms            func(context.Context, control.CredentialRequest, control.TermsAcceptanceRequest) (control.TermsAcceptance, error)
	session                func(context.Context, control.CredentialRequest) (control.Session, error)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func (f *fakeAPI) Health(context.Context) error { return nil }
func (f *fakeAPI) StartAuthorization(ctx context.Context, request control.AuthorizationRequest) (control.Authorization, error) {
	if f.startAuthorization == nil {
		return control.Authorization{}, errors.New("unexpected StartAuthorization")
	}
	return f.startAuthorization(ctx, request)
}
func (f *fakeAPI) PollAuthorization(ctx context.Context, authorization control.Authorization) (control.Token, error) {
	if f.pollAuthorization == nil {
		return control.Token{}, errors.New("unexpected PollAuthorization")
	}
	return f.pollAuthorization(ctx, authorization)
}
func (f *fakeAPI) RefreshAuthorization(ctx context.Context, refreshToken string) (control.Token, error) {
	if f.refreshAuthorization == nil {
		return control.Token{}, errors.New("unexpected RefreshAuthorization")
	}
	return f.refreshAuthorization(ctx, refreshToken)
}
func (f *fakeAPI) BootstrapSandbox(ctx context.Context, credential control.CredentialRequest, request control.BootstrapRequest) (control.Bootstrap, error) {
	if f.bootstrapSandbox == nil {
		return control.Bootstrap{}, errors.New("unexpected BootstrapSandbox")
	}
	return f.bootstrapSandbox(ctx, credential, request)
}
func (f *fakeAPI) Activation(ctx context.Context, credential control.CredentialRequest, project string) (control.Activation, error) {
	if f.activation == nil {
		return control.Activation{}, errors.New("unexpected Activation")
	}
	return f.activation(ctx, credential, project)
}
func (f *fakeAPI) Plan(ctx context.Context, credential control.CredentialRequest, request control.PlanRequest) (control.Plan, error) {
	if f.plan == nil {
		return control.Plan{}, errors.New("unexpected Plan")
	}
	return f.plan(ctx, credential, request)
}
func (f *fakeAPI) Deploy(ctx context.Context, credential control.CredentialRequest, request control.DeployRequest) (control.Deployment, error) {
	if f.deploy == nil {
		return control.Deployment{}, errors.New("unexpected Deploy")
	}
	return f.deploy(ctx, credential, request)
}
func (f *fakeAPI) GetProject(ctx context.Context, credential control.CredentialRequest, project string) (control.Project, error) {
	if f.getProject == nil {
		return control.Project{}, errors.New("unexpected GetProject")
	}
	return f.getProject(ctx, credential, project)
}
func (f *fakeAPI) ListProjects(ctx context.Context, credential control.CredentialRequest) ([]control.ProjectSummary, error) {
	if f.listProjects == nil {
		return nil, errors.New("unexpected ListProjects")
	}
	return f.listProjects(ctx, credential)
}
func (f *fakeAPI) Notifications(ctx context.Context, credential control.CredentialRequest, project, environment string) (control.NotificationConfiguration, error) {
	if f.notifications == nil {
		return control.NotificationConfiguration{}, errors.New("unexpected Notifications")
	}
	return f.notifications(ctx, credential, project, environment)
}
func (f *fakeAPI) ConfigureNotifications(ctx context.Context, credential control.CredentialRequest, project string, request control.NotificationConfigurationRequest) (control.NotificationConfiguration, error) {
	if f.configureNotifications == nil {
		return control.NotificationConfiguration{}, errors.New("unexpected ConfigureNotifications")
	}
	return f.configureNotifications(ctx, credential, project, request)
}
func (f *fakeAPI) Terms(ctx context.Context, credential control.CredentialRequest) (control.Terms, error) {
	if f.terms == nil {
		return control.Terms{}, errors.New("unexpected Terms")
	}
	return f.terms(ctx, credential)
}
func (f *fakeAPI) AcceptTerms(ctx context.Context, credential control.CredentialRequest, request control.TermsAcceptanceRequest) (control.TermsAcceptance, error) {
	if f.acceptTerms == nil {
		return control.TermsAcceptance{}, errors.New("unexpected AcceptTerms")
	}
	return f.acceptTerms(ctx, credential, request)
}

func (f *fakeAPI) Session(ctx context.Context, credential control.CredentialRequest) (control.Session, error) {
	if f.session == nil {
		return control.Session{}, errors.New("unexpected Session")
	}
	return f.session(ctx, credential)
}

func TestLoginPromptMatchesTheVerificationPage(t *testing.T) {
	for _, test := range []struct {
		name          string
		authorization control.Authorization
		want          string
	}{
		{"both URLs", control.Authorization{
			VerificationURL: "https://login.example/device?user_code=ABCD-EFGH", BareVerificationURL: "https://login.example/device",
			UserCode: "ABCD-EFGH", CodeInURL: true,
		}, "Open https://login.example/device?user_code=ABCD-EFGH and confirm that it shows the code ABCD-EFGH.\n" +
			"On another device, go to https://login.example/device and enter ABCD-EFGH."},
		{"complete URL only", control.Authorization{
			VerificationURL: "https://login.example/device?user_code=ABCD-EFGH", UserCode: "ABCD-EFGH", CodeInURL: true,
		}, "Open https://login.example/device?user_code=ABCD-EFGH and confirm that it shows the code ABCD-EFGH."},
		{"bare URL only", control.Authorization{
			VerificationURL: "https://login.example/device", BareVerificationURL: "https://login.example/device", UserCode: "ABCD-EFGH",
		}, "Open https://login.example/device and enter the code ABCD-EFGH."},
	} {
		if got := loginPrompt(test.authorization); got != test.want {
			t.Fatalf("%s prompt: %q, want %q", test.name, got, test.want)
		}
	}
}
