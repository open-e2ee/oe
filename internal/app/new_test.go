package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

// newControl is a control API that answers POST /v1/projects/bootstrap with
// respond, and records the idempotency key, the bearer token, and the body of
// each call. It lists the projects in listed.
type newControl struct {
	api     control.API
	mux     *http.ServeMux
	mu      sync.Mutex
	keys    []string
	tokens  []string
	bodies  []map[string]any
	listed  []string
	respond func(call int, body map[string]any) (int, string)
}

func startNewControl(t *testing.T, respond func(call int, body map[string]any) (int, string)) *newControl {
	t.Helper()
	mux := http.NewServeMux()
	server := &newControl{respond: respond, mux: mux}
	mux.HandleFunc("POST /v1/projects/bootstrap", func(response http.ResponseWriter, request *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode the bootstrap body: %v", err)
		}
		server.mu.Lock()
		server.keys = append(server.keys, request.Header.Get("Idempotency-Key"))
		server.tokens = append(server.tokens, request.Header.Get("Authorization"))
		server.bodies = append(server.bodies, body)
		call := len(server.bodies)
		server.mu.Unlock()
		status, answer := server.respond(call, body)
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		io.WriteString(response, answer)
	})
	mux.HandleFunc("GET /v1/projects", func(response http.ResponseWriter, _ *http.Request) {
		server.mu.Lock()
		projects := []control.ProjectSummary{}
		for _, slug := range server.listed {
			projects = append(projects, control.ProjectSummary{Slug: slug, Name: slug, Product: "signal-relay"})
		}
		server.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(projects)
	})
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	api, err := control.New(httpServer.URL, httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	server.api = api
	return server
}

func (s *newControl) calls() ([]string, []string, []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...), append([]string(nil), s.tokens...), append([]map[string]any(nil), s.bodies...)
}

// created answers a new project with its Sandbox environment.
func created(call int, body map[string]any) (int, string) {
	return http.StatusOK, fmt.Sprintf(`{"created":true,"project":%q,"writer":"config","revision":"1","environment":"sandbox","sandboxRelayUrl":%q}`,
		body["project"], sandboxRelayURL)
}

// never fails the test when oe new calls the control API.
func never(t *testing.T) func(int, map[string]any) (int, string) {
	return func(int, map[string]any) (int, string) {
		t.Errorf("oe new called the control API")
		return http.StatusInternalServerError, `{"code":"UNEXPECTED"}`
	}
}

// entries lists the names in directory.
func entries(t *testing.T, directory string) []string {
	t.Helper()
	listed, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range listed {
		names = append(names, entry.Name())
	}
	return names
}

func storeSession(t *testing.T, store credential.Store, token string) {
	t.Helper()
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(profile, credential.Credential{AccessToken: token, Scopes: []string{"project:write"}}); err != nil {
		t.Fatal(err)
	}
}

// emptyDirectory is a new directory named name, so the slug of its name is
// known.
func emptyDirectory(t *testing.T, name string) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestNewCreatesSandboxAndWritesTheFiles(t *testing.T) {
	server := startNewControl(t, created)
	store := credential.NewMemory()
	token := sessionToken()
	storeSession(t, store, token)
	directory := emptyDirectory(t, "Acme Chat")

	exit, stdout, stderr := run(t, Dependencies{
		API: server.api, Store: store, WorkingDir: directory, Getenv: environment(nil),
	}, "--json", "new")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Command != "new" || result.Next != "oe doctor --wait" {
		t.Fatalf("oe new failed: exit=%d %s %s", exit, stdout, stderr)
	}
	if result.Data["project"] != "acme-chat" || result.Data["product"] != "signal-relay" {
		t.Fatalf("oe new reported the wrong project: %s", stdout)
	}
	environments, _ := result.Data["environments"].(map[string]any)
	sandbox, _ := environments["sandbox"].(map[string]any)
	if sandbox["state"] != "active" || sandbox["revision"] != "1" {
		t.Fatalf("oe new did not report the active Sandbox: %s", stdout)
	}

	keys, tokens, bodies := server.calls()
	if len(bodies) != 1 {
		t.Fatalf("oe new made %d bootstrap calls, want 1", len(bodies))
	}
	body := bodies[0]
	policy, _ := body["policy"].(map[string]any)
	if body["project"] != "acme-chat" || body["writer"] != "config" ||
		policy["attachmentRetentionSeconds"] != float64(86_400) || policy["deliveryTtlSeconds"] != float64(86_400) {
		t.Fatalf("oe new sent the wrong bootstrap: %v", body)
	}
	if !strings.HasPrefix(keys[0], "oe_new_") || tokens[0] != "Bearer "+token {
		t.Fatalf("oe new sent key %q and authorization %q", keys[0], tokens[0])
	}

	configSource := string(mustRead(t, filepath.Join(directory, "open-e2ee.config.ts")))
	if !strings.Contains(configSource, `project: "acme-chat"`) || !strings.Contains(configSource, "sandbox: {") || strings.Contains(configSource, "production") {
		t.Fatalf("oe new wrote the wrong config:\n%s", configSource)
	}
	if env := string(mustRead(t, filepath.Join(directory, ".env.local"))); !strings.HasSuffix(env, "\nOPEN_E2EE_RELAY_URL="+sandboxRelayURL+"\n") {
		t.Fatalf("oe new wrote the wrong .env.local: %q", env)
	}
	ignored := string(mustRead(t, filepath.Join(directory, ".gitignore")))
	if !strings.Contains(ignored, ".env.local\n") || !strings.Contains(ignored, ".open-e2ee.lock\n") {
		t.Fatalf("oe new did not ignore .env.local and the lock file: %q", ignored)
	}
	if _, err := os.Stat(filepath.Join(directory, "package.json")); !os.IsNotExist(err) {
		t.Fatalf("oe new created a package.json: %v", err)
	}
}

func TestNewInASetUpDirectoryIsAlreadySetUp(t *testing.T) {
	root := initializedProject(t, "set-chat")
	source := mustRead(t, filepath.Join(root, config.Filename))
	directory := filepath.Join(root, "web")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	server := startNewControl(t, never(t))

	for _, dependencies := range []Dependencies{
		{API: server.api, Store: store, WorkingDir: root},
		{API: server.api, Store: store, WorkingDir: directory},
	} {
		exit, stdout, _ := run(t, dependencies, "--json", "new", "--project", "other-chat")
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitUsage || failure.Code != "ALREADY_SET_UP" || failure.Next != "oe link" ||
			failure.Data["project"] != "set-chat" || failure.Data["config"] != filepath.Join(root, config.Filename) {
			t.Fatalf("oe new in %s was not ALREADY_SET_UP: exit=%d %s", dependencies.WorkingDir, exit, stdout)
		}
	}
	if names := entries(t, directory); len(names) != 0 {
		t.Fatalf("oe new wrote %v in a set-up directory", names)
	}
	if after := mustRead(t, filepath.Join(root, config.Filename)); !bytes.Equal(after, source) {
		t.Fatalf("oe new changed the config:\n%s", after)
	}
}

func TestNewOnAnExistingProjectIsProjectExistsAndNeverLinks(t *testing.T) {
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	for name, test := range map[string]struct {
		status  int
		answer  string
		code    string
		exit    int
		message string
	}{
		"same organization": {
			http.StatusOK, `{"created":false,"project":"taken-chat","writer":"config"}`,
			"PROJECT_EXISTS", exitUsage, "Project taken-chat already exists in your organization. Run oe new --project taken-chat-2 to create a project with another slug, or run oe link taken-chat to use the existing project.",
		},
		"other organization": {
			http.StatusNotFound, `{"code":"PROJECT_NOT_FOUND","message":"Project not found."}`,
			"PROJECT_NOT_FOUND", exitFailure, "This account cannot create a project named taken-chat. Choose another name.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := startNewControl(t, func(int, map[string]any) (int, string) { return test.status, test.answer })
			directory := emptyDirectory(t, "taken-chat")
			exit, stdout, _ := run(t, Dependencies{API: server.api, Store: store, WorkingDir: directory}, "--json", "new")
			failure := decodeEvent(t, []byte(stdout))
			if exit != test.exit || failure.Code != test.code || failure.Error != test.message ||
				failure.Next != "oe new --project taken-chat-2" || strings.Contains(failure.Next, "link") {
				t.Fatalf("an existing project gave exit=%d %s", exit, stdout)
			}
			if names := entries(t, directory); len(names) != 0 {
				t.Fatalf("oe new wrote %v for an existing project", names)
			}
		})
	}
}

func TestNewRetryReplaysTheOperationID(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	server := startNewControl(t, func(call int, body map[string]any) (int, string) {
		if unavailable.Load() {
			return http.StatusServiceUnavailable, `{"code":"AUTHORITY_UNAVAILABLE","message":"The authority is unavailable."}`
		}
		return created(call, body)
	})
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	directory := emptyDirectory(t, "retry-chat")
	dependencies := Dependencies{API: server.api, Store: store, WorkingDir: directory, Getenv: environment(nil)}

	exit, stdout, _ := run(t, dependencies, "--json", "new")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitTemporary || failure.Next != "oe --json new" {
		t.Fatalf("an unavailable control API did not exit 6 with the same command: exit=%d %s", exit, stdout)
	}
	if names := entries(t, directory); len(names) != 0 {
		t.Fatalf("a failed create wrote %v", names)
	}
	unavailable.Store(false)
	if exit, stdout, _ := run(t, dependencies, "--json", "new"); exit != 0 {
		t.Fatalf("the retry failed: exit=%d %s", exit, stdout)
	}
	sum := sha256.Sum256([]byte("org_example\x00retry-chat\x00" + directory))
	want := "oe_new_" + hex.EncodeToString(sum[:])
	keys, _, _ := server.calls()
	if len(keys) < 2 {
		t.Fatalf("oe new made %d calls", len(keys))
	}
	for _, key := range keys {
		if key != want {
			t.Fatalf("the calls used keys %v, want each %s", keys, want)
		}
	}

	other := dependencies
	other.WorkingDir = emptyDirectory(t, "retry-chat")
	if exit, stdout, _ := run(t, other, "--json", "new"); exit != 0 {
		t.Fatalf("oe new in another directory failed: %s", stdout)
	}
	supplied := dependencies
	supplied.WorkingDir = emptyDirectory(t, "retry-chat")
	supplied.Getenv = environment(map[string]string{"OE_OPERATION_ID": "oe_supplied_key"})
	if exit, stdout, _ := run(t, supplied, "--json", "new"); exit != 0 {
		t.Fatalf("oe new with OE_OPERATION_ID failed: %s", stdout)
	}
	keys, _, _ = server.calls()
	if another, last := keys[len(keys)-2], keys[len(keys)-1]; another == want || !strings.HasPrefix(another, "oe_new_") || last != "oe_supplied_key" {
		t.Fatalf("another directory used %s and OE_OPERATION_ID gave %s", another, last)
	}
}

func TestNewUnderAnAgentWithoutTermsExitsFive(t *testing.T) {
	var accepted atomic.Bool
	server := startNewControl(t, func(call int, body map[string]any) (int, string) {
		if !accepted.Load() {
			return http.StatusForbidden, `{"code":"TERMS_REQUIRED","message":"Accept the OpenE2EE terms.","canAccept":true,"documents":[{"name":"Relay Service Terms","url":"https://open-e2ee.dev/legal/relay-terms","version":"2026-09-29"}]}`
		}
		return created(call, body)
	})
	var actors []string
	server.mux.HandleFunc("POST /v1/terms/acceptance", func(response http.ResponseWriter, request *http.Request) {
		var body control.TermsAcceptanceRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode the acceptance: %v", err)
		}
		server.mu.Lock()
		actors = append(actors, body.Actor)
		server.mu.Unlock()
		accepted.Store(true)
		io.WriteString(response, `{"state":"accepted","canAccept":true,"documents":[],"acceptedAt":"2026-09-30T00:00:00Z","changed":true}`)
	})
	server.mux.HandleFunc("GET /v1/auth/session", func(response http.ResponseWriter, _ *http.Request) {
		io.WriteString(response, `{"schemaVersion":1,"user":{"id":"user_example","email":"jane@example.com","name":null},"organization":{"id":"org_example","name":"Acme Inc."},"role":"admin","agent":null}`)
	})
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())

	// The agent has a terminal and an answer, so only the agent check stops
	// the prompt.
	directory := emptyDirectory(t, "terms-chat")
	exit, stdout, stderr := run(t, Dependencies{
		API: server.api, Store: store, WorkingDir: directory, Interactive: terminal,
		In: strings.NewReader("y\n"), Getenv: environment(map[string]string{"CLAUDECODE": "1"}),
	}, "new")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || failure.Code != "TERMS_REQUIRED" || failure.Next != "oe auth login --accept-terms" || failure.Data["retry"] != "oe new" || stderr != "" {
		t.Fatalf("an agent without terms did not exit 5: exit=%d %s %q", exit, stdout, stderr)
	}
	server.mu.Lock()
	accepts := len(actors)
	server.mu.Unlock()
	if names := entries(t, directory); len(names) != 0 || accepts != 0 {
		t.Fatalf("an agent without terms wrote %v or accepted %v", names, actors)
	}

	exit, stdout, stderr = run(t, Dependencies{
		API: server.api, Store: store, WorkingDir: directory, Interactive: terminal,
		In: strings.NewReader("y\n"), Getenv: environment(nil),
	}, "new")
	server.mu.Lock()
	accepters := strings.Join(actors, ",")
	server.mu.Unlock()
	if exit != 0 || !strings.Contains(stderr, "Accept these terms for Acme Inc.?") || accepters != "person" {
		t.Fatalf("a person could not accept the terms in oe new: exit=%d %q %q actors=%v", exit, stdout, stderr, actors)
	}
	keys, _, _ := server.calls()
	for _, key := range keys {
		if key != keys[0] {
			t.Fatalf("the retry after the terms used another key: %v", keys)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, config.Filename)); err != nil {
		t.Fatalf("oe new wrote no config after the terms: %v", err)
	}
}

func TestNewDryRunWritesNothing(t *testing.T) {
	directory := emptyDirectory(t, "dry-chat")
	files := map[string]string{
		"package.json": "{\n  \"name\": \"dry-chat\"\n}\n",
		".gitignore":   "node_modules\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	server := startNewControl(t, never(t))
	server.listed = []string{"other-chat"}
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())

	exit, stdout, _ := run(t, Dependencies{API: server.api, Store: store, WorkingDir: directory}, "--json", "new", "--dry-run", "--name", "Dry Chat")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["dryRun"] != true || result.Data["changed"] != false || result.Next != "oe new --project dry-chat --name 'Dry Chat'" {
		t.Fatalf("the dry run failed: exit=%d %s", exit, stdout)
	}
	planned, _ := json.Marshal(result.Data["files"])
	if string(planned) != `[{"change":"created","path":"open-e2ee.config.ts"},{"change":"created","path":".env.local"},{"change":"updated","path":".gitignore"},{"change":"updated","path":"package.json"}]` {
		t.Fatalf("the dry run planned %s", planned)
	}
	if names := entries(t, directory); strings.Join(names, ",") != ".gitignore,package.json" {
		t.Fatalf("the dry run wrote files: %v", names)
	}
	for name, contents := range files {
		if after := string(mustRead(t, filepath.Join(directory, name))); after != contents {
			t.Fatalf("the dry run changed %s: %q", name, after)
		}
	}
}

// TestNewDryRunReportsAnExistingProject proves that the dry run reports the
// plan of the real run: a slug that the organization already uses fails with
// the PROJECT_EXISTS of the real run, and the dry run does not say that it
// would create the project.
func TestNewDryRunReportsAnExistingProject(t *testing.T) {
	directory := emptyDirectory(t, "taken-chat")
	server := startNewControl(t, never(t))
	server.listed = []string{"taken-chat"}
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	exit, stdout, _ := run(t, Dependencies{API: server.api, Store: store, WorkingDir: directory}, "--json", "new", "--dry-run")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || failure.Code != "PROJECT_EXISTS" || failure.Next != "oe new --project taken-chat-2" ||
		strings.Contains(stdout, "would create") || !strings.Contains(failure.Error, failure.Next) {
		t.Fatalf("the dry run for an existing project gave exit=%d %s", exit, stdout)
	}
	if names := entries(t, directory); len(names) != 0 {
		t.Fatalf("the dry run wrote %v", names)
	}
}

func TestNewNeverPrintsTheConnectionURL(t *testing.T) {
	server := startNewControl(t, created)
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	for _, mode := range [][]string{{}, {"--json"}, {"--json-stream"}} {
		directory := emptyDirectory(t, "quiet-chat")
		exit, stdout, stderr := run(t, Dependencies{API: server.api, Store: store, WorkingDir: directory}, append(mode, "new")...)
		if exit != 0 {
			t.Fatalf("oe new %v failed: %s %s", mode, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, "pk_sandbox_public") || strings.Contains(stdout+stderr, "relay.open-e2ee.dev") {
			t.Fatalf("oe new %v printed the Relay connection URL: %q %q", mode, stdout, stderr)
		}
		if !strings.Contains(string(mustRead(t, filepath.Join(directory, ".env.local"))), sandboxRelayURL) {
			t.Fatalf("oe new %v did not write the Relay connection URL", mode)
		}
	}
}

func TestNewAddsTheDevDependencyAndTheWrittenConfigLoads(t *testing.T) {
	directory := emptyDirectory(t, "dep-chat")
	manifest := "{\n    \"name\": \"dep-chat\",\n    \"private\": true,\n    \"devDependencies\": {\n        \"@types/node\": \"24.0.0\",\n        \"typescript\": \"5.9.0\"\n    },\n    \"scripts\": {\n        \"build\": \"tsc\"\n    }\n}\n"
	for name, contents := range map[string]string{"package.json": manifest, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	server := startNewControl(t, created)
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())

	exit, stdout, _ := run(t, Dependencies{API: server.api, Store: store, WorkingDir: directory}, "--json", "new")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["install"] != "pnpm install" || !strings.Contains(result.Message, "Run pnpm install to install @open-e2ee/oe.") || result.Next != "oe doctor --wait" {
		t.Fatalf("oe new did not name the install command: exit=%d %s", exit, stdout)
	}
	want := strings.Replace(manifest, "{\n        \"@types/node\"", "{\n        \"@open-e2ee/oe\": \""+Version+"\",\n        \"@types/node\"", 1)
	if after := string(mustRead(t, filepath.Join(directory, "package.json"))); after != want {
		t.Fatalf("oe new wrote package.json:\n%s\nwant:\n%s", after, want)
	}
	loaded, err := config.Load(filepath.Join(directory, config.Filename))
	if err != nil {
		t.Fatalf("the written config does not load: %v", err)
	}
	policy, err := loaded.RelayPolicyFor("sandbox")
	if err != nil || loaded.Project != "dep-chat" || loaded.Product != "signal-relay" || loaded.Environments.Production != nil ||
		policy != (config.RelayPolicy{DeliveryRetention: "1d", AttachmentRetention: "1d"}) {
		t.Fatalf("the written config loaded as %+v %+v %v", loaded, policy, err)
	}

	for name, test := range map[string]struct{ source, want string }{
		"no devDependencies": {`{"name":"x"}`, "{\n  \"name\": \"x\",\n  \"devDependencies\": {\n    \"@open-e2ee/oe\": \"1.2.3\"\n  }\n}"},
		"tab indent":         {"{\n\t\"devDependencies\": {\n\t\t\"zod\": \"4.0.0\"\n\t}\n}\n", "{\n\t\"devDependencies\": {\n\t\t\"@open-e2ee/oe\": \"1.2.3\",\n\t\t\"zod\": \"4.0.0\"\n\t}\n}\n"},
		"a dependency":       {`{"dependencies":{"@open-e2ee/oe":"1.0.0"}}`, ""},
	} {
		edited, err := addDevDependency([]byte(test.source), cliPackage, "1.2.3")
		if err != nil || string(edited) != test.want {
			t.Fatalf("%s: addDevDependency gave %q %v, want %q", name, edited, err, test.want)
		}
	}
	if _, err := addDevDependency([]byte(`{"devDependencies":[]}`), cliPackage, "1.2.3"); err == nil {
		t.Fatal("addDevDependency accepted devDependencies that is not an object")
	}
}

func TestInitAndSandboxAreUsageErrors(t *testing.T) {
	for _, command := range []string{"init", "sandbox", "setup", "create"} {
		for directory, next := range map[string]string{t.TempDir(): "oe new", initializedProject(t, "old-chat"): "oe link"} {
			exit, stdout, _ := run(t, Dependencies{WorkingDir: directory}, "--json", command)
			if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" || failure.Next != next {
				t.Fatalf("oe %s gave exit=%d %s, want next %s", command, exit, stdout, next)
			}
		}
	}
	_, stdout, _ := run(t, Dependencies{}, "--json", "help")
	var names []string
	commands, _ := decodeEvent(t, []byte(stdout)).Data["commands"].([]any)
	for _, command := range commands {
		spec, _ := command.(map[string]any)
		names = append(names, fmt.Sprint(spec["name"]))
	}
	if !slices.Contains(names, "new") || slices.Contains(names, "init") || slices.Contains(names, "sandbox") {
		t.Fatalf("help lists %v", names)
	}
}

func TestNewNeedsAProductAndAProject(t *testing.T) {
	directory := emptyDirectory(t, "choice-chat")
	store := credential.NewMemory()
	storeSession(t, store, sessionToken())
	api := &fakeAPI{listProjects: func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error) { return nil, nil }}
	exit, stdout, _ := run(t, Dependencies{WorkingDir: directory}, "--json", "new", "bogus")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" || fmt.Sprint(failure.Data["choices"]) != "[signal-relay]" {
		t.Fatalf("an unknown product gave exit=%d %s", exit, stdout)
	}
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "new", "signal-relay", "--dry-run")
	if result := decodeEvent(t, []byte(stdout)); exit != 0 || result.Next != "oe new signal-relay --project choice-chat" {
		t.Fatalf("a named product gave exit=%d %s", exit, stdout)
	}

	defer func(saved []string) { products = saved }(products)
	products = []string{"mls", "signal-relay"}
	exit, stdout, _ = run(t, Dependencies{WorkingDir: directory, Getenv: environment(map[string]string{"CLAUDECODE": "1"})}, "new", "--dry-run")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "PRODUCT_REQUIRED" || failure.Next != "oe new mls" {
		t.Fatalf("an agent without a product gave exit=%d %s", exit, stdout)
	}
	exit, stdout, _ = run(t, Dependencies{
		API: api, Store: store, WorkingDir: directory, Interactive: terminal, In: strings.NewReader("2\n"), Getenv: environment(nil),
	}, "--json", "new", "--dry-run")
	if result := decodeEvent(t, []byte(stdout)); exit != 0 || result.Data["product"] != "signal-relay" {
		t.Fatalf("a person could not pick the product: exit=%d %s", exit, stdout)
	}
	products = []string{"signal-relay"}

	for _, test := range []struct {
		directory string
		args      []string
		code      string
		next      string
	}{
		{emptyDirectory(t, "___"), []string{"--json", "new"}, "PROJECT_REQUIRED", "oe new --project my-app"},
		{directory, []string{"--json", "new", "--project", "My App"}, "PROJECT_INVALID", "oe new --project my-app"},
		{directory, []string{"--json", "new", "--project", "-"}, "PROJECT_INVALID", "oe new --project my-app"},
	} {
		exit, stdout, _ := run(t, Dependencies{WorkingDir: test.directory}, test.args...)
		if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != test.code || failure.Next != test.next {
			t.Fatalf("%v gave exit=%d %s", test.args, exit, stdout)
		}
	}
}
