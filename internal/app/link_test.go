package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/projectlock"
)

const (
	linkSandboxURL    = "https://sandbox.relay.open-e2ee.dev/signal/v1/connection/pk_sandbox_linked"
	linkProductionURL = "https://relay.open-e2ee.dev/signal/v1/connection/pk_prod_linked"
)

// linkedProject is a project read as the console answers it: Sandbox keeps 3d
// of deliveries and 1d of attachments with Relay delivery receipts on, and
// Production is active with 7d and 30d and Relay delivery receipts off.
var linkedProject = fmt.Sprintf(`{"slug":"%%s","writer":"config",
	"sandbox":{"attachmentRetentionSeconds":86400,"deliveryTtlSeconds":259200,"relayReceipts":true,"relayUrl":%q,"revision":"3"},
	"production":{"state":"active","blockedBy":null,"canActivate":false,"cardOnFile":true,
		"attachmentRetentionSeconds":2592000,"deliveryTtlSeconds":604800,"relayReceipts":false,"relayUrl":%q,"revision":"2"}}`,
	linkSandboxURL, linkProductionURL)

// sandboxOnlyProject is a project read whose Production is not active. The
// console then sends the Production standing and no environment fields.
const sandboxOnlyProject = `{"slug":"sandbox-chat","writer":"config",
	"sandbox":{"attachmentRetentionSeconds":86400,"deliveryTtlSeconds":86400,"relayReceipts":true,"relayUrl":"` + linkSandboxURL + `","revision":"1"},
	"production":{"state":"available","blockedBy":null,"canActivate":true,"cardOnFile":false}}`

// linkConsole serves the project read and the project list of the console
// CLI routes. projects maps a slug to the body of its read, and any other
// slug is PROJECT_NOT_FOUND, as for a project that the caller cannot read.
func linkConsole(t *testing.T, projects map[string]string, list string) (control.API, *[]string) {
	t.Helper()
	var requested []string
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	authorized := func(response http.ResponseWriter, request *http.Request) bool {
		requested = append(requested, request.Method+" "+request.URL.Path)
		if request.Header.Get("Authorization") != "Bearer test-token" {
			response.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(response, `{"code":"AUTHENTICATION_REQUIRED","message":"sign in"}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /v1/projects", func(response http.ResponseWriter, request *http.Request) {
		if authorized(response, request) {
			fmt.Fprint(response, list)
		}
	})
	mux.HandleFunc("GET /v1/projects/{slug}", func(response http.ResponseWriter, request *http.Request) {
		if !authorized(response, request) {
			return
		}
		body, ok := projects[request.PathValue("slug")]
		if !ok {
			response.WriteHeader(http.StatusNotFound)
			fmt.Fprint(response, `{"code":"PROJECT_NOT_FOUND","message":"The project was not found, or this account has no access to it."}`)
			return
		}
		fmt.Fprint(response, body)
	})
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return api, &requested
}

func readSession(t *testing.T) credential.Store {
	t.Helper()
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	return store
}

// changedFiles returns the path and change of each entry in data.files.
func changedFiles(t *testing.T, data map[string]any) []string {
	t.Helper()
	entries, ok := data["files"].([]any)
	if !ok {
		t.Fatalf("data.files is not a list: %#v", data)
	}
	files := []string{}
	for _, entry := range entries {
		file := entry.(map[string]any)
		files = append(files, fmt.Sprintf("%s %s", file["path"], file["change"]))
	}
	slices.Sort(files)
	return files
}

func TestLinkAttachesPullsAndWritesEnvFiles(t *testing.T) {
	api, _ := linkConsole(t, map[string]string{
		"chat-demo":    fmt.Sprintf(linkedProject, "chat-demo"),
		"sandbox-chat": sandboxOnlyProject,
	}, "[]")
	store := readSession(t)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "package.json"), []byte(`{"dependencies":{"next":"16.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "chat-demo")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Command != "link" || result.Next != "oe doctor" {
		t.Fatalf("oe link chat-demo failed: exit=%d %s", exit, stdout)
	}
	if result.Data["project"] != "chat-demo" || result.Data["product"] != "signal-relay" || result.Data["changed"] != true {
		t.Fatalf("oe link did not report the attachment: %s", stdout)
	}
	want := []string{".env.local created", ".env.production.local created", ".gitignore created", "open-e2ee.config.ts created", "package.json updated"}
	if files := changedFiles(t, result.Data); !slices.Equal(files, want) {
		t.Fatalf("oe link reported files %q, want %q", files, want)
	}
	environments, _ := result.Data["environments"].(map[string]any)
	production, _ := environments["production"].(map[string]any)
	sandbox, _ := environments["sandbox"].(map[string]any)
	if sandbox["state"] != "active" || production["state"] != "active" || production["blockedBy"] != nil {
		t.Fatalf("oe link did not report the environment states: %s", stdout)
	}
	if strings.Contains(stdout, linkSandboxURL) || strings.Contains(stdout, linkProductionURL) {
		t.Fatalf("oe link printed a Relay connection URL: %s", stdout)
	}

	linked, err := config.Load(filepath.Join(directory, config.Filename))
	if err != nil {
		t.Fatal(err)
	}
	if linked.Product != "signal-relay" || linked.Project != "chat-demo" || linked.Environments.Production == nil {
		t.Fatalf("oe link wrote the wrong attachment: %#v", linked)
	}
	for environment, expected := range map[string]config.RelayPolicy{
		"sandbox":    {DeliveryRetention: "3d", AttachmentRetention: "1d", RelayReceipts: true},
		"production": {DeliveryRetention: "7d", AttachmentRetention: "30d", RelayReceipts: false},
	} {
		if policy, err := linked.RelayPolicyFor(environment); err != nil || policy != expected {
			t.Fatalf("the %s policy is %#v (%v), want the server policy %#v", environment, policy, err, expected)
		}
	}
	for filename, expected := range map[string]string{".env.local": linkSandboxURL, ".env.production.local": linkProductionURL} {
		if value, err := envfile.Read(filepath.Join(directory, filename), "NEXT_PUBLIC_OPEN_E2EE_RELAY_URL"); err != nil || value != expected {
			t.Fatalf("%s holds %q (%v), want %q", filename, value, err, expected)
		}
	}
	if ignored := string(mustRead(t, filepath.Join(directory, ".gitignore"))); ignored != projectlock.Filename+"\n.env.local\n.env.production.local\n" {
		t.Fatalf(".gitignore is %q", ignored)
	}

	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "chat-demo")
	again := decodeEvent(t, []byte(stdout))
	if exit != 0 || again.Message != "Nothing to change." || again.Data["changed"] != false || len(changedFiles(t, again.Data)) != 0 {
		t.Fatalf("a second oe link changed files: exit=%d %s", exit, stdout)
	}

	// A project whose Production is not active gets no Production section
	// and no .env.production.local.
	directory = t.TempDir()
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "sandbox-chat")
	result = decodeEvent(t, []byte(stdout))
	environments, _ = result.Data["environments"].(map[string]any)
	production, _ = environments["production"].(map[string]any)
	if exit != 0 || production["state"] != "available" {
		t.Fatalf("oe link sandbox-chat failed: exit=%d %s", exit, stdout)
	}
	if want := []string{".env.local created", ".gitignore created", "open-e2ee.config.ts created"}; !slices.Equal(changedFiles(t, result.Data), want) {
		t.Fatalf("oe link sandbox-chat reported %s", stdout)
	}
	linked, err = config.Load(filepath.Join(directory, config.Filename))
	if err != nil {
		t.Fatal(err)
	}
	if linked.Environments.Production != nil {
		t.Fatalf("oe link added a Production section for an inactive Production: %#v", linked)
	}
	if policy, err := linked.RelayPolicyFor("sandbox"); err != nil || policy != (config.RelayPolicy{DeliveryRetention: "1d", AttachmentRetention: "1d", RelayReceipts: true}) {
		t.Fatalf("the sandbox policy is %#v (%v)", policy, err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".env.production.local")); !os.IsNotExist(err) {
		t.Fatalf("oe link wrote .env.production.local for an inactive Production: %v", err)
	}
}

func TestLinkThatCreatesTheConfigAddsTheDevDependency(t *testing.T) {
	api, _ := linkConsole(t, map[string]string{"sandbox-chat": sandboxOnlyProject}, "[]")
	store := readSession(t)
	directory := t.TempDir()
	manifest := "{\n  \"name\": \"sandbox-chat\",\n  \"devDependencies\": {\n    \"typescript\": \"5.9.0\"\n  }\n}\n"
	for name, contents := range map[string]string{"package.json": manifest, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := strings.Replace(manifest, "{\n    \"typescript\"", "{\n    \"@open-e2ee/oe\": \""+Version+"\",\n    \"typescript\"", 1)

	// The dry run plans the package.json change and writes nothing.
	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "sandbox-chat", "--dry-run")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || !slices.Contains(changedFiles(t, result.Data), "package.json updated") || result.Data["install"] != "pnpm install" {
		t.Fatalf("oe link --dry-run did not plan the devDependency: exit=%d %s", exit, stdout)
	}
	if after := string(mustRead(t, filepath.Join(directory, "package.json"))); after != manifest {
		t.Fatalf("oe link --dry-run wrote package.json:\n%s", after)
	}

	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "sandbox-chat")
	result = decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["install"] != "pnpm install" || !strings.Contains(result.Message, "Run pnpm install to install @open-e2ee/oe.") {
		t.Fatalf("oe link did not name the install command: exit=%d %s", exit, stdout)
	}
	if after := string(mustRead(t, filepath.Join(directory, "package.json"))); after != want {
		t.Fatalf("oe link wrote package.json:\n%s\nwant:\n%s", after, want)
	}

	// Without a package.json, oe link writes none, as oe new does. oe reads the
	// config with its own copy of @open-e2ee/oe/config.
	directory = t.TempDir()
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "sandbox-chat")
	result = decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["install"] != nil || strings.Contains(result.Message, "install") {
		t.Fatalf("oe link without package.json named an install: exit=%d %s", exit, stdout)
	}
	if _, err := os.Stat(filepath.Join(directory, "package.json")); !os.IsNotExist(err) {
		t.Fatalf("oe link created a package.json: %v", err)
	}
	if _, err := config.Load(filepath.Join(directory, config.Filename)); err != nil {
		t.Fatalf("the config that oe link wrote without package.json does not load: %v", err)
	}
}

func TestLinkWithoutArgumentRewritesOnlyTheEnvFiles(t *testing.T) {
	api, requested := linkConsole(t, map[string]string{"chat-demo": fmt.Sprintf(linkedProject, "chat-demo")}, "[]")
	store := readSession(t)
	directory := initializedProject(t, "chat-demo")
	path := filepath.Join(directory, config.Filename)
	source := mustRead(t, path)
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, "https://sandbox.relay.open-e2ee.dev/signal/v1/connection/stale"); err != nil {
		t.Fatal(err)
	}

	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["project"] != "chat-demo" || result.Data["changed"] != true {
		t.Fatalf("oe link failed: exit=%d %s", exit, stdout)
	}
	if want := []string{".env.local updated", ".env.production.local created", ".gitignore updated"}; !slices.Equal(changedFiles(t, result.Data), want) {
		t.Fatalf("oe link reported %s", stdout)
	}
	// The server policy differs from the file, and the file is not touched.
	if after := mustRead(t, path); string(after) != string(source) {
		t.Fatalf("oe link without a project changed the config:\n%s", after)
	}
	for filename, expected := range map[string]string{".env.local": linkSandboxURL, ".env.production.local": linkProductionURL} {
		if value, err := envfile.Read(filepath.Join(directory, filename), envfile.DefaultVariable); err != nil || value != expected {
			t.Fatalf("%s holds %q (%v), want %q", filename, value, err, expected)
		}
	}
	if !slices.Equal(*requested, []string{"GET /v1/projects/chat-demo"}) {
		t.Fatalf("oe link sent %q", *requested)
	}

	// Without a config and a project, an agent gets the command that lists
	// the projects.
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store}, "--json", "link")
	if refusal := decodeEvent(t, []byte(stdout)); exit != exitUsage || refusal.Code != "PROJECT_REQUIRED" || refusal.Next != "oe project list" {
		t.Fatalf("oe link without a config was not PROJECT_REQUIRED: exit=%d %s", exit, stdout)
	}
}

func TestLinkToAnotherProjectNeedsYes(t *testing.T) {
	api, _ := linkConsole(t, map[string]string{"new-chat": fmt.Sprintf(linkedProject, "new-chat")}, "[]")
	store := readSession(t)
	directory := initializedProject(t, "old-chat")
	path := filepath.Join(directory, config.Filename)
	oldSandbox := "https://sandbox.relay.open-e2ee.dev/signal/v1/connection/old-sandbox"
	oldProduction := "https://relay.open-e2ee.dev/signal/v1/connection/old-production"
	if err := writeRelayEnvironment(directory, ".env.local", envfile.DefaultVariable, oldSandbox); err != nil {
		t.Fatal(err)
	}
	if err := writeRelayEnvironment(directory, ".env.production.local", envfile.DefaultVariable, oldProduction); err != nil {
		t.Fatal(err)
	}
	source := mustRead(t, path)
	unchanged := func() {
		t.Helper()
		if after := mustRead(t, path); string(after) != string(source) {
			t.Fatalf("the config changed:\n%s", after)
		}
		for filename, expected := range map[string]string{".env.local": oldSandbox, ".env.production.local": oldProduction} {
			if value, _ := envfile.Read(filepath.Join(directory, filename), envfile.DefaultVariable); value != expected {
				t.Fatalf("%s changed to %q", filename, value)
			}
		}
	}

	exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "new-chat")
	refusal := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || refusal.Code != "CONFIRMATION_REQUIRED" || refusal.Next != "oe link new-chat --yes" {
		t.Fatalf("a link to another project did not need --yes: exit=%d %s", exit, stdout)
	}
	if refusal.Data["project"] != "old-chat" || refusal.Data["requested"] != "new-chat" {
		t.Fatalf("CONFIRMATION_REQUIRED did not name both projects: %s", stdout)
	}
	unchanged()

	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "new-chat", "--dry-run")
	preview := decodeEvent(t, []byte(stdout))
	if exit != 0 || preview.Data["dryRun"] != true || preview.Data["changed"] != false {
		t.Fatalf("oe link --dry-run failed: exit=%d %s", exit, stdout)
	}
	if want := []string{".env.local updated", ".env.production.local updated", ".gitignore updated", "open-e2ee.config.ts updated"}; !slices.Equal(changedFiles(t, preview.Data), want) {
		t.Fatalf("oe link --dry-run reported %s", stdout)
	}
	unchanged()

	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "link", "new-chat", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["project"] != "new-chat" || result.Data["changed"] != true {
		t.Fatalf("oe link new-chat --yes failed: exit=%d %s", exit, stdout)
	}
	linked, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if linked.Project != "new-chat" {
		t.Fatalf("oe link --yes did not change the project: %#v", linked)
	}
	for environment, expected := range map[string]config.RelayPolicy{
		"sandbox":    {DeliveryRetention: "3d", AttachmentRetention: "1d", RelayReceipts: true},
		"production": {DeliveryRetention: "7d", AttachmentRetention: "30d", RelayReceipts: false},
	} {
		if policy, err := linked.RelayPolicyFor(environment); err != nil || policy != expected {
			t.Fatalf("the %s policy is %#v (%v), want the server policy %#v", environment, policy, err, expected)
		}
	}
	// The pull changes only the values that differ: the shared policy stays.
	if linked.Relay != (config.RelayPolicy{DeliveryRetention: "30d", AttachmentRetention: "30d", RelayReceipts: true}) {
		t.Fatalf("the pull changed the shared policy: %#v", linked.Relay)
	}
	for filename, expected := range map[string]string{".env.local": linkSandboxURL, ".env.production.local": linkProductionURL} {
		contents := string(mustRead(t, filepath.Join(directory, filename)))
		if !strings.Contains(contents, "OPEN_E2EE_RELAY_URL="+expected) || strings.Contains(contents, "old-") {
			t.Fatalf("%s did not converge to the linked project: %q", filename, contents)
		}
	}
}

func TestLinkOnAComputedProjectReturnsTheEdit(t *testing.T) {
	api, _ := linkConsole(t, map[string]string{"new-chat": fmt.Sprintf(linkedProject, "new-chat")}, "[]")
	store := readSession(t)
	directory := initializedProject(t, "old-chat")
	path := filepath.Join(directory, config.Filename)
	source := strings.Replace(string(mustRead(t, path)), `project: "old-chat"`, `project: ["old", "chat"].join("-")`, 1)
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	// --yes cannot change a computed value, so a run without it and a dry run
	// get the same edit.
	for _, args := range [][]string{{"link", "new-chat", "--yes"}, {"link", "new-chat"}, {"link", "new-chat", "--dry-run"}} {
		exit, stdout, _ := run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, append([]string{"--json"}, args...)...)
		refusal := decodeEvent(t, []byte(stdout))
		edits, _ := refusal.Data["edits"].([]any)
		var edit map[string]any
		if len(edits) == 1 {
			edit, _ = edits[0].(map[string]any)
		}
		if exit != exitPersonAction || refusal.Code != "CONFIG_EDIT_REQUIRED" || edit["path"] != "project" ||
			edit["currentExpression"] != `["old", "chat"].join("-")` || edit["newValue"] != "new-chat" {
			t.Fatalf("oe %v on a computed project was not CONFIG_EDIT_REQUIRED with the edit: exit=%d %s", args, exit, stdout)
		}
	}
	if after := mustRead(t, path); string(after) != source {
		t.Fatalf("CONFIG_EDIT_REQUIRED changed the file: %q", after)
	}
	for _, filename := range []string{".env.local", ".env.production.local"} {
		if _, err := os.Stat(filepath.Join(directory, filename)); !os.IsNotExist(err) {
			t.Fatalf("CONFIG_EDIT_REQUIRED wrote %s: %v", filename, err)
		}
	}
}

func TestLinkUnknownProjectNamesProjectList(t *testing.T) {
	api, _ := linkConsole(t, map[string]string{}, "[]")
	directory := t.TempDir()
	exit, stdout, _ := run(t, Dependencies{API: api, Store: readSession(t), WorkingDir: directory}, "--json", "link", "missing-chat")
	refusal := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || refusal.Code != "PROJECT_NOT_FOUND" || refusal.Next != "oe project list" {
		t.Fatalf("an unknown project did not name oe project list: exit=%d %s", exit, stdout)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("oe link wrote files for an unknown project: %v %v", entries, err)
	}
}

func TestLinkLetsAPersonChooseTheProject(t *testing.T) {
	api, requested := linkConsole(t, map[string]string{"side-chat": fmt.Sprintf(linkedProject, "side-chat")}, `[
		{"name":"Chat demo","product":"signal-relay","production":{"state":"active"},"slug":"chat-demo"},
		{"name":"Side chat","product":"signal-relay","production":{"state":"active"},"slug":"side-chat"}]`)
	directory := t.TempDir()
	exit, stdout, stderr := run(t, Dependencies{
		API: api, Store: readSession(t), WorkingDir: directory, Getenv: environment(nil),
		Interactive: func() bool { return true }, In: strings.NewReader("2\n"),
	}, "link")
	if exit != 0 || !strings.Contains(stderr, "1. chat-demo") || !strings.Contains(stderr, "2. side-chat") {
		t.Fatalf("oe link did not offer the projects: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
	linked, err := config.Load(filepath.Join(directory, config.Filename))
	if err != nil || linked.Project != "side-chat" {
		t.Fatalf("oe link did not link the chosen project: %#v %v", linked, err)
	}
	if !slices.Equal(*requested, []string{"GET /v1/projects", "GET /v1/projects/side-chat"}) {
		t.Fatalf("oe link sent %q", *requested)
	}
}

func TestProjectListShowsProductionState(t *testing.T) {
	api, requested := linkConsole(t, nil, `[
		{"name":"Chat demo","product":"signal-relay","production":{"state":"active"},"slug":"chat-demo"},
		{"name":"Side chat","product":"signal-relay","production":{"state":"available"},"slug":"side-chat"}]`)
	store := readSession(t)

	exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, "--json", "project", "list")
	result := decodeEvent(t, []byte(stdout))
	projects, _ := result.Data["projects"].([]any)
	if exit != 0 || len(projects) != 2 {
		t.Fatalf("oe project list failed: exit=%d %s", exit, stdout)
	}
	first, _ := projects[0].(map[string]any)
	second, _ := projects[1].(map[string]any)
	firstProduction, _ := first["production"].(map[string]any)
	secondProduction, _ := second["production"].(map[string]any)
	if first["slug"] != "chat-demo" || first["name"] != "Chat demo" || first["product"] != "signal-relay" || firstProduction["state"] != "active" ||
		second["slug"] != "side-chat" || secondProduction["state"] != "available" {
		t.Fatalf("oe project list did not show each project and its Production state: %s", stdout)
	}
	if !slices.Equal(*requested, []string{"GET /v1/projects"}) {
		t.Fatalf("oe project list sent %q", *requested)
	}

	exit, stdout, _ = run(t, Dependencies{API: api, Store: store}, "project", "list")
	if exit != 0 || !strings.Contains(stdout, "chat-demo") || !strings.Contains(stdout, "Production active") ||
		!strings.Contains(stdout, "side-chat") || !strings.Contains(stdout, "Production available") {
		t.Fatalf("oe project list text did not show the Production states: exit=%d %q", exit, stdout)
	}
}

func TestProjectSelectIsAUsageError(t *testing.T) {
	directory := initializedProject(t, "old-chat")
	exit, stdout, _ := run(t, Dependencies{Store: readSession(t), WorkingDir: directory}, "--json", "project", "select", "new-chat")
	refusal := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || refusal.Code != "USAGE_ERROR" || refusal.Next != "oe help project" {
		t.Fatalf("oe project select was not a usage error: exit=%d %s", exit, stdout)
	}
	exit, stdout, _ = run(t, Dependencies{}, "--json", "help", "project")
	if help := decodeEvent(t, []byte(stdout)); exit != 0 || strings.Contains(stdout, "select") || !strings.Contains(fmt.Sprint(help.Data["usage"]), "oe project list") {
		t.Fatalf("oe help project still names select or lacks list: %s", stdout)
	}
}
