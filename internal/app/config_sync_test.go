package app

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/projectlock"
)

// sandboxOnly is a config with no Production section. The shared policy is
// 30d, and Sandbox overrides both fields with 1d.
const sandboxOnly = `// Public service policy. Do not put secrets in this file.
import { defineConfig } from "@open-e2ee/oe/config";

export default defineConfig({
  product: "signal-relay",
  project: "pull-chat",
  relay: {
    deliveryRetention: "30d",
    attachmentRetention: "30d",
  },
  environments: {
    sandbox: {
      relay: {
        deliveryRetention: "1d",
        attachmentRetention: "1d",
      },
    },
  },
});
`

// retention gives the policy of an active environment in seconds, with
// Relay delivery receipts on.
func retention(delivery, attachment int) *control.ProjectEnvironment {
	return &control.ProjectEnvironment{
		DeliveryRetentionSeconds: delivery, AttachmentRetentionSeconds: attachment, RelayReceipts: new(true),
		RelayURL: "https://relay.example/signal/v1/connection/pk_public", Revision: "4",
	}
}

const (
	hour = 3_600
	day  = 86_400
)

// pullServer is a control API whose project read answers the policy of each
// active environment. A nil environment is not active. It counts the reads.
func pullServer(t *testing.T, slug string, sandbox, production *control.ProjectEnvironment) (Dependencies, *int) {
	t.Helper()
	reads := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/projects/"+slug, func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(response, `{"code":"AUTHENTICATION_REQUIRED"}`, http.StatusUnauthorized)
			return
		}
		reads++
		_ = json.NewEncoder(response).Encode(control.Project{Slug: slug, Writer: "config", Sandbox: sandbox, Production: production})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	return Dependencies{API: api, HTTP: server.Client(), Store: store}, &reads
}

// projectWith writes source as the config file of a new directory.
func projectWith(t *testing.T, source string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, config.Filename)
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory, path
}

func mustLoad(t *testing.T, path string) config.Config {
	t.Helper()
	value, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// entry returns data.environments.<name> of a pull result.
func entry(t *testing.T, result event, name string) map[string]any {
	t.Helper()
	environments, _ := result.Data["environments"].(map[string]any)
	value, ok := environments[name].(map[string]any)
	if !ok {
		t.Fatalf("the result has no %s entry: %#v", name, result.Data)
	}
	return value
}

func TestPullAddsWithoutConsent(t *testing.T) {
	directory, path := projectWith(t, sandboxOnly)
	dependencies, _ := pullServer(t, "pull-chat", retention(day, day), retention(7*day, 30*day))
	dependencies.WorkingDir = directory

	exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Command != "config pull" || result.Data["changed"] != true {
		t.Fatalf("a pull that only adds did not apply without --yes: exit=%d %s", exit, stdout)
	}
	if status := entry(t, result, "sandbox")["status"]; status != "unchanged" {
		t.Fatalf("sandbox status = %v, want unchanged: %s", status, stdout)
	}
	production := entry(t, result, "production")
	changes, _ := production["changes"].([]any)
	if production["status"] != "applied" || len(changes) != 1 {
		t.Fatalf("production was not applied with one change: %s", stdout)
	}
	if change := changes[0].(map[string]any); change["action"] != "add" || change["path"] != "environments.production.relay.deliveryRetention" || change["to"] != "7d" {
		t.Fatalf("the production change is not the delivery override: %#v", change)
	}
	// The shared policy already gives the attachment retention, so only the
	// delivery retention becomes an override.
	value := mustLoad(t, path)
	if value.Environments.Production == nil || value.Environments.Production.Relay == nil ||
		*value.Environments.Production.Relay != (config.RelayOverride{DeliveryRetention: "7d"}) || value.Relay.DeliveryRetention != "30d" {
		t.Fatalf("the pull did not add the fewest values: %#v", value)
	}

	exit, stdout, _ = run(t, dependencies, "--json", "config", "pull")
	result = decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["changed"] != false || entry(t, result, "production")["status"] != "unchanged" {
		t.Fatalf("a second pull changed the file: exit=%d %s", exit, stdout)
	}
}

func TestPullReplacingAValueNeedsYes(t *testing.T) {
	for _, test := range []struct {
		name       string
		production *control.ProjectEnvironment
		path       string
		from       string
	}{
		// Sandbox overrides 1d in the file.
		{"an override", nil, "environments.sandbox.relay.deliveryRetention", "1d"},
		// Production takes the shared 30d; a new override replaces its value.
		{"a shared value", retention(7*day, 30*day), "environments.production.relay.deliveryRetention", "30d"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := initializedProject(t, "pull-chat")
			path := filepath.Join(directory, config.Filename)
			before := mustRead(t, path)
			sandbox := retention(day, day)
			if test.production == nil {
				sandbox = retention(3*day, day)
			}
			dependencies, _ := pullServer(t, "pull-chat", sandbox, test.production)
			dependencies.WorkingDir = directory

			exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
			refusal := decodeEvent(t, []byte(stdout))
			if exit != exitUsage || refusal.Code != "CONFIRMATION_REQUIRED" || refusal.Next != "oe config pull --yes" {
				t.Fatalf("a replaced value did not need --yes: exit=%d %s", exit, stdout)
			}
			if !strings.Contains(stdout, `"path":"`+test.path+`"`) || !strings.Contains(stdout, `"from":"`+test.from+`"`) {
				t.Fatalf("the refusal does not list the replaced value: %s", stdout)
			}
			if after := mustRead(t, path); string(after) != string(before) {
				t.Fatalf("CONFIRMATION_REQUIRED changed the file:\n%s", after)
			}

			// A person at a terminal answers the prompt instead.
			person := dependencies
			person.In, person.Interactive = strings.NewReader("n\n"), terminal
			exit, _, stderr := run(t, person, "config", "pull")
			if exit != exitFailure || !strings.Contains(stderr, "Replace 1 value(s)") || !strings.Contains(stderr, test.path) {
				t.Fatalf("a person who declined was not asked or did not stop the pull: exit=%d %s", exit, stderr)
			}
			if after := mustRead(t, path); string(after) != string(before) {
				t.Fatalf("a declined pull changed the file:\n%s", after)
			}

			exit, stdout, _ = run(t, dependencies, "--json", "config", "pull", "--yes")
			if result := decodeEvent(t, []byte(stdout)); exit != 0 || result.Data["changed"] != true {
				t.Fatalf("pull --yes did not apply: exit=%d %s", exit, stdout)
			}
			if !strings.Contains(string(mustRead(t, path)), `deliveryRetention: "`) {
				t.Fatal("the pull removed the delivery retention")
			}
			policy, err := mustLoad(t, path).RelayPolicyFor(strings.Split(test.path, ".")[1])
			if err != nil || (policy.DeliveryRetention != "3d" && policy.DeliveryRetention != "7d") {
				t.Fatalf("pull --yes did not write the server value: %#v %v", policy, err)
			}
		})
	}

	t.Run("with --env", func(t *testing.T) {
		directory := initializedProject(t, "pull-chat")
		dependencies, _ := pullServer(t, "pull-chat", retention(3*day, day), nil)
		dependencies.WorkingDir = directory
		exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "-e", "sandbox")
		if refusal := decodeEvent(t, []byte(stdout)); exit != exitUsage || refusal.Next != "oe config pull --yes --env sandbox" {
			t.Fatalf("the next command dropped --env: exit=%d %s", exit, stdout)
		}
	})
}

func TestPullKeepsComments(t *testing.T) {
	source := `// Public service policy. Do not put secrets in this file.
import { defineConfig } from "@open-e2ee/oe/config";

/* The Relay policy of every environment. */
export default defineConfig({
  product: "signal-relay",
  project: "pull-chat", // the console slug
  relay: {
    // Keep a month of history.
    deliveryRetention: "30d",
    attachmentRetention: "30d", /* attachments too */
  },
  environments: {
    sandbox: {
      relay: {
        deliveryRetention: "1d", // short for tests
        attachmentRetention: "1d",
      },
    },
    // Production takes the shared policy.
    production: {},
  },
});
`
	directory, path := projectWith(t, source)
	dependencies, _ := pullServer(t, "pull-chat", retention(3*day, day), retention(30*day, 14*day))
	dependencies.WorkingDir = directory

	exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "--yes")
	if exit != 0 {
		t.Fatalf("pull --yes failed: exit=%d %s", exit, stdout)
	}
	want := strings.Replace(source, `deliveryRetention: "1d", // short for tests`, `deliveryRetention: "3d", // short for tests`, 1)
	want = strings.Replace(want, `production: {},`, `production: {
      relay: {
        attachmentRetention: "14d",
      },
    },`, 1)
	if got := string(mustRead(t, path)); got != want {
		t.Fatalf("the pull changed more than the values\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestPullOfAComputedValueWritesNothingAndReturnsTheEdits(t *testing.T) {
	source := strings.Replace(sandboxOnly, `import { defineConfig } from "@open-e2ee/oe/config";
`, `import { defineConfig } from "@open-e2ee/oe/config";

const short = ["1", "d"].join("");
`, 1)
	source = strings.Replace(source, `        deliveryRetention: "1d",
        attachmentRetention: "1d",`, `        deliveryRetention: short,
        attachmentRetention: short,`, 1)
	directory, path := projectWith(t, source)
	// Both computed Sandbox values change, and Production adds a section
	// that the splicer could write.
	dependencies, _ := pullServer(t, "pull-chat", retention(3*day, 12*hour), retention(7*day, 30*day))
	dependencies.WorkingDir = directory

	for _, args := range [][]string{{"--json", "config", "pull"}, {"--json", "config", "pull", "--yes"}} {
		exit, stdout, _ := run(t, dependencies, args...)
		refusal := decodeEvent(t, []byte(stdout))
		if exit != exitPersonAction || refusal.Code != "CONFIG_EDIT_REQUIRED" {
			t.Fatalf("%v: a computed value was not CONFIG_EDIT_REQUIRED: exit=%d %s", args, exit, stdout)
		}
		edits, _ := refusal.Data["edits"].([]any)
		var got []string
		for _, edit := range edits {
			edit := edit.(map[string]any)
			if edit["currentExpression"] != "short" || edit["file"] != path {
				t.Fatalf("%v: the edit does not name the expression and the file: %#v", args, edit)
			}
			got = append(got, edit["path"].(string)+"="+edit["newValue"].(string))
		}
		slices.Sort(got)
		if want := []string{"environments.sandbox.relay.attachmentRetention=12h", "environments.sandbox.relay.deliveryRetention=3d"}; !slices.Equal(got, want) {
			t.Fatalf("%v: edits = %v, want %v: %s", args, got, want, stdout)
		}
		if after := mustRead(t, path); string(after) != source {
			t.Fatalf("%v: CONFIG_EDIT_REQUIRED changed the file:\n%s", args, after)
		}
	}
}

func TestPullIgnoresOEEnv(t *testing.T) {
	for _, selected := range []string{"sandbox", "production", "stage"} {
		t.Run(selected, func(t *testing.T) {
			directory, path := projectWith(t, sandboxOnly)
			dependencies, _ := pullServer(t, "pull-chat", retention(day, day), retention(7*day, 30*day))
			dependencies.WorkingDir = directory
			dependencies.Getenv = environment(map[string]string{"OE_ENV": selected})

			exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
			result := decodeEvent(t, []byte(stdout))
			if exit != 0 || entry(t, result, "sandbox")["status"] != "unchanged" || entry(t, result, "production")["status"] != "applied" {
				t.Fatalf("OE_ENV=%s narrowed the pull: exit=%d %s", selected, exit, stdout)
			}
			if mustLoad(t, path).Environments.Production == nil {
				t.Fatalf("OE_ENV=%s kept the Production section out of the file", selected)
			}
		})
	}

	t.Run("--env narrows", func(t *testing.T) {
		directory, path := projectWith(t, sandboxOnly)
		dependencies, _ := pullServer(t, "pull-chat", retention(day, day), retention(7*day, 30*day))
		dependencies.WorkingDir = directory
		exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "--env", "sandbox")
		result := decodeEvent(t, []byte(stdout))
		environments, _ := result.Data["environments"].(map[string]any)
		if _, ok := environments["production"]; exit != 0 || ok || result.Data["changed"] != false {
			t.Fatalf("--env sandbox did not narrow the pull: exit=%d %s", exit, stdout)
		}
		if after := mustRead(t, path); string(after) != sandboxOnly {
			t.Fatalf("--env sandbox changed the file:\n%s", after)
		}
	})
}

func TestPullDryRunWritesNothing(t *testing.T) {
	directory := initializedProject(t, "pull-chat")
	path := filepath.Join(directory, config.Filename)
	before := mustRead(t, path)
	dependencies, _ := pullServer(t, "pull-chat", retention(3*day, day), retention(7*day, 30*day))
	dependencies.WorkingDir = directory

	// A replacement needs no --yes in a dry run, because nothing is written.
	exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "--dry-run")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["changed"] != false || entry(t, result, "sandbox")["status"] != "planned" || entry(t, result, "production")["status"] != "planned" {
		t.Fatalf("the dry run did not report the plan: exit=%d %s", exit, stdout)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if after := mustRead(t, path); string(after) != string(before) || len(entries) != 1 {
		t.Fatalf("the dry run wrote to the directory: %v\n%s", entries, after)
	}

	// A dry run reports the edits that a person must make, and exits 0.
	computed, computedPath := projectWith(t, strings.Replace(sandboxOnly, `deliveryRetention: "1d"`, `deliveryRetention: ["1", "d"].join("")`, 1))
	dependencies.WorkingDir = computed
	exit, stdout, _ = run(t, dependencies, "--json", "config", "pull", "--dry-run")
	result = decodeEvent(t, []byte(stdout))
	if edits, _ := result.Data["edits"].([]any); exit != 0 || len(edits) != 1 {
		t.Fatalf("the dry run did not report the computed value: exit=%d %s", exit, stdout)
	}
	if after := string(mustRead(t, computedPath)); !strings.Contains(after, `["1", "d"].join("")`) || strings.Contains(after, "production") {
		t.Fatalf("the dry run changed the file:\n%s", after)
	}
}

func TestPullKeepsTheSectionOfAnInactiveEnvironment(t *testing.T) {
	directory := initializedProject(t, "pull-chat")
	path := filepath.Join(directory, config.Filename)
	before := mustRead(t, path)
	dependencies, reads := pullServer(t, "pull-chat", retention(day, day), nil)
	dependencies.WorkingDir = directory

	exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
	result := decodeEvent(t, []byte(stdout))
	production := entry(t, result, "production")
	if exit != 0 || result.Data["changed"] != false || production["status"] != "skipped" || production["reason"] != "inactive" || *reads != 1 {
		t.Fatalf("an inactive Production was not skipped: exit=%d reads=%d %s", exit, *reads, stdout)
	}
	if after := mustRead(t, path); string(after) != string(before) {
		t.Fatalf("the pull removed or changed the Production section:\n%s", after)
	}
}

const cardSetupURL = "https://console.open-e2ee.dev/billing/setup"

// pushConsole keeps one project as the console does. A plan compares the
// policy with the environment, and a deploy of that plan applies the policy
// and activates a Production that is not active. It records each call in
// order, and fail injects a refusal for a call such as "deploy sandbox".
type pushConsole struct {
	fakeAPI
	t        *testing.T
	project  control.Project
	terms    control.Terms
	fail     map[string]error
	calls    []string
	deployed map[string]control.DeployRequest
}

// newPushConsole answers a project whose active Sandbox keeps a 30d policy and
// whose Production can open on the Free plan now.
func newPushConsole(t *testing.T, slug string) *pushConsole {
	sandbox := projectEnvironment(sandboxRelayURL, "3")
	sandbox.DeliveryRetentionSeconds, sandbox.AttachmentRetentionSeconds = 2_592_000, 2_592_000
	return &pushConsole{
		t: t, fail: map[string]error{}, deployed: map[string]control.DeployRequest{},
		terms: control.Terms{State: control.TermsRequired, CanAccept: true},
		project: control.Project{
			Slug: slug, Writer: "config", Sandbox: sandbox,
			Production: &control.ProjectEnvironment{
				State: control.ProductionAvailable, CanActivate: true, CardOnFile: true,
			},
		},
	}
}

// activeProduction makes Production active with a policy of seconds.
func (c *pushConsole) activeProduction(seconds int) {
	production := projectEnvironment(productionRelayURL, "7")
	production.DeliveryRetentionSeconds, production.AttachmentRetentionSeconds = seconds, seconds
	production.State, production.CardOnFile = control.ProductionActive, true
	c.project.Production = production
}

// blockProduction stops a Production activation at gate.
func (c *pushConsole) blockProduction(gate string) {
	c.project.Production.State, c.project.Production.CanActivate = control.ProductionInactive, false
	c.project.Production.BlockedBy = gate
	c.project.Production.CardOnFile = gate != control.BlockedByCard
}

func (c *pushConsole) environment(name string) *control.ProjectEnvironment {
	return environmentOf(c.project, name)
}

func (c *pushConsole) GetProject(context.Context, control.CredentialRequest, string) (control.Project, error) {
	project := c.project
	sandbox, production := *c.project.Sandbox, *c.project.Production
	project.Sandbox, project.Production = &sandbox, &production
	return project, nil
}

func (c *pushConsole) Plan(_ context.Context, request control.CredentialRequest, plan control.PlanRequest) (control.Plan, error) {
	c.calls = append(c.calls, "plan "+plan.Environment)
	if request.OperationID == "" || plan.Writer != "config" || plan.ProjectSlug != c.project.Slug {
		c.t.Fatalf("plan lost its contract: %#v %#v", request, plan)
	}
	if err := c.fail["plan "+plan.Environment]; err != nil {
		return control.Plan{}, err
	}
	current := c.environment(plan.Environment)
	active := plan.Environment == "sandbox" || current.State == control.ProductionActive
	result := control.Plan{
		ID: "plan_" + plan.Environment, ProjectSlug: c.project.Slug, Environment: plan.Environment,
		ExpectedRevision: cmp.Or(current.Revision, "0"), BillingReady: true, Changes: []control.Change{},
	}
	if !active {
		// The console names the activation with this path.
		result.Changes = append(result.Changes, control.Change{Path: "production.activation", Before: false, After: true})
		if !current.CardOnFile {
			result.BillingReady, result.BillingSetupURL = false, cardSetupURL
		}
	}
	for _, field := range []struct {
		path          string
		before, after int
	}{
		{"relay.deliveryRetentionSeconds", current.DeliveryRetentionSeconds, plan.Policy.DeliveryRetentionSeconds},
		{"relay.attachmentRetentionSeconds", current.AttachmentRetentionSeconds, plan.Policy.AttachmentRetentionSeconds},
	} {
		switch {
		case !active:
			result.Changes = append(result.Changes, control.Change{Path: field.path, After: field.after})
		case field.before != field.after:
			result.Changes = append(result.Changes, control.Change{Path: field.path, Before: field.before, After: field.after})
		}
	}
	switch receipts := plan.Policy.RelayReceipts; {
	case !active:
		result.Changes = append(result.Changes, control.Change{Path: "relay.relayReceipts", After: receipts})
	case current.RelayReceipts == nil:
		c.t.Fatalf("the active %s environment has no relayReceipts", plan.Environment)
	case *current.RelayReceipts != receipts:
		result.Changes = append(result.Changes, control.Change{Path: "relay.relayReceipts", Before: *current.RelayReceipts, After: receipts})
	}
	return result, nil
}

func (c *pushConsole) Deploy(_ context.Context, request control.CredentialRequest, deploy control.DeployRequest) (control.Deployment, error) {
	name := deploy.Environment
	c.calls = append(c.calls, "deploy "+name)
	if name != "sandbox" && name != "production" {
		c.t.Fatalf("deploy named no environment: %#v", deploy)
	}
	current := c.environment(name)
	if request.OperationID == "" || deploy.PlanID != "plan_"+name || deploy.ExpectedRevision != cmp.Or(current.Revision, "0") {
		c.t.Fatalf("deploy lost its contract: %#v %#v", request, deploy)
	}
	if err := c.fail["deploy "+name]; err != nil {
		return control.Deployment{}, err
	}
	c.deployed[name] = deploy
	revision, _ := strconv.Atoi(current.Revision)
	current.Revision = strconv.Itoa(revision + 1)
	current.DeliveryRetentionSeconds = deploy.Policy.DeliveryRetentionSeconds
	current.AttachmentRetentionSeconds = deploy.Policy.AttachmentRetentionSeconds
	current.RelayReceipts = new(deploy.Policy.RelayReceipts)
	if name == "production" {
		current.RelayURL, current.State, current.BlockedBy, current.CanActivate = productionRelayURL, control.ProductionActive, "", false
	}
	return control.Deployment{ID: "deployment_" + name, Revision: current.Revision, Status: "complete", RelayURL: current.RelayURL}, nil
}

func (c *pushConsole) Terms(context.Context, control.CredentialRequest) (control.Terms, error) {
	return c.terms, nil
}

// pushDependencies runs oe config push in directory against console with a
// stored session, and fails the test when the run waits or opens a browser.
func pushDependencies(t *testing.T, console *pushConsole, directory string) Dependencies {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read", "deploy:write")
	return Dependencies{
		API: console, Store: store, WorkingDir: directory, In: unreadable{t},
		OpenURL: func(target string) error {
			t.Errorf("the push opened %s", target)
			return nil
		},
		Sleep: func(context.Context, time.Duration) error {
			t.Error("the push waited")
			return errors.New("unexpected wait")
		},
	}
}

// environmentResult is data.environments.<name> of a push.
func environmentResult(t *testing.T, result event, name string) map[string]any {
	t.Helper()
	environments, _ := result.Data["environments"].(map[string]any)
	entry, _ := environments[name].(map[string]any)
	return entry
}

func pushStatus(t *testing.T, result event, name string) string {
	t.Helper()
	status, _ := environmentResult(t, result, name)["status"].(string)
	return status
}

func TestPushAppliesSandboxThenProduction(t *testing.T) {
	directory := initializedProject(t, "push-chat")
	console := newPushConsole(t, "push-chat")
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Command != "config push" {
		t.Fatalf("push failed: exit=%d %s", exit, stdout)
	}
	if want := []string{"plan sandbox", "deploy sandbox", "plan production", "deploy production"}; !slices.Equal(console.calls, want) {
		t.Fatalf("push called %v, want %v", console.calls, want)
	}
	if pushStatus(t, result, "sandbox") != "applied" || pushStatus(t, result, "production") != "applied" {
		t.Fatalf("push did not report both environments as applied: %s", stdout)
	}
	if environmentResult(t, result, "production")["activated"] != true || !strings.Contains(result.Message, "Production is active on the Free plan.") {
		t.Fatalf("push did not report the activation: %s", stdout)
	}
	sandbox, production := console.deployed["sandbox"], console.deployed["production"]
	if sandbox.Environment != "sandbox" || sandbox.Policy.DeliveryRetentionSeconds != 86_400 || sandbox.Policy.AttachmentRetentionSeconds != 86_400 {
		t.Fatalf("the Sandbox deploy did not carry the Sandbox section: %#v", sandbox)
	}
	if production.Environment != "production" || production.Policy.DeliveryRetentionSeconds != 2_592_000 || production.Policy.AttachmentRetentionSeconds != 2_592_000 {
		t.Fatalf("the Production deploy did not carry the shared policy: %#v", production)
	}
	connection, _ := result.Data["connection"].(map[string]any)
	if result.Next != "oe doctor --env production" || connection["file"] != ".env.production.local" || connection["variable"] != "OPEN_E2EE_RELAY_URL" {
		t.Fatalf("push did not hand over the Production connection: %s", stdout)
	}
	if strings.Contains(stdout, productionRelayURL) {
		t.Fatalf("push printed the Production connection URL: %s", stdout)
	}
	environment := mustRead(t, filepath.Join(directory, ".env.production.local"))
	if !strings.Contains(string(environment), "\nOPEN_E2EE_RELAY_URL="+productionRelayURL+"\n") {
		t.Fatalf(".env.production.local has no Production connection: %q", environment)
	}
}

func TestPushWithoutProductionSectionNeverTouchesProduction(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run("active="+strconv.FormatBool(active), func(t *testing.T) {
			directory := t.TempDir()
			value := config.New("sandbox-chat")
			value.Environments.Production = nil
			if err := config.Create(filepath.Join(directory, config.Filename), value); err != nil {
				t.Fatal(err)
			}
			console := newPushConsole(t, "sandbox-chat")
			if active {
				console.activeProduction(2_592_000)
			}
			exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push")
			result := decodeEvent(t, []byte(stdout))
			if exit != 0 || !slices.Equal(console.calls, []string{"plan sandbox", "deploy sandbox"}) {
				t.Fatalf("a push without a Production section called %v: exit=%d %s", console.calls, exit, stdout)
			}
			production := environmentResult(t, result, "production")
			switch {
			case active && (production["status"] != "skipped" || production["reason"] != "not_in_file"):
				t.Fatalf("an active Production was not reported as left as it is: %s", stdout)
			case !active && production != nil:
				t.Fatalf("a Production that is not active was reported: %s", stdout)
			}
			if _, err := os.Stat(filepath.Join(directory, ".env.production.local")); !os.IsNotExist(err) {
				t.Fatalf("the push wrote the Production connection: %v", err)
			}
		})
	}
}

func TestPushProductionChangeWithoutYesIsConfirmationRequired(t *testing.T) {
	directory := initializedProject(t, "consent-chat")
	console := newPushConsole(t, "consent-chat")
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || result.Code != "CONFIRMATION_REQUIRED" || result.Next != "oe config push --yes" {
		t.Fatalf("a Production change without --yes was not CONFIRMATION_REQUIRED: exit=%d %s", exit, stdout)
	}
	if !strings.Contains(result.Error, "one of the two Free Production projects") {
		t.Fatalf("the refusal did not name the Free slot that the activation uses: %s", result.Error)
	}
	if pushStatus(t, result, "sandbox") != "applied" || pushStatus(t, result, "production") != "blocked" {
		t.Fatalf("the refusal did not report Sandbox applied and Production blocked: %s", stdout)
	}
	if slices.Contains(console.calls, "deploy production") {
		t.Fatalf("a Production change without consent reached the deploy: %v", console.calls)
	}
}

func TestPushSandboxFailureSkipsProduction(t *testing.T) {
	directory := initializedProject(t, "conflict-chat")
	console := newPushConsole(t, "conflict-chat")
	console.fail["deploy sandbox"] = &control.APIError{Status: 409, Code: "REVISION_CONFLICT", Message: "The project changed."}
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || result.Code != "REVISION_CONFLICT" {
		t.Fatalf("a Sandbox failure did not fail the push with its code: exit=%d %s", exit, stdout)
	}
	if !slices.Equal(console.calls, []string{"plan sandbox", "deploy sandbox"}) {
		t.Fatalf("a Sandbox failure did not stop before Production: %v", console.calls)
	}
	production := environmentResult(t, result, "production")
	if pushStatus(t, result, "sandbox") != "failed" || production["status"] != "skipped" || production["reason"] != "sandbox_not_applied" {
		t.Fatalf("the push did not report Sandbox failed and Production skipped: %s", stdout)
	}
}

func TestPushPartialTakesTheFirstFailingCode(t *testing.T) {
	directory := initializedProject(t, "partial-chat")
	console := newPushConsole(t, "partial-chat")
	console.fail["deploy production"] = &control.APIError{Status: 503, Code: "AUTHORITY_UNAVAILABLE", Message: "The Relay authority is unavailable."}
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitTemporary || result.Code != "AUTHORITY_UNAVAILABLE" || result.Next != "oe config push --yes" {
		t.Fatalf("a partial push did not take the code of Production: exit=%d %s", exit, stdout)
	}
	if pushStatus(t, result, "sandbox") != "applied" || pushStatus(t, result, "production") != "failed" ||
		environmentResult(t, result, "production")["code"] != "AUTHORITY_UNAVAILABLE" {
		t.Fatalf("a partial push did not report each environment: %s", stdout)
	}
	if _, err := os.Stat(filepath.Join(directory, ".env.production.local")); !os.IsNotExist(err) {
		t.Fatalf("a failed Production deploy wrote the connection: %v", err)
	}
}

func TestPushMapsBlockedByToCodes(t *testing.T) {
	for _, test := range []struct {
		blockedBy, code, next, actionURL string
	}{
		{control.BlockedByBillingPermission, "BILLING_PERMISSION_REQUIRED", "", ""},
		{control.BlockedByTerms, "TERMS_REQUIRED", "oe auth login --accept-terms", ""},
		{control.BlockedByFreeProjectLimit, "FREE_PROJECT_LIMIT", "", ""},
		{control.BlockedByCard, "CARD_REQUIRED", "oe config push --yes", cardSetupURL},
	} {
		t.Run(test.blockedBy, func(t *testing.T) {
			directory := initializedProject(t, "gated-chat")
			console := newPushConsole(t, "gated-chat")
			console.blockProduction(test.blockedBy)
			exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
			result := decodeEvent(t, []byte(stdout))
			if exit != exitPersonAction || result.Code != test.code || result.Next != test.next || result.Action.URL != test.actionURL {
				t.Fatalf("blockedBy %s became exit=%d %s", test.blockedBy, exit, stdout)
			}
			production := environmentResult(t, result, "production")
			if pushStatus(t, result, "sandbox") != "applied" || production["status"] != "blocked" || production["code"] != test.code {
				t.Fatalf("blockedBy %s was not a blocked Production: %s", test.blockedBy, stdout)
			}
			if slices.Contains(console.calls, "deploy production") {
				t.Fatalf("a blocked Production reached the deploy: %v", console.calls)
			}
		})
	}
}

func TestPushUnderAnAgentWithoutACardExitsFiveWithActionURL(t *testing.T) {
	directory := initializedProject(t, "agent-card-chat")
	console := newPushConsole(t, "agent-card-chat")
	console.blockProduction(control.BlockedByCard)
	dependencies := pushDependencies(t, console, directory)
	dependencies.Getenv = environment(map[string]string{"CLAUDECODE": "1"})
	dependencies.Interactive = terminal
	exit, stdout, _ := run(t, dependencies, "config", "push", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || result.Code != "CARD_REQUIRED" || result.Next != "oe config push --yes" {
		t.Fatalf("an agent push without a card did not exit 5: exit=%d %s", exit, stdout)
	}
	if result.Action.URL != cardSetupURL || result.Action.Kind != "browser" || result.Action.Reason != "card" {
		t.Fatalf("an agent did not get the card page in action: %s", stdout)
	}
	if slices.Contains(console.calls, "deploy production") {
		t.Fatalf("a Production without a card reached the deploy: %v", console.calls)
	}
}

func TestPushPersonWaitsForTheCard(t *testing.T) {
	directory := initializedProject(t, "person-card-chat")
	console := newPushConsole(t, "person-card-chat")
	console.blockProduction(control.BlockedByCard)
	browser := &opener{}
	dependencies := pushDependencies(t, console, directory)
	dependencies.In, dependencies.Interactive, dependencies.OpenURL = strings.NewReader("y\n"), terminal, browser.open
	waits := 0
	dependencies.Sleep = func(context.Context, time.Duration) error {
		// The person adds the card during the second wait.
		if waits++; waits == 2 {
			console.project.Production.BlockedBy, console.project.Production.CardOnFile = "", true
		}
		return nil
	}
	exit, stdout, stderr := run(t, dependencies, "config", "push")
	if exit != 0 || waits != 2 || !slices.Equal(browser.opened, []string{cardSetupURL}) {
		t.Fatalf("a person did not wait for the card: exit=%d waits=%d opened=%v %q %q", exit, waits, browser.opened, stdout, stderr)
	}
	if !strings.Contains(stdout, "Waiting for the card") || !strings.Contains(stdout, "Card found.") || !strings.Contains(stdout, "Production is active on the Free plan.") {
		t.Fatalf("the card wait did not tell the person: %q", stdout)
	}
	if !strings.Contains(stderr, "Activate Production on the Free plan") || !strings.Contains(stderr, "[y/N]") {
		t.Fatalf("the person was not asked to consent after the card: %q", stderr)
	}
	if !slices.Contains(console.calls, "deploy production") {
		t.Fatalf("the push did not activate Production after the card: %v", console.calls)
	}
}

func TestPushDryRunWritesNothing(t *testing.T) {
	directory := initializedProject(t, "dry-chat")
	before := mustRead(t, filepath.Join(directory, config.Filename))
	console := newPushConsole(t, "dry-chat")
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--dry-run")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || !strings.HasPrefix(result.Message, "Dry run. Nothing changed.") {
		t.Fatalf("dry run failed: exit=%d %s", exit, stdout)
	}
	if !slices.Equal(console.calls, []string{"plan sandbox", "plan production"}) {
		t.Fatalf("dry run called %v", console.calls)
	}
	production := environmentResult(t, result, "production")
	if pushStatus(t, result, "sandbox") != "planned" || production["status"] != "planned" || production["activation"] != "free" {
		t.Fatalf("dry run did not report the plan: %s", stdout)
	}
	if changes, _ := production["changes"].([]any); len(changes) != 4 {
		t.Fatalf("dry run did not report the Production changes: %s", stdout)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != config.Filename || string(mustRead(t, filepath.Join(directory, config.Filename))) != string(before) {
		t.Fatalf("dry run wrote to the project directory: %v", entries)
	}
}

func TestPushNoChangeReportsUnchanged(t *testing.T) {
	directory := initializedProject(t, "steady-chat")
	console := newPushConsole(t, "steady-chat")
	console.project.Sandbox.DeliveryRetentionSeconds, console.project.Sandbox.AttachmentRetentionSeconds = 86_400, 86_400
	console.activeProduction(2_592_000)
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || pushStatus(t, result, "sandbox") != "unchanged" || pushStatus(t, result, "production") != "unchanged" || result.Next != "" {
		t.Fatalf("a push with no change did not report unchanged: exit=%d %s", exit, stdout)
	}
	if !slices.Equal(console.calls, []string{"plan sandbox", "plan production"}) {
		t.Fatalf("a push with no change deployed: %v", console.calls)
	}
	if _, err := os.Stat(filepath.Join(directory, ".env.production.local")); !os.IsNotExist(err) {
		t.Fatalf("a push with no change wrote the Production connection: %v", err)
	}
}

func TestPushIgnoresOEEnv(t *testing.T) {
	for _, selected := range []string{"sandbox", "production"} {
		directory := initializedProject(t, "variable-chat")
		console := newPushConsole(t, "variable-chat")
		dependencies := pushDependencies(t, console, directory)
		dependencies.Getenv = environment(map[string]string{"OE_ENV": selected})
		exit, stdout, _ := run(t, dependencies, "--json", "config", "push", "--yes")
		if exit != 0 || !slices.Equal(console.calls, []string{"plan sandbox", "deploy sandbox", "plan production", "deploy production"}) {
			t.Fatalf("OE_ENV=%s narrowed the push to %v: exit=%d %s", selected, console.calls, exit, stdout)
		}
	}
	directory := initializedProject(t, "narrow-chat")
	console := newPushConsole(t, "narrow-chat")
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "--env", "production", "config", "push", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || !slices.Equal(console.calls, []string{"plan production", "deploy production"}) || environmentResult(t, result, "sandbox") != nil {
		t.Fatalf("--env production did not narrow the push: %v exit=%d %s", console.calls, exit, stdout)
	}
}

func TestPushAppliesAComputedValue(t *testing.T) {
	directory := initializedProject(t, "computed-chat")
	path := filepath.Join(directory, config.Filename)
	source := string(mustRead(t, path))
	computed := strings.Replace(source, "production: {}", `production: { relay: { deliveryRetention: ["3", "d"].join("") as "3d" } }`, 1)
	if computed == source {
		t.Fatalf("the config has no Production section to compute: %s", source)
	}
	if err := os.WriteFile(path, []byte(computed), 0o644); err != nil {
		t.Fatal(err)
	}
	console := newPushConsole(t, "computed-chat")
	exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
	if exit != 0 {
		t.Fatalf("a computed value failed the push: exit=%d %s", exit, stdout)
	}
	if production := console.deployed["production"]; production.Policy.DeliveryRetentionSeconds != 3*86_400 || production.Policy.AttachmentRetentionSeconds != 2_592_000 {
		t.Fatalf("the push did not apply the computed value: %#v", production.Policy)
	}
	if after := string(mustRead(t, path)); after != computed {
		t.Fatalf("the push changed %s: %q", config.Filename, after)
	}
}

func TestDeployAndPlanAreUsageErrorsNamingPushDryRun(t *testing.T) {
	for _, args := range [][]string{{"plan"}, {"deploy"}, {"deploy", "--confirm"}, {"diff"}} {
		exit, stdout, _ := run(t, Dependencies{WorkingDir: initializedProject(t, "old-chat")}, append([]string{"--json"}, args...)...)
		result := decodeEvent(t, []byte(stdout))
		if exit != exitUsage || result.Code != "USAGE_ERROR" || result.Next != "oe config push --dry-run" || !strings.Contains(result.Error, "oe config push") {
			t.Fatalf("oe %v was not a usage error that names oe config push --dry-run: exit=%d %s", args, exit, stdout)
		}
	}
}

// TestConfigWritesIgnoreTheLockFile proves that oe config push and oe config
// pull keep the lock file that they leave out of version control, in a
// directory that oe new and oe link did not set up.
func TestConfigWritesIgnoreTheLockFile(t *testing.T) {
	ignored := func(t *testing.T, directory string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(directory, projectlock.Filename)); err != nil {
			t.Fatalf("the command left no lock file: %v", err)
		}
		if contents := string(mustRead(t, filepath.Join(directory, ".gitignore"))); !strings.HasPrefix(contents, "node_modules\n"+projectlock.Filename+"\n") {
			t.Fatalf(".gitignore is %q", contents)
		}
	}
	gitignore := func(t *testing.T, directory string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, ".gitignore"), []byte("node_modules"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("push", func(t *testing.T) {
		directory := initializedProject(t, "push-chat")
		gitignore(t, directory)
		console := newPushConsole(t, "push-chat")
		exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
		if exit != 0 {
			t.Fatalf("push failed: exit=%d %s", exit, stdout)
		}
		ignored(t, directory)
	})
	t.Run("pull", func(t *testing.T) {
		directory, _ := projectWith(t, sandboxOnly)
		gitignore(t, directory)
		dependencies, _ := pullServer(t, "pull-chat", retention(day, day), retention(7*day, 30*day))
		dependencies.WorkingDir = directory
		exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
		if exit != 0 {
			t.Fatalf("pull failed: exit=%d %s", exit, stdout)
		}
		ignored(t, directory)
	})
}

func TestPushCarriesRelayReceipts(t *testing.T) {
	for _, test := range []struct {
		name                string
		from, to            string
		sandbox, production bool
	}{
		{"default on", "", "", true, true},
		{
			"shared off",
			"    attachmentRetention: \"30d\",\n  },",
			"    attachmentRetention: \"30d\",\n    relayReceipts: false,\n  },",
			false, false,
		},
		{
			"sandbox override off",
			`relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`,
			`relay: { deliveryRetention: "1d", attachmentRetention: "1d", relayReceipts: false },`,
			false, true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := strings.Replace(sandboxOnly, "\n  },\n});", "\n    production: {},\n  },\n});", 1)
			source = strings.Replace(source, "relay: {\n        deliveryRetention: \"1d\",\n        attachmentRetention: \"1d\",\n      },",
				`relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`, 1)
			if !strings.Contains(source, test.from) {
				t.Fatalf("the source has no %q", test.from)
			}
			directory, _ := projectWith(t, strings.Replace(source, test.from, test.to, 1))
			console := newPushConsole(t, "pull-chat")
			console.activeProduction(2_592_000)

			exit, stdout, _ := run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--dry-run")
			if exit != 0 {
				t.Fatalf("the dry run failed: exit=%d %s", exit, stdout)
			}
			// The console holds relayReceipts on, so only a change to off is
			// a planned change.
			for name, want := range map[string]bool{"sandbox": test.sandbox, "production": test.production} {
				changes, _ := environmentResult(t, decodeEvent(t, []byte(stdout)), name)["changes"].([]any)
				planned := slices.ContainsFunc(changes, func(change any) bool {
					fields, _ := change.(map[string]any)
					return fields["path"] == "relay.relayReceipts" && fields["before"] == true && fields["after"] == false
				})
				if planned == want {
					t.Fatalf("the %s dry run planned relayReceipts %v, want %v: %s", name, !planned, want, stdout)
				}
			}

			exit, stdout, _ = run(t, pushDependencies(t, console, directory), "--json", "config", "push", "--yes")
			if exit != 0 {
				t.Fatalf("the push failed: exit=%d %s", exit, stdout)
			}
			// Sandbox always deploys, because its retention changes. Production
			// deploys only when relayReceipts changes.
			for name, want := range map[string]bool{"sandbox": test.sandbox, "production": test.production} {
				deploy, ok := console.deployed[name]
				if !ok && name == "production" && want {
					continue
				}
				if !ok || deploy.Policy.RelayReceipts != want {
					t.Fatalf("the %s deploy sent %#v (deployed %v), want relayReceipts %v", name, deploy.Policy, ok, want)
				}
				if receipts := console.environment(name).RelayReceipts; receipts == nil || *receipts != want {
					t.Fatalf("the console holds relayReceipts %v for %s, want %v", receipts, name, want)
				}
			}
		})
	}
}

func TestPullWritesRelayReceipts(t *testing.T) {
	off := func(environment *control.ProjectEnvironment) *control.ProjectEnvironment {
		environment.RelayReceipts = new(false)
		return environment
	}
	for _, test := range []struct {
		name                string
		sandbox, production *control.ProjectEnvironment
		path                string
		action              string
		from                any
		want                map[string]bool
	}{
		{
			"sandbox off replaces the shared value",
			off(retention(day, day)), nil,
			"environments.sandbox.relay.relayReceipts", "replace", true,
			map[string]bool{"sandbox": false},
		},
		{
			"production off adds an override",
			retention(day, day), off(retention(30*day, 30*day)),
			"environments.production.relay.relayReceipts", "add", nil,
			map[string]bool{"sandbox": true, "production": false},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory, path := projectWith(t, sandboxOnly)
			dependencies, _ := pullServer(t, "pull-chat", test.sandbox, test.production)
			dependencies.WorkingDir = directory

			exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "--yes")
			result := decodeEvent(t, []byte(stdout))
			if exit != 0 || result.Data["changed"] != true {
				t.Fatalf("the pull did not apply: exit=%d %s", exit, stdout)
			}
			name := strings.Split(test.path, ".")[1]
			changes, _ := entry(t, result, name)["changes"].([]any)
			if len(changes) != 1 {
				t.Fatalf("the %s pull made %d changes, want 1: %s", name, len(changes), stdout)
			}
			change := changes[0].(map[string]any)
			if change["path"] != test.path || change["action"] != test.action || change["from"] != test.from || change["to"] != false {
				t.Fatalf("the pull change is %#v", change)
			}
			value := mustLoad(t, path)
			for environment, want := range test.want {
				if policy, err := value.RelayPolicyFor(environment); err != nil || policy.RelayReceipts != want {
					t.Fatalf("the %s policy is %#v (%v), want relayReceipts %v", environment, policy, err, want)
				}
			}
			if !value.Relay.RelayReceipts {
				t.Fatalf("the pull changed the shared policy: %#v", value.Relay)
			}
		})
	}

	t.Run("a read without relayReceipts", func(t *testing.T) {
		directory, path := projectWith(t, sandboxOnly)
		before := mustRead(t, path)
		sandbox := retention(day, day)
		sandbox.RelayReceipts = nil
		dependencies, _ := pullServer(t, "pull-chat", sandbox, nil)
		dependencies.WorkingDir = directory
		exit, stdout, _ := run(t, dependencies, "--json", "config", "pull", "--yes")
		if exit == 0 || !strings.Contains(stdout, "no relayReceipts for the sandbox environment") {
			t.Fatalf("a pull guessed a missing relayReceipts: exit=%d %s", exit, stdout)
		}
		if after := mustRead(t, path); string(after) != string(before) {
			t.Fatalf("the refused pull changed the file:\n%s", after)
		}
	})
}
