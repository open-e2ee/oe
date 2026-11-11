package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/skills"
)

// v2Source returns source, a config file in the config-v3.json form, in the
// deprecated config-v2.json form.
func v2Source(source string) string {
	return strings.ReplaceAll(source, "signalRelay", "relay")
}

// TestEveryDualNameReaderStaysUntilTheContractRelease fails when a reader
// of an old OpenE2EE Signal Protocol Relay name goes before v7.0.0. Each
// case reads one input under the old name and the same input under the new
// name. The v7.0.0 contract release removes the readers and this test.
func TestEveryDualNameReaderStaysUntilTheContractRelease(t *testing.T) {
	const scopeWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"scope"}`
	const readinessWire = `{"relayScopeId":"scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"reason":null}`
	// rename returns input with each old name replaced by the new name.
	rename := func(old, new string) func(string) string {
		return func(input string) string { return strings.ReplaceAll(input, old, new) }
	}
	readers := []struct {
		item     string
		old, new string
		input    string
		rename   func(string) string
		read     func(string) bool
	}{
		{"oe-01 config file", "relay", "signalRelay", v2Source(initialSource(t)), func(string) string { return initialSource(t) }, func(source string) bool {
			_, path := projectWith(t, source)
			value, err := config.Load(path)
			return err == nil && value.SignalProtocolRelay.DeliveryRetention == "30d"
		}},
		{"oe-02 project receipts", "relayReceipts", "signalRelayReceipts", `{"relayReceipts":false}`, nil,
			decodes(func(environment control.ProjectEnvironment) bool {
				return environment.SignalProtocolRelayReceipts != nil && !*environment.SignalProtocolRelayReceipts
			})},
		{"oe-08 project URL", "relayUrl", "signalRelayUrl", `{"relayUrl":"https://r"}`, nil,
			decodes(func(environment control.ProjectEnvironment) bool {
				return environment.SignalProtocolRelayURL == "https://r"
			})},
		{"oe-08 deployment URL", "relayUrl", "signalRelayUrl", `{"relayUrl":"https://r"}`, nil,
			decodes(func(deployment control.Deployment) bool { return deployment.SignalProtocolRelayURL == "https://r" })},
		{"oe-09 bootstrap URL", "sandboxRelayUrl", "sandboxSignalProtocolRelayUrl", `{"sandboxRelayUrl":"https://r"}`, nil,
			decodes(func(bootstrap control.Bootstrap) bool { return bootstrap.SandboxSignalProtocolRelayURL == "https://r" })},
		{"oe-10 reported MAU", "relayMau", "signalRelayMau", `{"relayMau":"5"}`, nil,
			decodes(func(reported control.UsageReported) bool {
				return reported.SignalProtocolRelayMAU != nil && *reported.SignalProtocolRelayMAU == "5"
			})},
		{"oe-10 MAU limit", "relayMau", "signalRelayMau", `{"relayMau":5}`, nil,
			decodes(func(limits control.UsageLimits) bool { return limits.SignalProtocolRelayMAU == 5 })},
		{"oe-11 identity scope", "relayScopeId", "signalRelayScopeId", scopeWire, nil,
			decodes(func(identity.Scope) bool { return true })},
		{"oe-11 admission readiness", "relayScopeId", "signalRelayScopeId", readinessWire, nil,
			decodes(func(identity.AdmissionReadiness) bool { return true })},
		{"oe-13 installed skill", "open-e2ee-relay-config", "open-e2ee-signal-relay-config", "open-e2ee-relay-config", nil, func(name string) bool {
			root := t.TempDir()
			file := filepath.Join(root, ".agents", "skills", name, "SKILL.md")
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("skill"), 0o644); err != nil {
				t.Fatal(err)
			}
			return skills.Installed(root)
		}},
	}
	for _, reader := range readers {
		if reader.rename == nil {
			reader.rename = rename(reader.old, reader.new)
		}
		renamed := reader.rename(reader.input)
		if renamed == reader.input {
			t.Fatalf("%s: the input does not use the old name %s", reader.item, reader.old)
		}
		if !reader.read(reader.input) {
			t.Errorf("%s: oe no longer reads the old name %s", reader.item, reader.old)
		}
		if !reader.read(renamed) {
			t.Errorf("%s: oe does not read the new name %s", reader.item, reader.new)
		}
	}
	for _, failure := range []struct {
		problem      *problem
		code, legacy string
	}{
		{connectionStale("sandbox"), "SIGNAL_RELAY_CONNECTION_STALE", "RELAY_CONNECTION_STALE"},
		{connectionMissing("sandbox", ".env.local", "oe link"), "SIGNAL_RELAY_CONNECTION_MISSING", "RELAY_CONNECTION_MISSING"},
	} {
		if failure.problem.code != failure.code || failure.problem.data["legacyCode"] != failure.legacy {
			t.Errorf("oe-06 doctor code %s: oe no longer gives the old code %s in data.legacyCode", failure.code, failure.legacy)
		}
	}
}

// TestPlanMeaningStaysUntilTheContractRelease fails when planMeaning stops
// reading the two spellings of a plan ID as one plan before v7.0.0, and when
// oe v7.0.0 ships with planMeaning. The Homebrew formula names the latest oe
// release. The v7.0.0 contract release removes planMeaning and this test.
func TestPlanMeaningStaysUntilTheContractRelease(t *testing.T) {
	if planMeaning("signal_relay_starter_v1") != planMeaning("relay_starter_v1") {
		t.Errorf("oe no longer reads signal_relay_starter_v1 and relay_starter_v1 as one plan")
	}
	formula := string(mustRead(t, filepath.Join("..", "..", "Formula", "oe.rb")))
	release := regexp.MustCompile(`refs/tags/v([0-9]+)\.[0-9]+\.[0-9]+`).FindStringSubmatch(formula)
	if release == nil {
		t.Fatalf("the Homebrew formula names no oe release:\n%s", formula)
	}
	if major, err := strconv.Atoi(release[1]); err != nil || major >= 7 {
		t.Errorf("oe %s shipped with planMeaning; the v7.0.0 contract release removes it", strings.TrimPrefix(release[0], "refs/tags/"))
	}
}

// TestDoctorKeepsTheOldCodeInLegacyCode proves that the JSON output of each
// renamed doctor diagnostic gives the oe 5 code in data.legacyCode.
func TestDoctorKeepsTheOldCodeInLegacyCode(t *testing.T) {
	directory := initializedProject(t, "legacy-chat")
	exit, stdout, _ := run(t, Dependencies{WorkingDir: directory}, "--json", "--env", "sandbox", "doctor")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitFailure || failure.Code != "SIGNAL_RELAY_CONNECTION_MISSING" ||
		failure.Data["legacyCode"] != "RELAY_CONNECTION_MISSING" {
		t.Fatalf("doctor of a missing connection gave exit=%d %s", exit, stdout)
	}

	t.Setenv("OPEN_E2EE_ACCESS_TOKEN", "")
	const stale = "https://signal-relay.example/signal/v1/connection/pk_sandbox_old"
	if err := writeSignalProtocolRelayEnvironment(directory, ".env.local", envfile.Default, stale, noWarning(t)); err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "legacy-chat", Writer: "config", Sandbox: projectEnvironment(sandboxSignalProtocolRelayURL, "1")}, nil
	}}
	exit, stdout, _ = run(t, Dependencies{API: api, Store: store, WorkingDir: directory}, "--json", "--env", "sandbox", "doctor")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitFailure || failure.Code != "SIGNAL_RELAY_CONNECTION_STALE" ||
		failure.Data["legacyCode"] != "RELAY_CONNECTION_STALE" {
		t.Fatalf("doctor of a stale connection gave exit=%d %s", exit, stdout)
	}
}

// decodes returns a reader that decodes data into a new T and reports
// whether field accepts the value.
func decodes[T any](field func(T) bool) func(string) bool {
	return func(data string) bool {
		var value T
		return json.Unmarshal([]byte(data), &value) == nil && field(value)
	}
}

// initialSource is the config file that oe new writes.
func initialSource(t *testing.T) string {
	t.Helper()
	return string(mustRead(t, filepath.Join(initializedProject(t, "names-chat"), config.Filename)))
}

func TestDoctorWarnsAboutTheDeprecatedConfigKeys(t *testing.T) {
	for _, test := range []struct {
		name string
		v2   bool
	}{{"config-v2.json", true}, {"config-v3.json", false}} {
		t.Run(test.name, func(t *testing.T) {
			source := initialSource(t)
			if test.v2 {
				source = v2Source(source)
			}
			directory, _ := projectWith(t, source)
			exit, stdout, stderr := run(t, Dependencies{WorkingDir: directory}, "--json", "--env", "sandbox", "doctor")
			if failure := decodeEvent(t, []byte(stdout)); exit != exitFailure || failure.Code != "SIGNAL_RELAY_CONNECTION_MISSING" {
				t.Fatalf("doctor of a project with no env file gave exit=%d %s", exit, stdout)
			}
			warned := strings.Contains(stderr, "uses the deprecated relay and relayReceipts keys") &&
				strings.Contains(stderr, "signalRelay and signalRelayReceipts") && strings.Contains(stderr, "v7.0.0")
			if warned != test.v2 {
				t.Fatalf("doctor of a %s file warned=%t: %q", test.name, warned, stderr)
			}
		})
	}
}

// TestPullOfAV2FileKeepsTheRelayKeys proves that a pull writes the keys of
// the file that it edits, and names the change with those keys.
func TestPullOfAV2FileKeepsTheRelayKeys(t *testing.T) {
	directory, path := projectWith(t, v2Source(sandboxOnly))
	dependencies, _ := pullServer(t, "pull-chat", retention(day, day), retention(7*day, 30*day))
	dependencies.WorkingDir = directory

	exit, stdout, _ := run(t, dependencies, "--json", "config", "pull")
	result := decodeEvent(t, []byte(stdout))
	changes, _ := entry(t, result, "production")["changes"].([]any)
	if exit != 0 || len(changes) != 1 {
		t.Fatalf("the pull of a v2 file did not apply one change: exit=%d %s", exit, stdout)
	}
	if path := changes[0].(map[string]any)["path"]; path != "environments.production.relay.deliveryRetention" {
		t.Fatalf("the change path is %v, want the relay key of the file", path)
	}
	source := string(mustRead(t, path))
	if strings.Contains(source, "signalRelay") {
		t.Fatalf("the pull wrote a signalRelay key into a v2 file:\n%s", source)
	}
	value := mustLoad(t, path)
	policy, err := value.SignalProtocolRelayPolicyFor("production")
	if err != nil || value.Format != config.FormatV2 || policy.DeliveryRetention != "7d" {
		t.Fatalf("the pull did not write the value in the v2 form: %#v %v\n%s", policy, err, source)
	}
}
