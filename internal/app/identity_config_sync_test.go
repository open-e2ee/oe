package app

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
)

func publicConfigBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPublicIdentityPullEnrollmentAndExactRoundTrip(t *testing.T) {
	variants := []struct{ name, installed, desired string }{
		{"configured", configuredExecutionWire, configuredExecutionWire},
		{"clerk-explicit-false", publicClerkWire, publicClerkWire},
		{"firebase", publicFirebaseWire, publicFirebaseWire},
		{"device-owned", `{"mode":"device-owned","algorithms":["EdDSA"],"issuer":"device-authority","audience":"device-audience"}`, `{"mode":"device-owned"}`},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.current.Configuration.IdentityProfile = executionDecode[identity.InstalledProfile](t, variant.installed)
			before := publicConfigBytes(t, f.path)
			exit, out, stderr := f.run(t, "config", "pull", "--env", "sandbox")
			if exit != 0 || f.count("current") != 0 || string(publicConfigBytes(t, f.path)) != string(before) {
				t.Fatal("ordinary absent identity enrolled implicitly", exit, out, stderr)
			}
			exit, out, stderr = f.run(t, "config", "pull", "--identity", "--env", "sandbox")
			if exit != 0 || f.count("current") != 1 {
				t.Fatal("explicit identity enrollment failed", exit, out, stderr)
			}
			loaded, err := config.Load(f.path)
			if err != nil {
				t.Fatal(err)
			}
			target, err := loaded.IdentityFor("sandbox")
			expected := executionDecode[identity.SelectionTarget](t, variant.desired)
			if err != nil || target == nil || !target.Equal(expected) {
				t.Fatal("pull lost public identity policy", err)
			}
			after := publicConfigBytes(t, f.path)
			exit, out, stderr = f.run(t, "config", "pull", "--env", "sandbox")
			if exit != 0 || f.count("current") != 2 || string(publicConfigBytes(t, f.path)) != string(after) {
				t.Fatal("repeated identity pull was not exact", exit, out, stderr)
			}
			exit, out, stderr = f.run(t, "config", "push", "--dry-run", "--env", "sandbox")
			if exit != 0 {
				t.Fatal("pulled policy failed dry-run", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicIdentityPullDryRunAndUnrepresentableValuesWriteNothing(t *testing.T) {
	for _, name := range []string{"dry-run", "historical-issuer", "historical-key", "read-refusal"} {
		t.Run(name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			switch name {
			case "historical-issuer":
				text, _ := identity.Text("https://members.example/" + strings.Repeat("x", 256))
				f.current.Configuration.IdentityProfile.Issuer = &text
			case "historical-key":
				(*f.current.Configuration.IdentityProfile.Keys)[0].X = identity.TextFromUnits([]uint16{'o', 'l', 'd'})
			case "read-refusal":
				f.denyCurrent = true
			}
			before := publicConfigBytes(t, f.path)
			args := []string{"config", "pull", "--identity", "--env", "sandbox"}
			if name == "dry-run" {
				args = append(args, "--dry-run")
			}
			exit, out, stderr := f.run(t, args...)
			if (exit == 0) != (name == "dry-run") || string(publicConfigBytes(t, f.path)) != string(before) {
				t.Fatal("pull wrote despite dry-run or invalid projection", exit, out, stderr)
			}
			if name == "historical-issuer" || name == "historical-key" {
				if !strings.Contains(out, `"code":"IDENTITY_CONFIG_UNREPRESENTABLE"`) {
					t.Fatal("historical receiver was narrowed instead of projection refusal", out)
				}
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicIdentityPullPreservesCommentsAndComputedRefusal(t *testing.T) {
	for _, computed := range []bool{false, true} {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		source := string(publicConfigBytes(t, f.path))
		source = "// KEEP_PUBLIC_COMMENT\n" + source
		if computed {
			source = strings.Replace(source, `identity: {`, `identity: (() => ({`, 1)
			// Use one explicit computed section rather than splice generated braces.
			source = `// KEEP_PUBLIC_COMMENT
import { defineConfig } from "@open-e2ee/oe/config";
const policy = { mode: "device-owned" };
export default defineConfig({product:"signal-relay",project:"sample",relay:{deliveryRetention:"1d",attachmentRetention:"1d"},environments:{sandbox:{identity:policy}}});
`
		}
		if err := os.WriteFile(f.path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		exit, out, stderr := f.run(t, "config", "pull", "--identity", "--yes", "--env", "sandbox")
		after := string(publicConfigBytes(t, f.path))
		if computed {
			if exit != exitPersonAction || after != source || !strings.Contains(out, `"code":"CONFIG_EDIT_REQUIRED"`) {
				t.Fatal("computed identity was overwritten", exit, out, stderr)
			}
		} else if exit != 0 || !strings.Contains(after, "// KEEP_PUBLIC_COMMENT") {
			t.Fatal("pull lost unrelated comments", exit, out, stderr)
		}
		f.requireNoMutation(t)
	}
}

func TestPublicIdentityPullReplacementNeedsExistingConsent(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	before := publicConfigBytes(t, f.path)
	exit, out, stderr := f.run(t, "config", "pull", "--identity", "--env", "sandbox")
	if exit != exitUsage || string(publicConfigBytes(t, f.path)) != string(before) || !strings.Contains(out, "--identity") {
		t.Fatal("replacement lacked exact consent step", exit, out, stderr)
	}
	exit, out, stderr = f.run(t, "config", "pull", "--identity", "--yes", "--env", "sandbox")
	if exit != 0 || string(publicConfigBytes(t, f.path)) == string(before) {
		t.Fatal("approved pull did not replace public identity", exit, out, stderr)
	}
}

func TestPublicIdentityPushAppliesEveryDeclaredEnvironment(t *testing.T) {
	entry := func(t *testing.T, result event, name string) map[string]any {
		t.Helper()
		environments, _ := result.Data["environments"].(map[string]any)
		value, _ := environments[name].(map[string]any)
		if value == nil {
			t.Fatal("push did not report the environment", name, result)
		}
		return value
	}
	for _, source := range []string{"default", "OPEN_E2EE_ENV"} {
		t.Run(source, func(t *testing.T) {
			f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
			if source == "OPEN_E2EE_ENV" {
				f.dependencies.Getenv = func(key string) string {
					if key == "OPEN_E2EE_ENV" {
						return "sandbox"
					}
					return ""
				}
			}
			exit, out, stderr := f.run(t, "config", "push", "--dry-run")
			if exit != 0 || f.count("preview") != 2 || f.count("/v1/projects/sample/deploys/plan") != 2 {
				t.Fatal("plain identity push did not preview every declared environment", exit, out, stderr)
			}
			result := decodeEvent(t, []byte(out))
			for _, name := range []string{"sandbox", "production"} {
				entry(t, result, name)
			}
			f.requireNoMutation(t)
		})
	}
	t.Run("literal", func(t *testing.T) {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		exit, out, stderr := f.run(t, "config", "push", "--dry-run", "--env", "sandbox")
		if exit != 0 || f.count("preview") != 1 {
			t.Fatal("identity-only diff vanished behind empty retention plan", exit, out, stderr)
		}
		f.requireNoMutation(t)
	})
	t.Run("sandbox-failure-skips-production", func(t *testing.T) {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		f.lose["select"] = true
		exit, out, stderr := f.run(t, "config", "push", "--yes")
		result := decodeEvent(t, []byte(out))
		production := entry(t, result, "production")
		if exit != exitTemporary || result.Code != "IDENTITY_UNAVAILABLE" || production["status"] != "skipped" || production["reason"] != "sandbox_not_applied" ||
			!strings.HasPrefix(result.Next, "oe identity operation status --kind selection --operation-id oe_") ||
			f.count("preview") != 3 || f.count("select") != 1 || f.count("/v1/deploys") != 0 {
			t.Fatal("a Sandbox identity failure did not skip Production", exit, out, stderr)
		}
	})
	t.Run("sandbox-only-file", func(t *testing.T) {
		f := publicIdentityTestFixture(t, "")
		source := config.New("sample")
		target := executionDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
		source.Environments.Sandbox.Identity = &target
		source.Environments.Production = nil
		if err := os.Remove(f.path); err != nil {
			t.Fatal(err)
		}
		if err := config.Create(f.path, source); err != nil {
			t.Fatal(err)
		}
		exit, out, stderr := f.run(t, "config", "push", "--dry-run")
		if exit != 0 || f.count("preview") != 1 {
			t.Fatal("a Sandbox-only identity file did not preview Sandbox", exit, out, stderr)
		}
		production := entry(t, decodeEvent(t, []byte(out)), "production")
		if production["status"] != "skipped" || production["reason"] != "not_in_file" {
			t.Fatal("an active Production without a section was not reported as kept", out)
		}
		f.requireNoMutation(t)
	})
	t.Run("inactive-production", func(t *testing.T) {
		f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
		f.project.Production.State = control.ProductionInactive
		f.project.Production.Revision = ""
		f.project.Production.BlockedBy = ""
		exit, out, stderr := f.run(t, "config", "push", "--dry-run")
		result := decodeEvent(t, []byte(out))
		if exit != exitPersonAction || result.Code != "IDENTITY_ACTIVATION_REQUIRED" || entry(t, result, "sandbox")["identity"] == nil || f.count("preview") != 1 {
			t.Fatal("inactive Production did not keep its separate activation phase", exit, out, stderr)
		}
		f.requireNoMutation(t)
	})
}

func TestPublicIdentityPushDoesNotReuseGenericOperationEnvironment(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.dependencies.Getenv = func(key string) string {
		if key == "OPEN_E2EE_OPERATION_ID" {
			return "retained_exact_001"
		}
		return ""
	}
	exit, out, stderr := f.run(t, "config", "push", "--env", "sandbox")
	if exit != exitUsage || f.count("/v1/projects/sample/deploys/plan") != 0 || f.count("/v1/deploys") != 0 {
		t.Fatal("identity ID entered generic deployment", exit, out, stderr)
	}
}

func TestConfigPushUnchangedIdentityTouchesNoLocalState(t *testing.T) {
	actual := t.TempDir()
	home := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(actual, home); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "APPDATA"} {
		t.Setenv(name, home)
	}
	configDirectory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	f := publicIdentityTestFixture(t, configuredExecutionWire)
	f.planChanges = []control.Change{{Path: "relay.deliveryRetention", Before: "1d", After: "3d"}}
	exit, out, stderr := f.run(t, "config", "push", "--env", "sandbox")
	if exit != 0 || f.count("/v1/deploys") != 1 || f.count("select") != 0 || f.count("keys-replace") != 0 {
		t.Fatal("an unchanged identity blocked a retention-only push", exit, out, stderr)
	}
	for _, root := range []string{actual, configDirectory} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Name() == "identity-attempts" {
				t.Error("config push created local identity state", path)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
}

func TestPublicIdentityInactiveProductionHasSeparateActivationAndPreview(t *testing.T) {
	for _, dryRun := range []bool{true, false} {
		f := publicIdentityTestFixture(t, publicFirebaseWire)
		f.project.Production.State = control.ProductionInactive
		f.project.Production.Revision = ""
		f.project.Production.BlockedBy = ""
		f.planChanges = []control.Change{{Path: activationChange, After: "active"}}
		args := []string{"config", "push", "--env", "production", "--yes"}
		if dryRun {
			args = append(args, "--dry-run")
		}
		exit, out, stderr := f.run(t, args...)
		if exit != exitPersonAction || !strings.Contains(out, `"code":"IDENTITY_ACTIVATION_REQUIRED"`) || f.count("current") != 0 || f.count("preview") != 0 || f.count("select") != 0 {
			t.Fatal("activation claimed identity preview or selection", exit, out, stderr)
		}
		expectedDeploys := 1
		if dryRun {
			expectedDeploys = 0
		}
		if f.count("/v1/deploys") != expectedDeploys {
			t.Fatal("activation phase effects changed")
		}
		if !dryRun {
			exit, out, stderr = f.run(t, "config", "push", "--dry-run", "--env", "production")
			if exit != 0 || f.count("current") != 1 || f.count("preview") != 1 {
				t.Fatal("active follow-up did not use fresh identity context", exit, out, stderr)
			}
		}
	}
}

func TestPublicIdentityPullFailureIsAtomicAcrossSelectedEnvironments(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	f.hook = func(action string, r *http.Request) {
		if action == "current" && r.URL.Query().Get("environment") == "production" {
			f.denyCurrent = true
		}
	}
	before := publicConfigBytes(t, f.path)
	exit, out, stderr := f.run(t, "config", "pull", "--identity", "--yes")
	if exit == 0 || f.count("current") != 2 || string(publicConfigBytes(t, f.path)) != string(before) {
		t.Fatal("partial identity reads caused partial file edit", exit, out, stderr)
	}
	f.requireNoMutation(t)
}

func TestPublicIdentityRemovalDoesNotResetServicePolicy(t *testing.T) {
	f := publicIdentityTestFixture(t, "")
	exit, out, stderr := f.run(t, "config", "push", "--dry-run", "--env", "sandbox")
	if exit != 0 || f.count("current") != 0 || f.count("preview") != 0 || f.count("select") != 0 {
		t.Fatal("unmanaged config reset remote identity", exit, out, stderr)
	}
}

func TestPublicIdentityPlanProjectionIsDetachedAndDoesNotUseRevisionsAsCAS(t *testing.T) {
	f := publicIdentityTestFixture(t, configuredExecutionWire)
	f.project.Sandbox.Revision = "91"
	f.project.Production.Revision = "91"
	desired := executionDecode[identity.SelectionTarget](t, configuredExecutionWire)
	desired.Keys = new([]identity.SigningPublicKey{executionDecode[identity.SigningPublicKey](t, strings.Replace(keyExecutionWire, "key-one", "key-two", 1))})
	next, err := planIdentityConfig(f.current, desired)
	if err != nil || next.kind != "keys-only" || next.keys == nil {
		t.Fatal("public keys diff refused", err)
	}
	data, err := json.Marshal(next.keys)
	if err != nil || strings.Contains(string(data), "91") {
		t.Fatal("retention revision replaced identity configuration version")
	}
}

func TestPublicIdentityPushDryRunShowsIdentityChange(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	exit, out, stderr := f.run(t, "config", "push", "--dry-run", "--env", "sandbox")
	var result struct {
		Data struct {
			Environments map[string]struct {
				Identity struct {
					Changes []struct {
						Path   string `json:"path"`
						Action string `json:"action"`
						From   struct {
							Mode string `json:"mode"`
						} `json:"from"`
						To struct {
							Mode string `json:"mode"`
						} `json:"to"`
					} `json:"changes"`
				} `json:"identity"`
			} `json:"environments"`
		} `json:"data"`
	}
	if exit != 0 || json.Unmarshal([]byte(out), &result) != nil {
		t.Fatal("identity dry-run failed", exit, out, stderr)
	}
	changes := result.Data.Environments["sandbox"].Identity.Changes
	if len(changes) != 1 || changes[0].Path != "environments.sandbox.identity" || changes[0].Action != "replace" ||
		changes[0].To.Mode != "device-owned" || changes[0].From.Mode != "custom-token" {
		t.Fatal("identity dry-run did not show the identity change", out)
	}
	for _, forbidden := range []string{"verificationPolicyFingerprint", "publishableKey", "recoveryGeneration", "precondition", "scope"} {
		if strings.Contains(out+stderr, forbidden) {
			t.Fatal("identity change exposed internal context", forbidden, out)
		}
	}
	f.requireNoMutation(t)
}

func TestPublicIdentityPushRefusesProfileChangeForInUseEnvironment(t *testing.T) {
	const anchor = "https://docs.open-e2ee.dev/relay/identity#in-use-environments"
	pending, err := identity.Text("oe_pending_selection")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mark   func(*identity.Inventory)
		detail string
	}{
		{"ever-admitted", func(v *identity.Inventory) { v.EverAdmitted = true }, anchor},
		{"pending-operation", func(v *identity.Inventory) { v.PendingOperationID = &pending }, "has no final result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
			tc.mark(&f.current.Configuration.Inventory)
			exit, out, stderr := f.run(t, "config", "push", "--env", "sandbox")
			result := decodeEvent(t, []byte(out))
			if exit != exitFailure || result.Code != "IDENTITY_MIGRATION_REQUIRED" || result.Next != "oe identity current" {
				t.Fatal("in-use profile change lost its stable refusal", exit, out, stderr)
			}
			if !strings.Contains(result.Error, tc.detail) || strings.Contains(out+stderr, "migration flow") {
				t.Fatalf("refusal detail %q does not contain %q or names the retired migration flow", result.Error, tc.detail)
			}
			if tc.name == "pending-operation" && strings.Contains(result.Error, anchor) {
				t.Fatal("a pending operation without account history was called in use", result.Error)
			}
			if f.count("preview") != 0 {
				t.Fatal("refused profile change reached preview")
			}
			f.requireNoMutation(t)
		})
	}
}
