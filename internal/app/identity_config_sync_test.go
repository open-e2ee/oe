package app

import (
	"encoding/json"
	"net/http"
	"os"
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

func TestPublicIdentityPushRequiresLiteralSingleEnvironment(t *testing.T) {
	for _, source := range []string{"default", "OE_ENV", "literal"} {
		t.Run(source, func(t *testing.T) {
			f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
			args := []string{"config", "push", "--dry-run"}
			if source == "OE_ENV" {
				f.dependencies.Getenv = func(key string) string {
					if key == "OE_ENV" {
						return "sandbox"
					}
					return ""
				}
			}
			if source == "literal" {
				args = append(args, "--env", "sandbox")
			}
			exit, out, stderr := f.run(t, args...)
			if source == "literal" {
				if exit != 0 || f.count("preview") != 1 {
					t.Fatal("identity-only diff vanished behind empty retention plan", exit, out, stderr)
				}
			} else if exit != exitUsage || f.count("current") != 0 || f.count("/v1/projects/sample/deploys/plan") != 0 {
				t.Fatal("implicit multi-environment identity push accepted", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicIdentityPushDoesNotReuseGenericOperationEnvironment(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.dependencies.Getenv = func(key string) string {
		if key == "OE_OPERATION_ID" {
			return "retained_exact_001"
		}
		return ""
	}
	exit, out, stderr := f.run(t, "config", "push", "--env", "sandbox")
	if exit != exitUsage || f.count("/v1/projects/sample/deploys/plan") != 0 || f.count("/v1/deploys") != 0 {
		t.Fatal("identity ID entered generic deployment", exit, out, stderr)
	}
}

func TestPublicIdentityPushLocalStateGuardPrecedesRetentionMutation(t *testing.T) {
	f := publicIdentityTestFixture(t, `{"mode":"device-owned"}`)
	f.planChanges = []control.Change{{Path: "relay.deliveryRetention", Before: "1d", After: "3d"}}
	exit, out, stderr := f.run(t, "config", "push", "--env", "sandbox")
	attempts := f.dependencies.IdentityAttempts.(*identityCountingFactory)
	if exit == 0 || attempts.opens != 1 || f.count("/v1/deploys") != 0 || f.count("select") != 0 {
		t.Fatal("unavailable retained state allowed retention or selection mutation", exit, out, stderr)
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
		attempts := f.dependencies.IdentityAttempts.(*identityCountingFactory)
		if attempts.opens != 0 || attempts.bootstraps != 0 {
			t.Fatal("activation initialized identity state")
		}
		if !dryRun {
			exit, out, stderr = f.run(t, "config", "push", "--dry-run", "--env", "production")
			if exit != 0 || f.count("current") != 1 || f.count("preview") != 1 {
				t.Fatal("active follow-up did not use fresh identity context", exit, out, stderr)
			}
		}
	}
}

func TestPublicIdentityActivationRejectsFirstUseDeclarationsBeforePlan(t *testing.T) {
	f := publicIdentityTestFixture(t, publicFirebaseWire)
	f.project.Production.State = control.ProductionInactive
	exit, out, stderr := f.run(t, "config", "push", "--env", "production", "--yes", "--confirm-state-never-used", "--confirm-slot-never-used")
	if exit != exitUsage || f.count("/v1/projects/sample/deploys/plan") != 0 || f.count("/v1/deploys") != 0 {
		t.Fatal("activation accepted identity first-use declaration", exit, out, stderr)
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
