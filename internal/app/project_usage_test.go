package app

import (
	"context"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

func usageDependencies(t *testing.T, read func(string) control.Usage) Dependencies {
	t.Helper()
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	return Dependencies{
		Store: store, WorkingDir: initializedProject(t, "local-chat"),
		API: &fakeAPI{
			getProject: func(_ context.Context, _ control.CredentialRequest, slug string) (control.Project, error) {
				return control.Project{Slug: slug, Sandbox: projectEnvironment(sandboxSignalProtocolRelayURL, "1"), Production: projectEnvironment(productionSignalProtocolRelayURL, "1")}, nil
			},
			projectUsage: func(_ context.Context, auth control.CredentialRequest, slug, environment string) (control.Usage, error) {
				if auth.AccessToken == "" || slug != "local-chat" || environment != "sandbox" {
					t.Fatalf("usage read used wrong auth, project, or environment: %q %q %q", auth.AccessToken, slug, environment)
				}
				return read(slug), nil
			},
		},
	}
}

func TestProjectUsageDefaultsToDirectoryAndShowsVerifiedZero(t *testing.T) {
	zero := "0"
	dependencies := usageDependencies(t, func(slug string) control.Usage {
		return control.Usage{
			Project: slug, Environment: "sandbox", Period: "2026-10", Status: "no_usage",
			Reported: &control.UsageReported{DeliveryUnits: &zero, AttachmentOperations: &zero, SignalProtocolRelayMAU: &zero, LiveBytes: "0"},
		}
	})
	exit, stdout, _ := run(t, dependencies, "project", "usage")
	if exit != 0 || !strings.Contains(stdout, "No usage yet.") || !strings.Contains(stdout, "Delivery units: 0") {
		t.Fatalf("verified zero was not shown: exit=%d %s", exit, stdout)
	}
	exit, stdout, _ = run(t, dependencies, "--json", "project", "usage")
	usage, _ := decodeEvent(t, []byte(stdout)).Data["usage"].(map[string]any)
	if exit != 0 || usage["project"] != "local-chat" || usage["status"] != "no_usage" {
		t.Fatalf("JSON usage did not name the directory project: exit=%d %s", exit, stdout)
	}
}

func TestProjectUsageFailsWhenReportingCannotConfirmZero(t *testing.T) {
	for _, status := range []string{"unknown", "unavailable", "no_usage"} {
		dependencies := usageDependencies(t, func(slug string) control.Usage {
			return control.Usage{Project: slug, Environment: "sandbox", Period: "2026-10", Status: status}
		})
		exit, stdout, _ := run(t, dependencies, "--json", "project", "usage")
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitTemporary || failure.Code != "USAGE_UNAVAILABLE" || strings.Contains(stdout, `"liveBytes":"0"`) {
			t.Fatalf("%s reporting was presented as usage: exit=%d %s", status, exit, stdout)
		}
	}
}

// TestProjectUsageSandboxContract pins the Sandbox usage text and JSON. MAU is
// the enforced Sandbox limit until account capacity activates, so the Relay MAU
// line stays in Sandbox usage.
func TestProjectUsageSandboxContract(t *testing.T) {
	delivery, attachments, mau := "12", "3", "4"
	dependencies := usageDependencies(t, func(slug string) control.Usage {
		return control.Usage{
			Project: slug, Environment: "sandbox", Period: "2026-11", Status: "reported",
			Reported: &control.UsageReported{DeliveryUnits: &delivery, AttachmentOperations: &attachments, SignalProtocolRelayMAU: &mau, LiveBytes: "2048"},
		}
	})
	exit, stdout, stderr := run(t, dependencies, "project", "usage")
	if want := "local-chat sandbox usage, 2026-11 UTC\nDelivery units: 12\nAttachment operations: 3\nRelay MAU: 4\nLive bytes: 2048\n"; exit != 0 || stdout != want || stderr != "" {
		t.Fatalf("Sandbox usage text changed: exit=%d\n got %q\nwant %q\nstderr %q", exit, stdout, want, stderr)
	}
	exit, stdout, stderr = run(t, dependencies, "--json", "project", "usage")
	want := `{"status":"ok","command":"project usage","message":"local-chat sandbox usage, 2026-11 UTC\nDelivery units: 12\nAttachment operations: 3\nRelay MAU: 4\nLive bytes: 2048",` +
		`"data":{"usage":{"project":"local-chat","environment":"sandbox","period":"2026-11","status":"reported",` +
		`"reported":{"deliveryUnits":"12","attachmentOperations":"3","relayMau":"4","liveBytes":"2048","signalRelayMau":"4"},"coverage":null,"limits":null}}}` + "\n"
	if exit != 0 || stdout != want || stderr != "" {
		t.Fatalf("Sandbox usage JSON changed: exit=%d\n got %q\nwant %q\nstderr %q", exit, stdout, want, stderr)
	}
}
