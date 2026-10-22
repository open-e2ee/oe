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
				return control.Project{Slug: slug, Sandbox: projectEnvironment(sandboxRelayURL, "1"), Production: projectEnvironment(productionRelayURL, "1")}, nil
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
			Reported: &control.UsageReported{DeliveryUnits: &zero, AttachmentOperations: &zero, RelayMAU: &zero, LiveBytes: "0"},
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
