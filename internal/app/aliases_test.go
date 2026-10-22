package app

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

func TestCommandAliasesUseCanonicalResults(t *testing.T) {
	zero := "0"
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	dependencies := Dependencies{
		Store: store, WorkingDir: initializedProject(t, "local-chat"),
		API: &fakeAPI{
			getProject: func(_ context.Context, _ control.CredentialRequest, slug string) (control.Project, error) {
				return control.Project{Slug: slug, Writer: "config", Sandbox: projectEnvironment(sandboxRelayURL, "1"), Production: projectEnvironment(productionRelayURL, "2")}, nil
			},
			listProjects: func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error) {
				return []control.ProjectSummary{{Slug: "local-chat"}}, nil
			},
			projectUsage: func(_ context.Context, _ control.CredentialRequest, slug, environment string) (control.Usage, error) {
				return control.Usage{Project: slug, Environment: environment, Period: "2026-10", Status: "no_usage", Reported: &control.UsageReported{
					DeliveryUnits: &zero, AttachmentOperations: &zero, RelayMAU: &zero, LiveBytes: "0",
				}}, nil
			},
			session: func(context.Context, control.CredentialRequest) (control.Session, error) {
				return control.Session{User: control.SessionUser{ID: "user_one", Email: "a@example.com"}, Organization: control.SessionOrganization{ID: "org_one", Name: "Acme"}, Role: "admin"}, nil
			},
			terms: func(context.Context, control.CredentialRequest) (control.Terms, error) {
				return control.Terms{State: control.TermsAccepted}, nil
			},
			listOrganizations: func(context.Context, control.CredentialRequest) (control.OrganizationList, error) {
				return control.OrganizationList{Current: "org_one", Organizations: []control.Organization{{ID: "org_one", Name: "Acme", Role: "admin"}}}, nil
			},
			notifications: func(_ context.Context, _ control.CredentialRequest, _, environment string) (control.NotificationConfiguration, error) {
				return control.NotificationConfiguration{Environment: environment, ConfigurationVersion: 1}, nil
			},
		},
	}
	for _, test := range []struct {
		canonical []string
		aliases   [][]string
	}{
		{[]string{"project", "show"}, [][]string{{"project"}, {"app"}, {"project", "view"}, {"app", "show"}, {"app", "view"}}},
		{[]string{"project", "show", "local-chat", "--env", "production"}, [][]string{{"project", "view", "local-chat", "--env", "production"}, {"app", "view", "local-chat", "--env", "production"}}},
		{[]string{"project", "list"}, [][]string{{"projects"}, {"apps"}, {"app", "list"}, {"projects", "list"}, {"apps", "list"}}},
		{[]string{"project", "usage", "local-chat"}, [][]string{{"app", "usage", "local-chat"}}},
		{[]string{"project", "connection", "local-chat"}, [][]string{{"app", "connection", "local-chat"}}},
		{[]string{"auth", "status"}, [][]string{{"auth"}}},
		{[]string{"org", "show"}, [][]string{{"org"}, {"org", "view"}}},
		{[]string{"org", "list"}, [][]string{{"orgs"}, {"organizations"}}},
		{[]string{"notifications", "status"}, [][]string{{"notifications"}}},
		{[]string{"agent", "setup", "--check"}, [][]string{{"agent"}, {"agent", "status"}}},
	} {
		canonicalArgs := append([]string{"--json"}, test.canonical...)
		wantExit, wantOutput, _ := run(t, dependencies, canonicalArgs...)
		want := decodeEvent(t, []byte(wantOutput))
		for _, alias := range test.aliases {
			t.Run(strings.Join(alias, " "), func(t *testing.T) {
				aliasArgs := append([]string{"--json"}, alias...)
				exit, stdout, _ := run(t, dependencies, aliasArgs...)
				got := decodeEvent(t, []byte(stdout))
				if exit != wantExit || got.Command != want.Command || got.Code != want.Code || !reflect.DeepEqual(got.Data, want.Data) {
					t.Fatalf("alias exit=%d result=%#v; canonical exit=%d result=%#v", exit, got, wantExit, want)
				}
			})
		}
	}
}

func TestProjectAliasDoesNotSelectAnUnlinkedProject(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{listProjects: func(context.Context, control.CredentialRequest) ([]control.ProjectSummary, error) {
		t.Fatal("a project shortcut listed projects to pick one")
		return nil, nil
	}}
	for _, alias := range [][]string{{"project"}, {"app"}, {"app", "view"}} {
		exit, stdout, _ := run(t, Dependencies{Store: store, API: api, WorkingDir: t.TempDir()}, append([]string{"--json"}, alias...)...)
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitFailure || failure.Command != "project show" || failure.Code != "CONFIG_NOT_FOUND" {
			t.Fatalf("%q selected an unlinked project: exit=%d %s", alias, exit, stdout)
		}
	}
	exit, stdout, _ := run(t, Dependencies{Store: store, API: api, WorkingDir: t.TempDir()}, "--json", "project", "my-chat")
	if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" {
		t.Fatalf("oe project my-chat became an alias: exit=%d %s", exit, stdout)
	}
}

func TestProjectViewAliasesKeepTheCanonicalFailure(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	dependencies := Dependencies{Store: store, WorkingDir: initializedProject(t, "local-chat")}
	for _, args := range [][]string{{"project", "show", "Bad_Slug"}, {"project", "view", "Bad_Slug"}, {"app", "view", "Bad_Slug"}} {
		exit, stdout, _ := run(t, dependencies, append([]string{"--json"}, args...)...)
		failure := decodeEvent(t, []byte(stdout))
		if exit != exitUsage || failure.Command != "project show" || failure.Code != "PROJECT_INVALID" {
			t.Fatalf("%q changed the project read error: exit=%d %s", args, exit, stdout)
		}
	}
	wantExit, wantOutput, _ := run(t, dependencies, "--json", "project", "show", "local-chat", "--env")
	for _, args := range [][]string{{"project", "view", "local-chat", "--env"}, {"app", "view", "local-chat", "--env"}} {
		exit, stdout, _ := run(t, dependencies, append([]string{"--json"}, args...)...)
		if exit != wantExit || stdout != wantOutput {
			t.Fatalf("%q changed a global flag error: exit=%d %s, want exit=%d %s", args, exit, stdout, wantExit, wantOutput)
		}
	}
}

func TestOrgShowRequiresASelectedOrganization(t *testing.T) {
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	api := &fakeAPI{session: func(context.Context, control.CredentialRequest) (control.Session, error) {
		return control.Session{}, nil
	}}
	exit, stdout, _ := run(t, Dependencies{Store: store, API: api}, "--json", "org")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || failure.Command != "org show" || failure.Code != "ORGANIZATION_REQUIRED" || failure.Next != "oe org switch" {
		t.Fatalf("org show without a selected organization: exit=%d %s", exit, stdout)
	}
}
