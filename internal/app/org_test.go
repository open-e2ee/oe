package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

// recordingStore records each Set in a log that the fake API shares, so a
// test can prove the order of the refresh, the store, and the session check.
type recordingStore struct {
	credential.Store
	log *[]string
}

func (s recordingStore) Set(profile string, value credential.Credential) error {
	*s.log = append(*s.log, "set "+value.AccessToken)
	return s.Store.Set(profile, value)
}

func switchable(value bool) *bool { return &value }

// orgFixture is a stored session in Acme Inc. that needs no refresh, the
// organization list of its person, and a fake API that logs each refresh and
// each session read.
type orgFixture struct {
	store   recordingStore
	memory  *credential.Memory
	log     *[]string
	api     *fakeAPI
	list    control.OrganizationList
	profile string
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	t.Setenv("OE_ACCESS_TOKEN", "")
	profile, err := credential.Profile(defaultControlURL)
	if err != nil {
		t.Fatal(err)
	}
	memory := credential.NewMemory()
	if err := memory.Set(profile, credential.Credential{
		AccessToken: "old-token", RefreshToken: "old-refresh",
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	log := &[]string{}
	fixture := &orgFixture{
		store: recordingStore{Store: memory, log: log}, memory: memory, log: log, profile: profile,
		list: control.OrganizationList{SchemaVersion: 1, Current: "org_acme", Organizations: []control.Organization{
			{ID: "org_acme", Name: "Acme Inc.", Role: "admin"},
			{ID: "org_beta", Name: "Beta LLC", Role: "member"},
			{ID: "org_gamma_one", Name: "Gamma", Role: "member"},
			{ID: "org_gamma_two", Name: "gamma", Role: "admin"},
		}},
	}
	names := map[string]string{"org_acme": "Acme Inc.", "org_beta": "Beta LLC", "org_gamma_one": "Gamma", "org_gamma_two": "gamma"}
	organizationOf := map[string]string{"old-token": "org_acme"}
	fixture.api = &fakeAPI{
		listOrganizations: func(_ context.Context, request control.CredentialRequest) (control.OrganizationList, error) {
			if request.AccessToken != "old-token" {
				t.Errorf("the list read used %q", request.AccessToken)
			}
			return fixture.list, nil
		},
		refreshAuthorization: func(_ context.Context, refreshToken, organizationID string) (control.Token, error) {
			*log = append(*log, "refresh "+organizationID)
			if refreshToken != "old-refresh" {
				t.Errorf("the switch refreshed with %q", refreshToken)
			}
			organizationOf["new-token"] = organizationID
			return control.Token{AccessToken: "new-token", RefreshToken: "new-refresh", ExpiresAt: "2099-01-01T00:00:00Z"}, nil
		},
		session: func(_ context.Context, request control.CredentialRequest) (control.Session, error) {
			*log = append(*log, "session "+request.AccessToken)
			id := organizationOf[request.AccessToken]
			return control.Session{
				SchemaVersion: 1, User: control.SessionUser{ID: "user_example", Email: "jane@example.com"},
				Organization: control.SessionOrganization{ID: id, Name: names[id]}, Role: "member",
			}, nil
		},
	}
	return fixture
}

func (f *orgFixture) dependencies() Dependencies {
	return Dependencies{API: f.api, Store: f.store, Interactive: func() bool { return false }}
}

func (f *orgFixture) stored(t *testing.T) credential.Credential {
	t.Helper()
	value, err := f.memory.Get(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestOrgListMarksTheCurrentOrganizationWithoutIDs(t *testing.T) {
	fixture := newOrgFixture(t)
	exit, stdout, stderr := run(t, fixture.dependencies(), "org", "list")
	want := "* Acme Inc.  admin\n  Beta LLC   member\n  Gamma      member\n  gamma      admin\n"
	if exit != 0 || stdout != want || strings.Contains(stdout, "org_") {
		t.Fatalf("org list: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}

	exit, stdout, _ = run(t, fixture.dependencies(), "--json", "org", "list")
	result := decodeEvent(t, []byte(stdout))
	organizations, _ := result.Data["organizations"].([]any)
	if exit != 0 || result.Command != "org list" || result.Data["current"] != "org_acme" || len(organizations) != 4 {
		t.Fatalf("org list --json: exit=%d %#v", exit, result)
	}
	first, _ := organizations[0].(map[string]any)
	if first["id"] != "org_acme" || first["name"] != "Acme Inc." || first["role"] != "admin" || first["current"] != true || first["switchable"] != true {
		t.Fatalf("the current organization entry is %#v", first)
	}
	if second, _ := organizations[1].(map[string]any); second["current"] != false {
		t.Fatalf("a second organization is marked current: %#v", second)
	}
}

func TestOrgSwitchStoresTheRotatedPairOnceBeforeTheSessionCheck(t *testing.T) {
	for name, argument := range map[string]string{"by ID": "org_beta", "by name": "beta llc"} {
		t.Run(name, func(t *testing.T) {
			fixture := newOrgFixture(t)
			exit, stdout, stderr := run(t, fixture.dependencies(), "--json", "org", "switch", argument)
			result := decodeEvent(t, []byte(stdout))
			if exit != 0 || result.Command != "org switch" || result.Data["changed"] != true || result.Next != "oe project list" {
				t.Fatalf("org switch: exit=%d %#v stderr=%q", exit, result, stderr)
			}
			if organization, _ := result.Data["organization"].(map[string]any); organization["id"] != "org_beta" || organization["name"] != "Beta LLC" {
				t.Fatalf("data.organization is %#v", result.Data["organization"])
			}
			if previous, _ := result.Data["previous"].(map[string]any); previous["id"] != "org_acme" {
				t.Fatalf("data.previous is %#v", result.Data["previous"])
			}
			if want := []string{"refresh org_beta", "set new-token", "session new-token"}; !slices.Equal(*fixture.log, want) {
				t.Fatalf("the switch ran %q, want %q", *fixture.log, want)
			}
			if stored := fixture.stored(t); stored.AccessToken != "new-token" || stored.RefreshToken != "new-refresh" || stored.ExpiresAt != "2099-01-01T00:00:00Z" {
				t.Fatalf("the store holds %#v", stored)
			}
		})
	}
}

func TestOrgSwitchTextNamesBothOrganizations(t *testing.T) {
	fixture := newOrgFixture(t)
	exit, stdout, stderr := run(t, fixture.dependencies(), "org", "switch", "Beta LLC")
	if exit != 0 || stdout != "Switched from Acme Inc. to Beta LLC.\nnext: oe project list\n" {
		t.Fatalf("org switch: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
}

func TestOrgSwitchToTheCurrentOrganizationChangesNothing(t *testing.T) {
	fixture := newOrgFixture(t)
	exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "ACME INC.")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Data["changed"] != false || len(*fixture.log) != 0 {
		t.Fatalf("a switch to the current organization: exit=%d %#v log=%q", exit, result, *fixture.log)
	}
}

func TestOrgSwitchRefusesAnUnknownAmbiguousOrNonMemberTarget(t *testing.T) {
	for _, test := range []struct {
		argument   string
		candidates []string
		message    string
	}{
		{"Nope Corp", []string{"org_acme", "org_beta", "org_gamma_one", "org_gamma_two"}, "not a member"},
		{"org_other", []string{"org_acme", "org_beta", "org_gamma_one", "org_gamma_two"}, "not a member"},
		{"GAMMA", []string{"org_gamma_one", "org_gamma_two"}, "name one by ID: org_gamma_one, org_gamma_two"},
	} {
		t.Run(test.argument, func(t *testing.T) {
			fixture := newOrgFixture(t)
			exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", test.argument)
			result := decodeEvent(t, []byte(stdout))
			if exit != exitUsage || result.Code != "USAGE_ERROR" || result.Next != "oe org list" || !strings.Contains(result.Error, test.message) {
				t.Fatalf("org switch %s: exit=%d %#v", test.argument, exit, result)
			}
			entries, _ := result.Data["candidates"].([]any)
			var ids []string
			for _, entry := range entries {
				candidate, _ := entry.(map[string]any)
				id, _ := candidate["id"].(string)
				ids = append(ids, id)
			}
			if !slices.Equal(ids, test.candidates) || result.Data["organization"] != test.argument {
				t.Fatalf("data is %#v, want candidates %q", result.Data, test.candidates)
			}
			if len(*fixture.log) != 0 || fixture.stored(t).AccessToken != "old-token" {
				t.Fatalf("a refused switch changed the session: log=%q", *fixture.log)
			}
		})
	}
}

func TestOrgSwitchKeepsTheRotatedPairWhenTheSessionNamesAnotherOrganization(t *testing.T) {
	fixture := newOrgFixture(t)
	fixture.api.refreshAuthorization = func(_ context.Context, _, organizationID string) (control.Token, error) {
		*fixture.log = append(*fixture.log, "refresh "+organizationID)
		// WorkOS rotated the pair but kept the organization: the new token
		// still names Acme Inc.
		return control.Token{AccessToken: "old-token", RefreshToken: "new-refresh", ExpiresAt: "2099-01-01T00:00:00Z"}, nil
	}
	exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "org_beta")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || result.Code != "ORGANIZATION_SWITCH_FAILED" || result.Next != "oe org list" {
		t.Fatalf("a mismatched switch: exit=%d %#v", exit, result)
	}
	if requested, _ := result.Data["requested"].(map[string]any); requested["id"] != "org_beta" {
		t.Fatalf("data.requested is %#v", result.Data["requested"])
	}
	if organization, _ := result.Data["organization"].(map[string]any); organization["id"] != "org_acme" {
		t.Fatalf("data.organization is %#v", result.Data["organization"])
	}
	if want := []string{"refresh org_beta", "set old-token", "session old-token"}; !slices.Equal(*fixture.log, want) {
		t.Fatalf("the switch ran %q, want %q", *fixture.log, want)
	}
	if stored := fixture.stored(t); stored.RefreshToken != "new-refresh" {
		t.Fatalf("the failed switch lost the rotated pair: %#v", stored)
	}
}

func TestOrgSwitchNeedsANewSignInAndKeepsTheSession(t *testing.T) {
	for _, reason := range []string{"sso_required", "mfa_enrollment", "authkit_redirect_url"} {
		t.Run(reason, func(t *testing.T) {
			fixture := newOrgFixture(t)
			fixture.api.refreshAuthorization = func(_ context.Context, _, organizationID string) (control.Token, error) {
				*fixture.log = append(*fixture.log, "refresh "+organizationID)
				return control.Token{}, &control.SignInRequiredError{Reason: reason}
			}
			exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "beta llc")
			result := decodeEvent(t, []byte(stdout))
			if exit != exitPersonAction || result.Code != "ORGANIZATION_SIGN_IN_REQUIRED" || result.Next != "oe auth login --organization 'Beta LLC'" {
				t.Fatalf("a sign-in refusal: exit=%d %#v", exit, result)
			}
			if result.Data["reason"] != reason {
				t.Fatalf("data.reason is %#v", result.Data["reason"])
			}
			if want := []string{"refresh org_beta"}; !slices.Equal(*fixture.log, want) {
				t.Fatalf("the switch ran %q, want %q", *fixture.log, want)
			}
			if stored := fixture.stored(t); stored.AccessToken != "old-token" || stored.RefreshToken != "old-refresh" {
				t.Fatalf("a sign-in refusal changed the store: %#v", stored)
			}
		})
	}
}

func TestOrgSwitchNamesTheIDWhenTheNameIsNotUnique(t *testing.T) {
	fixture := newOrgFixture(t)
	fixture.api.refreshAuthorization = func(context.Context, string, string) (control.Token, error) {
		return control.Token{}, &control.SignInRequiredError{Reason: "sso_required"}
	}
	_, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "org_gamma_two")
	if result := decodeEvent(t, []byte(stdout)); result.Next != "oe auth login --organization org_gamma_two" {
		t.Fatalf("next is %q", result.Next)
	}
}

func TestOrgSwitchRefusesAnEnvironmentToken(t *testing.T) {
	fixture := newOrgFixture(t)
	t.Setenv("OE_ACCESS_TOKEN", "environment-token")
	fixture.api.listOrganizations = nil
	exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "org_beta")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || result.Code != "USAGE_ERROR" || !strings.Contains(result.Error, "unset OE_ACCESS_TOKEN to switch") || result.Next != "" {
		t.Fatalf("an environment token: exit=%d %#v", exit, result)
	}
	if len(*fixture.log) != 0 {
		t.Fatalf("an environment token ran %q", *fixture.log)
	}
}

func TestOrgSwitchRefusesAnAgentToken(t *testing.T) {
	fixture := newOrgFixture(t)
	fixture.list = control.OrganizationList{SchemaVersion: 1, Current: "org_acme", Organizations: []control.Organization{
		{ID: "org_acme", Name: "Acme Inc.", Role: "member", Switchable: switchable(false)},
	}}
	exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "switch", "org_beta")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitUsage || result.Code != "USAGE_ERROR" || !strings.Contains(result.Error, "an agent session belongs to one organization") {
		t.Fatalf("an agent token: exit=%d %#v", exit, result)
	}
	if len(*fixture.log) != 0 {
		t.Fatalf("an agent token ran %q", *fixture.log)
	}
}

func TestOrgSwitchWithoutAnOrganizationNeverPromptsUnderJSONOrAnAgent(t *testing.T) {
	for name, global := range map[string]struct {
		args   []string
		getenv func(string) string
	}{
		"json":  {[]string{"--json"}, nil},
		"agent": {nil, underClaudeCode},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newOrgFixture(t)
			dependencies := fixture.dependencies()
			dependencies.In, dependencies.Getenv = unreadable{t}, global.getenv
			dependencies.Interactive = func() bool { return true }
			exit, stdout, stderr := run(t, dependencies, append(global.args, "org", "switch")...)
			result := decodeEvent(t, []byte(stdout))
			organizations, _ := result.Data["organizations"].([]any)
			if exit != exitUsage || result.Code != "USAGE_ERROR" || result.Data["current"] != "org_acme" || len(organizations) != 4 || stderr != "" {
				t.Fatalf("org switch without ORG: exit=%d %#v stderr=%q", exit, result, stderr)
			}
		})
	}
}

func TestOrgSwitchLetsAPersonChoose(t *testing.T) {
	fixture := newOrgFixture(t)
	dependencies := fixture.dependencies()
	dependencies.In, dependencies.Interactive = strings.NewReader("2\n"), func() bool { return true }
	exit, stdout, stderr := run(t, dependencies, "org", "switch")
	if exit != 0 || !strings.Contains(stderr, "  1. Acme Inc. (current)\n  2. Beta LLC\n") ||
		!strings.Contains(stderr, "Switch to which organization? [1-4, Enter keeps Acme Inc.]") ||
		stdout != "Switched from Acme Inc. to Beta LLC.\nnext: oe project list\n" {
		t.Fatalf("the picker: exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}

	fixture = newOrgFixture(t)
	dependencies = fixture.dependencies()
	dependencies.In, dependencies.Interactive = strings.NewReader("\n"), func() bool { return true }
	exit, stdout, _ = run(t, dependencies, "org", "switch")
	if exit != 0 || stdout != "The session is already in Acme Inc.\nnext: oe project list\n" || len(*fixture.log) != 0 {
		t.Fatalf("Enter did not keep the organization: exit=%d stdout=%q log=%q", exit, stdout, *fixture.log)
	}
}

func TestOrgCommandsSayUpdateRequiredWhenTheConsoleHasNoList(t *testing.T) {
	t.Setenv("OE_ACCESS_TOKEN", "")
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"org", "list"}, {"org", "switch", "org_beta"}} {
		store := credential.NewMemory()
		storeCredential(t, store)
		exit, stdout, _ := run(t, Dependencies{API: api, Store: store}, append([]string{"--json"}, args...)...)
		result := decodeEvent(t, []byte(stdout))
		if exit != exitFailure || result.Code != "CONTROL_UPDATE_REQUIRED" || !strings.Contains(result.Error, "update required") {
			t.Fatalf("oe %s on an older console: exit=%d %#v", strings.Join(args, " "), exit, result)
		}
	}
}

func TestOrgListReportsAControlFailure(t *testing.T) {
	fixture := newOrgFixture(t)
	fixture.api.listOrganizations = func(context.Context, control.CredentialRequest) (control.OrganizationList, error) {
		return control.OrganizationList{}, &control.APIError{Status: http.StatusServiceUnavailable, Code: "AUTHORITY_UNAVAILABLE", Message: "try later"}
	}
	exit, stdout, _ := run(t, fixture.dependencies(), "--json", "org", "list")
	if result := decodeEvent(t, []byte(stdout)); exit != exitTemporary || result.Next != "oe --json org list" {
		t.Fatalf("a temporary failure: exit=%d %#v", exit, result)
	}
}
