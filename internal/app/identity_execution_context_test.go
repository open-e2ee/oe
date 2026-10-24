package app

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

type identityCountingFactory struct {
	opens, bootstraps int
	failure           error
}

func (f *identityCountingFactory) Open() (*identityattempt.Store, error) {
	f.opens++
	return nil, f.failure
}
func (f *identityCountingFactory) BootstrapFirstUse(context.Context, identityattempt.FirstUse) (*identityattempt.Store, error) {
	f.bootstraps++
	return nil, f.failure
}

type identityRefusingFactory struct {
	slots   []identityattempt.Slot
	failure error
}

func (f *identityRefusingFactory) Identity(slot identityattempt.Slot) (control.IdentityTransport, error) {
	f.slots = append(f.slots, slot)
	return nil, f.failure
}

func identityContextRunner(t *testing.T) (*runner, *fakeAPI, *identityRefusingFactory, *identityCountingFactory) {
	t.Helper()
	store := credential.NewMemory()
	storeCredential(t, store)
	api := &fakeAPI{session: acmeSession, getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "sample", Sandbox: &control.ProjectEnvironment{}, Production: &control.ProjectEnvironment{State: control.ProductionActive}}, nil
	}}
	factory := &identityRefusingFactory{failure: errIdentityExecution}
	attempts := &identityCountingFactory{failure: identityattempt.ErrLocation}
	r := &runner{api: api, identities: factory, identityAttempts: attempts, store: store,
		controlURL: defaultControlURL, environment: "sandbox", now: time.Now, getenv: func(string) string {
			return ""
		}}
	return r, api, factory, attempts
}

func TestIdentityContextUsesActualSessionOrganizationAndProjectBeforeFactory(t *testing.T) {
	r, api, factory, attempts := identityContextRunner(t)
	order := []string{}
	api.session = func(ctx context.Context, credential control.CredentialRequest) (control.Session, error) {
		order = append(order, "session")
		if credential.AccessToken != "test-token" || credential.OperationID != "" {
			t.Error("context manufactured credential or operation")
		}
		return acmeSession(ctx, credential)
	}
	api.getProject = func(_ context.Context, _ control.CredentialRequest, project string) (control.Project, error) {
		order = append(order, "project")
		if project != "sample" {
			t.Error("project address changed")
		}
		return control.Project{Slug: project, Sandbox: &control.ProjectEnvironment{}}, nil
	}
	_, err := r.identityContext(context.Background(), "sample", identityattempt.Selection)
	if !errors.Is(err, errIdentityExecution) || len(order) != 2 || order[0] != "session" || order[1] != "project" || len(factory.slots) != 1 {
		t.Fatal("context order changed")
	}
	slot := factory.slots[0]
	if slot.OrganizationID() != "org_example" || slot.ProjectSlug() != "sample" || slot.Environment() != "sandbox" || slot.Kind() != identityattempt.Selection {
		t.Fatal("slot was not associated with actual reads")
	}
	if attempts.opens != 0 || attempts.bootstraps != 0 {
		t.Fatal("context opened attempt state")
	}
}

func TestIdentityContextRefusalsNeverOpenAttemptStore(t *testing.T) {
	for _, name := range []string{"missing-factory", "invalid-base", "project-input", "environment", "session-loss", "session-shape", "missing-organization", "project-loss", "project-address", "missing-sandbox", "inactive-production"} {
		t.Run(name, func(t *testing.T) {
			r, api, factory, attempts := identityContextRunner(t)
			project := "sample"
			switch name {
			case "missing-factory":
				r.identities = nil
			case "invalid-base":
				r.controlURL = "https://CANARY@console.example/api/cli"
			case "project-input":
				project = "../CANARY"
			case "environment":
				r.environment = "other"
			case "session-loss":
				api.session = func(context.Context, control.CredentialRequest) (control.Session, error) {
					return control.Session{}, errors.New("lost session")
				}
			case "session-shape":
				api.session = func(context.Context, control.CredentialRequest) (control.Session, error) {
					return control.Session{}, nil
				}
			case "missing-organization":
				api.session = func(ctx context.Context, c control.CredentialRequest) (control.Session, error) {
					s, _ := acmeSession(ctx, c)
					s.Organization.ID = ""
					return s, nil
				}
			case "project-loss":
				api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
					return control.Project{}, errors.New("lost project")
				}
			case "project-address":
				api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
					return control.Project{Slug: "other", Sandbox: &control.ProjectEnvironment{}}, nil
				}
			case "missing-sandbox":
				api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
					return control.Project{Slug: "sample"}, nil
				}
			case "inactive-production":
				r.environment = "production"
				api.getProject = func(context.Context, control.CredentialRequest, string) (control.Project, error) {
					return control.Project{Slug: "sample", Production: &control.ProjectEnvironment{State: control.ProductionAvailable}}, nil
				}
			}
			if _, err := r.identityContext(context.Background(), project, identityattempt.Selection); err == nil {
				t.Fatal("invalid context accepted")
			}
			if attempts.opens != 0 || attempts.bootstraps != 0 || len(factory.slots) != 0 {
				t.Fatal("refused context reached store or transport factory")
			}
		})
	}
}

func TestIdentityExplicitStoreFactoryNeverFallsBack(t *testing.T) {
	r, _, _, attempts := identityContextRunner(t)
	baseClient, err := control.New(defaultControlURL, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	r.identities = baseClient
	base, err := identity.ParseControlBaseURL(r.controlURL)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := identityattempt.NewSlot(base, "org_example", "sample", "sandbox", identityattempt.Selection)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = r.identityStore(ctx, slot, true, true)
	if !errors.Is(err, identityattempt.ErrLocation) || attempts.opens != 1 || attempts.bootstraps != 0 {
		t.Fatal("explicit failure fell back")
	}
	attempts.failure = nil
	_, err = r.identityStore(ctx, slot, true, true)
	if !errors.Is(err, errIdentityExecution) || attempts.opens != 2 || attempts.bootstraps != 0 {
		t.Fatal("explicit nil store fell back")
	}
}
