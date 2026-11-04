package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

type identityRefusingFactory struct {
	addresses []control.IdentityAddress
	failure   error
}

func (f *identityRefusingFactory) Identity(address control.IdentityAddress) (control.IdentityTransport, error) {
	f.addresses = append(f.addresses, address)
	return nil, f.failure
}

func identityContextRunner(t *testing.T) (*runner, *fakeAPI, *identityRefusingFactory) {
	t.Helper()
	store := credential.NewMemory()
	storeCredential(t, store)
	api := &fakeAPI{session: acmeSession, getProject: func(context.Context, control.CredentialRequest, string) (control.Project, error) {
		return control.Project{Slug: "sample", Sandbox: &control.ProjectEnvironment{}, Production: &control.ProjectEnvironment{State: control.ProductionActive}}, nil
	}}
	factory := &identityRefusingFactory{failure: errIdentityExecution}
	r := &runner{api: api, identities: factory, store: store,
		controlURL: defaultControlURL, environment: "sandbox", now: time.Now, getenv: func(string) string {
			return ""
		}}
	return r, api, factory
}

func TestIdentityContextUsesActualSessionOrganizationAndProjectBeforeFactory(t *testing.T) {
	r, api, factory := identityContextRunner(t)
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
	_, err := r.identityContext(context.Background(), "sample")
	if !errors.Is(err, errIdentityExecution) || len(order) != 2 || order[0] != "session" || order[1] != "project" || len(factory.addresses) != 1 {
		t.Fatal("context order changed")
	}
	address := factory.addresses[0]
	if address.ProjectSlug() != "sample" || address.Environment() != "sandbox" || address.ControlBase().String() != defaultControlURL {
		t.Fatal("address was not associated with actual reads")
	}
}

func TestIdentityContextRefusalsNeverReachTransport(t *testing.T) {
	for _, name := range []string{"missing-factory", "invalid-base", "project-input", "environment", "session-loss", "session-shape", "missing-organization", "project-loss", "project-address", "missing-sandbox", "inactive-production"} {
		t.Run(name, func(t *testing.T) {
			r, api, factory := identityContextRunner(t)
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
			if _, err := r.identityContext(context.Background(), project); err == nil {
				t.Fatal("invalid context accepted")
			}
			if len(factory.addresses) != 0 {
				t.Fatal("refused context reached the transport factory")
			}
		})
	}
}
