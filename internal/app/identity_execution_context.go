package app

import (
	"context"
	"errors"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
)

var errIdentityExecution = errors.New("The identity execution context is invalid.")
var errIdentityConsent = errors.New("Explicit consent is required before an identity mutation.")

type identityExecutionContext struct {
	address    control.IdentityAddress
	credential control.CredentialRequest
	transport  control.IdentityTransport
	writer     string
}

// identityContext uses actual existing credential, Session and project reads.
// The server repeats current Membership, resource, audit and binding checks.
func (r *runner) identityContext(ctx context.Context, project string) (identityExecutionContext, error) {
	if !validSlug(project) || (r.environment != "sandbox" && r.environment != "production") ||
		r.api == nil || r.identities == nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	base, err := identity.ParseControlBaseURL(r.controlURL)
	if err != nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	access, err := r.access(ctx, "", false)
	if err != nil {
		return identityExecutionContext{}, err
	}
	credential := control.CredentialRequest{AccessToken: access.AccessToken}
	session, err := r.api.Session(ctx, credential)
	if err != nil {
		return identityExecutionContext{}, err
	}
	if session.SchemaVersion != 1 || session.Organization.ID == "" || session.Organization.Name == "" ||
		session.User.ID == "" || session.User.Email == "" || session.Agent != nil && session.Agent.RegistrationID == "" {
		return identityExecutionContext{}, errIdentityExecution
	}
	projectValue, err := r.getProject(ctx, access, project)
	if err != nil {
		return identityExecutionContext{}, err
	}
	if projectValue.Slug != project {
		return identityExecutionContext{}, errIdentityExecution
	}
	if r.environment == "sandbox" && projectValue.Sandbox == nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	if r.environment == "production" && (projectValue.Production == nil || projectValue.Production.State != control.ProductionActive) {
		return identityExecutionContext{}, r.environmentNotActive(project, projectValue.Writer, r.environment)
	}
	address, err := control.NewIdentityAddress(base, project, r.environment)
	if err != nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	transport, err := r.identities.Identity(address)
	if err != nil {
		return identityExecutionContext{}, err
	}
	if transport == nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	return identityExecutionContext{address, credential, transport, projectValue.Writer}, nil
}
