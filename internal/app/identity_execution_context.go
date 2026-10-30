package app

import (
	"context"
	"errors"
	"sync"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

// An injected factory returns the concrete store at its explicitly owned location.
// It cannot substitute an in-memory lease or fall back to a selected user root.
type identityAttemptStoreFactory interface {
	Open() (*identityattempt.Store, error)
	BootstrapFirstUse(context.Context, identityattempt.FirstUse) (*identityattempt.Store, error)
}

type selectedIdentityAttemptStore struct {
	once     sync.Once
	selected identityattempt.Location
	failure  error
}

// Select once per invocation. An environment change cannot move bootstrap away
// from the location whose actual absence this factory inspected.
func (f *selectedIdentityAttemptStore) location() (identityattempt.Location, error) {
	if f == nil {
		return identityattempt.Location{}, identityattempt.ErrLocation
	}
	f.once.Do(func() {
		f.selected, f.failure = identityattempt.DefaultLocation()
	})
	return f.selected, f.failure
}

func (f *selectedIdentityAttemptStore) Open() (*identityattempt.Store, error) {
	location, err := f.location()
	if err != nil {
		return nil, err
	}
	return identityattempt.Open(location)
}

func (f *selectedIdentityAttemptStore) BootstrapFirstUse(ctx context.Context, declaration identityattempt.FirstUse) (*identityattempt.Store, error) {
	location, err := f.location()
	if err != nil {
		return nil, err
	}
	return identityattempt.BootstrapFirstUse(ctx, location, declaration)
}

var errIdentityExecution = errors.New("The identity execution context is invalid. Preserve the retained attempt.")
var errIdentityConsent = errors.New("Explicit consent is required before an identity mutation or identity store first use.")

type identityExecutionContext struct {
	slot       identityattempt.Slot
	credential control.CredentialRequest
	transport  control.IdentityTransport
}

// identityContext uses actual existing credential, Session and project reads.
// The server repeats current Membership, resource, audit and binding checks.
func (r *runner) identityContext(ctx context.Context, project string, kind identityattempt.Kind) (identityExecutionContext, error) {
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
	slot, err := identityattempt.NewSlot(base, session.Organization.ID, project, r.environment, kind)
	if err != nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	transport, err := r.identities.Identity(slot)
	if err != nil {
		return identityExecutionContext{}, err
	}
	if transport == nil {
		return identityExecutionContext{}, errIdentityExecution
	}
	return identityExecutionContext{slot, credential, transport}, nil
}

func (r *runner) identityStore(ctx context.Context, slot identityattempt.Slot, namespaceFirstUse, slotFirstUse bool) (*identityattempt.Lease, error) {
	if r.identityAttempts == nil {
		return nil, errIdentityExecution
	}
	store, err := r.identityAttempts.Open()
	if err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errIdentityExecution
	}
	observation, err := store.Inspect(ctx, slot)
	if err != nil {
		return nil, err
	}
	switch observation.State() {
	case identityattempt.AbsentNamespace:
		if !slotFirstUse {
			return nil, identityattempt.ErrFirstUseRequired
		}
		if r.getenv("OE_OPERATION_ID") != "" {
			return nil, identityattempt.ErrOperationIDUnretained
		}
		if !namespaceFirstUse {
			return store.InitializeForFirstSlot(ctx, slot, identityattempt.SlotNeverUsed)
		}
		store, err = r.identityAttempts.BootstrapFirstUse(ctx, identityattempt.NamespaceNeverUsed)
		if err != nil {
			return nil, err
		}
		if store == nil {
			return nil, errIdentityExecution
		}
		return store.EnrollFirstUse(ctx, slot, identityattempt.SlotNeverUsed)
	case identityattempt.AbsentSlot:
		if !slotFirstUse || namespaceFirstUse {
			return nil, identityattempt.ErrFirstUseRequired
		}
		if r.getenv("OE_OPERATION_ID") != "" {
			return nil, identityattempt.ErrOperationIDUnretained
		}
		return store.EnrollFirstUse(ctx, slot, identityattempt.SlotNeverUsed)
	case identityattempt.Ready:
		if namespaceFirstUse || slotFirstUse {
			return nil, identityattempt.ErrAlreadyInitialized
		}
		return store.BeginExisting(ctx, slot)
	default:
		return nil, errIdentityExecution
	}
}
