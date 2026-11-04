package control

import (
	"context"
	"regexp"

	"github.com/open-e2ee/oe/internal/identity"
)

// IdentityFactory binds every identity call to one public project address.
// The address does not itself prove server authority.
type IdentityFactory interface {
	Identity(IdentityAddress) (IdentityTransport, error)
}

// IdentityTransport owns fixed methods, complete receivers and the exact
// association of each result with the request that produced it. The server
// holds every identity operation. Each mutation takes its complete command
// value, and the server replays a repeated operation ID.
type IdentityTransport interface {
	Current(context.Context, CredentialRequest) (AddressedCurrent, error)
	Preview(context.Context, CredentialRequest, identity.PreviewRequest) (identity.PreviewResult, error)
	KeysCurrent(context.Context, CredentialRequest) (AddressedCurrent, error)
	LifecycleTarget(context.Context, CredentialRequest, identity.LifecycleInputTarget) (identity.TargetObservation, error)
	LifecyclePrepare(context.Context, CredentialRequest, AddressedCurrent, LifecyclePreparationInput) (identity.Preparation, error)
	SelectionApply(context.Context, CredentialRequest, identity.SelectionCommand) (identity.SelectionResult, error)
	SelectionStatus(context.Context, CredentialRequest, AddressedCurrent, identity.SelectionOperationID) (identity.SelectionResult, error)
	SelectionCancel(context.Context, CredentialRequest, AddressedCurrent, identity.CancellationOperationID, identity.SelectionOperationID) (identity.SelectionResult, error)
	KeysReplace(context.Context, CredentialRequest, identity.KeysCommand) (identity.KeysResult, error)
	KeysStatus(context.Context, CredentialRequest, AddressedCurrent, identity.SelectionOperationID) (identity.KeysResult, error)
	KeysCancel(context.Context, CredentialRequest, AddressedCurrent, identity.CancellationOperationID, identity.SelectionOperationID) (identity.KeysResult, error)
	LifecycleOperation(context.Context, CredentialRequest, AddressedCurrent, identity.ContractText) (identity.LifecycleStatus, error)
	LifecycleApply(context.Context, CredentialRequest, AddressedCurrent, identity.LifecycleAttempt, identity.LifecycleInputTarget) (identity.LifecycleStatus, error)
	LifecycleResume(context.Context, CredentialRequest, AddressedCurrent, identity.ContractText) (identity.LifecycleStatus, error)
}

var identityProjectSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// IdentityAddress is the public control address of one project environment.
// The caller checks the Organization and the project before it builds one.
type IdentityAddress struct {
	base        identity.ControlBaseURL
	project     string
	environment string
}

func NewIdentityAddress(base identity.ControlBaseURL, project, environment string) (IdentityAddress, error) {
	value := IdentityAddress{base: base, project: project, environment: environment}
	if value.Validate() != nil {
		return IdentityAddress{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	return value, nil
}

func (v IdentityAddress) Validate() error {
	if v.base.Validate() != nil || len(v.project) > 63 || !identityProjectSlug.MatchString(v.project) ||
		v.environment != "sandbox" && v.environment != "production" {
		return identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	return nil
}

func (v IdentityAddress) ControlBase() identity.ControlBaseURL { return v.base }
func (v IdentityAddress) ProjectSlug() string                  { return v.project }
func (v IdentityAddress) Environment() string                  { return v.environment }

func (v IdentityAddress) Equal(other IdentityAddress) bool {
	return v.Validate() == nil && other.Validate() == nil && v == other
}

// LifecyclePreparationInput is transient. The CLI keeps no copy of it.
type LifecyclePreparationInput struct {
	Target                   identity.LifecycleInputTarget
	State                    string
	ExpectedLifecycleVersion identity.SafeInteger
	Nonce                    string
}

func (v LifecyclePreparationInput) validate() error {
	if v.Target.Validate() != nil || (v.State != "active" && v.State != "suspended") ||
		v.ExpectedLifecycleVersion.Validate() != nil || identity.ValidatePreparationNonce(v.Nonce) != nil {
		return identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	return nil
}

// AddressedCurrent has actual receiver provenance, not a wire origin claim.
// The opaque Relay project ID comes from the complete current reply, never a slug.
type AddressedCurrent struct {
	address IdentityAddress
	value   identity.CurrentContext
}

func (v AddressedCurrent) Context() (identity.CurrentContext, error) {
	if v.address.Validate() != nil || v.value.Validate() != nil {
		return identity.CurrentContext{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return v.value.Clone()
}

func (v AddressedCurrent) matches(address IdentityAddress) bool {
	return v.address.Equal(address) && v.value.Validate() == nil &&
		v.value.Precondition.Scope.EnvironmentKind == address.Environment()
}

func (AddressedCurrent) MarshalJSON() ([]byte, error) {
	return nil, identityTransportFailure("IDENTITY_RESULT_INVALID")
}

func (*AddressedCurrent) UnmarshalJSON([]byte) error {
	return identityTransportFailure("IDENTITY_RESULT_INVALID")
}

var _ IdentityFactory = (*Client)(nil)
var _ IdentityTransport = (*identityHTTP)(nil)
