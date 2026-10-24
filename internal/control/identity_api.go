package control

import (
	"context"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

// IdentityFactory binds every identity operation to one public local slot.
// Slot association does not itself prove server authority.
type IdentityFactory interface {
	Identity(identityattempt.Slot) (IdentityTransport, error)
}

// IdentityTransport owns fixed methods, complete receivers and receipt sources.
// Occupied calls accept only real one-use permits, never caller command copies.
type IdentityTransport interface {
	Current(context.Context, CredentialRequest) (AddressedCurrent, error)
	Preview(context.Context, CredentialRequest, identity.PreviewRequest) (identity.PreviewResult, error)
	KeysCurrent(context.Context, CredentialRequest) (AddressedCurrent, error)
	LifecycleTarget(context.Context, CredentialRequest, identity.LifecycleInputTarget) (identity.TargetObservation, error)
	LifecyclePrepare(context.Context, CredentialRequest, AddressedCurrent, *identityattempt.PreparationPermit, LifecyclePreparationInput) (identity.Preparation, error)
	SelectionApply(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.SelectionReceipt, error)
	SelectionStatus(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.SelectionReceipt, error)
	SelectionCancel(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.SelectionReceipt, error)
	KeysReplace(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.KeysReceipt, error)
	KeysStatus(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.KeysReceipt, error)
	KeysCancel(context.Context, CredentialRequest, *identityattempt.DispatchPermit) (identity.KeysReceipt, error)
	LifecycleOperation(context.Context, CredentialRequest, AddressedCurrent, *identityattempt.DispatchPermit) (LifecycleReply, error)
	LifecycleApply(context.Context, CredentialRequest, AddressedCurrent, *identityattempt.DispatchPermit, identity.LifecycleInputTarget) (LifecycleReply, error)
	LifecycleResume(context.Context, CredentialRequest, AddressedCurrent, *identityattempt.DispatchPermit) (LifecycleReply, error)
}

// LifecyclePreparationInput is transient. It is never written to the attempt store.
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
	slot  identityattempt.Slot
	value identity.CurrentContext
}

func (v AddressedCurrent) Context() (identity.CurrentContext, error) {
	if v.slot.Validate() != nil || v.value.Validate() != nil {
		return identity.CurrentContext{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return v.value.Clone()
}

func (v AddressedCurrent) matches(slot identityattempt.Slot) bool {
	return v.slot.Equal(slot) && v.value.Validate() == nil &&
		v.value.Precondition.Scope.EnvironmentKind == slot.Environment()
}

func (AddressedCurrent) MarshalJSON() ([]byte, error) {
	return nil, identityTransportFailure("IDENTITY_RESULT_INVALID")
}

func (*AddressedCurrent) UnmarshalJSON([]byte) error {
	return identityTransportFailure("IDENTITY_RESULT_INVALID")
}

// LifecycleReply associates an actual method receipt with independently read scope.
// It settles command uncertainty only; it grants no current service readiness.
type LifecycleReply struct {
	receipt identity.LifecycleReceipt
	scope   identity.Scope
	slot    identityattempt.Slot
}

func (v LifecycleReply) Receipt() (identity.LifecycleReceipt, error) {
	if v.slot.Validate() != nil || v.scope.Validate() != nil {
		return identity.LifecycleReceipt{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	if _, err := v.receipt.Result(); err != nil {
		return identity.LifecycleReceipt{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return v.receipt, nil
}

func (v LifecycleReply) Scope() (identity.Scope, error) {
	if _, err := v.Receipt(); err != nil {
		return identity.Scope{}, err
	}
	return v.scope.Clone()
}

func (LifecycleReply) MarshalJSON() ([]byte, error) {
	return nil, identityTransportFailure("IDENTITY_RESULT_INVALID")
}

func (*LifecycleReply) UnmarshalJSON([]byte) error {
	return identityTransportFailure("IDENTITY_RESULT_INVALID")
}

var _ IdentityFactory = (*Client)(nil)
var _ IdentityTransport = (*identityHTTP)(nil)
