package control

import (
	"context"
	"errors"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

func (c *identityHTTP) addressed(value identity.CurrentContext) (AddressedCurrent, error) {
	if value.Validate() != nil || value.Precondition.Scope.EnvironmentKind != c.slot.Environment() {
		return AddressedCurrent{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	copy, err := value.Clone()
	if err != nil {
		return AddressedCurrent{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return AddressedCurrent{slot: c.slot, value: copy}, nil
}

func (c *identityHTTP) Current(ctx context.Context, credential CredentialRequest) (AddressedCurrent, error) {
	var value identity.CurrentContext
	if err := c.request(ctx, credential, "current", nil, &value); err != nil {
		return AddressedCurrent{}, err
	}
	return c.addressed(value)
}

func (c *identityHTTP) KeysCurrent(ctx context.Context, credential CredentialRequest) (AddressedCurrent, error) {
	if c.slot.Kind() != identityattempt.KeysOnly {
		return AddressedCurrent{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	var value identity.CurrentContext
	body := struct {
		Action string `json:"action"`
	}{"keys-read"}
	if err := c.request(ctx, credential, "keys-read", body, &value); err != nil {
		return AddressedCurrent{}, err
	}
	return c.addressed(value)
}

func (c *identityHTTP) Preview(ctx context.Context, credential CredentialRequest, input identity.PreviewRequest) (identity.PreviewResult, error) {
	var value identity.PreviewResult
	if input.Validate() != nil || string(c.slot.Kind()) != input.Kind {
		return value, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	// Explicit fields avoid promoting PreviewRequest.MarshalJSON and losing action.
	wire := map[string]any{"action": "preview", "kind": input.Kind,
		"expectedConfigurationVersion": input.ExpectedConfigurationVersion}
	if input.Target != nil {
		wire["target"] = input.Target
	} else {
		wire["keys"] = input.Keys
	}
	if err := c.request(ctx, credential, "preview", wire, &value); err != nil {
		return identity.PreviewResult{}, err
	}
	returned := identity.PreviewRequest{Kind: value.Kind, ExpectedConfigurationVersion: value.ExpectedConfigurationVersion,
		Target: value.Target, Keys: value.Keys}
	if !returned.Equal(input) || value.Current.Precondition.Scope.EnvironmentKind != c.slot.Environment() {
		return identity.PreviewResult{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}

func (c *identityHTTP) LifecycleTarget(ctx context.Context, credential CredentialRequest, target identity.LifecycleInputTarget) (identity.TargetObservation, error) {
	var value identity.TargetObservation
	if c.slot.Kind() != identityattempt.Lifecycle || target.Validate() != nil {
		return value, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	body := struct {
		Action string                        `json:"action"`
		Target identity.LifecycleInputTarget `json:"target"`
	}{"target", target}
	if err := c.request(ctx, credential, "target", body, &value); err != nil {
		return identity.TargetObservation{}, err
	}
	if value.Target.Kind != target.Kind || value.Scope.EnvironmentKind != c.slot.Environment() {
		return identity.TargetObservation{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}

func (c *identityHTTP) LifecyclePrepare(ctx context.Context, credential CredentialRequest, current AddressedCurrent,
	permit *identityattempt.PreparationPermit, input LifecyclePreparationInput) (value identity.Preparation, err error) {
	call, err := permit.Begin(ctx)
	if err != nil {
		return value, err
	}
	defer func() {
		if joinErr := call.Join(); joinErr != nil {
			value = identity.Preparation{}
			err = errors.Join(err, joinErr)
		}
	}()
	if !call.Slot().Equal(c.slot) || !current.matches(c.slot) || input.validate() != nil {
		return identity.Preparation{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	body := struct {
		Action                   string                        `json:"action"`
		Target                   identity.LifecycleInputTarget `json:"target"`
		State                    string                        `json:"state"`
		ExpectedLifecycleVersion identity.SafeInteger          `json:"expectedLifecycleVersion"`
		Nonce                    string                        `json:"nonce"`
	}{"prepare", input.Target, input.State, input.ExpectedLifecycleVersion, input.Nonce}
	if err := c.request(call.Context(), credential, "prepare", body, &value); err != nil {
		return identity.Preparation{}, err
	}
	if !value.Scope.Equal(current.value.Precondition.Scope) || value.Target.Kind != input.Target.Kind ||
		value.State != input.State || value.ExpectedLifecycleVersion != input.ExpectedLifecycleVersion {
		return identity.Preparation{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}
