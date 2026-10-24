package control

import (
	"context"
	"errors"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

func (c *identityHTTP) begin(ctx context.Context, permit *identityattempt.DispatchPermit, action identityattempt.Action) (*identityattempt.DispatchCall, identityattempt.Attempt, error) {
	call, err := permit.Begin(ctx, action)
	if err != nil {
		return nil, identityattempt.Attempt{}, err
	}
	attempt, err := call.Attempt()
	if err != nil || !call.Slot().Equal(c.slot) || call.Action() != action {
		failure := identityTransportFailure("IDENTITY_CONTEXT_CHANGED")
		return nil, identityattempt.Attempt{}, errors.Join(failure, call.Join())
	}
	return call, attempt, nil
}

func cancellation(attempt identityattempt.Attempt) *identity.CancellationOperationID {
	if id, present := attempt.CancellationID(); present {
		return &id
	}
	return nil
}

func (c *identityHTTP) SelectionApply(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.SelectionReceipt, error) {
	return c.selection(ctx, credential, permit, identityattempt.SelectionApplyAction)
}

func (c *identityHTTP) SelectionStatus(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.SelectionReceipt, error) {
	return c.selection(ctx, credential, permit, identityattempt.SelectionStatusAction)
}

func (c *identityHTTP) SelectionCancel(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.SelectionReceipt, error) {
	return c.selection(ctx, credential, permit, identityattempt.SelectionCancelAction)
}

func (c *identityHTTP) selection(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit,
	action identityattempt.Action) (receipt identity.SelectionReceipt, err error) {
	call, attempt, err := c.begin(ctx, permit, action)
	if err != nil {
		return receipt, err
	}
	defer func() {
		if joinErr := call.Join(); joinErr != nil {
			receipt = identity.SelectionReceipt{}
			err = errors.Join(err, joinErr)
		}
	}()
	command, err := attempt.SelectionCommand()
	if err != nil {
		return receipt, err
	}
	wire := map[string]any{"precondition": command.Precondition}
	var selector string
	var source identity.SelectionReceiptSource
	switch action {
	case identityattempt.SelectionApplyAction:
		selector, source = "select", identity.SelectionApply
		wire["operationId"], wire["expectedConfigurationVersion"], wire["target"] = command.OperationID, command.ExpectedConfigurationVersion, command.Target
	case identityattempt.SelectionStatusAction:
		selector, source = "selection-operation", identity.SelectionStatus
		wire["selectedOperationId"] = command.OperationID
	case identityattempt.SelectionCancelAction:
		selector, source = "selection-cancel", identity.SelectionCancel
		wire["operationId"], wire["selectionOperationId"] = cancellation(attempt), command.OperationID
	default:
		return receipt, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire["action"] = selector
	var value identity.SelectionResult
	if err := c.request(call.Context(), credential, selector, wire, &value); err != nil {
		return receipt, err
	}
	receipt, err = identity.NewSelectionReceipt(command, cancellation(attempt), source, value)
	if err != nil {
		return identity.SelectionReceipt{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return receipt, nil
}

func (c *identityHTTP) KeysReplace(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.KeysReceipt, error) {
	return c.keys(ctx, credential, permit, identityattempt.KeysReplaceAction)
}

func (c *identityHTTP) KeysStatus(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.KeysReceipt, error) {
	return c.keys(ctx, credential, permit, identityattempt.KeysStatusAction)
}

func (c *identityHTTP) KeysCancel(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit) (identity.KeysReceipt, error) {
	return c.keys(ctx, credential, permit, identityattempt.KeysCancelAction)
}

func (c *identityHTTP) keys(ctx context.Context, credential CredentialRequest, permit *identityattempt.DispatchPermit,
	action identityattempt.Action) (receipt identity.KeysReceipt, err error) {
	call, attempt, err := c.begin(ctx, permit, action)
	if err != nil {
		return receipt, err
	}
	defer func() {
		if joinErr := call.Join(); joinErr != nil {
			receipt = identity.KeysReceipt{}
			err = errors.Join(err, joinErr)
		}
	}()
	command, err := attempt.KeysCommand()
	if err != nil {
		return receipt, err
	}
	wire := map[string]any{"precondition": command.Precondition}
	var selector string
	var source identity.SelectionReceiptSource
	switch action {
	case identityattempt.KeysReplaceAction:
		selector, source = "keys-replace", identity.KeysReplace
		wire["operationId"], wire["expectedConfigurationVersion"], wire["keys"] = command.OperationID, command.ExpectedConfigurationVersion, command.Keys
	case identityattempt.KeysStatusAction:
		selector, source = "keys-read", identity.SelectionStatus
		wire["selectionOperationId"] = command.OperationID
	case identityattempt.KeysCancelAction:
		selector, source = "keys-cancel", identity.SelectionCancel
		wire["operationId"], wire["selectionOperationId"] = cancellation(attempt), command.OperationID
	default:
		return receipt, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire["action"] = selector
	var value identity.KeysResult
	if err := c.request(call.Context(), credential, selector, wire, &value); err != nil {
		return receipt, err
	}
	receipt, err = identity.NewKeysReceipt(command, cancellation(attempt), source, value)
	if err != nil {
		return identity.KeysReceipt{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return receipt, nil
}

func (c *identityHTTP) LifecycleOperation(ctx context.Context, credential CredentialRequest, current AddressedCurrent, permit *identityattempt.DispatchPermit) (LifecycleReply, error) {
	return c.lifecycle(ctx, credential, current, permit, identityattempt.LifecycleStatusAction, nil)
}

func (c *identityHTTP) LifecycleApply(ctx context.Context, credential CredentialRequest, current AddressedCurrent, permit *identityattempt.DispatchPermit, target identity.LifecycleInputTarget) (LifecycleReply, error) {
	return c.lifecycle(ctx, credential, current, permit, identityattempt.LifecycleApplyAction, &target)
}

func (c *identityHTTP) LifecycleResume(ctx context.Context, credential CredentialRequest, current AddressedCurrent, permit *identityattempt.DispatchPermit) (LifecycleReply, error) {
	return c.lifecycle(ctx, credential, current, permit, identityattempt.LifecycleResumeAction, nil)
}

func (c *identityHTTP) lifecycle(ctx context.Context, credential CredentialRequest, current AddressedCurrent,
	permit *identityattempt.DispatchPermit, action identityattempt.Action, target *identity.LifecycleInputTarget) (reply LifecycleReply, err error) {
	call, attempt, err := c.begin(ctx, permit, action)
	if err != nil {
		return reply, err
	}
	defer func() {
		if joinErr := call.Join(); joinErr != nil {
			reply = LifecycleReply{}
			err = errors.Join(err, joinErr)
		}
	}()
	command, err := attempt.LifecycleCommand()
	if err != nil || !current.matches(c.slot) {
		return reply, identityTransportFailure("IDENTITY_CONTEXT_CHANGED")
	}
	wire := map[string]any{}
	var selector string
	var source identity.ReceiptSource
	switch action {
	case identityattempt.LifecycleStatusAction:
		selector, source = "operation", identity.LifecycleStatusSource
		wire["lifecycleOperationId"] = command.OperationID
	case identityattempt.LifecycleResumeAction:
		if identity.ValidateResumeOperationID(command.OperationID) != nil {
			return reply, identityTransportFailure("IDENTITY_INPUT_INVALID")
		}
		selector, source = "resume", identity.LifecycleResumeSource
		wire["operationId"] = command.OperationID
	case identityattempt.LifecycleApplyAction:
		if target == nil || target.Validate() != nil || target.Kind != command.TargetKind || identity.ValidatePreparedOperationID(command.OperationID) != nil {
			return reply, identityTransportFailure("IDENTITY_INPUT_INVALID")
		}
		selector, source = "apply", identity.LifecycleApplySource
		wire["operationId"], wire["target"] = command.OperationID, target
		wire["state"], wire["expectedLifecycleVersion"] = command.State, command.ExpectedLifecycleVersion
	default:
		return reply, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire["action"] = selector
	var value identity.LifecycleStatus
	if err := c.request(call.Context(), credential, selector, wire, &value); err != nil {
		return reply, err
	}
	receipt, err := identity.NewLifecycleReceipt(command, current.value.Precondition.Scope, source, value)
	if err != nil {
		return reply, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return LifecycleReply{receipt: receipt, scope: current.value.Precondition.Scope, slot: c.slot}, nil
}
