package control

import (
	"context"

	"github.com/open-e2ee/oe/internal/identity"
)

// Each mutation is one HTTP attempt with its complete command. A repeated
// operation ID with the same command makes the server replay its result, and
// a changed command under that ID is a server conflict.

func (c *identityHTTP) SelectionApply(ctx context.Context, credential CredentialRequest, command identity.SelectionCommand) (identity.SelectionResult, error) {
	if command.Validate() != nil || command.Precondition.Scope.EnvironmentKind != c.address.Environment() {
		return identity.SelectionResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "select", "operationId": command.OperationID,
		"expectedConfigurationVersion": command.ExpectedConfigurationVersion, "target": command.Target, "precondition": command.Precondition}
	return c.selection(ctx, credential, "select", wire, command.OperationID)
}

func (c *identityHTTP) SelectionStatus(ctx context.Context, credential CredentialRequest, current AddressedCurrent, id identity.SelectionOperationID) (identity.SelectionResult, error) {
	if id.Validate() != nil || !current.matches(c.address) {
		return identity.SelectionResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "selection-operation", "selectionOperationId": id, "precondition": current.value.Precondition}
	return c.selection(ctx, credential, "selection-operation", wire, id)
}

func (c *identityHTTP) SelectionCancel(ctx context.Context, credential CredentialRequest, current AddressedCurrent,
	cancel identity.CancellationOperationID, id identity.SelectionOperationID) (identity.SelectionResult, error) {
	if cancel.Validate() != nil || id.Validate() != nil || !current.matches(c.address) {
		return identity.SelectionResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "selection-cancel", "operationId": cancel, "selectionOperationId": id, "precondition": current.value.Precondition}
	return c.selection(ctx, credential, "selection-cancel", wire, id)
}

// selection accepts only a result for the exact selection operation ID. A
// cancel result names the selection operation, not the cancellation.
func (c *identityHTTP) selection(ctx context.Context, credential CredentialRequest, selector string, wire map[string]any,
	id identity.SelectionOperationID) (identity.SelectionResult, error) {
	var value identity.SelectionResult
	if err := c.request(ctx, credential, selector, wire, &value); err != nil {
		return identity.SelectionResult{}, err
	}
	if identity.ClassifySelectionResult(id, value) == identity.ReceiptMismatch {
		return identity.SelectionResult{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}

func (c *identityHTTP) KeysReplace(ctx context.Context, credential CredentialRequest, command identity.KeysCommand) (identity.KeysResult, error) {
	if command.Validate() != nil || command.Precondition.Scope.EnvironmentKind != c.address.Environment() {
		return identity.KeysResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "keys-replace", "operationId": command.OperationID,
		"expectedConfigurationVersion": command.ExpectedConfigurationVersion, "keys": command.Keys, "precondition": command.Precondition}
	return c.keys(ctx, credential, "keys-replace", wire, command.OperationID)
}

func (c *identityHTTP) KeysStatus(ctx context.Context, credential CredentialRequest, current AddressedCurrent, id identity.SelectionOperationID) (identity.KeysResult, error) {
	if id.Validate() != nil || !current.matches(c.address) {
		return identity.KeysResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "keys-read", "selectionOperationId": id, "precondition": current.value.Precondition}
	return c.keys(ctx, credential, "keys-read", wire, id)
}

func (c *identityHTTP) KeysCancel(ctx context.Context, credential CredentialRequest, current AddressedCurrent,
	cancel identity.CancellationOperationID, id identity.SelectionOperationID) (identity.KeysResult, error) {
	if cancel.Validate() != nil || id.Validate() != nil || !current.matches(c.address) {
		return identity.KeysResult{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "keys-cancel", "operationId": cancel, "selectionOperationId": id, "precondition": current.value.Precondition}
	return c.keys(ctx, credential, "keys-cancel", wire, id)
}

func (c *identityHTTP) keys(ctx context.Context, credential CredentialRequest, selector string, wire map[string]any,
	id identity.SelectionOperationID) (identity.KeysResult, error) {
	var value identity.KeysResult
	if err := c.request(ctx, credential, selector, wire, &value); err != nil {
		return identity.KeysResult{}, err
	}
	if identity.ClassifyKeysResult(id, value) == identity.ReceiptMismatch {
		return identity.KeysResult{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}

func (c *identityHTTP) LifecycleOperation(ctx context.Context, credential CredentialRequest, current AddressedCurrent, id identity.ContractText) (identity.LifecycleStatus, error) {
	if identity.ValidateResumeOperationID(id) != nil || !current.matches(c.address) {
		return identity.LifecycleStatus{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "operation", "lifecycleOperationId": id}
	return c.lifecycle(ctx, credential, current, "operation", identity.LifecycleStatusSource, wire, id)
}

func (c *identityHTTP) LifecycleResume(ctx context.Context, credential CredentialRequest, current AddressedCurrent, id identity.ContractText) (identity.LifecycleStatus, error) {
	if identity.ValidateResumeOperationID(id) != nil || !current.matches(c.address) {
		return identity.LifecycleStatus{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "resume", "operationId": id}
	return c.lifecycle(ctx, credential, current, "resume", identity.LifecycleResumeSource, wire, id)
}

// LifecycleApply sends the prepared operation. Its result must match the
// prepared target kind, state and expected version, not only the ID.
func (c *identityHTTP) LifecycleApply(ctx context.Context, credential CredentialRequest, current AddressedCurrent,
	attempt identity.LifecycleAttempt, target identity.LifecycleInputTarget) (identity.LifecycleStatus, error) {
	if attempt.Validate() != nil || identity.ValidatePreparedOperationID(attempt.OperationID) != nil || target.Validate() != nil ||
		target.Kind != attempt.TargetKind || !current.matches(c.address) {
		return identity.LifecycleStatus{}, identityTransportFailure("IDENTITY_INPUT_INVALID")
	}
	wire := map[string]any{"action": "apply", "operationId": attempt.OperationID, "target": target,
		"state": attempt.State, "expectedLifecycleVersion": attempt.ExpectedLifecycleVersion}
	value, err := c.lifecycle(ctx, credential, current, "apply", identity.LifecycleApplySource, wire, attempt.OperationID)
	if err != nil {
		return value, err
	}
	if _, err := identity.NewLifecycleReceipt(attempt, current.value.Precondition.Scope, identity.LifecycleApplySource, value); err != nil {
		return identity.LifecycleStatus{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}

func (c *identityHTTP) lifecycle(ctx context.Context, credential CredentialRequest, current AddressedCurrent, selector string,
	source identity.ReceiptSource, wire map[string]any, id identity.ContractText) (identity.LifecycleStatus, error) {
	var value identity.LifecycleStatus
	if err := c.request(ctx, credential, selector, wire, &value); err != nil {
		return identity.LifecycleStatus{}, err
	}
	if identity.ClassifyLifecycleResult(id, current.value.Precondition.Scope, source, value) == identity.ReceiptMismatch {
		return identity.LifecycleStatus{}, identityTransportFailure("IDENTITY_RESULT_INVALID")
	}
	return value, nil
}
