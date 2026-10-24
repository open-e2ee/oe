package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

// identityExecutionInput is an internal workflow input, not a CLI flag schema.
// Only new work uses transient targets. Continuation reads the retained record.
type identityExecutionInput struct {
	Project           string
	Kind              identityattempt.Kind
	Action            identityattempt.Action
	Target            *identity.SelectionTarget
	Keys              *identity.ReplacementKeys
	LifecycleTarget   *identity.LifecycleInputTarget
	LifecycleState    string
	Consent           bool
	NamespaceFirstUse bool
	SlotFirstUse      bool
	Approved          *identity.CurrentContext
	ApprovedTarget    *identity.TargetObservation
}

type identityExecutionResult struct {
	Disposition identity.ReceiptDisposition
	Envelope    identityattempt.Envelope
	Selection   *identity.SelectionResult
	Keys        *identity.KeysResult
	Lifecycle   *identity.LifecycleStatus
}

func identityActionKind(action identityattempt.Action) identityattempt.Kind {
	switch action {
	case identityattempt.SelectionApplyAction, identityattempt.SelectionStatusAction, identityattempt.SelectionCancelAction:
		return identityattempt.Selection
	case identityattempt.KeysReplaceAction, identityattempt.KeysStatusAction, identityattempt.KeysCancelAction:
		return identityattempt.KeysOnly
	case identityattempt.LifecycleApplyAction, identityattempt.LifecycleStatusAction, identityattempt.LifecycleResumeAction:
		return identityattempt.Lifecycle
	}
	return ""
}

func (v identityExecutionInput) validate() error {
	if identityActionKind(v.Action) != v.Kind || v.Kind == "" || !validSlug(v.Project) {
		return errIdentityExecution
	}
	switch v.Action {
	case identityattempt.SelectionApplyAction:
		if v.Keys != nil || v.LifecycleTarget != nil || v.LifecycleState != "" || v.Target != nil && v.Target.Validate() != nil {
			return errIdentityExecution
		}
	case identityattempt.KeysReplaceAction:
		if v.Target != nil || v.LifecycleTarget != nil || v.LifecycleState != "" || v.Keys != nil && v.Keys.Validate() != nil {
			return errIdentityExecution
		}
	case identityattempt.LifecycleApplyAction:
		if v.Target != nil || v.Keys != nil || v.LifecycleTarget != nil && v.LifecycleTarget.Validate() != nil ||
			v.LifecycleState != "" && v.LifecycleState != "active" && v.LifecycleState != "suspended" {
			return errIdentityExecution
		}
	default:
		if v.Target != nil || v.Keys != nil || v.LifecycleTarget != nil || v.LifecycleState != "" {
			return errIdentityExecution
		}
	}
	return nil
}

func identityNewID() (identity.SelectionOperationID, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errIdentityExecution
	}
	return identity.SelectionOperationID("oe_" + hex.EncodeToString(value[:])), nil
}

func identityNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errIdentityExecution
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func confirmIdentityEnvironment(value string, attempt *identityattempt.Attempt, action identityattempt.Action) error {
	if value == "" {
		return nil
	}
	if attempt == nil {
		return identityattempt.ErrOperationIDUnretained
	}
	var expected string
	if action == identityattempt.SelectionCancelAction || action == identityattempt.KeysCancelAction {
		id, present := attempt.CancellationID()
		if !present {
			return identityattempt.ErrOperationIDUnretained
		}
		expected = string(id)
	} else {
		switch attempt.Kind() {
		case identityattempt.Selection:
			command, _ := attempt.SelectionCommand()
			expected = string(command.OperationID)
		case identityattempt.KeysOnly:
			command, _ := attempt.KeysCommand()
			expected = string(command.OperationID)
		case identityattempt.Lifecycle:
			command, _ := attempt.LifecycleCommand()
			var scalar bool
			expected, scalar = command.OperationID.ScalarString()
			if !scalar {
				return identityattempt.ErrContinuationUnsupported
			}
		}
	}
	if expected != value {
		return identityattempt.ErrOperationIDMismatch
	}
	return nil
}

// executeIdentity retains the exact command before one mutation dispatch.
// New targets require the complete context that the caller approved.
func (r *runner) executeIdentity(ctx context.Context, input identityExecutionInput) (result identityExecutionResult, err error) {
	if input.validate() != nil || ctx == nil {
		return result, errIdentityExecution
	}
	if deadline, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !time.Now().Before(deadline) {
		return result, identityattempt.ErrTimeout
	}
	newTarget := input.Target != nil || input.Keys != nil || input.LifecycleTarget != nil
	if newTarget {
		if input.Approved == nil || input.Approved.Validate() != nil {
			return result, errIdentityExecution
		}
		approved, cloneErr := input.Approved.Clone()
		if cloneErr != nil {
			return result, errIdentityExecution
		}
		input.Approved = &approved
		if input.LifecycleTarget != nil {
			if input.ApprovedTarget == nil || input.ApprovedTarget.Validate() != nil {
				return result, errIdentityExecution
			}
			target, cloneErr := input.ApprovedTarget.Clone()
			if cloneErr != nil {
				return result, errIdentityExecution
			}
			input.ApprovedTarget = &target
		}
	}
	address, err := r.identityContext(ctx, input.Project, input.Kind)
	if err != nil {
		return result, err
	}
	// An identity read never opens or enrolls the attempt store.
	// Read-only current/preview entry points use identityContext and transport directly.
	current, err := address.transport.Current(ctx, address.credential)
	if err != nil {
		return result, err
	}
	contextValue, err := current.Context()
	if err != nil {
		return result, err
	}
	if newTarget && !sameIdentityApprovalContext(*input.Approved, contextValue) {
		return result, errIdentityExecution
	}
	var targetObservation *identity.TargetObservation
	if input.LifecycleTarget != nil {
		observed, observationErr := address.transport.LifecycleTarget(ctx, address.credential, *input.LifecycleTarget)
		if observationErr != nil {
			return result, observationErr
		}
		if !sameIdentityTargetEvidence(*input.ApprovedTarget, observed) || !observed.Scope.Equal(contextValue.Precondition.Scope) {
			return result, errIdentityExecution
		}
		targetObservation = &observed
	}
	status := input.Action == identityattempt.SelectionStatusAction || input.Action == identityattempt.KeysStatusAction || input.Action == identityattempt.LifecycleStatusAction
	if (!status || input.NamespaceFirstUse || input.SlotFirstUse) && !input.Consent {
		return result, errIdentityConsent
	}
	lease, err := r.identityStore(ctx, address.slot, input.NamespaceFirstUse, input.SlotFirstUse)
	if err != nil {
		return result, err
	}
	defer func() {
		if closeErr := lease.Close(); closeErr != nil {
			result = identityExecutionResult{}
			err = errors.Join(err, closeErr)
		}
	}()
	envelope, err := lease.Read(ctx)
	if err != nil {
		return result, err
	}
	attempt, err := envelope.RetainedAttempt()
	if err != nil {
		return result, err
	}
	if err := confirmIdentityEnvironment(r.getenv("OE_OPERATION_ID"), attempt, input.Action); err != nil {
		return result, err
	}
	if attempt == nil {
		if status || input.Action == identityattempt.SelectionCancelAction || input.Action == identityattempt.KeysCancelAction || input.Action == identityattempt.LifecycleResumeAction {
			return result, identityattempt.ErrOperationIDUnretained
		}
		var retained identityattempt.Attempt
		retained, err = r.newIdentityAttempt(ctx, address, current, lease, envelope, input, targetObservation)
		if err != nil {
			return result, err
		}
		envelope, err = lease.Retain(ctx, envelope, retained)
		if err != nil {
			return result, err
		}
		attempt = &retained
	} else if newTarget {
		return result, identityattempt.ErrChanged
	} else if err := retainedIdentityInput(*attempt, input); err != nil {
		return result, err
	}
	if input.Action == identityattempt.SelectionCancelAction || input.Action == identityattempt.KeysCancelAction {
		if _, present := attempt.CancellationID(); !present {
			id, err := identityNewID()
			if err != nil {
				return result, err
			}
			envelope, err = lease.AppendCancellation(ctx, envelope, identity.CancellationOperationID(id))
			if err != nil {
				return result, err
			}
		}
	}
	permit, err := lease.Confirm(ctx, envelope, input.Action)
	if err != nil {
		return result, err
	}
	resolution, receipt, err := dispatchIdentity(ctx, address, current, lease, envelope, permit, input)
	if err != nil {
		return result, err
	}
	result = receipt
	result.Envelope, err = resolution.Envelope()
	result.Disposition = resolution.Disposition()
	return result, err
}

func retainedIdentityInput(attempt identityattempt.Attempt, input identityExecutionInput) error {
	switch attempt.Kind() {
	case identityattempt.Selection:
		command, _ := attempt.SelectionCommand()
		if input.Target != nil && !input.Target.Equal(command.Target) {
			return identityattempt.ErrChanged
		}
	case identityattempt.KeysOnly:
		command, _ := attempt.KeysCommand()
		if input.Keys != nil && !input.Keys.Equal(command.Keys) {
			return identityattempt.ErrChanged
		}
	case identityattempt.Lifecycle:
		command, _ := attempt.LifecycleCommand()
		if input.Action == identityattempt.LifecycleApplyAction && (input.LifecycleTarget == nil ||
			input.LifecycleTarget.Kind != command.TargetKind || input.LifecycleState != command.State) {
			return identityattempt.ErrContinuationUnsupported
		}
	}
	return nil
}

func (r *runner) newIdentityAttempt(ctx context.Context, address identityExecutionContext, current control.AddressedCurrent,
	lease *identityattempt.Lease, envelope identityattempt.Envelope, input identityExecutionInput, targetObservation *identity.TargetObservation) (identityattempt.Attempt, error) {
	contextValue, err := current.Context()
	if err != nil {
		return identityattempt.Attempt{}, err
	}
	if input.Kind == identityattempt.Lifecycle {
		if input.LifecycleTarget == nil || input.LifecycleState == "" {
			return identityattempt.Attempt{}, errIdentityExecution
		}
		if targetObservation == nil || input.ApprovedTarget == nil || !sameIdentityTargetEvidence(*input.ApprovedTarget, *targetObservation) {
			return identityattempt.Attempt{}, errIdentityExecution
		}
		observation := *targetObservation
		nonce, err := identityNonce()
		if err != nil {
			return identityattempt.Attempt{}, err
		}
		permit, err := lease.ConfirmPreparation(ctx, envelope)
		if err != nil {
			return identityattempt.Attempt{}, err
		}
		prepared, err := address.transport.LifecyclePrepare(ctx, address.credential, current, permit,
			control.LifecyclePreparationInput{Target: *input.LifecycleTarget, State: input.LifecycleState,
				ExpectedLifecycleVersion: observation.ObservedVersion, Nonce: nonce})
		if err != nil {
			return identityattempt.Attempt{}, err
		}
		command, err := prepared.Attempt()
		if err != nil {
			return identityattempt.Attempt{}, err
		}
		return identityattempt.NewLifecycleAttempt(command)
	}
	preview := identity.PreviewRequest{Kind: string(input.Kind), ExpectedConfigurationVersion: contextValue.Configuration.ConfigurationVersion,
		Target: input.Target, Keys: input.Keys}
	if preview.Validate() != nil {
		return identityattempt.Attempt{}, errIdentityExecution
	}
	observed, err := address.transport.Preview(ctx, address.credential, preview)
	if err != nil {
		return identityattempt.Attempt{}, err
	}
	if !sameIdentityApprovalContext(observed.Current, contextValue) || input.Approved == nil || !sameIdentityApprovalContext(observed.Current, *input.Approved) || !identityNativeAvailable(input.Target, observed) {
		return identityattempt.Attempt{}, errIdentityExecution
	}
	id, err := identityNewID()
	if err != nil {
		return identityattempt.Attempt{}, err
	}
	if input.Kind == identityattempt.Selection {
		return identityattempt.NewSelectionAttempt(identity.SelectionCommand{OperationID: id,
			ExpectedConfigurationVersion: preview.ExpectedConfigurationVersion, Target: *input.Target, Precondition: contextValue.Precondition})
	}
	return identityattempt.NewKeysAttempt(identity.KeysCommand{OperationID: id,
		ExpectedConfigurationVersion: preview.ExpectedConfigurationVersion, Keys: *input.Keys, Precondition: contextValue.Precondition})
}

func dispatchIdentity(ctx context.Context, address identityExecutionContext, current control.AddressedCurrent, lease *identityattempt.Lease,
	envelope identityattempt.Envelope, permit *identityattempt.DispatchPermit, input identityExecutionInput) (identityattempt.Resolution, identityExecutionResult, error) {
	switch input.Action {
	case identityattempt.SelectionApplyAction, identityattempt.SelectionStatusAction, identityattempt.SelectionCancelAction:
		var receipt identity.SelectionReceipt
		var err error
		switch input.Action {
		case identityattempt.SelectionApplyAction:
			receipt, err = address.transport.SelectionApply(ctx, address.credential, permit)
		case identityattempt.SelectionStatusAction:
			receipt, err = address.transport.SelectionStatus(ctx, address.credential, permit)
		case identityattempt.SelectionCancelAction:
			receipt, err = address.transport.SelectionCancel(ctx, address.credential, permit)
		}
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		value, err := receipt.Result()
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		resolution, err := lease.ResolveSelection(ctx, envelope, receipt)
		return resolution, identityExecutionResult{Selection: &value}, err
	case identityattempt.KeysReplaceAction, identityattempt.KeysStatusAction, identityattempt.KeysCancelAction:
		var receipt identity.KeysReceipt
		var err error
		switch input.Action {
		case identityattempt.KeysReplaceAction:
			receipt, err = address.transport.KeysReplace(ctx, address.credential, permit)
		case identityattempt.KeysStatusAction:
			receipt, err = address.transport.KeysStatus(ctx, address.credential, permit)
		case identityattempt.KeysCancelAction:
			receipt, err = address.transport.KeysCancel(ctx, address.credential, permit)
		}
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		value, err := receipt.Result()
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		resolution, err := lease.ResolveKeys(ctx, envelope, receipt)
		return resolution, identityExecutionResult{Keys: &value}, err
	default:
		var reply control.LifecycleReply
		var err error
		switch input.Action {
		case identityattempt.LifecycleStatusAction:
			reply, err = address.transport.LifecycleOperation(ctx, address.credential, current, permit)
		case identityattempt.LifecycleResumeAction:
			reply, err = address.transport.LifecycleResume(ctx, address.credential, current, permit)
		case identityattempt.LifecycleApplyAction:
			if input.LifecycleTarget == nil {
				return identityattempt.Resolution{}, identityExecutionResult{}, errIdentityExecution
			}
			reply, err = address.transport.LifecycleApply(ctx, address.credential, current, permit, *input.LifecycleTarget)
		default:
			return identityattempt.Resolution{}, identityExecutionResult{}, errIdentityExecution
		}
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		receipt, err := reply.Receipt()
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		scope, err := reply.Scope()
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		value, err := receipt.Result()
		if err != nil {
			return identityattempt.Resolution{}, identityExecutionResult{}, err
		}
		resolution, err := lease.ResolveLifecycle(ctx, envelope, scope, receipt)
		return resolution, identityExecutionResult{Lifecycle: &value}, err
	}
}

// Each target read has an independent correlation ID. It grants no continuation.
// All remaining fields, including optional presence, must match the approval.
func sameIdentityTargetEvidence(approved, current identity.TargetObservation) bool {
	if approved.Validate() != nil || current.Validate() != nil {
		return false
	}
	detached, err := current.Clone()
	if err != nil {
		return false
	}
	detached.OperationID = approved.OperationID
	return approved.Equal(detached)
}

// Admission evidence receives a new check time on every maintained Relay read.
// All authority fields and optional presence remain part of the approval.
func sameIdentityApprovalContext(approved, current identity.CurrentContext) bool {
	if approved.Validate() != nil || current.Validate() != nil {
		return false
	}
	left, err := approved.Clone()
	if err != nil {
		return false
	}
	right, err := current.Clone()
	if err != nil {
		return false
	}
	left.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds = 0
	right.Configuration.AdmissionReadiness.Evidence.CheckedAtSeconds = 0
	return left.Equal(right)
}
