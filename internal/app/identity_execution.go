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
}

type identityExecutionResult struct {
	Disposition identity.ReceiptDisposition
	Envelope    identityattempt.Envelope
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

// executeIdentity has no command route yet. Its successful app.Run composition
// requires the later command grant; local store/control integration is separate.
func (r *runner) executeIdentity(ctx context.Context, input identityExecutionInput) (result identityExecutionResult, err error) {
	if input.validate() != nil || ctx == nil {
		return result, errIdentityExecution
	}
	if deadline, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !time.Now().Before(deadline) {
		return result, identityattempt.ErrTimeout
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
	if _, err := current.Context(); err != nil {
		return result, err
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
		retained, err = r.newIdentityAttempt(ctx, address, current, lease, envelope, input)
		if err != nil {
			return result, err
		}
		envelope, err = lease.Retain(ctx, envelope, retained)
		if err != nil {
			return result, err
		}
		attempt = &retained
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
	resolution, err := dispatchIdentity(ctx, address, current, lease, envelope, permit, input)
	if err != nil {
		return result, err
	}
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
	lease *identityattempt.Lease, envelope identityattempt.Envelope, input identityExecutionInput) (identityattempt.Attempt, error) {
	contextValue, err := current.Context()
	if err != nil {
		return identityattempt.Attempt{}, err
	}
	if input.Kind == identityattempt.Lifecycle {
		if input.LifecycleTarget == nil || input.LifecycleState == "" {
			return identityattempt.Attempt{}, errIdentityExecution
		}
		observation, err := address.transport.LifecycleTarget(ctx, address.credential, *input.LifecycleTarget)
		if err != nil {
			return identityattempt.Attempt{}, err
		}
		if !observation.Scope.Equal(contextValue.Precondition.Scope) || observation.Target.Kind != input.LifecycleTarget.Kind {
			return identityattempt.Attempt{}, errIdentityExecution
		}
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
	if !observed.Current.Precondition.Equal(contextValue.Precondition) {
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
	envelope identityattempt.Envelope, permit *identityattempt.DispatchPermit, input identityExecutionInput) (identityattempt.Resolution, error) {
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
			return identityattempt.Resolution{}, err
		}
		return lease.ResolveSelection(ctx, envelope, receipt)
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
			return identityattempt.Resolution{}, err
		}
		return lease.ResolveKeys(ctx, envelope, receipt)
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
				return identityattempt.Resolution{}, errIdentityExecution
			}
			reply, err = address.transport.LifecycleApply(ctx, address.credential, current, permit, *input.LifecycleTarget)
		default:
			return identityattempt.Resolution{}, errIdentityExecution
		}
		if err != nil {
			return identityattempt.Resolution{}, err
		}
		receipt, err := reply.Receipt()
		if err != nil {
			return identityattempt.Resolution{}, err
		}
		scope, err := reply.Scope()
		if err != nil {
			return identityattempt.Resolution{}, err
		}
		return lease.ResolveLifecycle(ctx, envelope, scope, receipt)
	}
}
