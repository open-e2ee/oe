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
)

// identityExecutionInput is an internal workflow input, not a CLI flag schema.
// New work carries its transient target. Status, cancel and resume carry the
// server operation ID instead.
type identityExecutionInput struct {
	Project         string
	Action          identity.Action
	OperationID     string
	Target          *identity.SelectionTarget
	Keys            *identity.ReplacementKeys
	LifecycleTarget *identity.LifecycleInputTarget
	LifecycleState  string
	Consent         bool
	Approved        *identity.CurrentContext
	ApprovedTarget  *identity.TargetObservation
}

type identityExecutionResult struct {
	Disposition identity.ReceiptDisposition
	Selection   *identity.SelectionResult
	Keys        *identity.KeysResult
	Lifecycle   *identity.LifecycleStatus
}

func (v identityExecutionInput) validate() error {
	if v.Action.Kind() == "" || !validSlug(v.Project) {
		return errIdentityExecution
	}
	switch v.Action {
	case identity.SelectionApplyAction:
		if v.OperationID != "" || v.Target == nil || v.Target.Validate() != nil || v.Keys != nil || v.LifecycleTarget != nil || v.LifecycleState != "" {
			return errIdentityExecution
		}
	case identity.KeysReplaceAction:
		if v.OperationID != "" || v.Keys == nil || v.Keys.Validate() != nil || v.Target != nil || v.LifecycleTarget != nil || v.LifecycleState != "" {
			return errIdentityExecution
		}
	case identity.LifecycleApplyAction:
		if v.OperationID != "" || v.Target != nil || v.Keys != nil || v.LifecycleTarget == nil || v.LifecycleTarget.Validate() != nil ||
			v.LifecycleState != "active" && v.LifecycleState != "suspended" {
			return errIdentityExecution
		}
	case identity.LifecycleStatusAction:
		// Without an ID, the status of a bound account comes from its target.
		if v.Target != nil || v.Keys != nil || v.LifecycleState != "" || (v.OperationID == "") == (v.LifecycleTarget == nil) ||
			v.LifecycleTarget != nil && v.LifecycleTarget.Validate() != nil {
			return errIdentityExecution
		}
	default:
		if v.Target != nil || v.Keys != nil || v.LifecycleTarget != nil || v.LifecycleState != "" ||
			v.OperationID == "" && !v.Action.Status() {
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

var errIdentityDeadline = errors.New("The identity command deadline passed.")

// identityOperationFailure is a failure after the server received, or may
// have received, the operation with this ID. The ID is the only state that
// recovers the operation, so every such failure carries it.
type identityOperationFailure struct {
	kind identity.Kind
	id   string
	err  error
}

func (e *identityOperationFailure) Error() string { return e.err.Error() }
func (e *identityOperationFailure) Unwrap() error { return e.err }

func identityOperationError(kind identity.Kind, id string, err error) error {
	if err == nil {
		return nil
	}
	return &identityOperationFailure{kind: kind, id: id, err: err}
}

// identityMutationOperationID resolves the idempotency key of one selection or
// keys-only mutation. OE_OPERATION_ID repeats an earlier command, and the
// server replays its result while the command is the same.
func (r *runner) identityMutationOperationID() (identity.SelectionOperationID, error) {
	value := r.getenv("OE_OPERATION_ID")
	if value == "" {
		return identityNewID()
	}
	if identity.SelectionOperationID(value).Validate() != nil {
		return "", identityCommandProblem("IDENTITY_INPUT_INVALID", "OE_OPERATION_ID must be 8 to 96 letters, digits, underscores or hyphens.", "oe help identity", exitUsage)
	}
	return identity.SelectionOperationID(value), nil
}

// identityLifecycleOperationIDRefusal refuses OE_OPERATION_ID on a lifecycle
// command. Its operation ID comes from the server preparation.
func (r *runner) identityLifecycleOperationIDRefusal() error {
	if r.getenv("OE_OPERATION_ID") == "" {
		return nil
	}
	return identityCommandProblem("IDENTITY_OPERATION_CONFLICT",
		"A lifecycle command takes no OE_OPERATION_ID. Continue a lifecycle operation by its prepared operation ID.",
		"oe identity operation resume --kind lifecycle --operation-id ID --env "+r.environment, exitUsage)
}

// executeIdentity sends one identity command to the server. The server holds
// the operation, and the CLI keeps no local record of it.
func (r *runner) executeIdentity(ctx context.Context, input identityExecutionInput) (identityExecutionResult, error) {
	var result identityExecutionResult
	if ctx == nil || input.validate() != nil {
		return result, errIdentityExecution
	}
	if deadline, bounded := ctx.Deadline(); !bounded || ctx.Err() != nil || !time.Now().Before(deadline) {
		return result, errIdentityDeadline
	}
	if input.Action == identity.LifecycleApplyAction {
		if err := r.identityLifecycleOperationIDRefusal(); err != nil {
			return result, err
		}
	}
	newTarget := !input.Action.Status() && !input.Action.Cancel() && input.Action != identity.LifecycleResumeAction
	if newTarget {
		if input.Approved == nil || input.Approved.Validate() != nil {
			return result, errIdentityExecution
		}
		approved, err := input.Approved.Clone()
		if err != nil {
			return result, errIdentityExecution
		}
		input.Approved = &approved
		if input.LifecycleTarget != nil {
			if input.ApprovedTarget == nil || input.ApprovedTarget.Validate() != nil {
				return result, errIdentityExecution
			}
			target, err := input.ApprovedTarget.Clone()
			if err != nil {
				return result, errIdentityExecution
			}
			input.ApprovedTarget = &target
		}
	}
	if !input.Action.Status() && !input.Consent {
		return result, errIdentityConsent
	}
	address, err := r.identityContext(ctx, input.Project)
	if err != nil {
		return result, err
	}
	// Without an ID, keys-only status reads the keys-only current operation.
	read := address.transport.Current
	if input.Action == identity.KeysStatusAction && input.OperationID == "" {
		read = address.transport.KeysCurrent
	}
	current, err := read(ctx, address.credential)
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
	var observation *identity.TargetObservation
	if input.LifecycleTarget != nil {
		observed, err := address.transport.LifecycleTarget(ctx, address.credential, *input.LifecycleTarget)
		if err != nil {
			return result, err
		}
		if observed.Validate() != nil || !observed.Scope.Equal(contextValue.Precondition.Scope) || observed.Target.Kind != input.LifecycleTarget.Kind ||
			newTarget && !sameIdentityTargetEvidence(*input.ApprovedTarget, observed) {
			return result, errIdentityExecution
		}
		observation = &observed
	}
	kind := input.Action.Kind()
	scope := contextValue.Precondition.Scope
	selectionID := identity.SelectionOperationID(input.OperationID)
	lifecycleID, err := identity.Text(input.OperationID)
	if err != nil {
		return result, errIdentityExecution
	}
	switch input.Action {
	case identity.SelectionApplyAction, identity.KeysReplaceAction:
		preview := identity.PreviewRequest{Kind: string(kind), ExpectedConfigurationVersion: contextValue.Configuration.ConfigurationVersion,
			Target: input.Target, Keys: input.Keys}
		if preview.Validate() != nil {
			return result, errIdentityExecution
		}
		observed, err := address.transport.Preview(ctx, address.credential, preview)
		if err != nil {
			return result, err
		}
		if !sameIdentityApprovalContext(observed.Current, contextValue) || !sameIdentityApprovalContext(observed.Current, *input.Approved) || !identityNativeAvailable(input.Target, observed) {
			return result, errIdentityExecution
		}
		id, err := r.identityMutationOperationID()
		if err != nil {
			return result, err
		}
		if input.Action == identity.SelectionApplyAction {
			value, err := address.transport.SelectionApply(ctx, address.credential, identity.SelectionCommand{OperationID: id,
				ExpectedConfigurationVersion: preview.ExpectedConfigurationVersion, Target: *input.Target, Precondition: contextValue.Precondition})
			if err != nil {
				return result, identityOperationError(kind, string(id), err)
			}
			return identityExecutionResult{Disposition: identity.ClassifySelectionResult(id, value), Selection: &value}, nil
		}
		value, err := address.transport.KeysReplace(ctx, address.credential, identity.KeysCommand{OperationID: id,
			ExpectedConfigurationVersion: preview.ExpectedConfigurationVersion, Keys: *input.Keys, Precondition: contextValue.Precondition})
		if err != nil {
			return result, identityOperationError(kind, string(id), err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyKeysResult(id, value), Keys: &value}, nil
	case identity.SelectionStatusAction, identity.KeysStatusAction:
		if input.OperationID == "" {
			return identityCurrentOperation(kind, contextValue)
		}
		if input.Action == identity.SelectionStatusAction {
			value, err := address.transport.SelectionStatus(ctx, address.credential, current, selectionID)
			if err != nil {
				return result, identityOperationError(kind, input.OperationID, err)
			}
			return identityExecutionResult{Disposition: identity.ClassifySelectionResult(selectionID, value), Selection: &value}, nil
		}
		value, err := address.transport.KeysStatus(ctx, address.credential, current, selectionID)
		if err != nil {
			return result, identityOperationError(kind, input.OperationID, err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyKeysResult(selectionID, value), Keys: &value}, nil
	case identity.SelectionCancelAction, identity.KeysCancelAction:
		cancellation, err := r.identityMutationOperationID()
		if err != nil {
			return result, err
		}
		if input.Action == identity.SelectionCancelAction {
			value, err := address.transport.SelectionCancel(ctx, address.credential, current, identity.CancellationOperationID(cancellation), selectionID)
			if err != nil {
				return result, identityOperationError(kind, input.OperationID, err)
			}
			return identityExecutionResult{Disposition: identity.ClassifySelectionResult(selectionID, value), Selection: &value}, nil
		}
		value, err := address.transport.KeysCancel(ctx, address.credential, current, identity.CancellationOperationID(cancellation), selectionID)
		if err != nil {
			return result, identityOperationError(kind, input.OperationID, err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyKeysResult(selectionID, value), Keys: &value}, nil
	case identity.LifecycleStatusAction:
		if observation != nil {
			return identityBoundOperation(scope, *observation)
		}
		value, err := address.transport.LifecycleOperation(ctx, address.credential, current, lifecycleID)
		if err != nil {
			return result, identityOperationError(kind, input.OperationID, err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyLifecycleResult(lifecycleID, scope, identity.LifecycleStatusSource, value), Lifecycle: &value}, nil
	case identity.LifecycleResumeAction:
		value, err := address.transport.LifecycleResume(ctx, address.credential, current, lifecycleID)
		if err != nil {
			return result, identityOperationError(kind, input.OperationID, err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyLifecycleResult(lifecycleID, scope, identity.LifecycleResumeSource, value), Lifecycle: &value}, nil
	case identity.LifecycleApplyAction:
		nonce, err := identityNonce()
		if err != nil {
			return result, err
		}
		prepared, err := address.transport.LifecyclePrepare(ctx, address.credential, current,
			control.LifecyclePreparationInput{Target: *input.LifecycleTarget, State: input.LifecycleState,
				ExpectedLifecycleVersion: observation.ObservedVersion, Nonce: nonce})
		if err != nil {
			return result, err
		}
		attempt, err := prepared.Attempt()
		if err != nil {
			return result, errIdentityExecution
		}
		// From here on the prepared ID is the only way back to the operation.
		id, scalar := attempt.OperationID.ScalarString()
		if !scalar {
			return result, errIdentityExecution
		}
		value, err := address.transport.LifecycleApply(ctx, address.credential, current, attempt, *input.LifecycleTarget)
		if err != nil {
			return result, identityOperationError(kind, id, err)
		}
		return identityExecutionResult{Disposition: identity.ClassifyLifecycleResult(attempt.OperationID, scope, identity.LifecycleApplySource, value), Lifecycle: &value}, nil
	}
	return result, errIdentityExecution
}

// identityCurrentOperation reports the latest selection or keys-only
// operation that the current server read names.
func identityCurrentOperation(kind identity.Kind, current identity.CurrentContext) (identityExecutionResult, error) {
	operation := current.Configuration.Selection
	if operation != nil {
		id := identity.SelectionOperationID(identityScalar(operation.OperationID))
		if kind == identity.Selection && operation.Kind == nil {
			value := identity.SelectionResult(*operation)
			return identityExecutionResult{Disposition: identity.ClassifySelectionResult(id, value), Selection: &value}, nil
		}
		if kind == identity.KeysOnly && operation.Kind != nil && *operation.Kind == "keys-only" {
			value := identity.KeysResult(*operation)
			return identityExecutionResult{Disposition: identity.ClassifyKeysResult(id, value), Keys: &value}, nil
		}
	}
	return identityExecutionResult{}, identityOperationNotFound(kind, current.Precondition.Scope.EnvironmentKind)
}

// identityBoundOperation reports the current operation of a bound account.
func identityBoundOperation(scope identity.Scope, observation identity.TargetObservation) (identityExecutionResult, error) {
	bound, err := observation.Application.Bound()
	if err != nil || bound.CurrentOperation == nil {
		return identityExecutionResult{}, identityOperationNotFound(identity.Lifecycle, scope.EnvironmentKind)
	}
	value := *bound.CurrentOperation
	return identityExecutionResult{Disposition: identity.ClassifyLifecycleResult(value.Operation.OperationID, scope, identity.LifecycleStatusSource, value), Lifecycle: &value}, nil
}

func identityOperationNotFound(kind identity.Kind, environment string) error {
	return identityCommandProblem("IDENTITY_OPERATION_NOT_FOUND", "The server reports no current "+string(kind)+" operation.",
		"oe identity current --env "+environment, exitFailure)
}

// identityScalar is the plain string of a server text, or "" when the text
// has no plain form. An empty ID never classifies as a result.
func identityScalar(value identity.ContractText) string {
	scalar, valid := value.ScalarString()
	if !valid {
		return ""
	}
	return scalar
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
