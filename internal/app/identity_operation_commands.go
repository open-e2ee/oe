package app

import (
	"context"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

type identityCommandResult struct {
	Environment          string                      `json:"environment"`
	Kind                 identityattempt.Kind        `json:"kind"`
	OperationID          string                      `json:"operationId"`
	Status               string                      `json:"status"`
	State                string                      `json:"state,omitempty"`
	ConfigurationVersion *identity.SafeInteger       `json:"configurationVersion,omitempty"`
	LifecycleVersion     *identity.SafeInteger       `json:"lifecycleVersion,omitempty"`
	Disposition          identity.ReceiptDisposition `json:"commandReceipt"`
	ServiceReadiness     string                      `json:"serviceReadiness"`
}

func projectIdentityExecution(kind identityattempt.Kind, result identityExecutionResult) (identityCommandResult, error) {
	value := identityCommandResult{Kind: kind, Disposition: result.Disposition, ServiceReadiness: "unverified"}
	count := 0
	if result.Selection != nil {
		count++
	}
	if result.Keys != nil {
		count++
	}
	if result.Lifecycle != nil {
		count++
	}
	if count != 1 {
		return value, errIdentityExecution
	}
	var id identity.ContractText
	switch kind {
	case identityattempt.Selection:
		if result.Selection == nil || result.Selection.Validate() != nil {
			return value, errIdentityExecution
		}
		received := result.Selection
		id, value.Status = received.OperationID, received.State
		version := received.ConfigurationVersion
		value.ConfigurationVersion = &version
	case identityattempt.KeysOnly:
		if result.Keys == nil || result.Keys.Validate() != nil {
			return value, errIdentityExecution
		}
		received := result.Keys
		id, value.Status = received.OperationID, received.State
		version := received.ConfigurationVersion
		value.ConfigurationVersion = &version
	case identityattempt.Lifecycle:
		if result.Lifecycle == nil || result.Lifecycle.Validate() != nil {
			return value, errIdentityExecution
		}
		received := result.Lifecycle
		id, value.Status, value.State = received.Operation.OperationID, received.Status, received.State
		if received.Version != nil {
			version := *received.Version
			value.LifecycleVersion = &version
		}
	default:
		return value, errIdentityExecution
	}
	scalar, valid := id.ScalarString()
	if !valid {
		return identityCommandResult{}, errIdentityExecution
	}
	value.OperationID = scalar
	switch value.Disposition {
	case identity.ReceiptSettled, identity.ReceiptPending, identity.ReceiptContinuationRequired:
		return value, nil
	}
	return identityCommandResult{}, errIdentityExecution
}

func (r *runner) outputIdentityExecution(command string, kind identityattempt.Kind, result identityExecutionResult) error {
	value, err := projectIdentityExecution(kind, result)
	if err != nil {
		return err
	}
	value.Environment = r.environment
	data := map[string]any{"operation": value}
	if failure := identityResultFailure(value); failure != nil {
		failure.data = data
		return failure
	}
	return r.out.Success(command, "The exact command receipt is settled. Current service and application readiness remain unverified.", data)
}

func identityResultFailure(value identityCommandResult) *problem {
	next := "oe identity operation status --kind " + string(value.Kind) + " --env " + value.Environment
	if value.Disposition == identity.ReceiptContinuationRequired {
		return identityCommandProblem("IDENTITY_CONTINUATION_REQUIRED", "The exact command receipt still requires same-ID continuation.",
			"oe identity operation resume --kind lifecycle --env "+value.Environment, exitTemporary)
	}
	if value.Disposition == identity.ReceiptPending {
		return identityCommandProblem("IDENTITY_PENDING", "The exact operation is pending. Preserve its retained command.", next, exitTemporary)
	}
	switch value.Status {
	case "refused", "deleted", "superseded", "superseded_by_deletion":
		return identityCommandProblem("IDENTITY_OPERATION_REFUSED", "The exact operation ended without applying the requested change.",
			"oe identity current --env "+value.Environment, exitFailure)
	}
	return nil
}

func identityRetainedAction(verb string, kind identityattempt.Kind) identityattempt.Action {
	switch kind {
	case identityattempt.Selection:
		switch verb {
		case "status":
			return identityattempt.SelectionStatusAction
		case "retry":
			return identityattempt.SelectionApplyAction
		case "cancel":
			return identityattempt.SelectionCancelAction
		}
	case identityattempt.KeysOnly:
		switch verb {
		case "status":
			return identityattempt.KeysStatusAction
		case "retry":
			return identityattempt.KeysReplaceAction
		case "cancel":
			return identityattempt.KeysCancelAction
		}
	case identityattempt.Lifecycle:
		switch verb {
		case "status":
			return identityattempt.LifecycleStatusAction
		case "resume":
			return identityattempt.LifecycleResumeAction
		}
	}
	return ""
}

func (r *runner) identityOperationCommand(ctx context.Context, args []string) error {
	verb := args[0]
	options := identityCommandOptions{}
	flags := newFlags("identity operation " + verb)
	kindFlag := flags.String("kind", "", "exact retained kind: selection, keys-only or lifecycle")
	if verb != "status" {
		options.flags(flags, false, false)
	}
	if parseFlags(flags, "identity", args[1:]) != nil {
		return identityInputFailure()
	}
	kind := identityattempt.Kind(*kindFlag)
	action := identityRetainedAction(verb, kind)
	if action == "" {
		return identityInputFailure()
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	// A continuation takes no target, replacement file or first-use declaration.
	if verb != "status" {
		if _, err := r.identityContext(ctx, configuration.Project, kind); err != nil {
			return err
		}
		if err := r.approveIdentity("oe identity operation "+verb+" --kind "+string(kind), options); err != nil {
			return err
		}
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project, Kind: kind, Action: action, Consent: verb != "status"})
	if err != nil {
		return identityExecutionFailure(err, kind, r.environment)
	}
	return r.outputIdentityExecution("identity operation "+verb, kind, result)
}
