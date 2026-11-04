package app

import (
	"context"

	"github.com/open-e2ee/oe/internal/identity"
)

type identityCommandResult struct {
	Environment          string                      `json:"environment"`
	Kind                 identity.Kind               `json:"kind"`
	OperationID          string                      `json:"operationId"`
	Status               string                      `json:"status"`
	State                string                      `json:"state,omitempty"`
	ConfigurationVersion *identity.SafeInteger       `json:"configurationVersion,omitempty"`
	LifecycleVersion     *identity.SafeInteger       `json:"lifecycleVersion,omitempty"`
	Disposition          identity.ReceiptDisposition `json:"commandReceipt"`
	ServiceReadiness     string                      `json:"serviceReadiness"`
}

func projectIdentityExecution(kind identity.Kind, result identityExecutionResult) (identityCommandResult, error) {
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
	case identity.Selection:
		if result.Selection == nil || result.Selection.Validate() != nil {
			return value, errIdentityExecution
		}
		received := result.Selection
		id, value.Status = received.OperationID, received.State
		version := received.ConfigurationVersion
		value.ConfigurationVersion = &version
	case identity.KeysOnly:
		if result.Keys == nil || result.Keys.Validate() != nil {
			return value, errIdentityExecution
		}
		received := result.Keys
		id, value.Status = received.OperationID, received.State
		version := received.ConfigurationVersion
		value.ConfigurationVersion = &version
	case identity.Lifecycle:
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

// outputIdentityExecution reports one server result. repeat is the command
// line that OE_OPERATION_ID can repeat, or "" when the command cannot repeat.
func (r *runner) outputIdentityExecution(command string, kind identity.Kind, result identityExecutionResult, repeat string) error {
	value, err := projectIdentityExecution(kind, result)
	if err != nil {
		return err
	}
	value.Environment = r.environment
	data := map[string]any{"operation": value}
	if failure := identityResultFailure(value, repeat); failure != nil {
		failure.data = data
		return failure
	}
	return r.out.Success(command, "The exact command receipt is settled. Current service and application readiness remain unverified.", data)
}

func identityResultFailure(value identityCommandResult, repeat string) *problem {
	next := identityStatusCommand(value.Kind, value.OperationID, value.Environment)
	if value.Disposition == identity.ReceiptContinuationRequired {
		return identityCommandProblem("IDENTITY_CONTINUATION_REQUIRED", "The lifecycle operation continues only by a resume with the same operation ID.",
			commandLine([]string{"identity", "operation", "resume", "--kind", "lifecycle", "--operation-id", value.OperationID, "--env", value.Environment}), exitTemporary)
	}
	if value.Disposition == identity.ReceiptPending {
		message := "The operation is pending on the server. Read it by its operation ID."
		if repeat != "" {
			message = "The operation is pending on the server. To repeat the same command, run: OE_OPERATION_ID=" + value.OperationID + " " + repeat
		}
		return identityCommandProblem("IDENTITY_PENDING", message, next, exitTemporary)
	}
	switch value.Status {
	case "refused", "deleted", "superseded", "superseded_by_deletion":
		return identityCommandProblem("IDENTITY_OPERATION_REFUSED", "The operation ended without applying the requested change.",
			"oe identity current --env "+value.Environment, exitFailure)
	}
	return nil
}

func identityOperationAction(verb string, kind identity.Kind) identity.Action {
	switch kind {
	case identity.Selection:
		switch verb {
		case "status":
			return identity.SelectionStatusAction
		case "cancel":
			return identity.SelectionCancelAction
		}
	case identity.KeysOnly:
		switch verb {
		case "status":
			return identity.KeysStatusAction
		case "cancel":
			return identity.KeysCancelAction
		}
	case identity.Lifecycle:
		switch verb {
		case "status":
			return identity.LifecycleStatusAction
		case "resume":
			return identity.LifecycleResumeAction
		}
	}
	return ""
}

// validIdentityOperationID reports whether id has the form of a server
// operation ID of kind.
func validIdentityOperationID(kind identity.Kind, id string) bool {
	if kind != identity.Lifecycle {
		return identity.SelectionOperationID(id).Validate() == nil
	}
	text, err := identity.Text(id)
	return err == nil && identity.ValidateResumeOperationID(text) == nil
}

// identityOperationCommand reads, cancels or resumes one server operation.
// Status without --operation-id reads the current operation that the server
// names. Cancel and resume always name the operation.
func (r *runner) identityOperationCommand(ctx context.Context, args []string) error {
	verb := args[0]
	options := identityCommandOptions{}
	flags := newFlags("identity operation " + verb)
	kindFlag := flags.String("kind", "", "operation kind: selection, keys-only or lifecycle")
	idFlag := flags.String("operation-id", "", "the server operation ID")
	targetStdin := false
	if verb == "status" {
		flags.BoolVar(&targetStdin, "target-stdin", false, "read one private lifecycle target from stdin and report its current operation")
	} else {
		options.flags(flags, false)
	}
	if parseFlags(flags, "identity", args[1:]) != nil {
		return identityInputFailure()
	}
	kind, id := identity.Kind(*kindFlag), *idFlag
	action := identityOperationAction(verb, kind)
	if action == "" || id != "" && !validIdentityOperationID(kind, id) || id == "" && verb != "status" ||
		targetStdin && (kind != identity.Lifecycle || id != "") || kind == identity.Lifecycle && verb == "status" && id == "" && !targetStdin {
		return identityInputFailure()
	}
	if action.Cancel() {
		if err := r.identityOperationEnvironment(action, id); err != nil {
			return err
		}
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	input := identityExecutionInput{Project: configuration.Project, Action: action, OperationID: id, Consent: verb != "status"}
	if targetStdin {
		// Authority precedes private stdin. The input remains transient.
		if _, err := r.identityContext(ctx, configuration.Project); err != nil {
			return err
		}
		target, err := readIdentityTarget(r.in)
		if err != nil {
			return err
		}
		input.LifecycleTarget = &target
	}
	if verb != "status" {
		if _, err := r.identityContext(ctx, configuration.Project); err != nil {
			return err
		}
		command := commandLine([]string{"identity", "operation", verb, "--kind", string(kind), "--operation-id", id, "--env", r.environment})
		if err := r.approveIdentity(command, nil, options); err != nil {
			return err
		}
	}
	result, err := r.executeIdentity(ctx, input)
	if err != nil {
		return identityExecutionFailure(err, r.environment)
	}
	return r.outputIdentityExecution("identity operation "+verb, kind, result, "")
}
