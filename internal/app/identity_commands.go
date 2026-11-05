package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/output"
)

type identityCommandOptions struct {
	dryRun bool
	yes    bool
}

func (v *identityCommandOptions) flags(flags *flag.FlagSet, dryRun bool) {
	flags.BoolVar(&v.yes, "yes", false, "consent to the exact Production change")
	if dryRun {
		flags.BoolVar(&v.dryRun, "dry-run", false, "preview without mutation")
	}
}

func identityInputFailure() error {
	return &problem{code: "IDENTITY_INPUT_INVALID", message: "The identity command input is invalid.", next: "oe help identity", exit: exitUsage}
}

func identityCommandProblem(code, message, next string, exit int) *problem {
	return &problem{code: code, message: message, next: next, exit: exit}
}

func identityPublicFailure(err error) error {
	if err == nil {
		return nil
	}
	if value, ok := errors.AsType[*problem](err); ok {
		return value
	}
	code, exit, next := "IDENTITY_UNAVAILABLE", exitTemporary, "oe help identity"
	if value, ok := errors.AsType[*control.APIError](err); ok {
		switch value.Code {
		case "AUTHENTICATION_REQUIRED", "INVALID_SESSION", "ACCESS_TOKEN_INVALID", "SESSION_EXPIRED":
			code, exit, next = value.Code, exitAuthentication, "oe auth login"
		case "IDENTITY_INPUT_INVALID", "IDENTITY_METHOD_NOT_ALLOWED", "IDENTITY_CONTEXT_CHANGED", "IDENTITY_CHANGE_REFUSED", "NATIVE_IDENTITY_UNAVAILABLE", "IDENTITY_CONFLICT", "IDENTITY_OPERATION_NOT_FOUND", "PROJECT_NOT_FOUND", "ENVIRONMENT_NOT_FOUND", "IMPERSONATED_SESSION", "IDENTITY_CONTROL_DENIED":
			code, exit = value.Code, exitFailure
		case "ORGANIZATION_REQUIRED":
			code, exit, next = value.Code, exitPersonAction, "oe org switch"
		case "IDENTITY_RESULT_INVALID", "AUTHORITY_UNAVAILABLE", "IDENTITY_UNAVAILABLE", "IDENTITY_RESPONSE_TOO_LARGE":
			code = value.Code
		}
	} else if errors.Is(err, errIdentityConsent) {
		code, exit = "CONFIRMATION_REQUIRED", exitUsage
	} else if errors.Is(err, errIdentityExecution) {
		code, exit = "IDENTITY_CONTEXT_CHANGED", exitFailure
	}
	return identityCommandProblem(code, "The identity operation did not complete.", next, exit)
}

// identityExecutionFailure is the public failure of one identity command. A
// failure after the server received, or may have received, the operation
// names its operation ID, and status by that ID reads the server result.
func identityExecutionFailure(err error, environment string) error {
	failure := identityPublicFailure(err)
	operation, carried := errors.AsType[*identityOperationFailure](err)
	value, ok := errors.AsType[*problem](failure)
	if !carried || !ok {
		return failure
	}
	copy := *value
	if copy.code == "IDENTITY_OPERATION_NOT_FOUND" {
		// The server holds no operation with this ID, so status by it cannot help.
		copy.next = "oe identity current --env " + environment
	} else if copy.next == "oe help identity" {
		copy.next = identityStatusCommand(operation.kind, operation.id, environment)
	}
	data := map[string]any{}
	for key, item := range value.data {
		data[key] = item
	}
	data["kind"], data["operationId"] = operation.kind, operation.id
	if operation.cancellation != "" {
		data["cancellationOperationId"] = operation.cancellation
		copy.message += " The cancel has operation ID " + operation.cancellation + " and targets operation " + operation.id + "."
		if copy.code != "IDENTITY_OPERATION_NOT_FOUND" {
			copy.message += " To repeat the same cancel, run: OPEN_E2EE_OPERATION_ID=" + operation.cancellation + " " +
				commandLine([]string{"identity", "operation", "cancel", "--kind", string(operation.kind), "--operation-id", operation.id, "--env", environment})
		}
	}
	copy.data = data
	return &copy
}

// identityStatusCommand reads one server operation by its ID.
func identityStatusCommand(kind identity.Kind, id, environment string) string {
	return commandLine([]string{"identity", "operation", "status", "--kind", string(kind), "--operation-id", id, "--env", environment})
}

func (r *runner) identityCommands(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var err error
	switch {
	case len(args) == 1 && args[0] == "current":
		err = r.identityCurrentCommand(ctx)
	case len(args) > 0 && args[0] == "select":
		err = r.identitySelectCommand(ctx, args[1:])
	case len(args) > 1 && args[0] == "keys" && args[1] == "rotate":
		err = r.identityKeysCommand(ctx, args[2:])
	case len(args) > 1 && args[0] == "lifecycle":
		err = r.identityLifecycleCommand(ctx, args[1:])
	case len(args) > 1 && args[0] == "operation":
		err = r.identityOperationCommand(ctx, args[1:])
	default:
		err = identityInputFailure()
	}
	return identityPublicFailure(err)
}

func (r *runner) identityConfiguration() (string, config.Config, error) {
	path, value, err := r.loadConfig()
	if err != nil {
		if failure, ok := errors.AsType[*problem](err); ok && failure.code == "CONFIG_NOT_FOUND" {
			return "", config.Config{}, identityCommandProblem("CONFIG_NOT_FOUND", "Link this directory to an existing project.", "oe link", exitFailure)
		}
		if failure, ok := errors.AsType[*config.Error](err); ok && failure.Code == "NODE_REQUIRED" {
			return "", config.Config{}, &problem{
				code: "NODE_REQUIRED", exit: exitPersonAction, next: "oe doctor",
				message:   "oe needs Node.js 22.18 or later with type stripping enabled on PATH.",
				actionURL: "https://nodejs.org/en/download",
			}
		}
		return "", config.Config{}, identityCommandProblem("CONFIG_INVALID", "The public project configuration is invalid.", "oe help config", exitUsage)
	}
	return path, value, nil
}

func (r *runner) readIdentityCurrent(ctx context.Context, project string, kind identity.Kind) (identityExecutionContext, identity.CurrentContext, error) {
	address, err := r.identityContext(ctx, project)
	if err != nil {
		return address, identity.CurrentContext{}, err
	}
	value, err := readAddressedIdentityCurrent(ctx, address, kind)
	return address, value, err
}

func readAddressedIdentityCurrent(ctx context.Context, address identityExecutionContext, kind identity.Kind) (identity.CurrentContext, error) {
	var current control.AddressedCurrent
	var err error
	if kind == identity.KeysOnly {
		current, err = address.transport.KeysCurrent(ctx, address.credential)
	} else {
		current, err = address.transport.Current(ctx, address.credential)
	}
	if err != nil {
		return identity.CurrentContext{}, err
	}
	return current.Context()
}

func (r *runner) identityCurrentCommand(ctx context.Context) error {
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	_, current, err := r.readIdentityCurrent(ctx, configuration.Project, identity.Selection)
	if err != nil {
		return err
	}
	return r.out.Success("identity current", "Installed configuration was read. Application readiness remains unverified.", map[string]any{
		"environment": r.environment, "configurationVersion": current.Configuration.ConfigurationVersion,
		"admissionRevision": current.Configuration.AdmissionRevision, "identityProfile": current.Configuration.IdentityProfile,
		"evidence": "installed_configuration", "applicationIntegration": "unverified", "memberBinding": "unverified", "encryptedExchange": "unverified",
	})
}

func identityNativeAvailable(target *identity.SelectionTarget, preview identity.PreviewResult) bool {
	if target == nil || target.Provider == nil {
		return true
	}
	switch *target.Provider {
	case "clerk":
		return preview.NativeCapabilities.Clerk != "closed"
	case "firebase":
		return preview.NativeCapabilities.Firebase != "closed"
	}
	return false
}

func identityPreview(ctx context.Context, address identityExecutionContext, current identity.CurrentContext, target *identity.SelectionTarget, keys *identity.ReplacementKeys) (identity.PreviewResult, error) {
	kind := "selection"
	if keys != nil {
		kind = "keys-only"
	}
	request := identity.PreviewRequest{Kind: kind, ExpectedConfigurationVersion: current.Configuration.ConfigurationVersion, Target: target, Keys: keys}
	preview, err := address.transport.Preview(ctx, address.credential, request)
	if err != nil {
		return preview, err
	}
	if preview.Validate() != nil || !sameIdentityApprovalContext(preview.Current, current) {
		return identity.PreviewResult{}, errIdentityExecution
	}
	if !identityNativeAvailable(target, preview) {
		return identity.PreviewResult{}, identityCommandProblem("IDENTITY_CAPABILITY_CLOSED", "Native identity selection is unavailable for this environment.",
			"oe identity current --env "+address.address.Environment(), exitFailure)
	}
	return preview, nil
}

// approveIdentity asks for consent to a Production identity change. command
// is the full command line that ran, and the refusal names it with --yes.
// changes is the identity change that the person approves. A refusal returns
// it in data, and a person sees it before the prompt.
func (r *runner) approveIdentity(command string, changes []pullChange, options identityCommandOptions) error {
	if r.environment != "production" || options.yes {
		return nil
	}
	refusal := func(message string) error {
		failure := identityCommandProblem("CONFIRMATION_REQUIRED", message, command+" --yes", exitUsage)
		if changes != nil {
			failure.data = map[string]any{"changes": changes}
		}
		return failure
	}
	if r.mode != output.Text || r.credentialSource == "environment" || !r.canPrompt() {
		return refusal("Review the exact Production identity change, then supply --yes.")
	}
	if len(changes) > 0 {
		var text strings.Builder
		text.WriteString("The exact Production identity change:")
		writeChanges(&text, changes)
		fmt.Fprintln(r.errOut, text.String())
	}
	approved, err := askConfirmation(r.in, r.errOut, "Apply this exact Production identity change?")
	if err != nil || !approved {
		return refusal("The Production identity change was not approved.")
	}
	return nil
}

func (r *runner) identitySelectCommand(ctx context.Context, args []string) error {
	options := identityCommandOptions{}
	flags := newFlags("identity select")
	options.flags(flags, true)
	if parseFlags(flags, "identity", args) != nil {
		return identityInputFailure()
	}
	if err := r.identityOperationEnvironment(identity.SelectionApplyAction, ""); err != nil {
		return err
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	target, err := configuration.IdentityFor(r.environment)
	if err != nil || target == nil {
		return identityCommandProblem("IDENTITY_INPUT_INVALID", "Declare a complete public identity for the selected environment.", "oe help config", exitUsage)
	}
	address, current, err := r.readIdentityCurrent(ctx, configuration.Project, identity.Selection)
	if err != nil {
		return err
	}
	if _, err = identityPreview(ctx, address, current, target, nil); err != nil {
		return err
	}
	changes, err := identityChanges(r.environment, current, target, nil)
	if err != nil {
		return err
	}
	if options.dryRun {
		return r.out.Success("identity select", "Dry run. No identity operation was prepared or applied.", map[string]any{"status": "planned", "kind": "selection", "environment": r.environment, "configurationVersion": current.Configuration.ConfigurationVersion, "changes": changes})
	}
	command := commandLine([]string{"identity", "select", "--env", r.environment})
	if err := r.approveIdentity(command, changes, options); err != nil {
		return err
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project, Action: identity.SelectionApplyAction,
		Target: target, Approved: &current, Consent: true})
	if err != nil {
		return identityExecutionFailure(err, r.environment)
	}
	return r.outputIdentityExecution("identity select", identity.Selection, result, command)
}

func readIdentityPublicFile(path string, result any) error {
	file, err := os.Open(path)
	if err != nil {
		return identityInputFailure()
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 100000 {
		return identityInputFailure()
	}
	data, err := io.ReadAll(io.LimitReader(file, 100001))
	if err != nil || len(data) > 100000 || json.Unmarshal(data, result) != nil {
		return identityInputFailure()
	}
	return nil
}

// configOwnsIdentityKeys reports whether the next config push applies the
// file keys as a keys-only change (planIdentityConfig). A rotation outside the
// file would then be reverted by that push.
func configOwnsIdentityKeys(value config.Config, environment string) bool {
	target, err := value.IdentityFor(environment)
	return err == nil && target != nil && target.Keys != nil && target.Provider == nil
}

func (r *runner) identityKeysCommand(ctx context.Context, args []string) error {
	options := identityCommandOptions{}
	flags := newFlags("identity keys rotate")
	options.flags(flags, true)
	path := flags.String("keys", "", "public replacement-key JSON file")
	if parseFlags(flags, "identity", args) != nil || *path == "" {
		return identityInputFailure()
	}
	if err := r.identityOperationEnvironment(identity.KeysReplaceAction, ""); err != nil {
		return err
	}
	var keys identity.ReplacementKeys
	if err := readIdentityPublicFile(*path, &keys); err != nil {
		return err
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	address, err := r.identityContext(ctx, configuration.Project)
	if err != nil {
		return err
	}
	if address.writer == "config" && configOwnsIdentityKeys(configuration, r.environment) {
		return identityCommandProblem("IDENTITY_CONFIG_WRITER", config.Filename+" owns the "+r.environment+" identity keys. Edit environments."+r.environment+".identity.keys, then run oe config push.",
			"oe config push --dry-run --env "+r.environment, exitFailure)
	}
	current, err := readAddressedIdentityCurrent(ctx, address, identity.KeysOnly)
	if err != nil {
		return err
	}
	if current.Configuration.IdentityProfile.Provider != nil || current.Configuration.IdentityProfile.Mode == "device-owned" {
		return identityCommandProblem("IDENTITY_INPUT_INVALID", "Keys-only rotation requires a configured ES256 profile.", "oe identity current --env "+r.environment, exitFailure)
	}
	if _, err = identityPreview(ctx, address, current, nil, &keys); err != nil {
		return err
	}
	changes, err := identityChanges(r.environment, current, nil, &keys)
	if err != nil {
		return err
	}
	if options.dryRun {
		return r.out.Success("identity keys rotate", "Dry run. No keys were replaced.", map[string]any{"status": "planned", "kind": "keys-only", "environment": r.environment, "configurationVersion": current.Configuration.ConfigurationVersion, "changes": changes})
	}
	command := commandLine([]string{"identity", "keys", "rotate", "--keys", *path, "--env", r.environment})
	if err := r.approveIdentity(command, changes, options); err != nil {
		return err
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project, Action: identity.KeysReplaceAction,
		Keys: &keys, Approved: &current, Consent: true})
	if err != nil {
		return identityExecutionFailure(err, r.environment)
	}
	return r.outputIdentityExecution("identity keys rotate", identity.KeysOnly, result, command)
}
