package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
	"github.com/open-e2ee/oe/internal/output"
)

type identityCommandOptions struct {
	dryRun            bool
	yes               bool
	namespaceFirstUse bool
	slotFirstUse      bool
}

func (v *identityCommandOptions) flags(flags *flag.FlagSet, dryRun, firstUse bool) {
	flags.BoolVar(&v.yes, "yes", false, "consent to the exact Production change")
	if dryRun {
		flags.BoolVar(&v.dryRun, "dry-run", false, "preview without mutation or local state creation")
	}
	if firstUse {
		flags.BoolVar(&v.namespaceFirstUse, "confirm-state-never-used", false, "declare that the selected local namespace never existed")
		flags.BoolVar(&v.slotFirstUse, "confirm-slot-never-used", false, "declare that the addressed kind slot never existed. This can create absent storage for that slot")
	}
}

func (r *runner) validateIdentityOptions(v identityCommandOptions) error {
	if v.namespaceFirstUse || v.slotFirstUse {
		if v.dryRun || !r.environmentExplicit {
			return identityInputFailure()
		}
	}
	return nil
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
	} else if value, ok := errors.AsType[*identityattempt.Failure](err); ok {
		code, exit = value.Code(), exitFailure
	} else if errors.Is(err, errIdentityConsent) {
		code, exit = "CONFIRMATION_REQUIRED", exitUsage
	} else if errors.Is(err, errIdentityExecution) {
		code, exit = "IDENTITY_CONTEXT_CHANGED", exitFailure
	}
	return identityCommandProblem(code, "The identity operation did not complete. Preserve the retained attempt.", next, exit)
}

func identityExecutionFailure(err error, kind identityattempt.Kind, environment string) error {
	failure := identityPublicFailure(err)
	if value, ok := errors.AsType[*problem](failure); ok && value.next == "oe help identity" {
		copy := *value
		copy.next = "oe identity operation status --kind " + string(kind) + " --env " + environment
		return &copy
	}
	return failure
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
		return "", config.Config{}, identityCommandProblem("CONFIG_INVALID", "The public project configuration is invalid.", "oe help config", exitUsage)
	}
	return path, value, nil
}

func (r *runner) readIdentityCurrent(ctx context.Context, project string, kind identityattempt.Kind) (identityExecutionContext, identity.CurrentContext, error) {
	address, err := r.identityContext(ctx, project, kind)
	if err != nil {
		return address, identity.CurrentContext{}, err
	}
	var current control.AddressedCurrent
	if kind == identityattempt.KeysOnly {
		current, err = address.transport.KeysCurrent(ctx, address.credential)
	} else {
		current, err = address.transport.Current(ctx, address.credential)
	}
	if err != nil {
		return address, identity.CurrentContext{}, err
	}
	value, err := current.Context()
	return address, value, err
}

func (r *runner) identityCurrentCommand(ctx context.Context) error {
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	_, current, err := r.readIdentityCurrent(ctx, configuration.Project, identityattempt.Selection)
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
			"oe identity current --env "+address.slot.Environment(), exitFailure)
	}
	return preview, nil
}

func (r *runner) approveIdentity(command string, options identityCommandOptions) error {
	if r.environment != "production" || options.yes {
		return nil
	}
	if r.mode != output.Text || r.credentialSource == "environment" || !r.canPrompt() {
		return identityCommandProblem("CONFIRMATION_REQUIRED", "Review the exact Production identity change, then supply --yes.", command+" --yes --env production", exitUsage)
	}
	approved, err := askConfirmation(r.in, r.errOut, "Apply this exact Production identity change?")
	if err != nil || !approved {
		return identityCommandProblem("CONFIRMATION_REQUIRED", "The Production identity change was not approved.", command+" --yes --env production", exitUsage)
	}
	return nil
}

// This inspection never creates or repairs a namespace or record.
func (r *runner) requireIdentityVacant(ctx context.Context, slot identityattempt.Slot) error {
	if r.identityAttempts == nil {
		return errIdentityExecution
	}
	store, err := r.identityAttempts.Open()
	if err != nil {
		return err
	}
	if store == nil {
		return errIdentityExecution
	}
	observation, err := store.Inspect(ctx, slot)
	if err != nil {
		return err
	}
	if observation.State() != identityattempt.Ready {
		return nil
	}
	envelope, valid := observation.Envelope()
	if !valid {
		return errIdentityExecution
	}
	retained, err := envelope.RetainedAttempt()
	if err != nil {
		return err
	}
	if retained != nil {
		return identityCommandProblem("IDENTITY_OPERATION_CONFLICT", "An exact retained operation occupies this slot.", "oe identity operation status --kind "+string(slot.Kind())+" --env "+slot.Environment(), exitFailure)
	}
	return nil
}

func (r *runner) identitySelectCommand(ctx context.Context, args []string) error {
	options := identityCommandOptions{}
	flags := newFlags("identity select")
	options.flags(flags, true, true)
	if parseFlags(flags, "identity", args) != nil || r.validateIdentityOptions(options) != nil {
		return identityInputFailure()
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	target, err := configuration.IdentityFor(r.environment)
	if err != nil || target == nil {
		return identityCommandProblem("IDENTITY_INPUT_INVALID", "Declare a complete public identity for the selected environment.", "oe help config", exitUsage)
	}
	address, current, err := r.readIdentityCurrent(ctx, configuration.Project, identityattempt.Selection)
	if err != nil {
		return err
	}
	if _, err = identityPreview(ctx, address, current, target, nil); err != nil {
		return err
	}
	if options.dryRun {
		return r.out.Success("identity select", "Dry run. No identity operation was prepared or applied.", map[string]any{"status": "planned", "kind": "selection", "environment": r.environment, "configurationVersion": current.Configuration.ConfigurationVersion})
	}
	if err := r.approveIdentity("oe identity select", options); err != nil {
		return err
	}
	if err := r.requireIdentityVacant(ctx, address.slot); err != nil {
		return err
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project, Kind: identityattempt.Selection, Action: identityattempt.SelectionApplyAction,
		Target: target, Approved: &current, Consent: true, NamespaceFirstUse: options.namespaceFirstUse, SlotFirstUse: options.slotFirstUse})
	if err != nil {
		return identityExecutionFailure(err, identityattempt.Selection, r.environment)
	}
	return r.outputIdentityExecution("identity select", identityattempt.Selection, result)
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

func (r *runner) identityKeysCommand(ctx context.Context, args []string) error {
	options := identityCommandOptions{}
	flags := newFlags("identity keys rotate")
	options.flags(flags, true, true)
	path := flags.String("keys", "", "public replacement-key JSON file")
	if parseFlags(flags, "identity", args) != nil || *path == "" || r.validateIdentityOptions(options) != nil {
		return identityInputFailure()
	}
	var keys identity.ReplacementKeys
	if err := readIdentityPublicFile(*path, &keys); err != nil {
		return err
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	address, current, err := r.readIdentityCurrent(ctx, configuration.Project, identityattempt.KeysOnly)
	if err != nil {
		return err
	}
	if current.Configuration.IdentityProfile.Provider != nil || current.Configuration.IdentityProfile.Mode == "device-owned" {
		return identityCommandProblem("IDENTITY_INPUT_INVALID", "Keys-only rotation requires a configured ES256 profile.", "oe identity current --env "+r.environment, exitFailure)
	}
	if _, err = identityPreview(ctx, address, current, nil, &keys); err != nil {
		return err
	}
	if options.dryRun {
		return r.out.Success("identity keys rotate", "Dry run. No keys were replaced.", map[string]any{"status": "planned", "kind": "keys-only", "environment": r.environment, "configurationVersion": current.Configuration.ConfigurationVersion})
	}
	if err := r.approveIdentity(commandLine([]string{"identity", "keys", "rotate", "--keys", *path}), options); err != nil {
		return err
	}
	if err := r.requireIdentityVacant(ctx, address.slot); err != nil {
		return err
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project, Kind: identityattempt.KeysOnly, Action: identityattempt.KeysReplaceAction,
		Keys: &keys, Approved: &current, Consent: true, NamespaceFirstUse: options.namespaceFirstUse, SlotFirstUse: options.slotFirstUse})
	if err != nil {
		return identityExecutionFailure(err, identityattempt.KeysOnly, r.environment)
	}
	return r.outputIdentityExecution("identity keys rotate", identityattempt.KeysOnly, result)
}
