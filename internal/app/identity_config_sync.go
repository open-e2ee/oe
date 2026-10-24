package app

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

func configManagesIdentity(value config.Config, names []string) bool {
	for _, name := range names {
		target, err := value.IdentityFor(name)
		if err == nil && target != nil {
			return true
		}
	}
	return false
}

func (r *runner) planIdentityPull(ctx context.Context, value config.Config, plan *pullPlan, enroll bool) error {
	for _, name := range plan.names {
		entry := plan.environments[name]
		if entry == nil || entry.Reason == "inactive" {
			continue
		}
		var before *identity.SelectionTarget
		if name != "production" || value.Environments.Production != nil {
			var err error
			before, err = value.IdentityFor(name)
			if err != nil {
				return identityPublicFailure(err)
			}
		}
		if before == nil && !enroll {
			continue
		}
		addressed := *r
		addressed.environment = name
		_, current, err := addressed.readIdentityCurrent(ctx, value.Project, identityattempt.Selection)
		if err != nil {
			return identityPublicFailure(err)
		}
		target, err := config.ProjectInstalledIdentity(current.Configuration)
		if err != nil {
			return identityCommandProblem("IDENTITY_CONFIG_UNREPRESENTABLE", "The installed identity cannot form a supported config write. No file was changed.", "oe identity current --env "+name, exitFailure)
		}
		if before != nil && before.Equal(target) {
			continue
		}
		change := pullChange{Path: "environments." + name + ".identity", Action: "add", To: target}
		if before != nil {
			change.Action, change.From = "replace", before
			plan.replaced++
		}
		entry.Changes = append(entry.Changes, change)
		plan.changes = append(plan.changes, config.Change{Path: []string{"environments", name, "identity"}, Value: target})
	}
	return nil
}

type identityConfigChange struct {
	kind      identityattempt.Kind
	target    *identity.SelectionTarget
	keys      *identity.ReplacementKeys
	unchanged bool
}

func planIdentityConfig(current identity.CurrentContext, target identity.SelectionTarget) (identityConfigChange, error) {
	if current.Validate() != nil || target.Validate() != nil {
		return identityConfigChange{}, errIdentityExecution
	}
	installed, err := config.ProjectInstalledIdentity(current.Configuration)
	if err != nil {
		return identityConfigChange{}, identityCommandProblem("IDENTITY_CONFIG_UNREPRESENTABLE", "The installed identity cannot form a supported config write.", "oe identity current", exitFailure)
	}
	if installed.Equal(target) {
		return identityConfigChange{unchanged: true}, nil
	}
	if installed.Keys != nil && target.Keys != nil && installed.Provider == nil && target.Provider == nil {
		public, err := installed.Clone()
		if err != nil {
			return identityConfigChange{}, errIdentityExecution
		}
		public.Keys = target.Keys
		if public.Equal(target) {
			keys := identity.ReplacementKeys(*target.Keys)
			if keys.Validate() != nil {
				return identityConfigChange{}, identityInputFailure()
			}
			return identityConfigChange{kind: identityattempt.KeysOnly, keys: &keys}, nil
		}
	}
	inventory := current.Configuration.Inventory
	if inventory.EverAdmitted || inventory.BindingCount != 0 || inventory.HistoryCount != 0 || inventory.PendingOperationID != nil {
		return identityConfigChange{}, identityCommandProblem("IDENTITY_MIGRATION_REQUIRED", "The requested profile change requires the existing migration flow.", "oe identity current", exitFailure)
	}
	copy, err := target.Clone()
	if err != nil {
		return identityConfigChange{}, errIdentityExecution
	}
	return identityConfigChange{kind: identityattempt.Selection, target: &copy}, nil
}

func (r *runner) inspectConfigIdentityState(ctx context.Context, address identityExecutionContext, change identityConfigChange, options identityCommandOptions) error {
	if r.identityAttempts == nil {
		return errIdentityExecution
	}
	store, err := r.identityAttempts.Open()
	if err != nil || store == nil {
		if err != nil {
			return err
		}
		return errIdentityExecution
	}
	for _, kind := range []identityattempt.Kind{identityattempt.Selection, identityattempt.KeysOnly} {
		slot, err := identityattempt.NewSlot(address.slot.ControlBase(), address.slot.OrganizationID(), address.slot.ProjectSlug(), address.slot.Environment(), kind)
		if err != nil {
			return err
		}
		if err := r.requireIdentityVacant(ctx, slot); err != nil {
			return err
		}
		observation, err := store.Inspect(ctx, slot)
		if err != nil {
			return err
		}
		if change.unchanged || kind != change.kind {
			continue
		}
		switch observation.State() {
		case identityattempt.AbsentNamespace:
			if !options.namespaceFirstUse || !options.slotFirstUse {
				return identityattempt.ErrFirstUseRequired
			}
		case identityattempt.AbsentSlot:
			if options.namespaceFirstUse || !options.slotFirstUse {
				return identityattempt.ErrFirstUseRequired
			}
		case identityattempt.Ready:
			if options.namespaceFirstUse || options.slotFirstUse {
				return identityattempt.ErrAlreadyInitialized
			}
		default:
			return errIdentityExecution
		}
	}
	if change.unchanged && (options.namespaceFirstUse || options.slotFirstUse) {
		return identityInputFailure()
	}
	return nil
}

func configIdentityData(environment string, retention *pushEntry, status string, operation *identityCommandResult) map[string]any {
	identityData := map[string]any{"status": status, "serviceReadiness": "unverified"}
	if operation != nil {
		identityData["operation"] = operation
	}
	return map[string]any{"environments": map[string]any{environment: map[string]any{
		"retention": retention, "identity": identityData,
	}}}
}

func (r *runner) configPushIdentity(ctx context.Context, path string, value config.Config, options identityCommandOptions) error {
	if !r.environmentExplicit || r.validateIdentityOptions(options) != nil {
		return identityInputFailure()
	}
	if r.getenv("OE_OPERATION_ID") != "" {
		return identityCommandProblem("IDENTITY_OPERATION_CONFLICT", "Use the exact retained-operation command to confirm an operation ID.", "oe identity operation status --kind selection --env "+r.environment, exitUsage)
	}
	target, err := value.IdentityFor(r.environment)
	if err != nil || target == nil {
		return identityInputFailure()
	}
	policy, err := controlPolicy(value, r.environment)
	if err != nil {
		return err
	}
	connection, err := envfile.Detect(filepath.Dir(path), "")
	if err != nil {
		return err
	}
	scope := "deploy:write"
	if options.dryRun {
		scope = "project:read"
	}
	access, err := r.access(ctx, scope, false)
	if err != nil {
		return err
	}
	project, err := r.getProject(ctx, access, value.Project)
	if err != nil {
		return err
	}
	if project.Writer != "config" {
		return identityCommandProblem("CONSOLE_WRITER", "The Console owns this project's desired policy.", "oe project show", exitFailure)
	}
	inactive := r.environment == "production" && (project.Production == nil || project.Production.State != control.ProductionActive)
	if inactive && (options.namespaceFirstUse || options.slotFirstUse) {
		return identityInputFailure()
	}
	push := &pusher{r: r, yes: options.yes, value: value, directory: filepath.Dir(path), variable: connection.Variable,
		access: access, project: project, policies: map[string]control.RelayPolicyRequest{r.environment: policy}}
	if inactive {
		retention := push.environment(ctx, r.environment, options.dryRun)
		data := configIdentityData(r.environment, retention, "blocked", nil)
		if retention.failure != nil {
			retention.failure.data = data
			return retention.failure
		}
		failure := identityCommandProblem("IDENTITY_ACTIVATION_REQUIRED", "Identity needs a fresh preview after the existing Production activation phase.",
			"oe config push --dry-run --env production", exitPersonAction)
		failure.data = data
		return failure
	}
	identityContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	address, approved, err := r.readIdentityCurrent(identityContext, value.Project, identityattempt.Selection)
	if err != nil {
		return identityPublicFailure(err)
	}
	change, err := planIdentityConfig(approved, *target)
	if err != nil {
		return err
	}
	if change.kind == identityattempt.KeysOnly {
		keysAddress, keysCurrent, keysErr := r.readIdentityCurrent(identityContext, value.Project, identityattempt.KeysOnly)
		if keysErr != nil || !sameIdentityApprovalContext(approved, keysCurrent) {
			return identityPublicFailure(errIdentityExecution)
		}
		address = keysAddress
	}
	if !change.unchanged {
		if _, err = identityPreview(identityContext, address, approved, change.target, change.keys); err != nil {
			return identityPublicFailure(err)
		}
	}
	plan, err := push.plan(ctx, r.environment)
	if err != nil {
		return err
	}
	retention := &pushEntry{Status: "unchanged", Changes: slices.Clone(plan.Changes)}
	status := "unchanged"
	if !change.unchanged {
		status = "planned"
	}
	if options.dryRun {
		if len(plan.Changes) > 0 {
			retention.Status = "planned"
		}
		return r.out.Success("config push", "Dry run. No provider or service state changed.", configIdentityData(r.environment, retention, status, nil))
	}
	if err := r.inspectConfigIdentityState(identityContext, address, change, options); err != nil {
		return identityPublicFailure(err)
	}
	if !change.unchanged {
		if err := r.approveIdentity("oe config push --env "+r.environment, options); err != nil {
			return err
		}
	}
	if r.environment == "production" && len(plan.Changes) > 0 {
		blocked, err := push.consent(ctx, plan, false, "")
		if err != nil {
			return err
		}
		if blocked != nil {
			return blocked
		}
	}
	lock, err := lockProject(ctx, filepath.Dir(path))
	if err != nil {
		return err
	}
	defer lock.Release()
	if len(plan.Changes) > 0 {
		deployed, err := push.apply(ctx, plan, r.environment)
		if err != nil {
			failure := classify(err, push.command(push.yes), r.environment)
			failure.data = configIdentityData(r.environment, retention, "blocked", nil)
			return failure
		}
		retention.Status, retention.Revision = "applied", deployed.Revision
	}
	if change.unchanged {
		return r.out.Success("config push", "The declared identity is unchanged.", configIdentityData(r.environment, retention, "unchanged", nil))
	}
	finalContext, finalCancel := context.WithTimeout(ctx, 60*time.Second)
	defer finalCancel()
	freshAddress, fresh, err := r.readIdentityCurrent(finalContext, value.Project, change.kind)
	if err != nil || !sameIdentityApprovalContext(approved, fresh) {
		failure := identityCommandProblem("IDENTITY_CONTEXT_CHANGED", "The approved identity context changed. Retention and identity have separate outcomes.",
			"oe config push --dry-run --env "+r.environment, exitFailure)
		failure.data = configIdentityData(r.environment, retention, "blocked", nil)
		return failure
	}
	if _, err := identityPreview(finalContext, freshAddress, fresh, change.target, change.keys); err != nil {
		failure, ok := errors.AsType[*problem](identityPublicFailure(err))
		if !ok {
			return errIdentityExecution
		}
		failure.data = configIdentityData(r.environment, retention, "blocked", nil)
		return failure
	}
	action := identityattempt.SelectionApplyAction
	if change.kind == identityattempt.KeysOnly {
		action = identityattempt.KeysReplaceAction
	}
	result, err := r.executeIdentity(finalContext, identityExecutionInput{Project: value.Project, Kind: change.kind, Action: action,
		Target: change.target, Keys: change.keys, Approved: &approved, Consent: true,
		NamespaceFirstUse: options.namespaceFirstUse, SlotFirstUse: options.slotFirstUse})
	if err != nil {
		failure, ok := errors.AsType[*problem](identityExecutionFailure(err, change.kind, r.environment))
		if !ok {
			return errIdentityExecution
		}
		failure.data = configIdentityData(r.environment, retention, "failed", nil)
		return failure
	}
	operation, err := projectIdentityExecution(change.kind, result)
	if err != nil {
		return err
	}
	operation.Environment = r.environment
	data := configIdentityData(r.environment, retention, operation.Status, &operation)
	if failure := identityResultFailure(operation); failure != nil {
		failure.data = data
		return failure
	}
	return r.out.Success("config push", "The exact identity command receipt is settled. Current service readiness remains unverified.", data)
}
