package app

import (
	"context"
	"slices"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
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
			if !options.slotFirstUse {
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

// identityEntry is the push entry of an environment whose section declares
// identity. The retention entry holds the Relay policy changes.
func identityEntry(retention *pushEntry, status string, operation *identityCommandResult) *pushEntry {
	identityData := map[string]any{"status": status, "serviceReadiness": "unverified"}
	if operation != nil {
		identityData["operation"] = operation
	}
	return &pushEntry{Retention: retention, Identity: identityData}
}

// section applies one environment section. When the run manages identity, a
// section that declares identity takes the identity step.
func (p *pusher) section(ctx context.Context, environment string, dryRun bool) *pushEntry {
	if p.identity != nil {
		target, err := p.value.IdentityFor(environment)
		if err != nil {
			return (&pushEntry{Changes: []control.Change{}}).stop("failed", classify(identityInputFailure(), p.command(p.yes), environment))
		}
		if target != nil {
			return p.identityEnvironment(ctx, environment, *target, dryRun)
		}
	}
	return p.environment(ctx, environment, dryRun)
}

// identityEnvironment applies the retention policy and then the declared
// identity of one environment. It writes no output; the run reports every
// environment once.
func (p *pusher) identityEnvironment(ctx context.Context, environment string, target identity.SelectionTarget, dryRun bool) *pushEntry {
	options := *p.identity
	addressed := *p.r
	addressed.environment = environment
	r := &addressed
	failed := func(entry *pushEntry, status string, err error) *pushEntry {
		return entry.stop(status, classify(err, p.command(p.yes), environment))
	}
	inactive := environment == "production" && (p.project.Production == nil || p.project.Production.State != control.ProductionActive)
	if inactive && (options.namespaceFirstUse || options.slotFirstUse) {
		return failed(identityEntry(nil, "blocked", nil), "blocked", identityInputFailure())
	}
	if inactive {
		retention := p.environment(ctx, environment, dryRun)
		entry := identityEntry(retention, "blocked", nil)
		if retention.failure != nil {
			return entry.stop(retention.Status, retention.failure)
		}
		return entry.stop("blocked", identityCommandProblem("IDENTITY_ACTIVATION_REQUIRED", "Identity needs a fresh preview after the existing Production activation phase.",
			"oe config push --dry-run --env production", exitPersonAction))
	}
	identityContext, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	address, approved, err := r.readIdentityCurrent(identityContext, p.value.Project, identityattempt.Selection)
	if err != nil {
		return failed(identityEntry(nil, "blocked", nil), "failed", identityPublicFailure(err))
	}
	change, err := planIdentityConfig(approved, target)
	if err != nil {
		return failed(identityEntry(nil, "blocked", nil), "failed", err)
	}
	if change.kind == identityattempt.KeysOnly {
		keysAddress, keysCurrent, keysErr := r.readIdentityCurrent(identityContext, p.value.Project, identityattempt.KeysOnly)
		if keysErr != nil || !sameIdentityApprovalContext(approved, keysCurrent) {
			return failed(identityEntry(nil, "blocked", nil), "failed", identityPublicFailure(errIdentityExecution))
		}
		address = keysAddress
	}
	if !change.unchanged {
		if _, err = identityPreview(identityContext, address, approved, change.target, change.keys); err != nil {
			return failed(identityEntry(nil, "blocked", nil), "failed", identityPublicFailure(err))
		}
	}
	plan, err := p.plan(ctx, environment)
	if err != nil {
		return failed(identityEntry(nil, "blocked", nil), "failed", err)
	}
	retention := &pushEntry{Status: "unchanged", Changes: slices.Clone(plan.Changes)}
	status := "unchanged"
	if !change.unchanged {
		status = "planned"
	}
	if dryRun {
		if len(plan.Changes) > 0 {
			retention.Status = "planned"
		}
		entry := identityEntry(retention, status, nil)
		entry.Status = "unchanged"
		if retention.Status == "planned" || status == "planned" {
			entry.Status = "planned"
		}
		return entry
	}
	if err := r.inspectConfigIdentityState(identityContext, address, change, options); err != nil {
		return failed(identityEntry(retention, "blocked", nil), "blocked", identityPublicFailure(err))
	}
	if !change.unchanged {
		if err := r.approveIdentity("oe config push --env "+environment, options); err != nil {
			return failed(identityEntry(retention, "blocked", nil), "blocked", err)
		}
	}
	if environment == "production" && len(plan.Changes) > 0 {
		blocked, err := p.consent(ctx, plan, false, "")
		if err != nil {
			return failed(identityEntry(retention, "blocked", nil), "failed", err)
		}
		if blocked != nil {
			return identityEntry(retention, "blocked", nil).stop("blocked", blocked)
		}
	}
	if len(plan.Changes) > 0 {
		deployed, err := p.apply(ctx, plan, environment)
		if err != nil {
			return failed(identityEntry(retention, "blocked", nil), "failed", err)
		}
		retention.Status, retention.Revision = "applied", deployed.Revision
	}
	if change.unchanged {
		entry := identityEntry(retention, "unchanged", nil)
		entry.Status = retention.Status
		return entry
	}
	finalContext, finalCancel := context.WithTimeout(ctx, 60*time.Second)
	defer finalCancel()
	freshAddress, fresh, err := r.readIdentityCurrent(finalContext, p.value.Project, change.kind)
	if err != nil || !sameIdentityApprovalContext(approved, fresh) {
		return identityEntry(retention, "blocked", nil).stop("blocked", identityCommandProblem("IDENTITY_CONTEXT_CHANGED",
			"The approved identity context changed. Retention and identity have separate outcomes.", "oe config push --dry-run --env "+environment, exitFailure))
	}
	if _, err := identityPreview(finalContext, freshAddress, fresh, change.target, change.keys); err != nil {
		return failed(identityEntry(retention, "blocked", nil), "blocked", identityPublicFailure(err))
	}
	action := identityattempt.SelectionApplyAction
	if change.kind == identityattempt.KeysOnly {
		action = identityattempt.KeysReplaceAction
	}
	result, err := r.executeIdentity(finalContext, identityExecutionInput{Project: p.value.Project, Kind: change.kind, Action: action,
		Target: change.target, Keys: change.keys, Approved: &approved, Consent: true,
		NamespaceFirstUse: options.namespaceFirstUse, SlotFirstUse: options.slotFirstUse})
	if err != nil {
		return failed(identityEntry(retention, "failed", nil), "failed", identityExecutionFailure(err, change.kind, environment))
	}
	operation, err := projectIdentityExecution(change.kind, result)
	if err != nil {
		return failed(identityEntry(retention, "failed", nil), "failed", err)
	}
	operation.Environment = environment
	entry := identityEntry(retention, operation.Status, &operation)
	if failure := identityResultFailure(operation); failure != nil {
		return entry.stop("failed", failure)
	}
	entry.Status = "applied"
	return entry
}
