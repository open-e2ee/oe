package app

import (
	"context"
	"encoding/json"
	"io"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

func readIdentityTarget(reader io.Reader) (identity.LifecycleInputTarget, error) {
	var value identity.LifecycleInputTarget
	if reader == nil {
		return value, identityInputFailure()
	}
	data, err := io.ReadAll(io.LimitReader(reader, 100001))
	if err != nil || len(data) > 100000 || json.Unmarshal(data, &value) != nil {
		return identity.LifecycleInputTarget{}, identityInputFailure()
	}
	return value, nil
}

func (r *runner) identityLifecycleCommand(ctx context.Context, args []string) error {
	action := args[0]
	if action != "target" && action != "suspend" && action != "activate" {
		return identityInputFailure()
	}
	options := identityCommandOptions{}
	flags := newFlags("identity lifecycle " + action)
	targetStdin := flags.Bool("target-stdin", false, "read one private lifecycle target from stdin")
	if action != "target" {
		options.flags(flags, true, true)
	}
	if parseFlags(flags, "identity", args[1:]) != nil || !*targetStdin || r.validateIdentityOptions(options) != nil {
		return identityInputFailure()
	}
	_, configuration, err := r.identityConfiguration()
	if err != nil {
		return err
	}
	address, current, err := r.readIdentityCurrent(ctx, configuration.Project, identityattempt.Lifecycle)
	if err != nil {
		return err
	}
	// Authority precedes private stdin. The input remains transient.
	target, err := readIdentityTarget(r.in)
	if err != nil {
		return err
	}
	observation, err := address.transport.LifecycleTarget(ctx, address.credential, target)
	if err != nil {
		return err
	}
	if observation.Validate() != nil || !observation.Scope.Equal(current.Precondition.Scope) || observation.Target.Kind != target.Kind {
		return errIdentityExecution
	}
	if action == "target" || options.dryRun {
		data := map[string]any{"environment": r.environment, "targetKind": observation.Target.Kind,
			"observedVersion": observation.ObservedVersion, "observedState": observation.ObservedState,
			"applicationKind": observation.Application.Kind(), "serviceReadiness": "unverified"}
		if bound, err := observation.Application.Bound(); err == nil {
			data["effectiveAccountState"] = bound.EffectiveState
		}
		if options.dryRun {
			data["status"] = "planned"
		}
		return r.out.Success("identity lifecycle "+action, "The target was observed. No lifecycle operation was prepared or applied.", data)
	}
	if err := r.approveIdentity("oe identity lifecycle "+action+" --target-stdin", options); err != nil {
		return err
	}
	if err := r.requireIdentityVacant(ctx, address.slot); err != nil {
		return err
	}
	state := "suspended"
	if action == "activate" {
		state = "active"
	}
	result, err := r.executeIdentity(ctx, identityExecutionInput{Project: configuration.Project,
		Kind: identityattempt.Lifecycle, Action: identityattempt.LifecycleApplyAction,
		LifecycleTarget: &target, LifecycleState: state, Approved: &current, ApprovedTarget: &observation,
		Consent: true, NamespaceFirstUse: options.namespaceFirstUse, SlotFirstUse: options.slotFirstUse})
	if err != nil {
		return identityExecutionFailure(err, identityattempt.Lifecycle, r.environment)
	}
	return r.outputIdentityExecution("identity lifecycle "+action, identityattempt.Lifecycle, result)
}
