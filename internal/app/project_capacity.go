package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/control"
)

func (r *runner) projectCapacity(ctx context.Context, slug string) error {
	if r.environment != "sandbox" {
		return usageError("project", "account capacity is available only in Sandbox; use --env sandbox")
	}
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return err
	}
	project, err := r.getProject(ctx, access, slug)
	if err != nil {
		return err
	}
	environment := environmentOf(project, r.environment)
	if environment == nil || environment.SignalProtocolRelayURL == "" {
		return r.environmentNotActive(project.Slug, project.Writer, r.environment)
	}
	result, err := r.api.ProjectCapacity(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, project.Slug, r.environment)
	switch {
	case errors.Is(err, control.ErrSandboxCapacityNotServed):
		return r.capacityUnavailable(project.Slug, "the Console at "+r.controlURL+" does not serve Sandbox account capacity yet; no capacity value can be confirmed", err)
	case errors.Is(err, control.ErrSandboxCapacity):
		return r.capacityUnavailable(project.Slug, "the Sandbox account capacity response is invalid; no capacity value can be confirmed", err)
	case err != nil:
		return err
	}
	if result.Project != project.Slug || result.Environment != "sandbox" {
		return r.capacityUnavailable(project.Slug, "the Sandbox account capacity response is invalid; no capacity value can be confirmed", control.ErrSandboxCapacity)
	}
	now := r.now()
	result.Capacity = result.Capacity.At(now)
	return r.out.Success("project capacity", capacityText(result, result.Capacity.Stale(now)), map[string]any{"capacity": result})
}

func (r *runner) capacityUnavailable(slug, message string, cause error) error {
	return &problem{
		code: "CAPACITY_UNAVAILABLE", exit: exitTemporary, next: "oe project capacity " + slug + " --env sandbox", cause: cause,
		data:    map[string]any{"project": slug, "environment": "sandbox"},
		message: message,
	}
}

// capacityText shows the capacity read. stale is an observation that expired
// before this read, so its counts are old and its availability is unknown.
func capacityText(result control.ProjectCapacity, stale bool) string {
	value := result.Capacity
	readiness := value.State
	if stale {
		readiness = "stale"
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%s Sandbox account capacity\nReadiness: %s\nRegistered test accounts: %s\nReserved accounts: %s\nAvailable slots: %s\n", result.Project, readiness, capacityFigure(value.RegisteredAccounts), capacityFigure(value.ReservedAccounts), capacityFigure(value.AvailableSlots))
	if value.Limit == nil {
		text.WriteString("Account limit: unknown\n")
	} else {
		fmt.Fprintf(&text, "Account limit: %d\n", *value.Limit)
	}
	activation := capacityRevision(value.ActivationRevision)
	if value.State == "inactive" && value.ActivationRevision == nil {
		activation = "not activated"
	}
	fmt.Fprintf(&text, "Activation revision: %s\nCapacity revision: %s\n", activation, capacityRevision(value.CapacityRevision))
	if value.ObservedAtMilliseconds != nil {
		fmt.Fprintf(&text, "Observed at: %s", time.UnixMilli(*value.ObservedAtMilliseconds).UTC().Format(time.RFC3339))
		if stale {
			text.WriteString(" (stale)")
		}
		text.WriteString("\n")
	}
	if value.PendingLimit != nil {
		fmt.Fprintf(&text, "Pending account limit: %d at %s\n", value.PendingLimit.RegisteredTestAccounts, time.UnixMilli(value.PendingLimit.AppliesAtMilliseconds).UTC().Format(time.RFC3339))
	}
	switch {
	case stale:
		text.WriteString("This observation is stale. Available slots stay unknown until Relay reports a current observation.\n")
	case value.State == "inactive":
		text.WriteString("Account capacity is not activated for this Sandbox. Account admission does not use it yet.\n")
	case value.State == "ready":
		text.WriteString("Capacity is ready. Account admission has not been activated.\n")
	case value.State == "active" && value.OverCapacity != nil && *value.OverCapacity:
		text.WriteString("Over capacity. New accounts are blocked; existing accounts remain.\n")
	}
	text.WriteString("A slot is free only after deletion confirms capacity release. Removing a device or clearing local storage does not free a slot.")
	return text.String()
}

func capacityFigure(value *string) string {
	if value == nil {
		return "unknown"
	}
	return *value
}

func capacityRevision(value *int64) string {
	if value == nil {
		return "unknown"
	}
	return strconv.FormatInt(*value, 10)
}
