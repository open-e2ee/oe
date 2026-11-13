package app

import (
	"context"
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
	result, err := r.api.ProjectCapacity(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, project.Slug, "sandbox")
	if err != nil {
		return err
	}
	if result.Project != project.Slug || result.Environment != "sandbox" {
		return &problem{code: "CAPACITY_UNAVAILABLE", exit: exitTemporary, message: "Sandbox account capacity is unavailable"}
	}
	result.Capacity = result.Capacity.At(r.now())
	return r.out.Success("project capacity", capacityText(result), map[string]any{"capacity": result})
}

func capacityText(result control.ProjectCapacity) string {
	value := result.Capacity
	var text strings.Builder
	fmt.Fprintf(&text, "%s Sandbox account capacity\nReadiness: %s\nRegistered test accounts: %s\nReserved accounts: %s\nAvailable slots: %s\n", result.Project, value.State, capacityFigure(value.RegisteredAccounts), capacityFigure(value.ReservedAccounts), capacityFigure(value.AvailableSlots))
	if value.Limit == nil {
		text.WriteString("Account limit: unknown\n")
	} else {
		fmt.Fprintf(&text, "Account limit: %d\n", *value.Limit)
	}
	fmt.Fprintf(&text, "Activation revision: %s\nCapacity revision: %s\n", capacityRevision(value.ActivationRevision), capacityRevision(value.CapacityRevision))
	if value.ObservedAtMilliseconds != nil {
		fmt.Fprintf(&text, "Observed at: %s\n", time.UnixMilli(*value.ObservedAtMilliseconds).UTC().Format(time.RFC3339))
	}
	if value.PendingLimit != nil {
		fmt.Fprintf(&text, "Pending account limit: %d at %s\n", value.PendingLimit.RegisteredTestAccounts, time.UnixMilli(value.PendingLimit.AppliesAtMilliseconds).UTC().Format(time.RFC3339))
	}
	if value.State == "ready" {
		text.WriteString("Capacity is ready. Account admission has not been activated.\n")
	}
	if value.State == "active" && value.OverCapacity != nil && *value.OverCapacity {
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
