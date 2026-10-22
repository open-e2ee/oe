package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-e2ee/oe/internal/control"
)

func (r *runner) projectUsage(ctx context.Context, slug string) error {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return err
	}
	project, err := r.getProject(ctx, access, slug)
	if err != nil {
		return err
	}
	environment := environmentOf(project, r.environment)
	if environment == nil || environment.RelayURL == "" {
		return r.environmentNotActive(project.Slug, project.Writer, r.environment)
	}
	usage, err := r.api.ProjectUsage(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, project.Slug, r.environment)
	if err != nil {
		return err
	}
	if usage.Project != project.Slug || usage.Environment != r.environment || usage.Period == "" {
		return r.usageUnavailable(project.Slug)
	}
	switch usage.Status {
	case "unavailable", "unknown":
		return r.usageUnavailable(project.Slug)
	case "no_usage":
		if usage.Reported == nil || !usageIsZero(*usage.Reported) {
			return r.usageUnavailable(project.Slug)
		}
	case "reported", "partial", "stale":
		if usage.Reported == nil {
			return r.usageUnavailable(project.Slug)
		}
	default:
		return r.usageUnavailable(project.Slug)
	}
	return r.out.Success("project usage", usageText(usage), map[string]any{"usage": usage})
}

func (r *runner) usageUnavailable(slug string) error {
	command := "oe project usage " + slug + " --env " + r.environment
	return &problem{
		code: "USAGE_UNAVAILABLE", exit: exitTemporary, next: command,
		data:    map[string]any{"project": slug, "environment": r.environment},
		message: "Relay usage reporting is unavailable; no usage value can be confirmed",
	}
}

func usageIsZero(reported control.UsageReported) bool {
	return reported.DeliveryUnits != nil && *reported.DeliveryUnits == "0" &&
		reported.AttachmentOperations != nil && *reported.AttachmentOperations == "0" &&
		reported.RelayMAU != nil && *reported.RelayMAU == "0" && reported.LiveBytes == "0"
}

func usageText(usage control.Usage) string {
	var text strings.Builder
	fmt.Fprintf(&text, "%s %s usage, %s UTC\n", usage.Project, usage.Environment, usage.Period)
	switch usage.Status {
	case "no_usage":
		text.WriteString("No usage yet.\n")
	case "partial":
		text.WriteString("Partial report; some sources have not reported.\n")
	case "stale":
		text.WriteString("Stale report; figures may have changed.\n")
	}
	if usage.Reported != nil {
		fmt.Fprintf(&text, "Delivery units: %s\nAttachment operations: %s\nRelay MAU: %s\nLive bytes: %s",
			usageFigure(usage.Reported.DeliveryUnits), usageFigure(usage.Reported.AttachmentOperations),
			usageFigure(usage.Reported.RelayMAU), usage.Reported.LiveBytes)
	}
	return text.String()
}

func usageFigure(value *string) string {
	if value == nil {
		return "unreported"
	}
	return *value
}
