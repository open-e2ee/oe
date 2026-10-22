package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/open-e2ee/oe/internal/control"
	iosnotifications "github.com/open-e2ee/oe/internal/notifications"
)

func (r *runner) notifications(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("notifications", "name a notifications command: status, setup ios, add-nse, verify ios, or apple-filtering-request")
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return usageError("notifications", "usage: oe notifications status")
		}
		configuration, err := r.notificationConfiguration(ctx, "project:read")
		if err != nil {
			return err
		}
		return r.out.Success("notifications status", "Notification configuration loaded. Push is a best-effort wake; durable Relay mailbox pull is delivery.", map[string]any{
			"allowedProfiles": configuration.AllowedProfiles,
			"environment":     r.environment,
			"providers":       configuration.Providers,
		})
	case "setup":
		if len(args) < 2 || args[1] != "ios" {
			return usageError("notifications", "usage: oe notifications setup ios [--profile background-only|visible-alert]")
		}
		flags := newFlags("notifications setup ios")
		profile := flags.String("profile", string(control.NotificationBackgroundOnly), "device notification profile")
		if err := parseFlags(flags, "notifications", args[2:]); err != nil {
			return err
		}
		selected := control.NotificationProfile(*profile)
		if selected != control.NotificationBackgroundOnly && selected != control.NotificationVisibleAlert {
			return usageError("notifications", "--profile must be background-only or visible-alert")
		}
		root, _, err := r.loadConfig()
		if err != nil {
			return err
		}
		local, err := iosnotifications.SetupIOS(filepath.Dir(root))
		if err != nil {
			return err
		}
		configuration, err := r.addNotificationProfile(ctx, selected)
		if err != nil {
			return err
		}
		return r.out.Success("notifications setup ios", "iOS notification setup is staged. Push is a best-effort wake; durable Relay mailbox pull is delivery.", map[string]any{
			"allowedProfiles": configuration.AllowedProfiles,
			"changed":         local.Changed,
			"environment":     r.environment,
			"projectType":     local.Kind,
			"remainingAction": local.RemainingAction,
		})
	case "add-nse":
		if len(args) != 1 {
			return usageError("notifications", "usage: oe notifications add-nse")
		}
		root, _, err := r.loadConfig()
		if err != nil {
			return err
		}
		local, err := iosnotifications.AddNSE(filepath.Dir(root))
		if err != nil {
			return err
		}
		configuration, err := r.addNotificationProfile(ctx, control.NotificationNSEVisible)
		if err != nil {
			return err
		}
		return r.out.Success("notifications add-nse", "The Notification Service Extension is staged without Apple filtering authority.", map[string]any{
			"allowedProfiles": configuration.AllowedProfiles,
			"changed":         local.Changed,
			"environment":     r.environment,
			"projectType":     local.Kind,
			"remainingAction": local.RemainingAction,
		})
	case "apple-filtering-request":
		if len(args) != 1 {
			return usageError("notifications", "usage: oe notifications apple-filtering-request")
		}
		return r.out.Success("notifications apple-filtering-request", "Apple notification filtering is optional. It permits an approved Notification Service Extension to suppress an alert; it does not improve APNs delivery or execution.", map[string]any{
			"activation": "blocked until Apple approval, signed extension inspection, and physical-device suppression evidence pass",
			"requestUrl": "https://developer.apple.com/contact/request/notification-service/",
		})
	case "verify":
		if len(args) < 2 || args[1] != "ios" {
			return usageError("notifications", "usage: oe notifications verify ios [--app-bundle PATH]")
		}
		flags := newFlags("notifications verify ios")
		appBundle := flags.String("app-bundle", "", "signed .app bundle to inspect")
		if err := parseFlags(flags, "notifications", args[2:]); err != nil {
			return err
		}
		configuration, err := r.notificationConfiguration(ctx, "project:read")
		if err != nil {
			return err
		}
		requireNSE := hasNotificationProfile(configuration.AllowedProfiles, control.NotificationNSEVisible)
		root, _, err := r.loadConfig()
		if err != nil {
			return err
		}
		local, err := iosnotifications.VerifyIOS(filepath.Dir(root), requireNSE)
		if err != nil {
			return err
		}
		signed := false
		if *appBundle != "" {
			if err := iosnotifications.VerifySignedApp(*appBundle, requireNSE); err != nil {
				return err
			}
			signed = true
			local.RemainingAction = ""
		}
		physical := "not required for background-only or visible-alert"
		if requireNSE {
			physical = "required before nse-filtering activation; Simulator and signed-bundle inspection are not physical-device evidence"
		}
		return r.out.Success("notifications verify ios", "iOS notification configuration passed the available checks.", map[string]any{
			"environment":     r.environment,
			"physicalDevice":  physical,
			"projectType":     local.Kind,
			"remainingAction": local.RemainingAction,
			"signedBundle":    signed,
		})
	default:
		return usageError("notifications", fmt.Sprintf("unknown notifications command %q", args[0]))
	}
}

func (r *runner) notificationConfiguration(ctx context.Context, scope string) (control.NotificationConfiguration, error) {
	_, value, err := r.loadConfig()
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	access, err := r.access(ctx, scope, false)
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	configuration, err := r.api.Notifications(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, value.Project, r.environment)
	if err != nil {
		return control.NotificationConfiguration{}, r.productionNotFound(err, value.Project)
	}
	if configuration.Environment != r.environment || configuration.ConfigurationVersion < 1 {
		return control.NotificationConfiguration{}, errors.New("control API returned an invalid notification configuration")
	}
	return configuration, nil
}

func (r *runner) addNotificationProfile(ctx context.Context, profile control.NotificationProfile) (control.NotificationConfiguration, error) {
	_, value, err := r.loadConfig()
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	access, err := r.access(ctx, "project:write", false)
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	credential := control.CredentialRequest{AccessToken: access.AccessToken}
	current, err := r.api.Notifications(ctx, credential, value.Project, r.environment)
	if err != nil {
		return control.NotificationConfiguration{}, r.productionNotFound(err, value.Project)
	}
	profiles := append([]control.NotificationProfile{}, current.AllowedProfiles...)
	if !hasNotificationProfile(profiles, control.NotificationBackgroundOnly) {
		profiles = append(profiles, control.NotificationBackgroundOnly)
	}
	if !hasNotificationProfile(profiles, profile) {
		profiles = append(profiles, profile)
	}
	operation, err := operationID()
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	credential.OperationID = operation
	updated, err := r.api.ConfigureNotifications(ctx, credential, value.Project, control.NotificationConfigurationRequest{
		AllowedProfiles: profiles, Environment: r.environment,
		ExpectedConfigurationVersion: current.ConfigurationVersion,
	})
	if err != nil {
		return control.NotificationConfiguration{}, err
	}
	if updated.Environment != r.environment || updated.ConfigurationVersion <= current.ConfigurationVersion || !hasNotificationProfile(updated.AllowedProfiles, profile) {
		return control.NotificationConfiguration{}, errors.New("control API returned an invalid notification update")
	}
	return updated, nil
}

func hasNotificationProfile(profiles []control.NotificationProfile, expected control.NotificationProfile) bool {
	for _, profile := range profiles {
		if profile == expected {
			return true
		}
	}
	return false
}
