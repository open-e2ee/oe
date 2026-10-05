package app

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/agent"
	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	iosnotifications "github.com/open-e2ee/oe/internal/notifications"
	"github.com/open-e2ee/oe/internal/output"
)

const defaultControlURL = "https://console.open-e2ee.dev/api/cli"

type Dependencies struct {
	API     control.API
	Store   credential.Store
	HTTP    *http.Client
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
	OpenURL func(string) error
	Sleep   func(context.Context, time.Duration) error
	Now     func() time.Time
	Getenv  func(string) string
	// Interactive reports whether In is a terminal. The default reads In. A
	// person can answer a prompt only when it is true and no agent runs the
	// CLI.
	Interactive func() bool
	WorkingDir  string
	// Symlink makes the .claude/skills link of oe agent setup. The default is
	// os.Symlink.
	Symlink func(oldname, newname string) error
}

type runner struct {
	api         control.API
	http        *http.Client
	store       credential.Store
	in          io.Reader
	interactive func() bool
	out         *output.Writer
	errOut      io.Writer
	openURL     func(string) error
	sleep       func(context.Context, time.Duration) error
	now         func() time.Time
	getenv      func(string) string
	symlink     func(oldname, newname string) error
	directory   string
	controlURL  string
	environment string
	// environmentSelected is true when --env or OE_ENV names the environment.
	environmentSelected bool
	mode                output.Mode
	// underAgent is true when a coding agent runs the CLI. Then the CLI never
	// prompts and never opens a browser.
	underAgent bool
	// harness is the agent that the environment names. It is zero when no
	// variable names one, or when --agent no overrides the detection.
	harness agent.Harness
	// credentialSource is the source of the credential that access resolved,
	// such as environment for OE_ACCESS_TOKEN. It is empty before access.
	credentialSource string
}

func Run(ctx context.Context, args []string, dependencies Dependencies) int {
	if dependencies.Out == nil {
		dependencies.Out = os.Stdout
	}
	if dependencies.Err == nil {
		dependencies.Err = os.Stderr
	}
	if dependencies.Getenv == nil {
		dependencies.Getenv = os.Getenv
	}
	global, command, commandArgs, err := parseGlobal(args)
	harness, underAgent := agent.Resolve(global.agent, dependencies.Getenv)
	if underAgent && !global.modeExplicit {
		global.mode = output.JSON
	}
	writer := output.New(global.mode, dependencies.Out, dependencies.Err)
	if err != nil {
		return fail(writer, cmp.Or(command, "oe"), args, global.environment, err)
	}
	if command == "" {
		command = "help"
	}
	if dependencies.In == nil {
		dependencies.In = os.Stdin
	}
	if dependencies.Interactive == nil {
		in := dependencies.In
		dependencies.Interactive = func() bool { return isTerminal(in) }
	}
	if dependencies.Store == nil {
		dependencies.Store = credential.Keychain{}
	}
	if dependencies.OpenURL == nil {
		dependencies.OpenURL = openBrowser
	}
	if dependencies.Sleep == nil {
		dependencies.Sleep = sleepContext
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.HTTP == nil {
		dependencies.HTTP = &http.Client{Timeout: 20 * time.Second}
	}
	if dependencies.Symlink == nil {
		dependencies.Symlink = os.Symlink
	}
	if dependencies.WorkingDir == "" {
		dependencies.WorkingDir, err = os.Getwd()
		if err != nil {
			return fail(writer, command, args, global.environment, fmt.Errorf("determine working directory: %w", err))
		}
	}
	if !global.environmentSelected {
		global.environment, global.environmentSelected, err = defaultEnvironment(command, dependencies.Getenv)
		if err != nil {
			return fail(writer, command, args, global.environment, err)
		}
	}
	if err := validateControlURL(global.controlURL); err != nil {
		return fail(writer, command, args, global.environment, usageError(command, err.Error()))
	}
	api := dependencies.API
	if api == nil {
		api, err = control.New(global.controlURL, dependencies.HTTP)
		if err != nil {
			return fail(writer, command, args, global.environment, usageError(command, err.Error()))
		}
	}
	// One buffered reader serves every prompt of the run, so a prompt that
	// follows another reads the next line and not the buffer of the first.
	r := &runner{
		api: api, http: dependencies.HTTP, store: dependencies.Store, in: bufio.NewReader(dependencies.In),
		interactive: dependencies.Interactive, out: writer, errOut: dependencies.Err,
		openURL: dependencies.OpenURL, sleep: dependencies.Sleep, now: dependencies.Now,
		getenv: dependencies.Getenv, symlink: dependencies.Symlink, directory: dependencies.WorkingDir,
		controlURL: global.controlURL, environment: global.environment,
		environmentSelected: global.environmentSelected, mode: global.mode,
		underAgent: underAgent, harness: harness,
	}
	if err := r.execute(ctx, command, commandArgs); err != nil {
		if r.credentialSource == "environment" {
			err = environmentTokenFailure(err, commandLine(args), r.environment)
		}
		return fail(writer, envelopeCommand(command, commandArgs), args, r.environment, err)
	}
	return 0
}

// fail writes one failure and returns the exit status of its code. args is
// the command line of the run, which a temporary failure names as next.
// environment is the environment of the run, which some codes need for next.
func fail(writer *output.Writer, command string, args []string, environment string, err error) int {
	failure := classify(err, commandLine(args), environment)
	_ = writer.Failure(command, failure.output())
	return failure.exit
}

func (r *runner) execute(ctx context.Context, command string, args []string) error {
	if containsHelp(args) {
		return r.commandHelp(command)
	}
	switch command {
	case "help":
		if len(args) > 1 {
			return usageError("help", "help takes at most one command")
		}
		if len(args) == 1 {
			return r.commandHelp(args[0])
		}
		return r.help()
	case "version":
		if len(args) != 0 {
			return usageError("version", "version takes no arguments")
		}
		return r.out.Success("version", Version, map[string]any{"version": Version})
	case "new":
		return r.new(ctx, args)
	case "init", "setup", "create", "sandbox":
		return r.retired(command)
	case "auth":
		return r.auth(ctx, args)
	case "config":
		return r.config(ctx, args)
	case "plan", "deploy", "diff":
		return &problem{
			code: "USAGE_ERROR", exit: exitUsage, next: "oe config push --dry-run",
			message: "oe " + command + " was replaced by oe config push; oe config push --dry-run shows the changes",
		}
	case "doctor":
		return r.doctor(ctx, args)
	case "link":
		return r.link(ctx, args)
	case "project":
		return r.project(ctx, args)
	case "notifications":
		return r.notifications(ctx, args)
	case "agent":
		return r.agent(args)
	default:
		return unknownCommand(command)
	}
}

// interactiveLogin runs the device flow and stores the session. announce shows
// the person the verification URL and the code before the CLI polls.
func (r *runner) interactiveLogin(ctx context.Context, timeout time.Duration, announce func(control.Authorization)) (credential.Credential, error) {
	profile, err := credential.Profile(r.controlURL)
	if err != nil {
		return credential.Credential{}, err
	}
	authorization, err := r.api.StartAuthorization(ctx, control.AuthorizationRequest{})
	if err != nil {
		return credential.Credential{}, err
	}
	if authorization.DeviceCode == "" || authorization.VerificationURL == "" || authorization.UserCode == "" {
		return credential.Credential{}, errors.New("control API returned an incomplete browser authorization")
	}
	announce(authorization)
	// The prompt is already visible, so a browser that cannot open is not a
	// failure. An agent or a script hands the visible URL to a person.
	if r.canPrompt() {
		_ = r.openURL(authorization.VerificationURL)
	}
	interval := time.Duration(authorization.IntervalSeconds) * time.Second
	if interval < time.Second {
		interval = 2 * time.Second
	}
	authorizationLifetime := time.Duration(authorization.ExpiresInSeconds) * time.Second
	if authorizationLifetime > 0 && authorizationLifetime < timeout {
		timeout = authorizationLifetime
	}
	loginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		token, err := r.api.PollAuthorization(loginCtx, authorization)
		if err != nil {
			return credential.Credential{}, loginFailure(ctx, loginCtx, timeout, err)
		}
		if !token.Pending {
			if token.AccessToken == "" {
				return credential.Credential{}, errors.New("browser authorization completed without a credential")
			}
			value := credential.Credential{
				AccessToken: token.AccessToken, ExpiresAt: token.ExpiresAt,
				RefreshToken: token.RefreshToken,
			}
			if err := r.store.Set(profile, value); err != nil {
				return credential.Credential{}, err
			}
			value.Source = "keychain"
			return value, nil
		}
		if token.RetryAfterSeconds > 0 {
			interval = time.Duration(token.RetryAfterSeconds) * time.Second
		}
		if err := r.sleep(loginCtx, interval); err != nil {
			return credential.Credential{}, loginFailure(ctx, loginCtx, timeout, fmt.Errorf("login did not complete: %w", err))
		}
	}
}

// loginFailure gives a device flow that no person approved in time the code
// LOGIN_TIMED_OUT. The login timeout or the end of the device code ends the
// wait, so the failure is temporary: the same command starts a new login.
// When ctx ended, or the poll failed for another reason, err stays as it is.
func loginFailure(ctx, loginCtx context.Context, timeout time.Duration, err error) error {
	expired := errors.Is(err, control.ErrAuthorizationExpired)
	if !expired && (ctx.Err() != nil || !errors.Is(loginCtx.Err(), context.DeadlineExceeded)) {
		return err
	}
	return &problem{
		code: "LOGIN_TIMED_OUT", exit: exitTemporary, cause: err,
		message: fmt.Sprintf("no person approved the device within %s; run the command again, then approve the new code in the browser", timeout),
	}
}

// announceProgress shows the device flow of an automatic login as progress,
// so JSON mode keeps stdout for the one final document of the command.
func (r *runner) announceProgress(authorization control.Authorization) {
	prompt := loginPrompt(authorization)
	data := map[string]any{"verificationUrl": authorization.VerificationURL, "userCode": authorization.UserCode}
	if authorization.BareVerificationURL != "" {
		data["bareVerificationUrl"] = authorization.BareVerificationURL
	}
	_ = r.out.Progress("auth login", prompt, data)
	if r.mode == output.JSON {
		// The person who approves the login reads the prompt on stderr.
		fmt.Fprintln(r.errOut, prompt)
	}
}

// loginPrompt matches the verification page: a URL that carries the code opens a
// page that asks the person to confirm the code it shows; a bare URL opens a
// page that asks the person to type it. With both, a second line gives the bare
// URL for a person who approves on another device (RFC 8628 section 3.3.1).
func loginPrompt(authorization control.Authorization) string {
	if !authorization.CodeInURL {
		return fmt.Sprintf("Open %s and enter the code %s.", authorization.VerificationURL, authorization.UserCode)
	}
	prompt := fmt.Sprintf("Open %s and confirm that it shows the code %s.", authorization.VerificationURL, authorization.UserCode)
	if bare := authorization.BareVerificationURL; bare != "" && bare != authorization.VerificationURL {
		prompt += fmt.Sprintf("\nOn another device, go to %s and enter %s.", bare, authorization.UserCode)
	}
	return prompt
}

func (r *runner) project(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("project", "name a project command: list, show, or connection")
	}
	switch args[0] {
	case "list":
		if err := parseFlags(newFlags("project list"), "project", args[1:]); err != nil {
			return err
		}
		return r.projectList(ctx)
	case "show":
		slug, err := r.projectArgument("project show", args[1:])
		if err != nil {
			return err
		}
		project, err := r.readProject(ctx, slug)
		if err != nil {
			return err
		}
		return r.out.Success("project", projectText(project, r.shownEnvironments()), map[string]any{"project": projectSummary(project, r.shownEnvironments())})
	case "connection":
		slug, err := r.projectArgument("project connection", args[1:])
		if err != nil {
			return err
		}
		project, err := r.readProject(ctx, slug)
		if err != nil {
			return err
		}
		relayURL := ""
		if environment := environmentOf(project, r.environment); environment != nil {
			relayURL = environment.RelayURL
		}
		if relayURL == "" {
			return environmentNotActive(project.Slug, r.environment)
		}
		connection, err := envfile.Detect(filepath.Dir(mustConfigPath(r.directory)), "")
		if err != nil {
			return err
		}
		// Text mode prints only the URL, so a shell can capture it.
		return r.out.Success("project", relayURL, map[string]any{
			"project": project.Slug, "environment": r.environment,
			"relayUrl": relayURL, "variable": connection.Variable,
		})
	default:
		return usageError("project", fmt.Sprintf("unknown project command %q", args[0]))
	}
}

// projectArgument returns the PROJECT argument, or the project in
// open-e2ee.config.ts when the caller names none.
func (r *runner) projectArgument(command string, args []string) (string, error) {
	flags := newFlags(command)
	if err := parseArguments(flags, "project", args); err != nil {
		return "", err
	}
	switch flags.NArg() {
	case 0:
		_, value, err := r.loadConfig()
		if err != nil {
			return "", err
		}
		return value.Project, nil
	case 1:
		return flags.Arg(0), nil
	default:
		return "", usageError("project", "oe "+command+" takes at most one PROJECT")
	}
}

func (r *runner) readProject(ctx context.Context, slug string) (control.Project, error) {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return control.Project{}, err
	}
	return r.api.GetProject(ctx, control.CredentialRequest{AccessToken: access.AccessToken}, slug)
}

func environmentOf(project control.Project, environment string) *control.ProjectEnvironment {
	if environment == "production" {
		return project.Production
	}
	return project.Sandbox
}

func environmentNotActive(project, environment string) *problem {
	next := "oe new"
	if environment == "production" {
		next = "oe config push"
	}
	return &problem{
		code: "ENVIRONMENT_NOT_ACTIVE", exit: exitFailure, next: next,
		message: fmt.Sprintf("the %s environment of project %s is not active", environment, project),
	}
}

// shownEnvironments gives the environments that oe project show and oe config
// pull read: the one that --env names, or that OE_ENV names for project, else
// both.
func (r *runner) shownEnvironments() []string {
	if r.environmentSelected {
		return []string{r.environment}
	}
	return []string{"sandbox", "production"}
}

// projectSummary leaves out each Relay connection URL. Only oe project
// connection prints one, so a routine read does not copy it into a log.
func projectSummary(project control.Project, names []string) map[string]any {
	environments := map[string]any{}
	for _, name := range names {
		environment := environmentOf(project, name)
		if environment == nil || environment.RelayURL == "" {
			environments[name] = map[string]any{"active": false}
			continue
		}
		environments[name] = map[string]any{
			"active":                     true,
			"revision":                   environment.Revision,
			"attachmentRetentionSeconds": environment.AttachmentRetentionSeconds,
			"deliveryTtlSeconds":         environment.DeliveryTtlSeconds,
		}
	}
	return map[string]any{
		"slug":         project.Slug,
		"writer":       project.Writer,
		"environments": environments,
	}
}

func projectText(project control.Project, names []string) string {
	var text strings.Builder
	fmt.Fprintf(&text, "Project %s (writer: %s)", project.Slug, project.Writer)
	for _, name := range names {
		environment := environmentOf(project, name)
		if environment == nil || environment.RelayURL == "" {
			fmt.Fprintf(&text, "\n  %s: not active", name)
			continue
		}
		fmt.Fprintf(&text, "\n  %s: active, revision %s", name, environment.Revision)
	}
	text.WriteString("\nRun oe project connection --env sandbox|production for a Relay connection URL.")
	return text.String()
}

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
		return r.out.Success("notifications", "Notification configuration loaded. Push is a best-effort wake; durable Relay mailbox pull is delivery.", map[string]any{
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
		return r.out.Success("notifications", "iOS notification setup is staged. Push is a best-effort wake; durable Relay mailbox pull is delivery.", map[string]any{
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
		return r.out.Success("notifications", "The Notification Service Extension is staged without Apple filtering authority.", map[string]any{
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
		return r.out.Success("notifications", "Apple notification filtering is optional. It permits an approved Notification Service Extension to suppress an alert; it does not improve APNs delivery or execution.", map[string]any{
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
		return r.out.Success("notifications", "iOS notification configuration passed the available checks.", map[string]any{
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
		return control.NotificationConfiguration{}, err
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
		return control.NotificationConfiguration{}, err
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

func controlPolicy(value config.Config, environment string) (control.RelayPolicyRequest, error) {
	if environment == "production" && value.Environments.Production == nil {
		return control.RelayPolicyRequest{}, &problem{
			code: "USAGE_ERROR", exit: exitUsage,
			message: config.Filename + " has no Production section; add production: {} under environments to opt in to Production",
		}
	}
	policy, err := value.RelayPolicyFor(environment)
	if err != nil {
		return control.RelayPolicyRequest{}, err
	}
	attachment, err := config.RetentionSeconds(policy.AttachmentRetention)
	if err != nil {
		return control.RelayPolicyRequest{}, err
	}
	delivery, err := config.RetentionSeconds(policy.DeliveryRetention)
	if err != nil {
		return control.RelayPolicyRequest{}, err
	}
	return control.RelayPolicyRequest{
		AttachmentRetentionSeconds: attachment,
		DeliveryTtlSeconds:         delivery,
	}, nil
}

// access resolves and refreshes the session, and checks its local scope. An
// empty scope checks none; the control API checks the token either way.
func (r *runner) access(ctx context.Context, scope string, loginWhenMissing bool) (credential.Credential, error) {
	profile, err := credential.Profile(r.controlURL)
	if err != nil {
		return credential.Credential{}, err
	}
	value, err := credential.Resolve(r.store, profile)
	if errors.Is(err, credential.ErrNotFound) && loginWhenMissing {
		value, err = r.interactiveLogin(ctx, 5*time.Minute, r.announceProgress)
	}
	if errors.Is(err, credential.ErrNotFound) {
		return credential.Credential{}, loginRequired("AUTHENTICATION_REQUIRED", "no session is stored for "+profile+"; run oe auth login, or set OE_ACCESS_TOKEN", err)
	}
	if err != nil {
		return credential.Credential{}, err
	}
	r.credentialSource = value.Source
	if value.Source != "environment" && value.RefreshToken != "" && credentialNeedsRefresh(value, r.now()) {
		refreshed, refreshErr := r.api.RefreshAuthorization(ctx, value.RefreshToken)
		if refreshErr != nil {
			if errors.Is(refreshErr, control.ErrSessionExpired) {
				_ = r.store.Delete(profile)
				return credential.Credential{}, loginRequired("SESSION_EXPIRED", "the WorkOS session expired; run oe auth login again", refreshErr)
			}
			if !credentialIsCurrentlyValid(value, r.now()) {
				return credential.Credential{}, fmt.Errorf("refresh the WorkOS session: %w", refreshErr)
			}
		} else {
			value = credential.Credential{
				AccessToken: refreshed.AccessToken, ExpiresAt: refreshed.ExpiresAt,
				RefreshToken: refreshed.RefreshToken, Source: "keychain",
			}
			if err := r.store.Set(profile, value); err != nil {
				return credential.Credential{}, err
			}
		}
	}
	if scope == "" {
		return value, nil
	}
	if err := credential.RequireScope(value, scope); err != nil {
		return credential.Credential{}, &problem{code: "SCOPE_REQUIRED", message: err.Error(), exit: exitFailure, cause: err}
	}
	return value, nil
}

func credentialNeedsRefresh(value credential.Credential, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339, value.ExpiresAt)
	return err != nil || !expiresAt.After(now.Add(time.Minute))
}

func credentialIsCurrentlyValid(value credential.Credential, now time.Time) bool {
	expiresAt, err := time.Parse(time.RFC3339, value.ExpiresAt)
	return err == nil && expiresAt.After(now)
}

func (r *runner) loadConfig() (string, config.Config, error) {
	path, err := config.Find(r.directory)
	if err != nil {
		return "", config.Config{}, &problem{
			code: "CONFIG_NOT_FOUND", exit: exitFailure, next: "oe new", cause: err,
			message: err.Error() + " in " + r.directory + " or a parent directory",
		}
	}
	value, err := config.Load(path)
	if _, ok := errors.AsType[*config.Error](err); ok {
		return "", config.Config{}, err
	}
	if err != nil {
		return "", config.Config{}, &problem{code: "CONFIG_INVALID", message: err.Error(), exit: exitFailure, cause: err}
	}
	return path, value, nil
}

type globalOptions struct {
	mode                output.Mode
	modeExplicit        bool
	agent               agent.Mode
	controlURL          string
	environment         string
	environmentSelected bool
}

// parseGlobal reads the global flags before or after the command, up to a
// "--" terminator. The first other word is the command, and the remaining
// arguments go to the command in their order. A failure still returns the
// output mode, so the caller can report the failure in that mode.
func parseGlobal(args []string) (globalOptions, string, []string, error) {
	options := globalOptions{mode: output.Text, agent: agent.Auto, controlURL: defaultControlURL}
	command := ""
	var rest []string
	var failure error
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			remaining := args[index+1:]
			if command == "" && len(remaining) > 0 {
				command, remaining = remaining[0], remaining[1:]
			}
			rest = append(rest, remaining...)
			break
		}
		name, value, inline := strings.Cut(argument, "=")
		switch {
		case argument == "--json":
			options.mode, options.modeExplicit = output.JSON, true
		case argument == "--json-stream":
			options.mode, options.modeExplicit = output.JSONStream, true
		case name == "--control-url" || name == "--env" || name == "-e" || name == "--agent":
			if !inline {
				if index+1 == len(args) {
					failure = cmp.Or(failure, usageError(command, name+" needs a value"))
					continue
				}
				index++
				value = args[index]
			}
			switch name {
			case "--control-url":
				options.controlURL = value
			case "--agent":
				options.agent = agent.Mode(value)
			default:
				options.environment = value
				options.environmentSelected = true
			}
		case command != "":
			rest = append(rest, argument)
		case argument == "-h" || argument == "--help":
			command = "help"
		case argument == "--version":
			command = "version"
		case strings.HasPrefix(argument, "-"):
			failure = cmp.Or(failure, usageError("", fmt.Sprintf("unknown global flag %q", argument)))
		default:
			command = argument
		}
	}
	if failure == nil && options.environmentSelected && options.environment != "sandbox" && options.environment != "production" {
		failure = usageError(command, "--env must be sandbox or production")
	}
	if !options.agent.Valid() {
		failure = cmp.Or(failure, usageError(command, "--agent must be yes, no, or auto"))
		options.agent = agent.Auto
	}
	return options, command, rest, failure
}

// defaultEnvironment gives the environment of a run without --env. doctor,
// project, and notifications take OE_ENV, then sandbox. new keeps Sandbox, so
// a variable left in a shell never changes the target of a new project. config
// ignores OE_ENV, so the variable never narrows a pull or changes what a push
// applies.
func defaultEnvironment(command string, getenv func(string) string) (string, bool, error) {
	switch command {
	case "doctor", "project", "notifications":
		selected := getenv("OE_ENV")
		if selected == "" {
			return "sandbox", false, nil
		}
		if selected != "sandbox" && selected != "production" {
			return "", false, usageError(command, "OE_ENV must be sandbox or production")
		}
		return selected, true, nil
	}
	return "sandbox", false, nil
}

func containsHelp(args []string) bool {
	for _, argument := range args {
		if argument == "--help" || argument == "-h" {
			return true
		}
	}
	return false
}

func newFlags(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	return flags
}

// parseFlags parses the flags of command and refuses a positional argument.
func parseFlags(flags *flag.FlagSet, command string, args []string) error {
	if err := parseArguments(flags, command, args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return usageError(command, fmt.Sprintf("oe %s: unexpected argument %q", flags.Name(), flags.Arg(0)))
	}
	return nil
}

// parseArguments parses the flags of command and keeps its positional
// arguments in flags.Args.
func parseArguments(flags *flag.FlagSet, command string, args []string) error {
	if err := flags.Parse(args); err != nil {
		return usageError(command, "oe "+flags.Name()+": "+err.Error())
	}
	return nil
}

// canPrompt reports whether a person can answer a prompt: In is a terminal
// and no agent runs the CLI. When it is false, the CLI never prompts and
// never opens a browser.
func (r *runner) canPrompt() bool {
	return !r.underAgent && r.interactive()
}

// isTerminal reports whether in is a character device, so a person can answer
// a prompt on it.
func isTerminal(in io.Reader) bool {
	file, ok := in.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func validateControlURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid control URL %q", raw)
	}
	hostname := parsed.Hostname()
	if parsed.Scheme != "https" && hostname != "localhost" && hostname != "127.0.0.1" && hostname != "::1" {
		return errors.New("the control URL must use HTTPS except on loopback")
	}
	return nil
}

func operationID() (string, error) {
	if supplied := strings.TrimSpace(os.Getenv("OE_OPERATION_ID")); supplied != "" {
		return supplied, nil
	}
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "oe_" + hex.EncodeToString(value), nil
}

func askConfirmation(in io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprintf(out, "%s [y/N] ", prompt)
	answer, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	return command.Start()
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func slug(value string) string {
	value = strings.ToLower(value)
	var result strings.Builder
	lastHyphen := false
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			result.WriteRune(character)
			lastHyphen = false
		} else if !lastHyphen && result.Len() > 0 {
			result.WriteByte('-')
			lastHyphen = true
		}
	}
	return strings.Trim(result.String(), "-")
}

// environmentFiles names the env file that holds each environment's Relay
// connection.
var environmentFiles = map[string]string{"sandbox": ".env.local", "production": ".env.production.local"}

// writeRelayEnvironment writes relayURL to filename in the project directory
// under variable, and keeps the file out of version control.
func writeRelayEnvironment(directory, filename, variable, relayURL string) error {
	if err := envfile.Write(filepath.Join(directory, filename), variable, relayURL); err != nil {
		return err
	}
	return ensureIgnored(directory, filename)
}

// ensureIgnored adds filename to the .gitignore file in directory once.
func ensureIgnored(directory, filename string) error {
	ignorePath := filepath.Join(directory, ".gitignore")
	ignored, err := os.ReadFile(ignorePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, line := range strings.Split(string(ignored), "\n") {
		if strings.TrimSpace(line) == filename {
			return nil
		}
	}
	prefix := string(ignored)
	if prefix != "" && !strings.HasSuffix(prefix, "\n") {
		prefix += "\n"
	}
	return writePublicFile(ignorePath, []byte(prefix+filename+"\n"))
}

func writePublicFile(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".open-e2ee-environment-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func mustConfigPath(start string) string {
	path, err := config.Find(start)
	if err != nil {
		return filepath.Join(start, config.Filename)
	}
	return path
}

var Version = "0.0.0-development"
