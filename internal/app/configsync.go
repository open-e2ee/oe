package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/output"
)

// relayFields are the fields of a Relay policy, in the order of the file.
var relayFields = []string{"deliveryRetention", "attachmentRetention"}

// A person's push waits this long for a card, and reads the project at this
// interval while it waits.
const (
	cardWait     = 30 * time.Minute
	cardInterval = 5 * time.Second
)

// activationChange is the plan change that activates Production.
const activationChange = "production.activation"

func (r *runner) config(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("config", "name a config command: push or pull")
	}
	switch args[0] {
	case "push":
		return r.configPush(ctx, args[1:])
	case "pull":
		return r.configPull(ctx, args[1:])
	default:
		return usageError("config", fmt.Sprintf("unknown config command %q", args[0]))
	}
}

// configPull writes the Relay policy of each active environment into
// open-e2ee.config.ts with the fewest changes. An addition needs no consent,
// and a replaced value needs --yes or a person's answer. When a changed value
// is computed in the file, the pull writes nothing and returns every edit
// that a person must make.
func (r *runner) configPull(ctx context.Context, args []string) error {
	flags := newFlags("config pull")
	yes := flags.Bool("yes", false, "replace values without a prompt")
	dryRun := flags.Bool("dry-run", false, "show the changes and write nothing")
	if err := parseFlags(flags, "config", args); err != nil {
		return err
	}
	path, value, err := r.loadConfig()
	if err != nil {
		return err
	}
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return err
	}
	project, err := r.getProject(ctx, access, value.Project)
	if err != nil {
		return err
	}
	plan, err := planPull(value, project, r.shownEnvironments())
	if err != nil {
		return err
	}
	if len(plan.changes) == 0 {
		return r.out.Success("config pull", config.Filename+" matches the console.", plan.data("", false))
	}
	if err := config.CheckEdit(path, plan.changes...); err != nil {
		failure, ok := errors.AsType[*config.Error](err)
		if !*dryRun || !ok || failure.Code != "CONFIG_EDIT_REQUIRED" {
			return err
		}
		data := plan.data("planned", false)
		data["edits"] = failure.Data["edits"]
		return r.out.Success("config pull", plan.text("A pull needs these changes, and a person must make some of them:")+"\n"+failure.Message, data)
	}
	if *dryRun {
		return r.out.Success("config pull", plan.text("A pull makes these changes:"), plan.data("planned", false))
	}
	if plan.replaced > 0 && !*yes {
		next := "oe config pull --yes"
		if r.environmentSelected {
			next += " --env " + r.environment
		}
		if access.Source == "environment" || r.mode != output.Text || !r.canPrompt() {
			return &problem{
				code: "CONFIRMATION_REQUIRED", exit: exitUsage, next: next,
				message: fmt.Sprintf("a pull that replaces %d value(s) needs --yes when no person can answer a prompt; review the changes, then run %s", plan.replaced, next),
				data:    plan.data("planned", false),
			}
		}
		fmt.Fprintln(r.errOut, plan.text("A pull makes these changes:"))
		approved, err := askConfirmation(r.in, r.errOut, fmt.Sprintf("Replace %d value(s) in %s?", plan.replaced, config.Filename))
		if err != nil {
			return err
		}
		if !approved {
			return &problem{code: "PULL_CANCELLED", message: "config pull cancelled", exit: exitFailure}
		}
	}
	lock, err := lockProject(ctx, filepath.Dir(path))
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := config.Edit(path, plan.changes...); err != nil {
		return err
	}
	return r.out.Success("config pull", plan.text("Pulled the Relay policy into "+config.Filename+":"), plan.data("applied", true))
}

// pullPlan is the changes that a pull makes to open-e2ee.config.ts.
type pullPlan struct {
	names        []string
	environments map[string]*pulledEnvironment
	changes      []config.Change
	// replaced counts the changes that replace a value that the file gives.
	replaced int
}

type pulledEnvironment struct {
	Status  string       `json:"status"`
	Reason  string       `json:"reason,omitempty"`
	Changes []pullChange `json:"changes,omitempty"`
}

// pullChange is one value that a pull writes. From is the value that the file
// gives now, and a change that adds a section or an override has none.
type pullChange struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	From   string `json:"from,omitempty"`
	To     any    `json:"to"`
}

// planPull compares the Relay policy of each named environment with the
// file. A value that the shared policy already gives stays shared, and a
// different value becomes an override in the environment section. The shared
// policy never changes. An inactive environment keeps its section.
func planPull(value config.Config, project control.Project, names []string) (pullPlan, error) {
	plan := pullPlan{names: names, environments: map[string]*pulledEnvironment{}}
	for _, name := range names {
		remote := environmentOf(project, name)
		if remote == nil || remote.RelayURL == "" {
			plan.environments[name] = &pulledEnvironment{Status: "skipped", Reason: "inactive"}
			continue
		}
		delivery, err := config.Retention(remote.DeliveryRetentionSeconds)
		if err != nil {
			return pullPlan{}, fmt.Errorf("the %s delivery retention: %w", name, err)
		}
		attachment, err := config.Retention(remote.AttachmentRetentionSeconds)
		if err != nil {
			return pullPlan{}, fmt.Errorf("the %s attachment retention: %w", name, err)
		}
		server := policyFields(config.RelayPolicy{DeliveryRetention: delivery, AttachmentRetention: attachment})
		entry := &pulledEnvironment{Status: "unchanged"}
		plan.environments[name] = entry
		section := "environments." + name
		if name == "production" && value.Environments.Production == nil {
			// The file has no section for the environment, so each value that
			// the shared policy does not give is added as an override.
			shared := policyFields(value.Relay)
			for _, field := range relayFields {
				if server[field] == shared[field] {
					continue
				}
				entry.Changes = append(entry.Changes, pullChange{Path: section + ".relay." + field, Action: "add", To: server[field]})
				plan.changes = append(plan.changes, config.Change{Path: []string{"environments", name, "relay", field}, Value: server[field]})
			}
			if len(entry.Changes) == 0 {
				entry.Changes = []pullChange{{Path: section, Action: "add", To: map[string]any{}}}
				plan.changes = append(plan.changes, config.Change{Path: []string{"environments", name}, Value: map[string]any{}})
			}
			continue
		}
		current, err := value.RelayPolicyFor(name)
		if err != nil {
			return pullPlan{}, err
		}
		// A new override replaces the shared value that the environment
		// takes now, so it is a replacement too.
		effective := policyFields(current)
		for _, field := range relayFields {
			if server[field] == effective[field] {
				continue
			}
			entry.Changes = append(entry.Changes, pullChange{Path: section + ".relay." + field, Action: "replace", From: effective[field], To: server[field]})
			plan.changes = append(plan.changes, config.Change{Path: []string{"environments", name, "relay", field}, Value: server[field]})
			plan.replaced++
		}
	}
	return plan, nil
}

func policyFields(policy config.RelayPolicy) map[string]string {
	return map[string]string{"deliveryRetention": policy.DeliveryRetention, "attachmentRetention": policy.AttachmentRetention}
}

// data gives each environment with changes the status, and keeps the status
// of the others.
func (p pullPlan) data(status string, changed bool) map[string]any {
	environments := map[string]any{}
	for name, entry := range p.environments {
		result := *entry
		if len(result.Changes) > 0 {
			result.Status = status
		}
		environments[name] = result
	}
	return map[string]any{"changed": changed, "environments": environments}
}

// text lists the changes under heading, one per line.
func (p pullPlan) text(heading string) string {
	var text strings.Builder
	text.WriteString(heading)
	for _, name := range p.names {
		for _, change := range p.environments[name].Changes {
			to, _ := json.Marshal(change.To)
			if change.Action == "add" {
				fmt.Fprintf(&text, "\n  add %s: %s", change.Path, to)
				continue
			}
			fmt.Fprintf(&text, "\n  replace %s: %q -> %s", change.Path, change.From, to)
		}
	}
	return text.String()
}

// pushEntry is the result of oe config push for one environment. failure is
// set when the environment did not apply, and the run takes the code of the
// first such environment.
type pushEntry struct {
	Status     string           `json:"status"`
	Code       string           `json:"code,omitempty"`
	Changes    []control.Change `json:"changes"`
	Revision   string           `json:"revision,omitempty"`
	Activation string           `json:"activation,omitempty"`
	Activated  bool             `json:"activated,omitempty"`
	BlockedBy  string           `json:"blockedBy,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	failure    *problem
}

func (entry *pushEntry) stop(status string, failure *problem) *pushEntry {
	entry.Status, entry.Code, entry.failure = status, failure.code, failure
	return entry
}

// pusher holds one run of oe config push.
type pusher struct {
	r         *runner
	yes       bool
	value     config.Config
	directory string
	variable  string
	access    credential.Credential
	project   control.Project
	policies  map[string]control.RelayPolicyRequest
	// wrote is true when the run wrote the Production connection file.
	wrote bool
}

// configPush applies the environment sections of the config: Sandbox, then
// Production when the file has its section. --env narrows the sections, and
// OE_ENV does not. A Production change needs --yes or a person's consent. A
// Sandbox failure skips Production, so a policy never reaches Production when
// it did not apply to Sandbox.
func (r *runner) configPush(ctx context.Context, args []string) error {
	flags := newFlags("config push")
	yes := flags.Bool("yes", false, "consent to the Production changes")
	dryRun := flags.Bool("dry-run", false, "report the plan and change nothing")
	if err := parseFlags(flags, "config", args); err != nil {
		return err
	}
	path, value, err := r.loadConfig()
	if err != nil {
		return err
	}
	environments := []string{"sandbox"}
	if value.Environments.Production != nil {
		environments = append(environments, "production")
	}
	if r.environmentSelected {
		environments = []string{r.environment}
	}
	policies := map[string]control.RelayPolicyRequest{}
	for _, environment := range environments {
		if policies[environment], err = controlPolicy(value, environment); err != nil {
			return err
		}
	}
	directory := filepath.Dir(path)
	connection, err := envfile.Detect(directory, "")
	if err != nil {
		return err
	}
	scope := "deploy:write"
	if *dryRun {
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
		return &problem{
			code: "CONSOLE_WRITER", exit: exitFailure,
			message: "project " + project.Slug + " is console-first; change its policy in the console, because oe config push changes nothing",
		}
	}
	if !*dryRun {
		lock, err := lockProject(ctx, directory)
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	push := &pusher{
		r: r, yes: *yes, value: value, directory: directory, variable: connection.Variable,
		access: access, project: project, policies: policies,
	}
	return push.run(ctx, environments, *dryRun)
}

func (p *pusher) run(ctx context.Context, environments []string, dryRun bool) error {
	entries := map[string]*pushEntry{}
	order := slices.Clone(environments)
	first := ""
	for _, environment := range environments {
		if first != "" {
			entries[environment] = &pushEntry{Status: "skipped", Reason: "sandbox_not_applied", Changes: []control.Change{}}
			continue
		}
		entries[environment] = p.environment(ctx, environment, dryRun)
		if entries[environment].failure != nil {
			first = environment
		}
	}
	// A push never deactivates Production. An active Production with no
	// section in the file stays as it is.
	if !p.r.environmentSelected && !slices.Contains(environments, "production") &&
		p.project.Production != nil && p.project.Production.State == control.ProductionActive {
		entries["production"] = &pushEntry{Status: "skipped", Reason: "not_in_file", Changes: []control.Change{}}
		order = append(order, "production")
	}
	return p.report(order, entries, first, dryRun)
}

func (p *pusher) environment(ctx context.Context, environment string, dryRun bool) *pushEntry {
	entry := &pushEntry{Changes: []control.Change{}}
	plan, err := p.plan(ctx, environment)
	if err != nil {
		return entry.stop("failed", classify(err, p.command(p.yes), environment))
	}
	if plan.Changes != nil {
		entry.Changes = plan.Changes
	}
	activation := environment == "production" && slices.ContainsFunc(plan.Changes, func(change control.Change) bool {
		return change.Path == activationChange
	})
	blockedBy := ""
	if environment == "production" && p.project.Production != nil {
		blockedBy = p.project.Production.BlockedBy
	}
	if dryRun {
		entry.Status = "unchanged"
		if len(plan.Changes) > 0 {
			entry.Status = "planned"
		}
		if activation {
			entry.Activation, entry.BlockedBy = "free", blockedBy
		}
		return entry
	}
	if len(plan.Changes) == 0 {
		entry.Status = "unchanged"
		return entry
	}
	if environment == "production" {
		if blocked, err := p.consent(ctx, plan, activation, blockedBy); err != nil {
			return entry.stop("failed", classify(err, p.command(p.yes), environment))
		} else if blocked != nil {
			return entry.stop("blocked", blocked)
		}
	}
	deployment, err := p.apply(ctx, plan, environment)
	if err != nil {
		return entry.stop("failed", classify(err, p.command(p.yes), environment))
	}
	entry.Status, entry.Revision, entry.Activated = "applied", deployment.Revision, activation
	return entry
}

func (p *pusher) plan(ctx context.Context, environment string) (control.Plan, error) {
	operation, err := operationID()
	if err != nil {
		return control.Plan{}, err
	}
	plan, err := p.r.api.Plan(ctx, control.CredentialRequest{AccessToken: p.access.AccessToken, OperationID: operation}, control.PlanRequest{
		Environment: environment, Policy: p.policies[environment], ProjectSlug: p.value.Project, Writer: "config",
	})
	if err != nil {
		return control.Plan{}, err
	}
	if err := validatePlan(plan, p.project, environment); err != nil {
		return control.Plan{}, err
	}
	return plan, nil
}

// consent decides whether a Production change may go ahead. It returns the
// problem that blocks the change, or an error when a read fails. An activation
// checks the gates first, in the order that the console checks them, and the
// card last, so a person never adds a card and then meets a gate that the
// card does not open. A person waits on the card page and then answers the
// prompt. Any other caller needs --yes.
func (p *pusher) consent(ctx context.Context, plan control.Plan, activation bool, blockedBy string) (*problem, error) {
	if activation {
		if blocked, err := p.gate(ctx, blockedBy); blocked != nil || err != nil {
			return blocked, err
		}
	}
	// Text mode keeps the wait and the prompt out of a JSON document.
	person := p.access.Source != "environment" && p.r.canPrompt() && p.r.mode == output.Text
	prompt := !p.yes
	if prompt && !person {
		return &problem{
			code: "CONFIRMATION_REQUIRED", exit: exitUsage, next: p.command(true),
			message: changeText(plan.Changes, activation) + " need --yes when no person can answer" + freeSlotText(activation),
		}, nil
	}
	if activation && blockedBy == control.BlockedByCard {
		if plan.BillingSetupURL == "" {
			return nil, errors.New("control API returned no card setup URL for a Production activation")
		}
		if !person {
			return p.cardRequired(plan.BillingSetupURL, "the activation needs a card on the organization"), nil
		}
		if blocked, err := p.waitForCard(ctx, plan.BillingSetupURL); blocked != nil || err != nil {
			return blocked, err
		}
	}
	if prompt {
		question := fmt.Sprintf("Apply %s to Production?", changeText(plan.Changes, false))
		if activation {
			question = fmt.Sprintf("Activate Production on the Free plan, which uses one of the two Free Production projects of the organization, and apply %s?", changeText(plan.Changes, false))
		}
		approved, err := askConfirmation(p.r.in, p.r.errOut, question)
		if err != nil {
			return nil, err
		}
		if !approved {
			return &problem{code: "PUSH_CANCELLED", message: "the Production push was cancelled", exit: exitFailure}, nil
		}
	}
	return nil, nil
}

// gate gives the problem of a Production gate other than the card.
func (p *pusher) gate(ctx context.Context, blockedBy string) (*problem, error) {
	switch blockedBy {
	case control.BlockedByBillingPermission:
		return &problem{
			code: "BILLING_PERMISSION_REQUIRED", exit: exitPersonAction,
			message: "a Production activation needs the billing permission of the organization; a billing administrator must run oe config push, or grant this account the billing permission",
		}, nil
	case control.BlockedByTerms:
		terms, err := p.r.api.Terms(ctx, control.CredentialRequest{AccessToken: p.access.AccessToken})
		if err != nil {
			return nil, err
		}
		blocked := &problem{
			code: "TERMS_REQUIRED", exit: exitPersonAction,
			message: "the organization must accept the OpenE2EE terms before Production can activate",
			data: map[string]any{
				"canAccept": terms.CanAccept, "documents": termsDocuments(terms.Documents),
				"retry": p.command(p.yes),
			},
		}
		if terms.CanAccept {
			blocked.next = "oe auth login --accept-terms"
		} else {
			blocked.message += "; an administrator must accept them, in the console or with oe auth login --accept-terms"
		}
		return blocked, nil
	case control.BlockedByFreeProjectLimit:
		return &problem{
			code: "FREE_PROJECT_LIMIT", exit: exitPersonAction,
			message: "the organization already has two Free Production projects; change a plan at " + p.consoleURL() + ", then run " + p.command(p.yes) + " again",
		}, nil
	}
	return nil, nil
}

// waitForCard opens the card page for a person and reads the project until
// the card is on file. It then checks the gates again.
func (p *pusher) waitForCard(ctx context.Context, setupURL string) (*problem, error) {
	_ = p.r.out.Pending("config push",
		"Production needs a card on the organization. Opening "+setupURL+" to add a card. Waiting for the card... (press Ctrl-C to stop)",
		output.Action{Kind: "browser", URL: setupURL, Reason: "card"}, nil)
	_ = p.r.openURL(setupURL)
	waitCtx, cancel := context.WithTimeout(ctx, cardWait)
	defer cancel()
	for {
		if err := p.r.sleep(waitCtx, cardInterval); err != nil {
			return p.cardRequired(setupURL, "no card was on file before the wait ended"), nil
		}
		project, err := p.r.api.GetProject(waitCtx, control.CredentialRequest{AccessToken: p.access.AccessToken}, p.value.Project)
		if err != nil {
			return nil, err
		}
		if project.Production != nil && project.Production.BlockedBy != control.BlockedByCard {
			_ = p.r.out.Progress("config push", "Card found.", nil)
			return p.gate(ctx, project.Production.BlockedBy)
		}
	}
}

func (p *pusher) cardRequired(setupURL, reason string) *problem {
	return &problem{
		code: "CARD_REQUIRED", exit: exitPersonAction, next: p.command(true),
		actionURL: setupURL, actionReason: "card",
		message: reason + "; add one at " + setupURL + ", then run " + p.command(true),
	}
}

// apply deploys a plan. A Production deploy writes the Production
// connection file.
func (p *pusher) apply(ctx context.Context, plan control.Plan, environment string) (control.Deployment, error) {
	operation, err := operationID()
	if err != nil {
		return control.Deployment{}, err
	}
	deployment, err := p.r.api.Deploy(ctx, control.CredentialRequest{AccessToken: p.access.AccessToken, OperationID: operation}, control.DeployRequest{
		Environment: environment, ExpectedRevision: plan.ExpectedRevision, PlanID: plan.ID,
		Policy: p.policies[environment], ProjectSlug: p.value.Project, Writer: "config",
	})
	if err != nil {
		return control.Deployment{}, err
	}
	if environment != "production" {
		return deployment, nil
	}
	if deployment.RelayURL == "" {
		return control.Deployment{}, errors.New("control API returned an incomplete production Relay connection")
	}
	if err := writeRelayEnvironment(p.directory, environmentFiles["production"], p.variable, deployment.RelayURL); err != nil {
		return control.Deployment{}, err
	}
	p.wrote = true
	return deployment, nil
}

// report writes the result of every environment in data.environments. A run
// in which an environment did not apply fails with the code, the exit, and
// the next of the first such environment.
func (p *pusher) report(order []string, entries map[string]*pushEntry, first string, dryRun bool) error {
	summaries := make([]string, 0, len(order))
	for _, environment := range order {
		summaries = append(summaries, entrySummary(environment, entries[environment]))
	}
	summary := strings.Join(summaries, " ")
	data := map[string]any{"environments": entries}
	if first != "" {
		failure := entries[first].failure
		for key, value := range failure.data {
			data[key] = value
		}
		return &problem{
			code: failure.code, message: summary, next: failure.next, exit: failure.exit, data: data,
			cause: failure, actionURL: failure.actionURL, actionReason: failure.actionReason,
		}
	}
	if dryRun {
		return p.r.out.Success("config push", "Dry run. Nothing changed. "+summary, data)
	}
	next := ""
	if p.wrote {
		data["connection"] = map[string]any{"file": environmentFiles["production"], "variable": p.variable}
		summary += " Wrote " + environmentFiles["production"] + ": " + p.variable + "."
		next = "oe doctor --env production"
	}
	return p.r.out.SuccessNext("config push", summary, next, data)
}

func entrySummary(environment string, entry *pushEntry) string {
	name := "Sandbox"
	if environment == "production" {
		name = "Production"
	}
	switch {
	case entry.failure != nil:
		return name + ": " + entry.failure.message + "."
	case entry.Activated:
		return "Production is active on the Free plan."
	case entry.Reason == "not_in_file":
		return "Production: not changed, because " + config.Filename + " has no Production section."
	case entry.Reason == "sandbox_not_applied":
		return name + ": skipped, because Sandbox did not apply."
	case entry.Activation != "":
		return name + ": " + entry.Status + ", with a Free plan activation."
	default:
		return name + ": " + entry.Status + "."
	}
}

// changeText names the changes of a plan, such as "activation and 2 policy
// change(s)". The activation change is not a policy change.
func changeText(changes []control.Change, activation bool) string {
	policy := 0
	for _, change := range changes {
		if change.Path != activationChange {
			policy++
		}
	}
	if activation {
		return fmt.Sprintf("activation and %d policy change(s)", policy)
	}
	return fmt.Sprintf("%d policy change(s)", policy)
}

func freeSlotText(activation bool) string {
	if !activation {
		return ""
	}
	return "; the activation uses one of the two Free Production projects of the organization"
}

// command is the oe config push command line of this run, with --yes when yes
// is true.
func (p *pusher) command(yes bool) string {
	line := "oe config push"
	if p.r.environmentSelected {
		line += " --env " + p.r.environment
	}
	if yes {
		line += " --yes"
	}
	return line
}

// consoleURL is the console page of the signal-relay projects, on the host
// of the control API.
func (p *pusher) consoleURL() string {
	parsed, err := url.Parse(p.r.controlURL)
	if err != nil {
		return "the console"
	}
	return parsed.Scheme + "://" + parsed.Host + "/signal-relay"
}

func validatePlan(plan control.Plan, project control.Project, environment string) error {
	if plan.ID == "" {
		return errors.New("control API returned a plan without an ID")
	}
	if plan.Environment != environment {
		return errors.New("control API returned a plan for a different environment")
	}
	// An environment that is not active has no revision, and its plan
	// expects revision 0.
	expectedRevision := "0"
	if selected := environmentOf(project, environment); selected != nil && selected.Revision != "" {
		expectedRevision = selected.Revision
	}
	if plan.ExpectedRevision != expectedRevision {
		return errors.New("control API returned a plan for a stale project revision")
	}
	if plan.ProjectSlug != project.Slug {
		return errors.New("control API returned a plan for a different project")
	}
	return nil
}
