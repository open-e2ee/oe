package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/envfile"
)

func (r *runner) project(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("project", "name a project command: list, show, usage, or connection")
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
		return r.out.Success("project show", projectText(project, r.shownEnvironments()), map[string]any{"project": projectSummary(project, r.shownEnvironments())})
	case "usage":
		slug, err := r.projectArgument("project usage", args[1:])
		if err != nil {
			return err
		}
		return r.projectUsage(ctx, slug)
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
			return r.environmentNotActive(project.Slug, project.Writer, r.environment)
		}
		connection, err := envfile.Detect(filepath.Dir(mustConfigPath(r.directory)), "")
		if err != nil {
			return err
		}
		// Text mode prints only the URL, so a shell can capture it.
		return r.out.Success("project connection", relayURL, map[string]any{
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

func environmentOf(project control.Project, environment string) *control.ProjectEnvironment {
	if environment == "production" {
		return project.Production
	}
	return project.Sandbox
}

// environmentNotActive is a read of an environment that project has not
// activated. writer is the writer mode of the project.
func (r *runner) environmentNotActive(project, writer, environment string) *problem {
	failure := &problem{
		code: "ENVIRONMENT_NOT_ACTIVE", exit: exitFailure, next: "oe new",
		message: fmt.Sprintf("the %s environment of project %s is not active", environment, project),
	}
	if environment == "production" {
		var step string
		failure.next, step = r.productionActivation(project, writer)
		failure.message += "; " + step
	}
	return failure
}

// productionActivation returns the command and the step that activate the
// Production of project. oe config push activates Production only from a
// config of the project that has a production section, and only when the
// project takes its policy from the config. The console activates Production
// for every project. next is empty when no command alone activates it. writer
// is the writer mode of the project, or empty when the caller did not read it.
func (r *runner) productionActivation(project, writer string) (next, step string) {
	console := fmt.Sprintf("activate Production on the plan page of project %s in the console", project)
	if writer == "console" {
		return "", "the console writes the policy of this project, so " + console
	}
	_, value, err := r.loadConfig()
	switch {
	case err != nil || value.Project != project:
		return "", fmt.Sprintf("%s, or add production: {} under environments in the %s of project %s, then run oe config push in its directory",
			console, config.Filename, project)
	case value.Environments.Production == nil:
		return "", fmt.Sprintf("%s has no Production section; add production: {} under environments, then run oe config push, or %s",
			config.Filename, console)
	default:
		return "oe config push", fmt.Sprintf("run oe config push to apply the Production section of %s, or %s", config.Filename, console)
	}
}

// productionNotFound adds the activation step to a control API refusal of a
// Production read with ENVIRONMENT_NOT_FOUND. Every other error stays as it is.
func (r *runner) productionNotFound(err error, project string) error {
	refusal, ok := errors.AsType[*control.APIError](err)
	if !ok || refusal.Code != "ENVIRONMENT_NOT_FOUND" || r.environment != "production" {
		return err
	}
	next, step := r.productionActivation(project, "")
	return &problem{code: refusal.Code, exit: exitFailure, next: next, cause: err, message: err.Error() + "; " + step}
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
			"deliveryRetentionSeconds":   environment.DeliveryRetentionSeconds,
			"relayReceipts":              environment.RelayReceipts,
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

// projectList prints the projects that the account can read in the
// organization of the session, with the state of each Production. The text
// and data.organization name that organization. A failed organization read
// degrades the output to the projects alone. An empty list for a person with
// more than one organization names oe org switch; the command never reads the
// projects of another organization.
func (r *runner) projectList(ctx context.Context) error {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return err
	}
	request := control.CredentialRequest{AccessToken: access.AccessToken}
	projects, err := r.api.ListProjects(ctx, request)
	if err != nil {
		return err
	}
	data := map[string]any{"projects": projects}
	organization, others, known := r.sessionOrganization(ctx, request)
	if known {
		data["organization"] = map[string]any{"id": organization.ID, "name": organization.Name}
	}
	if len(projects) == 0 {
		switch {
		case known && others > 0:
			message := fmt.Sprintf("%s has no Relay project. You belong to %s; run oe org switch.",
				organization.Name, otherOrganizations(others))
			return r.out.SuccessNext("project list", message, "oe org switch", data)
		case known:
			return r.out.Success("project list", organization.Name+" has no Relay project.", data)
		}
		return r.out.Success("project list", "This account can read no Relay project.", data)
	}
	var text strings.Builder
	if known {
		text.WriteString("Projects in " + organization.Name + ":\n")
	}
	table := tabwriter.NewWriter(&text, 0, 0, 2, ' ', 0)
	for _, project := range projects {
		fmt.Fprintf(table, "%s\t%s\tProduction %s\n", project.Slug, project.Name, project.Production.State)
	}
	table.Flush()
	return r.out.Success("project list", strings.TrimSuffix(text.String(), "\n"), data)
}

// sessionOrganization reads the organization of the session and the number
// of the other organizations of the person. known is false when the read
// fails or the session has no organization.
func (r *runner) sessionOrganization(ctx context.Context, request control.CredentialRequest) (control.Organization, int, bool) {
	list, err := r.api.ListOrganizations(ctx, request)
	if err != nil {
		return control.Organization{}, 0, false
	}
	organization, ok := organizationByID(list, list.Current)
	if !ok {
		return control.Organization{}, 0, false
	}
	return organization, len(list.Organizations) - 1, true
}

// otherOrganizations counts the other organizations of the person in words.
func otherOrganizations(count int) string {
	if count == 1 {
		return "1 other organization"
	}
	return fmt.Sprintf("%d other organizations", count)
}

func (r *runner) listProjects(ctx context.Context) ([]control.ProjectSummary, error) {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return nil, err
	}
	return r.api.ListProjects(ctx, control.CredentialRequest{AccessToken: access.AccessToken})
}
