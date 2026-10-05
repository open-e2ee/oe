package app

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/envfile"
	"github.com/open-e2ee/oe/internal/output"
	"github.com/open-e2ee/oe/internal/projectlock"
)

// link attaches the directory to a project that exists and writes the env
// files. It never creates a project and never changes the server. A new
// attachment writes the server's policy into the config. Without PROJECT,
// link rewrites the env files of the project in the config and does not
// touch the config.
func (r *runner) link(ctx context.Context, args []string) error {
	flags := newFlags("link")
	variable := flags.String("env-var", "", "the variable that holds the Relay connection URL")
	yes := flags.Bool("yes", false, "link to another project without a prompt")
	dryRun := flags.Bool("dry-run", false, "report the changes and write nothing")
	positional, err := parseMixedArguments(flags, "link", args)
	if err != nil {
		return err
	}
	switch {
	case len(positional) > 1:
		return usageError("link", "oe link takes at most one PROJECT")
	case r.environmentSelected:
		return usageError("link", "oe link writes the file of each environment and takes no --env")
	}

	path, err := config.Find(r.directory)
	found := err == nil
	var value config.Config
	if found {
		if path, value, err = r.loadConfig(); err != nil {
			return err
		}
	} else {
		path = filepath.Join(r.directory, config.Filename)
	}
	directory := filepath.Dir(path)
	connection, err := envfile.Detect(directory, *variable)
	if err != nil {
		if *variable != "" {
			return usageError("link", err.Error())
		}
		return err
	}
	slug := ""
	if len(positional) == 1 {
		slug = positional[0]
	}
	switch {
	case slug == "" && found:
		slug = value.Project
	case slug == "":
		if slug, err = r.pickProject(ctx); err != nil {
			return err
		}
	}
	project, err := r.readProject(ctx, slug)
	if err != nil {
		return err
	}

	attach := !found || slug != value.Project
	// A link that creates the config adds the CLI to the devDependencies of
	// the app, as oe new does, because the config imports its types.
	var manifest manifestChange
	if !found {
		if manifest, err = manifestWithCLI(directory); err != nil {
			return err
		}
	}
	var changes []config.Change
	if attach {
		if !found {
			// The pull adds the Production section when Production is active.
			value = config.New(slug)
			value.Environments.Production = nil
		}
		plan, err := planPull(value, project, []string{"sandbox", "production"})
		if err != nil {
			return err
		}
		changes = plan.changes
		if found {
			changes = append([]config.Change{{Path: []string{"project"}, Value: slug}}, changes...)
			// --yes cannot change a computed value, so it stops the link
			// before the consent.
			if err := config.CheckEdit(path, changes...); err != nil {
				return err
			}
		} else if value, err = config.Apply(value, changes...); err != nil {
			return err
		}
	}
	if found && attach && !*yes && !*dryRun {
		if r.mode != output.Text || !r.canPrompt() {
			retry := []string{"link", slug, "--yes"}
			if *variable != "" {
				retry = append(retry, "--env-var", *variable)
			}
			return &problem{
				code: "CONFIRMATION_REQUIRED", exit: exitUsage, next: commandLine(retry),
				message: fmt.Sprintf("%s links project %s; a link to %s rewrites the committed file, so it needs --yes", config.Filename, value.Project, slug),
				data:    map[string]any{"config": config.Filename, "project": value.Project, "requested": slug},
			}
		}
		approved, err := askConfirmation(r.in, r.errOut, fmt.Sprintf("%s links project %s. Link this directory to %s and rewrite the file?", config.Filename, value.Project, slug))
		if err != nil {
			return err
		}
		if !approved {
			return &problem{code: "LINK_CANCELLED", message: "link cancelled", exit: exitFailure}
		}
	}

	if !*dryRun {
		lock, err := projectlock.Acquire(ctx, directory)
		if err != nil {
			return err
		}
		defer lock.Release()
	}
	files := []map[string]any{}
	record := func(path, change string) {
		if change == "" {
			return
		}
		if relative, err := filepath.Rel(r.directory, path); err == nil {
			path = filepath.ToSlash(relative)
		}
		files = append(files, map[string]any{"path": path, "change": change})
	}
	if attach {
		change := "updated"
		if !found {
			change = "created"
		}
		manifestPath := filepath.Join(directory, "package.json")
		if !*dryRun {
			if manifest.edited != nil {
				if err := writePublicFile(manifestPath, manifest.edited); err != nil {
					return err
				}
			}
			if found {
				err = config.Edit(path, changes...)
			} else {
				err = config.Create(path, value)
			}
			if err != nil {
				return err
			}
		}
		record(path, change)
		if manifest.edited != nil {
			record(manifestPath, "updated")
		}
	}
	// The lock file and each env file that link writes stay out of version
	// control.
	ignored := []string{projectlock.Filename}
	var connected []string
	for _, environment := range []string{"sandbox", "production"} {
		relayURL := ""
		if selected := environmentOf(project, environment); selected != nil {
			relayURL = selected.RelayURL
		}
		filename := environmentFiles[environment]
		target := filepath.Join(directory, filename)
		if relayURL != "" {
			connected = append(connected, filename)
		} else if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			// An inactive environment gets no file. A file that is there loses
			// any connection, which can belong to another project.
			continue
		}
		change, err := fileChange(target, *dryRun, func(path string) error {
			return envfile.Write(path, connection.Variable, relayURL)
		})
		if err != nil {
			return err
		}
		record(target, change)
		ignored = append(ignored, filename)
	}
	ignoreFile := filepath.Join(directory, ".gitignore")
	change, err := fileChange(ignoreFile, *dryRun, func(path string) error {
		for _, filename := range ignored {
			if err := ensureIgnored(filepath.Dir(path), filename); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	record(ignoreFile, change)

	data := map[string]any{
		"product": value.Product, "project": slug, "environments": linkEnvironments(project),
		"files": files, "changed": !*dryRun && len(files) > 0,
	}
	install := ""
	if manifest.exists {
		install = installCommand(directory)
		data["install"] = install
	}
	if *dryRun {
		data["dryRun"] = true
		return r.out.Success("link", fmt.Sprintf("Dry run: oe link would change %d file(s) and wrote nothing.", len(files)), data)
	}
	message := "Nothing to change."
	if len(files) > 0 {
		message = "Linked " + slug + "."
		if len(connected) > 0 {
			message += fmt.Sprintf(" The app reads %s from %s.", connection.Variable, strings.Join(connected, " and "))
		}
		if install != "" {
			message += fmt.Sprintf(" Run %s to install %s.", install, cliPackage)
		}
	}
	message += r.agentSetupHint(directory)
	return r.out.SuccessNext("link", message, "oe doctor", data)
}

// linkEnvironments gives the state of each environment of project, and the
// gate that stops Production when it cannot activate. It leaves out each
// Relay connection URL.
func linkEnvironments(project control.Project) map[string]any {
	state := func(environment *control.ProjectEnvironment) string {
		switch {
		case environment == nil:
			return "inactive"
		case environment.RelayURL != "":
			return "active"
		}
		return cmp.Or(environment.State, "inactive")
	}
	var blockedBy any
	if project.Production != nil && project.Production.BlockedBy != "" {
		blockedBy = project.Production.BlockedBy
	}
	return map[string]any{
		"sandbox":    map[string]any{"state": state(project.Sandbox)},
		"production": map[string]any{"state": state(project.Production), "blockedBy": blockedBy},
	}
}

// fileChange runs write on path and reports the change: "created",
// "updated", or "" when the bytes are the same. For a dry run, write gets a
// copy of path in a temporary directory, so path does not change.
func fileChange(path string, dryRun bool, write func(path string) error) (string, error) {
	before, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	target := path
	if dryRun {
		scratch, err := os.MkdirTemp("", "oe-link-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(scratch)
		target = filepath.Join(scratch, filepath.Base(path))
		if existed {
			if err := os.WriteFile(target, before, 0o600); err != nil {
				return "", err
			}
		}
	}
	if err := write(target); err != nil {
		return "", err
	}
	after, err := os.ReadFile(target)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", nil
	case err != nil:
		return "", err
	case !existed:
		return "created", nil
	case !bytes.Equal(before, after):
		return "updated", nil
	}
	return "", nil
}

// pickProject asks a person to choose one of the projects that the account
// can read. Any other caller must name the project.
func (r *runner) pickProject(ctx context.Context) (string, error) {
	if r.mode != output.Text || !r.canPrompt() {
		return "", &problem{
			code: "PROJECT_REQUIRED", exit: exitUsage, next: "oe project list",
			message: fmt.Sprintf("%s was not found in %s or a parent directory; name the project to link", config.Filename, r.directory),
		}
	}
	projects, err := r.listProjects(ctx)
	if err != nil {
		return "", err
	}
	if len(projects) == 0 {
		return "", &problem{
			code: "PROJECT_REQUIRED", exit: exitUsage, next: "oe auth status",
			message: "this account can read no Relay project; check the organization of the session",
		}
	}
	for index, project := range projects {
		fmt.Fprintf(r.errOut, "  %d. %s (%s)\n", index+1, project.Slug, project.Name)
	}
	fmt.Fprintf(r.errOut, "Link which project? [1-%d] ", len(projects))
	answer, err := bufio.NewReader(r.in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	choice, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || choice < 1 || choice > len(projects) {
		return "", &problem{code: "LINK_CANCELLED", message: "link cancelled: no project was chosen", exit: exitFailure}
	}
	return projects[choice-1].Slug, nil
}

// projectList prints the projects that the account can read, with the state
// of each Production.
func (r *runner) projectList(ctx context.Context) error {
	projects, err := r.listProjects(ctx)
	if err != nil {
		return err
	}
	message := "This account can read no Relay project."
	if len(projects) > 0 {
		var text strings.Builder
		table := tabwriter.NewWriter(&text, 0, 0, 2, ' ', 0)
		for _, project := range projects {
			fmt.Fprintf(table, "%s\t%s\tProduction %s\n", project.Slug, project.Name, project.Production.State)
		}
		table.Flush()
		message = strings.TrimSuffix(text.String(), "\n")
	}
	return r.out.Success("project list", message, map[string]any{"projects": projects})
}

func (r *runner) listProjects(ctx context.Context) ([]control.ProjectSummary, error) {
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return nil, err
	}
	return r.api.ListProjects(ctx, control.CredentialRequest{AccessToken: access.AccessToken})
}

// parseMixedArguments parses the flags of command before and after its
// positional arguments, and returns the positional arguments in their order.
func parseMixedArguments(flags *flag.FlagSet, command string, args []string) ([]string, error) {
	var positional []string
	for {
		if err := parseArguments(flags, command, args); err != nil {
			return nil, err
		}
		if flags.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, flags.Arg(0))
		args = flags.Args()[1:]
	}
}
