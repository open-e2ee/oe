package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/open-e2ee/oe/internal/skills"
)

// agent runs oe agent setup. The project scope writes the skills in the
// directory of the config, or in the working directory when there is no
// config. The user scope writes them in the home directory.
func (r *runner) agent(args []string) error {
	if len(args) == 0 || args[0] != "setup" {
		return usageError("agent", "usage: oe agent setup [--scope project|user] [--check]")
	}
	flags := newFlags("agent setup")
	scope := flags.String("scope", "project", "project or user")
	check := flags.Bool("check", false, "report the state of each skill and write nothing")
	if err := parseFlags(flags, "agent", args[1:]); err != nil {
		return err
	}
	var root string
	switch *scope {
	case "project":
		root = filepath.Dir(mustConfigPath(r.directory))
	case "user":
		home, err := r.homeDirectory()
		if err != nil {
			return err
		}
		root = home
	default:
		return usageError("agent", "--scope must be project or user")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	if *check {
		return r.agentCheck(root, *scope)
	}
	results, retirements, err := skills.Install(root, r.symlink)
	if err != nil {
		return err
	}
	changed := false
	var copies []string
	for _, result := range results {
		changed = changed || result.Change != skills.Current
		if result.Link == skills.Copy {
			copies = append(copies, result.Name)
		}
	}
	message := fmt.Sprintf("The %d OpenE2EE skills in %s are current.", len(results), root)
	if changed {
		message = fmt.Sprintf("Wrote the %d OpenE2EE skills to %s and linked .claude/skills to them.", len(results), filepath.Join(root, ".agents", "skills"))
	}
	if len(copies) > 0 {
		message += fmt.Sprintf(" .claude/skills holds a copy of %s, not a symbolic link. Run oe agent setup again after you update oe.", strings.Join(copies, ", "))
	}
	var removed, kept []string
	for _, retirement := range retirements {
		if retirement.Change == skills.Removed {
			changed = true
			removed = append(removed, retirement.Name)
		} else {
			kept = append(kept, fmt.Sprintf("%s (replaced by %s)", retirement.Name, retirement.Skill))
		}
	}
	if len(removed) > 0 {
		message += fmt.Sprintf(" Removed the old copies of %s.", strings.Join(removed, ", "))
	}
	if len(kept) > 0 {
		message += fmt.Sprintf(" Kept %s, because the files changed after oe wrote them. Delete each old skill after you move your changes.", strings.Join(kept, ", "))
	}
	data := map[string]any{"scope": *scope, "directory": root, "skills": results, "changed": changed}
	if len(retirements) > 0 {
		data["retired"] = retirements
	}
	return r.out.Success("agent setup", message, data)
}

// agentCheck reports each skill under root and writes nothing. A skill that
// is not current fails the check, so a script can run oe agent setup after it.
func (r *runner) agentCheck(root, scope string) error {
	statuses, err := skills.Check(root)
	if err != nil {
		return err
	}
	var stale []string
	for _, status := range statuses {
		if status.State != skills.Current {
			stale = append(stale, fmt.Sprintf("%s (%s)", status.Name, status.State))
		}
	}
	data := map[string]any{"scope": scope, "directory": root, "skills": statuses}
	if len(stale) == 0 {
		return r.out.Success("agent setup", fmt.Sprintf("The %d OpenE2EE skills in %s are current.", len(statuses), root), data)
	}
	next := "oe agent setup"
	if scope == "user" {
		next += " --scope user"
	}
	return &problem{
		code: "SKILLS_NOT_CURRENT", exit: exitFailure, next: next, data: data,
		message: fmt.Sprintf("%d of the %d OpenE2EE skills in %s are not current: %s", len(stale), len(statuses), root, strings.Join(stale, ", ")),
	}
}

// homeDirectory gives the home directory from the environment, as
// os.UserHomeDir reads it.
func (r *runner) homeDirectory() (string, error) {
	variable := "HOME"
	if runtime.GOOS == "windows" {
		variable = "USERPROFILE"
	}
	if home := r.getenv(variable); home != "" {
		return home, nil
	}
	return "", errors.New("the home directory is not known: " + variable + " is not set")
}

// agentSetupHint gives the sentence that names oe agent setup to an agent
// when neither project nor the home directory holds a skill. project is the
// directory of the config.
func (r *runner) agentSetupHint(project string) string {
	if !r.underAgent || skills.Installed(project) {
		return ""
	}
	if home, err := r.homeDirectory(); err == nil && skills.Installed(home) {
		return ""
	}
	return " Run oe agent setup to install the OpenE2EE skills for coding agents."
}
