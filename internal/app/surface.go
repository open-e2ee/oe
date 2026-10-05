package app

import (
	"fmt"
	"slices"
	"strings"

	"github.com/open-e2ee/oe/internal/output"
)

// commandSpec is one entry of the public command surface. Help text, the JSON
// help document, and usage errors all read this table, so they cannot drift.
type commandSpec struct {
	Name    string   `json:"name"`
	Summary string   `json:"summary"`
	Usage   []string `json:"usage"`
}

type globalFlagSpec struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

type exitCodeSpec struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

type variableSpec struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
}

const (
	exitFailure        = 1
	exitUsage          = 2
	exitAuthentication = 4
	exitPersonAction   = 5
	exitTemporary      = 6
)

var commandSurface = []commandSpec{
	{"new", "Create a project and its Sandbox environment, then write open-e2ee.config.ts, the Relay connection in .env.local, and the @open-e2ee/oe devDependency.", []string{
		"oe new [signal-relay] [--project SLUG] [--name NAME] [--env-var NAME] [--dry-run]",
	}},
	{"auth", "Log in with a browser and store the session in the OS keychain, then accept the OpenE2EE terms for the organization. In an app directory with no config, a person at a terminal then creates a project, links one, or skips. Show or remove the session.", []string{
		"oe auth login [--accept-terms] [--timeout DURATION]",
		"oe auth status",
		"oe auth logout",
	}},
	{"doctor", "Check the config, session, project, and Relay connection of the selected environment. With --wait, then wait for the first acknowledged Sandbox message.", []string{
		"oe doctor [--env sandbox|production] [--wait] [--timeout DURATION]",
	}},
	{"link", "Link this directory to a Relay project that exists and write the Relay connection of each active environment to its env file. With no config, write open-e2ee.config.ts from the server policy. Without PROJECT, rewrite only the env files.", []string{
		"oe link [PROJECT] [--env-var NAME] [--yes] [--dry-run]",
	}},
	{"project", "List the Relay projects, read one, or print a Relay connection URL.", []string{
		"oe project list",
		"oe project show [PROJECT] [--env sandbox|production]",
		"oe project connection [PROJECT] [--env sandbox|production]",
	}},
	{"config", "Keep open-e2ee.config.ts and the console in step. push applies the environment sections: Sandbox, then Production when the file has its section. pull writes the Relay policy of each active environment into the file with the fewest changes. A Production change or a replaced value needs --yes or a person's answer. --dry-run changes nothing.", []string{
		"oe config push [--env sandbox|production] [--yes] [--dry-run]",
		"oe config pull [--env sandbox|production] [--yes] [--dry-run]",
	}},
	{"notifications", "Stage and verify best-effort iOS notification profiles.", []string{
		"oe notifications status [--env sandbox|production]",
		"oe notifications setup ios [--profile background-only|visible-alert] [--env sandbox|production]",
		"oe notifications add-nse [--env sandbox|production]",
		"oe notifications verify ios [--app-bundle PATH] [--env sandbox|production]",
		"oe notifications apple-filtering-request",
	}},
	{"agent", "Install the OpenE2EE skills for coding agents: write .agents/skills/<name> and link .claude/skills/<name> to it, or write a copy when a link fails. The project scope uses the directory of open-e2ee.config.ts, else the working directory, and --scope user uses the home directory. --check reports each skill as current, missing, or changed, and writes nothing.", []string{
		"oe agent setup [--scope project|user] [--check]",
	}},
	{"version", "Print the CLI version.", []string{
		"oe version",
	}},
	{"help", "Show all commands, or the usage of one command.", []string{
		"oe help [COMMAND]",
	}},
}

var globalFlagSurface = []globalFlagSpec{
	{"--json", "Write one JSON document to stdout for the result, for success and for failure. oe auth login writes one pending event before it, while a person approves the device."},
	{"--json-stream", "Write newline-delimited JSON progress events, then one final event, to stdout."},
	{"--agent yes|no|auto", "Say whether a coding agent runs oe. The default, auto, reads the environment variables that coding agents set. Under an agent, the default output is JSON, and oe never prompts and never opens a browser. --agent no restores text output."},
	{"--env sandbox|production", "Select the environment. -e is the short form. Without it, doctor, project, and notifications read OE_ENV, then use sandbox. config pull reads each active environment, and config push applies each section of the config; --env narrows either to one."},
	{"--control-url URL", "Use another control API. It must use HTTPS except on loopback."},
	{"-h, --help", "Show help."},
}

var exitCodeSurface = []exitCodeSpec{
	{0, "The command succeeded."},
	{exitFailure, "The command failed. The error and its code tell why."},
	{exitUsage, "The command line is invalid or a required input is missing."},
	{exitAuthentication, "Authentication is required. Run next, which is oe auth login. ACCESS_TOKEN_INVALID has no next: set OE_ACCESS_TOKEN to a new token, or unset it and run oe auth login."},
	{exitPersonAction, "A person must act before the command can continue. The error tells what to do. When action.url is present, it is the page that the person opens."},
	{exitTemporary, "The failure is temporary. It is safe to run the same command again later. next is that command."},
}

var variableSurface = []variableSpec{
	{"OE_ACCESS_TOKEN", "A scoped CI credential. It takes precedence over the stored session, and oe auth login never replaces it. The CLI keeps it in memory and never stores it."},
	{"OE_ACCESS_TOKEN_SCOPES", "The scopes of OE_ACCESS_TOKEN, separated by commas or spaces."},
	{"OE_ENV", "The environment of doctor, project, and notifications when --env is not given: sandbox or production. new and config ignore it."},
	{"OE_OPERATION_ID", "The idempotency key for each remote mutation of one run. Set it only to retry one mutation."},
}

// commandPath gives the words of usage that name the command: the words
// after oe and before the first argument or flag, such as "project show" or
// "notifications setup ios".
func commandPath(usage string) string {
	var words []string
	for _, word := range strings.Fields(strings.TrimPrefix(usage, "oe ")) {
		if strings.HasPrefix(word, "[") || strings.HasPrefix(word, "-") || strings.ToLower(word) != word {
			break
		}
		words = append(words, word)
	}
	return strings.Join(words, " ")
}

// envelopeCommand is the command that the output of a run names: the longest
// command path of the surface that the command and its arguments start with,
// else the command. Every success of a command names the same path.
func envelopeCommand(command string, args []string) string {
	words := append([]string{command}, args...)
	result, length := command, 1
	for _, spec := range commandSurface {
		for _, usage := range spec.Usage {
			path := strings.Fields(commandPath(usage))
			if len(path) > length && len(path) <= len(words) && slices.Equal(path, words[:len(path)]) {
				result, length = strings.Join(path, " "), len(path)
			}
		}
	}
	return result
}

func lookupCommand(name string) (commandSpec, bool) {
	for _, spec := range commandSurface {
		if spec.Name == name {
			return spec, true
		}
	}
	return commandSpec{}, false
}

func (r *runner) help() error {
	var text strings.Builder
	text.WriteString("oe manages OpenE2EE Signal Protocol Relay projects from a repository.\n\n")
	text.WriteString("Usage: oe <command> [arguments] [global flags]\n\nCommands:\n")
	for _, spec := range commandSurface {
		fmt.Fprintf(&text, "  %-14s %s\n", spec.Name, spec.Summary)
	}
	text.WriteString("\nGlobal flags (before or after the command):\n")
	for _, flag := range globalFlagSurface {
		fmt.Fprintf(&text, "  %s\n      %s\n", flag.Name, flag.Summary)
	}
	text.WriteString("\nExit codes:\n")
	for _, exit := range exitCodeSurface {
		fmt.Fprintf(&text, "  %d  %s\n", exit.Code, exit.Meaning)
	}
	text.WriteString("\nEnvironment variables:\n")
	for _, variable := range variableSurface {
		fmt.Fprintf(&text, "  %s\n      %s\n", variable.Name, variable.Summary)
	}
	text.WriteString("\nRun oe help <command> for one command. Run oe help --json for this surface as JSON.")
	message := text.String()
	if r.out.Mode() != output.Text {
		message = "The data field describes every command. Run oe help <command> for one command."
	}
	return r.out.Success("help", message, map[string]any{
		"commands":             commandSurface,
		"globalFlags":          globalFlagSurface,
		"exitCodes":            exitCodeSurface,
		"environmentVariables": variableSurface,
	})
}

func (r *runner) commandHelp(name string) error {
	spec, ok := lookupCommand(name)
	if !ok {
		return unknownCommand(name)
	}
	message := spec.Summary
	if r.out.Mode() == output.Text {
		message += "\n\nUsage:\n  " + strings.Join(spec.Usage, "\n  ")
	}
	return r.out.Success(spec.Name, message, map[string]any{
		"name": spec.Name, "summary": spec.Summary, "usage": spec.Usage,
	})
}
