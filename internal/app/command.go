package app

import (
	"context"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// humanShort is separate from commandSurface because the latter is the stable
// JSON help contract. These labels appear only in the text command list.
var humanShort = map[string]string{
	"new":                                   "Create a Relay project and local config.",
	"auth":                                  "Manage the CLI session.",
	"auth login":                            "Log in to an organization.",
	"auth status":                           "Show the current session.",
	"auth logout":                           "Remove the stored session.",
	"org":                                   "Show or switch organizations.",
	"org show":                              "Show the current organization.",
	"org list":                              "List your organizations.",
	"org switch":                            "Switch the stored session to an organization.",
	"doctor":                                "Check local setup and the Relay connection.",
	"identity":                              "Check a public draft identity profile.",
	"identity check":                        "Check a public draft identity profile.",
	"link":                                  "Link this directory to a Relay project.",
	"project":                               "Show projects, usage, and connections.",
	"project list":                          "List projects in the current organization.",
	"project show":                          "Show a Relay project.",
	"project usage":                         "Show a Relay project's usage.",
	"project connection":                    "Print a Relay connection URL.",
	"config":                                "Sync local config with the console.",
	"config push":                           "Apply local Relay policy to the console.",
	"config pull":                           "Write console Relay policy to local config.",
	"notifications":                         "Manage iOS notification profiles.",
	"notifications status":                  "Show notification profiles.",
	"notifications setup":                   "Stage an iOS notification profile.",
	"notifications setup ios":               "Stage an iOS notification profile.",
	"notifications add-nse":                 "Add the notification service extension.",
	"notifications verify":                  "Verify an iOS notification profile.",
	"notifications verify ios":              "Verify an iOS notification profile.",
	"notifications apple-filtering-request": "Show the Apple filtering request.",
	"agent":                                 "Install or check coding-agent skills.",
	"agent setup":                           "Install or check coding-agent skills.",
	"version":                               "Print the CLI version.",
	"help":                                  "Show command help.",
}

var humanGlobalFlag = map[string]string{
	"--json":                   "Write one JSON result to stdout, including failures. Login can first emit a pending event.",
	"--json-stream":            "Write progress events and one final event as newline-delimited JSON.",
	"--agent yes|no|auto":      "Select agent mode. Auto detects agents. Agent mode uses JSON and never prompts or opens a browser.",
	"--env sandbox|production": "Select an environment; -e is the short form. Doctor, identity, project, and notifications use OE_ENV then Sandbox by default. Config commands use each active environment.",
	"--control-url URL":        "Use another control API. HTTPS is required except on loopback.",
	"-h, --help":               "Show help.",
	"--version":                "Print the CLI version.",
}

var humanExitCode = map[int]string{
	0: "Success.",
	1: "Failure; the error code gives the reason.",
	2: "Invalid command line or missing input.",
	4: "Authentication is required. Run next. For ACCESS_TOKEN_INVALID, set a new token or unset it and log in.",
	5: "A person must act. When action.url is present, open that page.",
	6: "Temporary failure; it is safe to retry next later.",
}

var humanVariable = map[string]string{
	"OE_ACCESS_TOKEN":        "Scoped CI credential. Overrides the stored session; never stored by oe.",
	"OE_ACCESS_TOKEN_SCOPES": "Token scopes, separated by commas or spaces.",
	"OE_PROTECTION_BYPASS":   "Control URL bypass secret. Overrides the stored bypass; never appears in output.",
	"OE_ENV":                 "Default environment for doctor, identity, project, and notifications. New and config ignore it.",
	"OE_OPERATION_ID":        "Idempotency key for one remote mutation. Set it only to retry that mutation.",
}

// commandTree supplies one canonical command hierarchy. Local handlers retain
// Go flag parsing because the CLI's positional and error contracts depend on
// those parsers. Cobra selects the path and supplies human help metadata.
func (r *runner) commandTree() *cobra.Command {
	root := &cobra.Command{
		Use: "oe", Short: "Manage OpenE2EE Signal Protocol Relay projects.",
		SilenceErrors: true, SilenceUsage: true, DisableSuggestions: true,
		DisableFlagParsing: true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetIn(r.in)
	root.SetOut(r.plainOut)
	root.SetErr(r.errOut)
	// These names are handled before Execute, but they belong in the tree so
	// contextual help resolves them like the other public commands.
	commands := map[string]*cobra.Command{"": root}
	for _, spec := range commandSurface {
		path := spec.Name
		node := &cobra.Command{
			Use: spec.Name, Short: humanShort[path], Long: spec.Summary,
			DisableFlagParsing: true, DisableFlagsInUseLine: true,
		}
		if spec.Name != "help" && spec.Name != "version" {
			top := spec.Name
			node.RunE = func(cmd *cobra.Command, args []string) error {
				return r.runCanonical(cmd.Context(), top, args)
			}
		} else {
			node.RunE = func(*cobra.Command, []string) error { return nil }
		}
		root.AddCommand(node)
		commands[path] = node
		for _, usage := range spec.Usage {
			words := strings.Fields(commandPath(usage))
			if len(words) == 1 {
				node.Use = strings.TrimPrefix(usage, "oe ")
				continue
			}
			for depth := 2; depth <= len(words); depth++ {
				childPath := strings.Join(words[:depth], " ")
				child, exists := commands[childPath]
				if !exists {
					prefix := slices.Clone(words[1:depth])
					child = &cobra.Command{
						Use: words[depth-1], Short: humanShort[childPath],
						DisableFlagParsing: true, DisableFlagsInUseLine: true,
					}
					child.RunE = func(cmd *cobra.Command, args []string) error {
						return r.runCanonical(cmd.Context(), words[0], append(slices.Clone(prefix), args...))
					}
					commands[strings.Join(words[:depth-1], " ")].AddCommand(child)
					commands[childPath] = child
				}
				if depth == len(words) {
					child.Use = strings.TrimPrefix(usage, "oe "+strings.Join(words[:depth-1], " ")+" ")
				}
			}
		}
	}
	return root
}

func (r *runner) executeCommandTree(ctx context.Context, command string, args []string) error {
	root := r.commandTree()
	node, remaining := leadingCommand(root, command, args)
	if node == nil || node.RunE == nil {
		return unknownCommand(command)
	}
	node.SetContext(ctx)
	return node.RunE(node, remaining)
}

// leadingCommand follows only command words at the start of args. Cobra's
// Find may move a child name past an earlier flag. Doing that here could turn
// an invalid command into an action before its existing local parser runs.
func leadingCommand(root *cobra.Command, command string, args []string) (*cobra.Command, []string) {
	node := namedChild(root, command)
	if node == nil {
		return nil, args
	}
	for i, word := range args {
		if strings.HasPrefix(word, "-") {
			return node, args[i:]
		}
		child := namedChild(node, word)
		if child == nil {
			return node, args[i:]
		}
		node = child
	}
	return node, nil
}

func namedChild(parent *cobra.Command, name string) *cobra.Command {
	for _, child := range parent.Commands() {
		if child.Name() == name {
			return child
		}
	}
	return nil
}

func (r *runner) humanTopicHelp(topic string) error {
	switch topic {
	case "app", "apps", "projects":
		topic = "project"
	case "orgs", "organizations":
		topic = "org"
	}
	if _, ok := lookupCommand(topic); !ok {
		return unknownCommand(topic)
	}
	return r.humanCommandHelp(topic, nil)
}

func (r *runner) humanCommandHelp(command string, args []string) error {
	if _, ok := lookupCommand(command); !ok {
		return unknownCommand(command)
	}
	root := r.commandTree()
	node, _ := leadingCommand(root, command, args)
	if node == nil {
		return unknownCommand(command)
	}
	return r.out.Success(command, r.renderCommandHelp(node), nil)
}

func (r *runner) humanRootHelp() string {
	width := r.helpWidth()
	var b strings.Builder
	writeWrapped(&b, "", "oe manages OpenE2EE Signal Protocol Relay projects from a repository.", width)
	b.WriteString("\nUsage: oe <command> [arguments] [global flags]\n\nCommands:\n")
	for _, spec := range commandSurface {
		writeEntry(&b, "  "+spec.Name, humanShort[spec.Name], width, 17)
	}
	b.WriteString("\nGlobal flags (before or after the command):\n")
	for _, flag := range globalFlagSurface {
		writeEntry(&b, "  "+flag.Name, humanGlobalFlag[flag.Name], width, 29)
	}
	b.WriteString("\nExit codes:\n")
	for _, code := range exitCodeSurface {
		writeWrapped(&b, fmt.Sprintf("  %d  ", code.Code), humanExitCode[code.Code], width)
	}
	b.WriteString("\nEnvironment variables:\n")
	for _, variable := range variableSurface {
		writeEntry(&b, "  "+variable.Name, humanVariable[variable.Name], width, 29)
	}
	b.WriteString("\n")
	writeWrapped(&b, "", "Run oe help <command> for one command. Run oe help --json for this surface as JSON.", width)
	return strings.TrimSuffix(b.String(), "\n")
}

var bracketGroupPattern = regexp.MustCompile(`\[[^\]]+\]`)

func (r *runner) renderCommandHelp(node *cobra.Command) string {
	width := r.helpWidth()
	path := strings.TrimPrefix(node.CommandPath(), "oe ")
	top := strings.Fields(path)[0]
	spec, _ := lookupCommand(top)
	var b strings.Builder
	if path == top {
		writeWrapped(&b, "", spec.Summary, width)
	} else {
		writeWrapped(&b, "", node.Short, width)
		b.WriteString("\n")
		writeWrapped(&b, "", spec.Summary, width)
	}
	b.WriteString("\nUsage:\n")
	var usages []string
	for _, usage := range spec.Usage {
		if commandPath(usage) == path || (path == top && strings.HasPrefix(commandPath(usage), top+" ")) || strings.HasPrefix(commandPath(usage), path+" ") {
			usages = append(usages, usage)
		}
	}
	for _, usage := range usages {
		writeWrapped(&b, "  ", usage, width)
	}
	if len(node.Commands()) > 0 {
		b.WriteString("\nCommands:\n")
		for _, child := range node.Commands() {
			writeEntry(&b, "  "+child.Name(), child.Short, width, 18)
		}
	}
	flags := usageFlags(usages)
	if len(flags) > 0 {
		b.WriteString("\nFlags:\n")
		for _, flag := range flags {
			writeWrapped(&b, "  ", flag, width)
		}
	}
	var aliases []string
	if path == top {
		aliases = commandAliases(spec)
	} else {
		aliases = aliasesByCommand[path]
	}
	if len(aliases) > 0 {
		b.WriteString("\nAliases:\n")
		for _, alias := range aliases {
			writeWrapped(&b, "  ", alias, width)
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func usageFlags(usages []string) []string {
	seen := make(map[string]bool)
	for _, usage := range usages {
		words := strings.Fields(usage)
		for i := 0; i < len(words); i++ {
			flag := strings.Trim(words[i], "[]")
			if !strings.HasPrefix(flag, "--") {
				continue
			}
			if i+1 < len(words) {
				value := strings.Trim(words[i+1], "[]")
				if !strings.HasPrefix(value, "-") && (strings.ToUpper(value) == value || strings.Contains(value, "|")) {
					flag += " " + value
					i++
				}
			}
			seen[flag] = true
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

func (r *runner) helpWidth() int {
	if file, ok := r.plainOut.(interface{ Fd() uintptr }); ok {
		if width, _, err := term.GetSize(int(file.Fd())); err == nil && width > 0 {
			return width
		}
	}
	if width, err := strconv.Atoi(r.getenv("COLUMNS")); err == nil && width > 0 {
		return width
	}
	return 80
}

func writeEntry(out io.Writer, name, detail string, width, column int) {
	if len(name)+1 >= column {
		fmt.Fprintln(out, name)
		writeWrapped(out, strings.Repeat(" ", column), detail, width)
		return
	}
	writeWrapped(out, name+strings.Repeat(" ", column-len(name)), detail, width)
}

func writeWrapped(out io.Writer, prefix, value string, width int) {
	// Keep bracketed usage operands and this public identity term together.
	// Restore ordinary spaces before writing so copied help remains plain text.
	value = strings.ReplaceAll(value, "member binding", "member\x01binding")
	value = bracketGroupPattern.ReplaceAllStringFunc(value, func(group string) string {
		return strings.ReplaceAll(group, " ", "\x01")
	})
	indent := strings.Repeat(" ", len(prefix))
	line := prefix
	for _, word := range strings.Fields(value) {
		if len(line) > len(prefix) && len(line)+1+len(word) > width {
			fmt.Fprintln(out, strings.ReplaceAll(line, "\x01", " "))
			line = indent + word
			continue
		}
		if len(line) > len(prefix) {
			line += " "
		}
		line += word
	}
	fmt.Fprintln(out, strings.ReplaceAll(line, "\x01", " "))
}
