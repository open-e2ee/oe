package app

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestCommandTreeContainsEveryPublishedPath(t *testing.T) {
	root := (&runner{}).commandTree()
	for _, spec := range commandSurface {
		if humanShort[spec.Name] == "" {
			t.Errorf("%q has no short human summary", spec.Name)
		}
		for _, usage := range spec.Usage {
			path := commandPath(usage)
			node, _, err := root.Find(strings.Fields(path))
			if err != nil || node == root || node.CommandPath() != "oe "+path {
				t.Errorf("%q resolves to %q, %v", path, node.CommandPath(), err)
			}
			if humanShort[path] == "" {
				t.Errorf("%q has no short human summary", path)
			}
		}
	}
	for _, flag := range globalFlagSurface {
		if humanGlobalFlag[flag.Name] == "" {
			t.Errorf("%q has no concise human description", flag.Name)
		}
	}
	for _, code := range exitCodeSurface {
		if humanExitCode[code.Code] == "" {
			t.Errorf("exit %d has no concise human meaning", code.Code)
		}
	}
	for _, variable := range variableSurface {
		if humanVariable[variable.Name] == "" {
			t.Errorf("%q has no concise human description", variable.Name)
		}
	}
}

func TestHumanHelpFitsTerminalAndPipeWidths(t *testing.T) {
	paths := [][]string{{}}
	for _, spec := range commandSurface {
		paths = append(paths, []string{"help", spec.Name})
		for _, usage := range spec.Usage {
			paths = append(paths, append(strings.Fields(commandPath(usage)), "--help"))
		}
	}
	for _, width := range []int{60, 80, 120} {
		for _, path := range paths {
			getenv := func(name string) string {
				if name == "COLUMNS" {
					return strconv.Itoa(width)
				}
				return ""
			}
			args := append([]string{"--agent", "no"}, path...)
			exit, stdout, stderr := run(t, Dependencies{Getenv: getenv}, args...)
			if exit != 0 || stderr != "" {
				t.Errorf("%q at %d columns: exit=%d stderr=%q", path, width, exit, stderr)
				continue
			}
			for _, line := range strings.Split(stdout, "\n") {
				if len(line) > width {
					t.Errorf("%q at %d columns: %d-column line %q", path, width, len(line), line)
				}
			}
			if strings.Contains(stdout, "\x1b[") {
				t.Errorf("%q has ANSI output", path)
			}
		}
	}
}

func TestRootAndLeafHumanHelp(t *testing.T) {
	exit, root, stderr := run(t, Dependencies{Getenv: func(string) string { return "" }}, "--agent", "no", "-h")
	if exit != 0 || stderr != "" {
		t.Fatalf("root help: exit=%d stderr=%q", exit, stderr)
	}
	if len(strings.Split(strings.TrimSpace(root), "\n")) > 60 {
		t.Fatalf("root help is too long: %d lines", len(strings.Split(strings.TrimSpace(root), "\n")))
	}
	for _, want := range []string{"Commands:", "Global flags", "Exit codes:", "Environment variables:", "OE_ACCESS_TOKEN", "OE_PROTECTION_BYPASS", "OE_ENV", "OE_OPERATION_ID", "oe help <command>"} {
		if !strings.Contains(root, want) {
			t.Errorf("root help omitted %q", want)
		}
	}
	exit, leaf, stderr := run(t, Dependencies{}, "--agent", "no", "project", "usage", "--help")
	if exit != 0 || stderr != "" || !strings.Contains(leaf, "Usage:\n  oe project usage") || !strings.Contains(leaf, "Flags:") {
		t.Fatalf("leaf help: exit=%d stdout=%q stderr=%q", exit, leaf, stderr)
	}
	exit, parent, _ := run(t, Dependencies{}, "--agent", "no", "project", "bogus", "--help")
	if exit != 0 || !strings.Contains(parent, "Usage:\n  oe project list") || strings.Contains(parent, "Usage:\n  oe project bogus") {
		t.Fatalf("unknown child did not fall back to parent help: exit=%d %q", exit, parent)
	}
	if !slices.Contains(strings.Fields(root), "help") {
		t.Fatal("root help does not list the help command")
	}
	exit, identity, _ := run(t, Dependencies{}, "--agent", "no", "identity", "check", "--help")
	if exit != 0 || !strings.Contains(identity, "--profile PATH") || !strings.Contains(identity, "member binding") {
		t.Fatalf("identity help lost its required flag or limit: exit=%d %q", exit, identity)
	}
}

func TestCommandPathDoesNotMoveWordsPastFlags(t *testing.T) {
	root := (&runner{}).commandTree()
	for _, test := range []struct {
		command   string
		args      []string
		path      string
		remaining []string
	}{
		{"auth", []string{"--timeout", "5s", "login"}, "oe auth", []string{"--timeout", "5s", "login"}},
		{"notifications", []string{"setup", "--profile", "visible-alert", "ios"}, "oe notifications setup", []string{"--profile", "visible-alert", "ios"}},
		{"project", []string{"--yes=true", "show"}, "oe project", []string{"--yes=true", "show"}},
		{"config", []string{"--dry-run", "push"}, "oe config", []string{"--dry-run", "push"}},
		{"project", []string{"usage", "--env", "production"}, "oe project usage", []string{"--env", "production"}},
	} {
		node, remaining := leadingCommand(root, test.command, test.args)
		if node == nil || node.CommandPath() != test.path || !slices.Equal(remaining, test.remaining) {
			t.Errorf("%q %q resolved to %v %q; want %s %q", test.command, test.args, node, remaining, test.path, test.remaining)
		}
	}
}

func TestHumanRootHelpKeepsGenericTemporaryFailureGuidance(t *testing.T) {
	exit, stdout, stderr := run(t, Dependencies{Getenv: func(string) string { return "" }}, "--agent", "no", "--help")
	if exit != 0 || stderr != "" {
		t.Fatal("human help failed", exit, stderr)
	}
	_, after, found := strings.Cut(stdout, "Exit codes:\n")
	if !found {
		t.Fatal("human help omitted the exit-code section")
	}
	after, _, found = strings.Cut(after, "\nEnvironment variables:")
	if !found || !strings.Contains(after, "6  Temporary failure; it is safe to retry next later.") {
		t.Fatal("nonidentity temporary failure lost its generic retry guidance", stdout)
	}
	if strings.Contains(after, "same retained identity operation") {
		t.Fatal("root help made nonidentity retries depend on an identity operation")
	}
}
