package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/config"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/skills"
)

// skillNames are the skills that oe agent setup installs.
var skillNames = []string{"open-e2ee-relay-config", "open-e2ee-relay-notifications", "open-e2ee-relay-production", "open-e2ee-relay-setup"}

// repositorySkill reads skills/<name>/SKILL.md from this repository on disk,
// so the test does not depend on the embed that it checks.
func repositorySkill(t *testing.T, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find the path of this test file")
	}
	return mustRead(t, filepath.Join(filepath.Dir(file), "..", "..", "skills", name, "SKILL.md"))
}

// home is a Getenv whose home directory is home on every platform.
func home(home string, values map[string]string) func(string) string {
	all := map[string]string{"HOME": home, "USERPROFILE": home}
	for name, value := range values {
		all[name] = value
	}
	return environment(all)
}

// skillResults returns data.skills of oe agent setup by name.
func skillResults(t *testing.T, result event) map[string]map[string]any {
	t.Helper()
	entries, ok := result.Data["skills"].([]any)
	if !ok {
		t.Fatalf("data.skills is not a list: %#v", result.Data)
	}
	results := map[string]map[string]any{}
	for _, entry := range entries {
		skill := entry.(map[string]any)
		results[skill["name"].(string)] = skill
	}
	return results
}

// requireInstalled fails unless root holds every skill with the repository
// bytes, and .claude/skills/<name> is the link or the copy that result says.
func requireInstalled(t *testing.T, root string, result event) {
	t.Helper()
	results := skillResults(t, result)
	for _, name := range skillNames {
		want := repositorySkill(t, name)
		if got := mustRead(t, filepath.Join(root, ".agents", "skills", name, "SKILL.md")); string(got) != string(want) {
			t.Errorf(".agents/skills/%s/SKILL.md differs from the repository file", name)
		}
		if got := mustRead(t, filepath.Join(root, ".claude", "skills", name, "SKILL.md")); string(got) != string(want) {
			t.Errorf(".claude/skills/%s/SKILL.md differs from the repository file", name)
		}
		info, err := os.Lstat(filepath.Join(root, ".claude", "skills", name))
		if err != nil {
			t.Fatal(err)
		}
		switch link := results[name]["link"]; {
		case link == skills.Symlink && info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(filepath.Join(root, ".claude", "skills", name))
			if err != nil || filepath.ToSlash(target) != "../../.agents/skills/"+name {
				t.Errorf(".claude/skills/%s links to %q, %v", name, target, err)
			}
		case link == skills.Copy && runtime.GOOS == "windows" && info.IsDir():
			// Windows refuses a symbolic link without the privilege.
		default:
			t.Errorf(".claude/skills/%s is %v, but oe agent setup reported link %v", name, info.Mode(), link)
		}
	}
}

func TestAgentSetupWritesFourSkills(t *testing.T) {
	root := initializedProject(t, "skill-chat")
	directory := filepath.Join(root, "web")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	user := t.TempDir()

	exit, stdout, stderr := run(t, Dependencies{WorkingDir: directory, Getenv: home(user, nil)}, "--json", "agent", "setup")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Command != "agent setup" || result.Data["changed"] != true {
		t.Fatalf("oe agent setup failed: exit=%d %s %s", exit, stdout, stderr)
	}
	if result.Data["scope"] != "project" || result.Data["directory"] != root {
		t.Fatalf("oe agent setup did not use the directory of the config: %s", stdout)
	}
	results := skillResults(t, result)
	if names := slices.Sorted(func(yield func(string) bool) {
		for name := range results {
			if !yield(name) {
				return
			}
		}
	}); !slices.Equal(names, skillNames) {
		t.Fatalf("oe agent setup reported skills %q, want %q", names, skillNames)
	}
	for _, name := range skillNames {
		if results[name]["change"] != skills.Created {
			t.Errorf("oe agent setup reported %s as %v, want created", name, results[name]["change"])
		}
	}
	requireInstalled(t, root, result)
	if _, err := os.Stat(filepath.Join(user, ".agents")); !os.IsNotExist(err) {
		t.Fatalf("the project scope wrote to the home directory: %v", err)
	}

	t.Run("user scope", func(t *testing.T) {
		project := t.TempDir()
		user := t.TempDir()
		exit, stdout, _ := run(t, Dependencies{WorkingDir: project, Getenv: home(user, nil)}, "--json", "agent", "setup", "--scope", "user")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || result.Data["scope"] != "user" || result.Data["directory"] != user {
			t.Fatalf("oe agent setup --scope user failed: exit=%d %s", exit, stdout)
		}
		requireInstalled(t, user, result)
		if entries, _ := os.ReadDir(project); len(entries) != 0 {
			t.Fatalf("the user scope wrote %d entries to the project", len(entries))
		}
	})

	t.Run("copy when a link fails", func(t *testing.T) {
		project := t.TempDir()
		refused := errors.New("A required privilege is not held by the client.")
		exit, stdout, _ := run(t, Dependencies{
			WorkingDir: project, Getenv: home(t.TempDir(), nil),
			Symlink: func(string, string) error { return refused },
		}, "--json", "agent", "setup")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || !strings.Contains(result.Message, "holds a copy of") {
			t.Fatalf("oe agent setup did not report the copy: exit=%d %s", exit, stdout)
		}
		for name, skill := range skillResults(t, result) {
			if skill["link"] != skills.Copy || skill["linkError"] != refused.Error() {
				t.Errorf("oe agent setup reported %s as %v", name, skill)
			}
			info, err := os.Lstat(filepath.Join(project, ".claude", "skills", name))
			if err != nil || !info.IsDir() {
				t.Errorf(".claude/skills/%s is not a directory: %v", name, err)
			}
			if got := mustRead(t, filepath.Join(project, ".claude", "skills", name, "SKILL.md")); string(got) != string(repositorySkill(t, name)) {
				t.Errorf("the copy of %s differs from the repository file", name)
			}
		}
	})

	t.Run("directory link", func(t *testing.T) {
		project := t.TempDir()
		if err := os.MkdirAll(filepath.Join(project, ".agents", "skills"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(project, ".claude"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", ".agents", "skills"), filepath.Join(project, ".claude", "skills")); err != nil {
			t.Skipf("this system cannot make a symbolic link: %v", err)
		}
		exit, stdout, _ := run(t, Dependencies{WorkingDir: project, Getenv: home(t.TempDir(), nil)}, "--json", "agent", "setup")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || strings.Contains(result.Message, "copy") {
			t.Fatalf("oe agent setup with a linked .claude/skills: exit=%d %s", exit, stdout)
		}
		for name, skill := range skillResults(t, result) {
			if skill["link"] != skills.Symlink || skill["change"] != skills.Created {
				t.Errorf("oe agent setup reported %s as %v", name, skill)
			}
		}
		if info, err := os.Lstat(filepath.Join(project, ".claude", "skills")); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("oe agent setup replaced the .claude/skills link: %v", err)
		}
	})

	t.Run("usage", func(t *testing.T) {
		for _, args := range [][]string{{"agent", "install"}, {"agent", "setup", "--scope", "team"}} {
			exit, stdout, _ := run(t, Dependencies{}, append([]string{"--json"}, args...)...)
			if failure := decodeEvent(t, []byte(stdout)); exit != exitUsage || failure.Code != "USAGE_ERROR" {
				t.Errorf("oe %s: exit=%d %s", strings.Join(args, " "), exit, stdout)
			}
		}
	})
}

func TestAgentSetupIsIdempotent(t *testing.T) {
	project := t.TempDir()
	dependencies := Dependencies{WorkingDir: project, Getenv: home(t.TempDir(), nil)}
	if exit, stdout, _ := run(t, dependencies, "--json", "agent", "setup"); exit != 0 {
		t.Fatalf("the first oe agent setup failed: %s", stdout)
	}
	second := decodeEvent(t, []byte(mustSetup(t, dependencies)))
	if second.Data["changed"] != false || !strings.Contains(second.Message, "are current") {
		t.Fatalf("a second oe agent setup changed the skills: %s", second.Message)
	}
	for name, skill := range skillResults(t, second) {
		if skill["change"] != skills.Current {
			t.Errorf("a second oe agent setup reported %s as %v", name, skill["change"])
		}
	}
	requireInstalled(t, project, second)

	edited := filepath.Join(project, ".agents", "skills", "open-e2ee-relay-config", "SKILL.md")
	if err := os.WriteFile(edited, []byte("an old skill\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repaired := decodeEvent(t, []byte(mustSetup(t, dependencies)))
	results := skillResults(t, repaired)
	if repaired.Data["changed"] != true || results["open-e2ee-relay-config"]["change"] != skills.Updated ||
		results["open-e2ee-relay-setup"]["change"] != skills.Current {
		t.Fatalf("oe agent setup did not update only the changed skill: %s", repaired.Message)
	}
	requireInstalled(t, project, repaired)
}

// mustSetup runs oe agent setup and returns stdout.
func mustSetup(t *testing.T, dependencies Dependencies) string {
	t.Helper()
	exit, stdout, stderr := run(t, dependencies, "--json", "agent", "setup")
	if exit != 0 {
		t.Fatalf("oe agent setup failed: exit=%d %s %s", exit, stdout, stderr)
	}
	return stdout
}

// skillStates returns data.skills of oe agent setup --check as name and
// state.
func skillStates(t *testing.T, result event) []string {
	t.Helper()
	var states []string
	for name, skill := range skillResults(t, result) {
		states = append(states, name+" "+skill["state"].(string))
	}
	slices.Sort(states)
	return states
}

func TestAgentSetupCheckWritesNothing(t *testing.T) {
	project := t.TempDir()
	dependencies := Dependencies{WorkingDir: project, Getenv: home(t.TempDir(), nil)}
	every := func(state string) []string {
		var states []string
		for _, name := range skillNames {
			states = append(states, name+" "+state)
		}
		return states
	}

	exit, stdout, _ := run(t, dependencies, "--json", "agent", "setup", "--check")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || failure.Code != "SKILLS_NOT_CURRENT" || failure.Next != "oe agent setup" {
		t.Fatalf("oe agent setup --check with no skills: exit=%d %s", exit, stdout)
	}
	if states := skillStates(t, failure); !slices.Equal(states, every(skills.Missing)) {
		t.Fatalf("oe agent setup --check reported %q", states)
	}
	if entries, _ := os.ReadDir(project); len(entries) != 0 {
		t.Fatalf("oe agent setup --check wrote %d entries", len(entries))
	}

	mustSetup(t, dependencies)
	exit, stdout, _ = run(t, dependencies, "--json", "agent", "setup", "--check")
	current := decodeEvent(t, []byte(stdout))
	if exit != 0 || current.Status != "ok" || !slices.Equal(skillStates(t, current), every(skills.Current)) {
		t.Fatalf("oe agent setup --check after setup: exit=%d %s", exit, stdout)
	}

	edited := filepath.Join(project, ".agents", "skills", "open-e2ee-relay-production", "SKILL.md")
	if err := os.WriteFile(edited, []byte("a local edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(project, ".claude", "skills", "open-e2ee-relay-setup")); err != nil {
		t.Fatal(err)
	}
	exit, stdout, _ = run(t, dependencies, "--json", "agent", "setup", "--check")
	stale := decodeEvent(t, []byte(stdout))
	want := []string{
		"open-e2ee-relay-config current", "open-e2ee-relay-notifications current",
		"open-e2ee-relay-production changed", "open-e2ee-relay-setup missing",
	}
	if exit != exitFailure || stale.Code != "SKILLS_NOT_CURRENT" || !slices.Equal(skillStates(t, stale), want) {
		t.Fatalf("oe agent setup --check after an edit: exit=%d %s", exit, stdout)
	}
	if got := string(mustRead(t, edited)); got != "a local edit\n" {
		t.Fatalf("oe agent setup --check rewrote an edited skill: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(project, ".claude", "skills", "open-e2ee-relay-setup")); !os.IsNotExist(err) {
		t.Fatalf("oe agent setup --check restored a link: %v", err)
	}

	exit, stdout, _ = run(t, Dependencies{WorkingDir: project, Getenv: home(t.TempDir(), nil)}, "--json", "agent", "setup", "--check", "--scope", "user")
	if user := decodeEvent(t, []byte(stdout)); exit != exitFailure || user.Next != "oe agent setup --scope user" {
		t.Fatalf("oe agent setup --check --scope user: exit=%d %s", exit, stdout)
	}
}

func TestNewAndLinkNameAgentSetupUnderAnAgent(t *testing.T) {
	const hint = "oe agent setup"
	newProject := func(t *testing.T, getenv func(string) string) event {
		t.Helper()
		server := startNewControl(t, created)
		store := credential.NewMemory()
		storeSession(t, store, sessionToken())
		exit, stdout, stderr := run(t, Dependencies{
			API: server.api, Store: store, WorkingDir: emptyDirectory(t, "agent-chat"), Getenv: getenv,
		}, "--json", "new")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || result.Next != "oe doctor --wait" {
			t.Fatalf("oe new failed: exit=%d %s %s", exit, stdout, stderr)
		}
		return result
	}
	link := func(t *testing.T, directory string, getenv func(string) string) event {
		t.Helper()
		api, _ := linkConsole(t, map[string]string{"chat-demo": fmt.Sprintf(linkedProject, "chat-demo")}, "[]")
		exit, stdout, stderr := run(t, Dependencies{API: api, Store: readSession(t), WorkingDir: directory, Getenv: getenv}, "--json", "link", "chat-demo")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || result.Next != "oe doctor" {
			t.Fatalf("oe link failed: exit=%d %s %s", exit, stdout, stderr)
		}
		return result
	}
	agent := func(user string) func(string) string {
		return home(user, map[string]string{"CLAUDECODE": "1"})
	}

	if result := newProject(t, agent(t.TempDir())); !strings.Contains(result.Message, hint) {
		t.Errorf("oe new under an agent with no skills did not name %s: %s", hint, result.Message)
	}
	if result := link(t, t.TempDir(), agent(t.TempDir())); !strings.Contains(result.Message, hint) {
		t.Errorf("oe link under an agent with no skills did not name %s: %s", hint, result.Message)
	}
	if result := newProject(t, home(t.TempDir(), nil)); strings.Contains(result.Message, hint) {
		t.Errorf("oe new without an agent named %s: %s", hint, result.Message)
	}

	user := t.TempDir()
	if _, err := skills.Install(user, os.Symlink); err != nil {
		t.Fatal(err)
	}
	if result := newProject(t, agent(user)); strings.Contains(result.Message, hint) {
		t.Errorf("oe new named %s with the user skills installed: %s", hint, result.Message)
	}
	project := t.TempDir()
	if _, err := skills.Install(project, os.Symlink); err != nil {
		t.Fatal(err)
	}
	if result := link(t, project, agent(t.TempDir())); strings.Contains(result.Message, hint) {
		t.Errorf("oe link named %s with the project skills installed: %s", hint, result.Message)
	}
}

// codeSpan is an inline code span. fence opens or closes a fenced block.
var (
	codeSpan    = regexp.MustCompile("`([^`]+)`")
	fence       = regexp.MustCompile("^\\s*```")
	proseOE     = regexp.MustCompile(`\boe ([a-z][a-z-]*)`)
	flagPattern = regexp.MustCompile(`(?:^|[\s\[|,])(--?[a-z][a-z-]*)`)
)

// retired are the names of commands and flags that oe does not have.
var retired = []string{
	"oe init", "oe sandbox", "oe plan", "oe deploy", "oe diff", "oe project select", "oe login", "create-oe", "--environment",
}

// commandsIn returns each oe command line in a skill: a code line or inline
// code span that starts with oe. prose is the text outside code.
func commandsIn(skill string) (commands []string, prose []string) {
	inFence := false
	for line := range strings.Lines(skill) {
		line = strings.TrimRight(line, "\r\n")
		if fence.MatchString(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "oe ") {
				commands = append(commands, trimmed)
			}
			continue
		}
		for _, match := range codeSpan.FindAllStringSubmatch(line, -1) {
			if strings.HasPrefix(match[1], "oe ") {
				commands = append(commands, match[1])
			}
		}
		prose = append(prose, codeSpan.ReplaceAllString(line, "CODE"))
	}
	return commands, prose
}

// matchUsage returns the usage line of command whose literal words are the
// longest prefix of command. A literal word is one before the first optional
// part, flag, or placeholder.
func matchUsage(command []string) (string, bool) {
	best, length := "", 0
	for _, spec := range commandSurface {
		for _, usage := range spec.Usage {
			var literal []string
			for _, word := range strings.Fields(usage) {
				if strings.ContainsAny(word, "[-|") || strings.ToLower(word) != word {
					break
				}
				literal = append(literal, word)
			}
			if len(literal) > length && len(literal) <= len(command) && slices.Equal(literal, command[:len(literal)]) {
				best, length = usage, len(literal)
			}
		}
	}
	return best, length > 0
}

func TestSkillsNameOnlyCommandsInHelp(t *testing.T) {
	var globals []string
	for _, flag := range globalFlagSurface {
		for _, match := range flagPattern.FindAllStringSubmatch(flag.Name, -1) {
			globals = append(globals, match[1])
		}
	}
	for _, name := range skills.Names() {
		skill := string(skills.Content(name))
		for _, word := range retired {
			if strings.Contains(skill, word) {
				t.Errorf("%s names %q, which oe does not have", name, word)
			}
		}
		commands, prose := commandsIn(skill)
		if len(commands) == 0 {
			t.Errorf("%s names no oe command", name)
		}
		for _, command := range commands {
			words := strings.Fields(command)
			usage, ok := matchUsage(words)
			if !ok {
				t.Errorf("%s names %q, but no usage line in oe help matches it", name, command)
				continue
			}
			var allowed []string
			for _, match := range flagPattern.FindAllStringSubmatch(usage, -1) {
				allowed = append(allowed, match[1])
			}
			for _, word := range words {
				flag, _, _ := strings.Cut(word, "=")
				if strings.HasPrefix(flag, "-") && !slices.Contains(allowed, flag) && !slices.Contains(globals, flag) {
					t.Errorf("%s names %q, but %q is not a flag of %q", name, command, flag, usage)
				}
			}
		}
		for _, line := range prose {
			for _, match := range proseOE.FindAllStringSubmatch(line, -1) {
				if _, ok := lookupCommand(match[1]); !ok {
					t.Errorf("%s names %q in prose, but oe help has no command %q", name, match[0], match[1])
				}
			}
		}
	}
	if !strings.Contains(string(skills.Content("open-e2ee-relay-config")), config.Filename) {
		t.Errorf("the config skill does not name %s", config.Filename)
	}
}
