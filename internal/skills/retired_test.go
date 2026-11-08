package skills

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// writtenV5 is the open-e2ee-relay-config/SKILL.md that oe v5.0.0 wrote.
func writtenV5(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "open-e2ee-relay-config-v5.0.0.md"))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

// installV5 writes the retired config skill under root as oe v5.0.0 did: a
// copy in .agents/skills and a relative link in .claude/skills.
func installV5(t *testing.T, root string) (agents, claude string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs developer mode on Windows")
	}
	agents = filepath.Join(root, ".agents", "skills", "open-e2ee-relay-config")
	claude = filepath.Join(root, ".claude", "skills", "open-e2ee-relay-config")
	writeFile(t, filepath.Join(agents, Filename), writtenV5(t))
	if err := os.MkdirAll(filepath.Dir(claude), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", ".agents", "skills", "open-e2ee-relay-config"), claude); err != nil {
		t.Fatal(err)
	}
	return agents, claude
}

func writeFile(t *testing.T, file string, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func requireAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still there: %v", path, err)
		}
	}
}

func requirePresent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s is gone: %v", path, err)
		}
	}
}

func install(t *testing.T, root string) []Retirement {
	t.Helper()
	_, retirements, err := Install(root, os.Symlink)
	if err != nil {
		t.Fatal(err)
	}
	return retirements
}

func TestInstallRemovesAnUnchangedRetiredCopy(t *testing.T) {
	root := t.TempDir()
	agents, claude := installV5(t, root)
	retirements := install(t, root)
	want := []Retirement{{Name: "open-e2ee-relay-config", Skill: "open-e2ee-signal-relay-config", Change: Removed}}
	if !slices.Equal(retirements, want) {
		t.Fatalf("Install reported %#v, want %#v", retirements, want)
	}
	requireAbsent(t, agents, claude)
	requirePresent(t, filepath.Join(root, ".agents", "skills", "open-e2ee-signal-relay-config", Filename),
		filepath.Join(root, ".claude", "skills", "open-e2ee-signal-relay-config", Filename))
	if again := install(t, root); len(again) != 0 {
		t.Fatalf("a second Install reported %#v", again)
	}
}

func TestInstallKeepsAChangedRetiredCopy(t *testing.T) {
	for name, change := range map[string]func(t *testing.T, agents, claude string){
		"edited file": func(t *testing.T, agents, _ string) {
			writeFile(t, filepath.Join(agents, Filename), append(writtenV5(t), "\nA local rule.\n"...))
		},
		"extra file": func(t *testing.T, agents, _ string) {
			writeFile(t, filepath.Join(agents, "notes.md"), []byte("local notes\n"))
		},
		"link elsewhere": func(t *testing.T, _, claude string) {
			if err := os.Remove(claude); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join("..", "..", "elsewhere"), claude); err != nil {
				t.Fatal(err)
			}
		},
		"edited claude copy": func(t *testing.T, _, claude string) {
			if err := os.Remove(claude); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(claude, Filename), []byte("a person wrote this\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			agents, claude := installV5(t, root)
			change(t, agents, claude)
			retirements := install(t, root)
			if len(retirements) != 1 || retirements[0].Change != Kept {
				t.Fatalf("Install reported %#v, want the config skill kept", retirements)
			}
			requirePresent(t, agents, claude)
		})
	}
}

func TestInstallRemovesAnUnchangedRetiredClaudeCopy(t *testing.T) {
	root := t.TempDir()
	agents, claude := installV5(t, root)
	if err := os.Remove(claude); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(claude, Filename), writtenV5(t))
	if retirements := install(t, root); len(retirements) != 1 || retirements[0].Change != Removed {
		t.Fatalf("Install reported %#v", retirements)
	}
	requireAbsent(t, agents, claude)
}

func TestInstallRemovesARetiredCopyThroughALinkedClaudeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a symbolic link needs developer mode on Windows")
	}
	root := t.TempDir()
	agents := filepath.Join(root, ".agents", "skills", "open-e2ee-relay-config")
	writeFile(t, filepath.Join(agents, Filename), writtenV5(t))
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", ".agents", "skills"), filepath.Join(root, ".claude", "skills")); err != nil {
		t.Fatal(err)
	}
	if retirements := install(t, root); len(retirements) != 1 || retirements[0].Change != Removed {
		t.Fatalf("Install reported %#v", retirements)
	}
	requireAbsent(t, agents)
	requirePresent(t, filepath.Join(root, ".claude", "skills", "open-e2ee-signal-relay-config", Filename))
}

func TestInstallRemovesADanglingRetiredLink(t *testing.T) {
	root := t.TempDir()
	agents, claude := installV5(t, root)
	if err := os.RemoveAll(agents); err != nil {
		t.Fatal(err)
	}
	if retirements := install(t, root); len(retirements) != 1 || retirements[0].Change != Removed {
		t.Fatalf("Install reported %#v", retirements)
	}
	requireAbsent(t, claude)
}

func TestInstalledCountsARetiredName(t *testing.T) {
	root := t.TempDir()
	if Installed(root) {
		t.Fatal("an empty root has skills")
	}
	writeFile(t, filepath.Join(root, ".agents", "skills", "open-e2ee-relay-config", Filename), writtenV5(t))
	if !Installed(root) {
		t.Fatal("Installed did not count the retired name")
	}
}

func TestEverySkillHasARetiredName(t *testing.T) {
	for _, name := range Names() {
		if retiredNames[name] == "" {
			t.Errorf("%s has no retired name", name)
		}
	}
	if len(retiredNames) != len(Names()) {
		t.Fatalf("retiredNames has %d entries for %d skills", len(retiredNames), len(Names()))
	}
}
