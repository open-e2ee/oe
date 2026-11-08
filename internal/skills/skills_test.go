package skills

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	source "github.com/open-e2ee/oe/skills"
)

// repositorySkills is the skills directory of this repository on disk.
func repositorySkills(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find the path of this test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "skills")
}

func TestEmbeddedSkillsMatchTheRepositoryFiles(t *testing.T) {
	want := []string{"open-e2ee-signal-relay-config", "open-e2ee-signal-relay-notifications", "open-e2ee-signal-relay-production", "open-e2ee-signal-relay-setup"}
	if names := Names(); !slices.Equal(names, want) {
		t.Fatalf("embedded skills are %q, want %q", names, want)
	}

	root := repositorySkills(t)
	var onDisk []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) == ".go" {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		onDisk = append(onDisk, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var embedded []string
	if err := fs.WalkDir(source.Files, ".", func(path string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			embedded = append(embedded, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(onDisk, embedded) {
		t.Fatalf("skills on disk are %q, but the binary embeds %q", onDisk, embedded)
	}

	for _, name := range want {
		disk, err := os.ReadFile(filepath.Join(root, name, Filename))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(Content(name), disk) {
			t.Errorf("the embedded %s/%s differs from the repository file", name, Filename)
		}
		// A Windows checkout can end each line with CRLF, so compare lines.
		lines := strings.Split(string(disk), "\n")
		for i := range lines {
			lines[i] = strings.TrimSuffix(lines[i], "\r")
		}
		if len(lines) < 4 || lines[0] != "---" || lines[1] != "name: "+name ||
			!strings.HasPrefix(lines[2], "description: ") || lines[3] != "---" {
			t.Errorf("%s/%s does not start with the name and description frontmatter", name, Filename)
		}
	}
}
