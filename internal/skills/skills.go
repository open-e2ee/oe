// Package skills installs the agent skills that the binary embeds. A skill
// lives at .agents/skills/<name>/SKILL.md under a root, and
// .claude/skills/<name> links to it, so each coding agent finds the same
// file.
package skills

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"

	source "github.com/open-e2ee/oe/skills"
)

// Filename is the file of each skill.
const Filename = "SKILL.md"

// The states that Check reports.
const (
	Current = "current"
	Missing = "missing"
	Changed = "changed"
)

// The changes that Install reports. An unchanged skill is Current.
const (
	Created = "created"
	Updated = "updated"
)

// The kinds of .claude/skills entry that Install reports.
const (
	Symlink = "symlink"
	Copy    = "copy"
)

// Names lists the embedded skills in sorted order.
func Names() []string {
	entries, err := fs.ReadDir(source.Files, ".")
	if err != nil {
		panic(err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

// Content returns the embedded SKILL.md of name.
func Content(name string) []byte {
	contents, err := fs.ReadFile(source.Files, path.Join(name, Filename))
	if err != nil {
		panic(err)
	}
	return contents
}

// Status is the state of one skill under a root.
type Status struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// Result is what Install did for one skill. LinkError is the reason of a
// copy.
type Result struct {
	Name      string `json:"name"`
	Change    string `json:"change"`
	Link      string `json:"link"`
	LinkError string `json:"linkError,omitempty"`
}

// Check reports each skill under root as current, missing, or changed. A
// skill is current only when both of its files hold the embedded bytes. Check
// writes nothing.
func Check(root string) ([]Status, error) {
	var statuses []Status
	for _, name := range Names() {
		state := Current
		for _, file := range []string{agentsFile(root, name), claudeFile(root, name)} {
			contents, err := os.ReadFile(file)
			switch {
			case errors.Is(err, os.ErrNotExist):
				state = Missing
			case err != nil:
				return nil, err
			case state == Current && !bytes.Equal(contents, Content(name)):
				state = Changed
			}
		}
		statuses = append(statuses, Status{name, state})
	}
	return statuses, nil
}

// Installed reports whether root holds a file of any skill, under its name or
// its retired name.
func Installed(root string) bool {
	for _, name := range Names() {
		retired := retiredNames[name]
		for _, file := range []string{agentsFile(root, name), claudeFile(root, name), agentsFile(root, retired), claudeFile(root, retired)} {
			if _, err := os.Stat(file); err == nil {
				return true
			}
		}
	}
	return false
}

// Install writes each skill to .agents/skills/<name> under root, and makes
// .claude/skills/<name> a link to it with link. When link fails, for example
// on Windows without the symlink privilege, Install writes a copy and reports
// it. A .claude/skills entry that is a copy stays a copy. A second Install
// changes nothing.
//
// Install then removes the entries of each retired skill name that hold only
// an unchanged copy that oe wrote, and returns a Retirement for each retired
// name that it finds.
func Install(root string, link func(oldname, newname string) error) ([]Result, []Retirement, error) {
	var results []Result
	for _, name := range Names() {
		change, err := writeSkill(agentsFile(root, name), Content(name))
		if err != nil {
			return nil, nil, err
		}
		result := Result{Name: name, Change: change, Link: Symlink}
		linkChange, err := installLink(root, name, link, &result)
		if err != nil {
			return nil, nil, err
		}
		if result.Change == Current && linkChange != Current {
			result.Change = Updated
		}
		results = append(results, result)
	}
	var retirements []Retirement
	for _, name := range Names() {
		retirement, err := removeRetired(root, name)
		if err != nil {
			return nil, nil, err
		}
		if retirement != nil {
			retirements = append(retirements, *retirement)
		}
	}
	return results, retirements, nil
}

// installLink makes .claude/skills/<name> under root show the skill in
// .agents/skills, and returns the change.
func installLink(root, name string, link func(oldname, newname string) error, result *Result) (string, error) {
	target := filepath.Join(root, ".agents", "skills", name)
	entry := filepath.Join(root, ".claude", "skills", name)
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		return "", err
	}
	change := Created
	info, err := os.Lstat(entry)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return "", err
	case info.Mode()&os.ModeSymlink != 0:
		if resolved, err := os.Stat(entry); err == nil {
			if wanted, err := os.Stat(target); err == nil && os.SameFile(resolved, wanted) {
				return Current, nil
			}
		}
		// The link points elsewhere, so it is replaced.
		if err := os.Remove(entry); err != nil {
			return "", err
		}
		change = Updated
	case info.IsDir():
		// When .claude/skills itself links to .agents/skills, the entry is
		// the skill directory.
		if wanted, err := os.Stat(target); err == nil && os.SameFile(info, wanted) {
			return Current, nil
		}
		result.Link = Copy
		return writeSkill(claudeFile(root, name), Content(name))
	default:
		return "", fmt.Errorf("%s is not a directory or a link; remove it, then run oe agent setup again", entry)
	}
	// A relative target keeps the link valid when the root moves or another
	// person checks out the repository.
	if err := link(filepath.Join("..", "..", ".agents", "skills", name), entry); err != nil {
		result.Link, result.LinkError = Copy, err.Error()
		if _, err := writeSkill(claudeFile(root, name), Content(name)); err != nil {
			return "", err
		}
	}
	return change, nil
}

// writeSkill writes contents to file when its bytes differ, and returns the
// change.
func writeSkill(file string, contents []byte) (string, error) {
	before, err := os.ReadFile(file)
	existed := err == nil
	switch {
	case existed && bytes.Equal(before, contents):
		return Current, nil
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(file, contents, 0o644); err != nil {
		return "", err
	}
	if !existed {
		return Created, nil
	}
	return Updated, nil
}

func agentsFile(root, name string) string {
	return filepath.Join(root, ".agents", "skills", name, Filename)
}

func claudeFile(root, name string) string {
	return filepath.Join(root, ".claude", "skills", name, Filename)
}
