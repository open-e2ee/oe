package skills

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

// Retirement is what Install did with the entries of one retired skill name.
// Name is the retired name, and Skill is the name that replaces it.
type Retirement struct {
	Name   string `json:"name"`
	Skill  string `json:"skill"`
	Change string `json:"change"`
}

// The changes that Install reports for a retired skill name.
const (
	// Removed is a retired entry that held an unchanged copy that oe wrote.
	Removed = "removed"
	// Kept is a retired entry that Install left in place, because a person
	// changed it or it holds more than the copy that oe wrote.
	Kept = "kept"
)

// retiredNames maps each skill to the name that oe 5 and earlier gave it.
// Until v7.0.0, Install removes an unchanged copy under the retired name, and
// Installed counts it.
var retiredNames = map[string]string{
	"open-e2ee-signal-relay-config":        "open-e2ee-relay-config",
	"open-e2ee-signal-relay-notifications": "open-e2ee-relay-notifications",
	"open-e2ee-signal-relay-production":    "open-e2ee-relay-production",
	"open-e2ee-signal-relay-setup":         "open-e2ee-relay-setup",
}

// writtenDigests holds the SHA-256 digest of each SKILL.md that a released oe
// wrote under a retired name: every version of skills/open-e2ee-relay-*/SKILL.md
// in the history of this repository.
var writtenDigests = map[string]bool{
	"0dcc6d3b0db6256faea581c1aeada91302fadd9a553d107d966fabcf107054b9": true,
	"ee453bd1237bb43c4088b87c1b1b99cec1fda52feaedc9283340928071338e93": true,
	"f6aac0bb14d71b53ef518db7394ba464fa3617397856d096fa924106ee6e2a42": true,
	"ff976ad91a4f44c5caf72a970a489574ede323a635b5304d94b5e0c81eaaa4f3": true,
	"7bfa2ea0ff637485a2bfd3b0a6772e5aa38b3f24cde25d1d4f91d1a35819dbeb": true,
	"afe1dd80daa1dcddcf63ac068cddb9abb966a7f926524831bc6597e4526a9aec": true,
	"c2a376d0d5d60a428cd3421ecdcec6f15d4fcaa330c8ed84010f516a12b36f6d": true,
	"95d0af2bb4f72689a32e4aaa63a570b196551a5d88d1080a6e02dc4f56ee5376": true,
	"a143c0909725c4d09e59b5bb4a9952fed9cd3cb17544e36cf72b8cc58da7e2fc": true,
	"e6981349f7dab1eb86527721393e5e86c83f297c2dc84ed4b6a2712839ea4f9a": true,
	"256de0f1a96a6bc2d1e1890a37121173f893c47e64e7886a8d728164978d6ab1": true,
	"51b03e83547ed6767bf4b263f0eac0f0f246b67e605b6affe4aa5aed0ace827f": true,
	"5f3dde8d58545b9cc3d351355f9c6f098aab792ae301e2f6848e01ebd589feed": true,
	"6c5f1865f576effaaee26faf464e327759026cd5be63060768ddb52a0374c60d": true,
	"7f25da605829b52efa180f215d1feae68a69974099820341e2bf30b980a0dba5": true,
	"8eafd87af556d4ee3a74a26ff0535487d1bdd24d7c046975a30b21051f8a4ddb": true,
	"c7e3f4d0ab46990312dd39475a14fedd0baec0c3c38e78192b3154069878fad3": true,
	"d59278fff963c0af409cfe730e2b0fdcd5c55dce29f68d4554c2e84d53400c38": true,
	"d628551498749a1a83560ba0bac8c508a58fb856b2db00ab8b4128f3fe5e4d65": true,
}

// removeRetired removes the entries of the retired name of the skill name
// under root when they hold only an unchanged copy that oe wrote, and returns
// what it did, or nil when root has no entry of the retired name.
func removeRetired(root, name string) (*Retirement, error) {
	retired := retiredNames[name]
	agents := filepath.Join(root, ".agents", "skills", retired)
	claude := filepath.Join(root, ".claude", "skills", retired)
	agentsState, err := writtenCopy(agents)
	if err != nil {
		return nil, err
	}
	claudeState, err := claudeEntry(claude, agents, agentsState)
	if err != nil {
		return nil, err
	}
	if agentsState == absent && claudeState == absent {
		return nil, nil
	}
	result := &Retirement{Name: retired, Skill: name, Change: Removed}
	if agentsState == changed || claudeState == changed {
		// A person changed one of the entries, so both stay: a link of
		// .claude/skills keeps showing the changed copy.
		result.Change = Kept
		return result, nil
	}
	if claudeState == written {
		if err := os.RemoveAll(claude); err != nil {
			return nil, err
		}
	}
	if agentsState == written {
		if err := os.RemoveAll(agents); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// The states of a retired entry.
const (
	absent = iota
	written
	changed
)

// writtenCopy reports whether directory is absent, holds only a SKILL.md that
// oe wrote, or holds something else.
func writtenCopy(directory string) (int, error) {
	info, err := os.Lstat(directory)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return absent, nil
	case err != nil:
		return 0, err
	case !info.IsDir():
		return changed, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	if len(entries) != 1 || entries[0].Name() != Filename || !entries[0].Type().IsRegular() {
		return changed, nil
	}
	contents, err := os.ReadFile(filepath.Join(directory, Filename))
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(contents)
	if !writtenDigests[hex.EncodeToString(digest[:])] {
		return changed, nil
	}
	return written, nil
}

// claudeEntry reports the state of the .claude/skills entry of a retired
// name. A link is written when it has the relative target that oe wrote and
// the copy that it shows is written or absent. A directory that is the agents
// directory, through a link of .claude/skills itself, is absent, so only the
// agents directory is removed.
func claudeEntry(entry, agents string, agentsState int) (int, error) {
	info, err := os.Lstat(entry)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return absent, nil
	case err != nil:
		return 0, err
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(entry)
		if err != nil {
			return 0, err
		}
		if filepath.Clean(target) != filepath.Join("..", "..", ".agents", "skills", filepath.Base(agents)) ||
			!slices.Contains([]int{absent, written}, agentsState) {
			return changed, nil
		}
		return written, nil
	case info.IsDir():
		if wanted, err := os.Stat(agents); err == nil && os.SameFile(info, wanted) {
			return absent, nil
		}
		return writtenCopy(entry)
	}
	return changed, nil
}
