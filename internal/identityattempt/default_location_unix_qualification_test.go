//go:build identity_default_qualification && (darwin || linux)

package identityattempt

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func defaultQualificationPlatform(t *testing.T, location Location) map[string]any {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || uid != os.Geteuid() || gid != os.Getegid() {
		t.Fatal("an actual ordinary Unix identity is required")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal("native Unix groups unavailable")
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		t.Fatal("the inherited login HOME is unavailable")
	}
	selected, err := os.UserConfigDir()
	if err != nil || selected != location.anchor {
		t.Fatal("production default selection differs from the actual Unix environment")
	}
	path := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(location.anchor, path), string(filepath.Separator))
	if location.anchor == path {
		parts = nil
	}
	paths := []string{path}
	for _, part := range parts {
		if !validLeaf(part) {
			t.Fatal("actual Unix default path contains an invalid component")
		}
		path = filepath.Join(path, part)
		paths = append(paths, path)
	}
	var ancestors []map[string]any
	for index, path := range paths {
		var info unix.Stat_t
		err := unix.Lstat(path, &info)
		if err == unix.ENOENT && index == len(paths)-1 {
			ancestors = append(ancestors, map[string]any{"path": path, "absentFinalAnchor": true})
			break
		}
		if err != nil || uint32(info.Mode)&unix.S_IFMT != unix.S_IFDIR {
			t.Fatal("actual Unix default ancestor prerequisite failed")
		}
		ancestors = append(ancestors, map[string]any{"path": path, "uid": info.Uid, "gid": info.Gid,
			"mode": uint32(info.Mode), "device": uint64(info.Dev), "object": uint64(info.Ino)})
	}
	return map[string]any{"identity": strconv.Itoa(uid), "uid": uid, "effectiveUID": os.Geteuid(), "gid": gid,
		"effectiveGID": os.Getegid(), "groups": groups, "home": home, "xdgConfigHome": os.Getenv("XDG_CONFIG_HOME"),
		"defaultAnchor": location.anchor, "ancestors": ancestors, "os": runtime.GOOS, "architecture": runtime.GOARCH}
}

func defaultQualificationEvidenceStamp(t *testing.T, file *os.File) fileStamp {
	t.Helper()
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil || uint32(info.Mode)&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 || info.Uid != uint32(os.Geteuid()) || info.Size < 0 || info.Size > 2097152 {
		t.Fatal("ordinary handoff native file identity unavailable")
	}
	return fileStamp{uint64(info.Dev), uint64(info.Ino), info.Size}
}
