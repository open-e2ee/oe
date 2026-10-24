package identityattempt

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func storeACLBuffer(entries []aclEntry, count uint32) []byte {
	data := make([]byte, 12+44+24*len(entries))
	binary.LittleEndian.PutUint32(data[:4], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[4:8], 8)
	binary.LittleEndian.PutUint32(data[8:12], uint32(len(data)-12))
	binary.LittleEndian.PutUint32(data[12:16], aclSecurityMagic)
	binary.LittleEndian.PutUint32(data[48:52], count)
	for index, entry := range entries {
		offset := 56 + 24*index
		copy(data[offset:offset+16], entry.principal[:])
		binary.LittleEndian.PutUint32(data[offset+16:offset+20], entry.flags)
		binary.LittleEndian.PutUint32(data[offset+20:offset+24], entry.rights)
	}
	return data
}

func TestStoreDarwinACLSeventeenParserVectors(t *testing.T) {
	owner := [16]byte{1}
	grant := aclEntry{owner, 1, 1}
	maximum := make([]aclEntry, 128)
	for index := range maximum {
		maximum[index] = grant
	}
	absent := make([]byte, 12)
	binary.LittleEndian.PutUint32(absent[:4], 12)
	positive := map[string][]byte{
		"owner grant":     storeACLBuffer([]aclEntry{grant}, 1),
		"maximum entries": storeACLBuffer(maximum, 128),
		"empty ACL":       storeACLBuffer(nil, 0),
		"no ACL marker":   storeACLBuffer(nil, ^uint32(0)),
		"absent security": absent,
		"deny":            storeACLBuffer([]aclEntry{{owner, 2, 1}}, 1),
		"zero rights":     storeACLBuffer([]aclEntry{{owner, 1, 0}}, 1),
		"inherited grant": storeACLBuffer([]aclEntry{{owner, 1 | 0x10, 1}}, 1),
	}
	for _, name := range []string{"owner grant", "maximum entries", "empty ACL", "no ACL marker", "absent security", "deny", "zero rights", "inherited grant"} {
		t.Run(name, func(t *testing.T) {
			entries, err := parseACLResponse(positive[name])
			if err != nil || checkACLGrants(entries, true, [][16]byte{owner}) != nil {
				t.Fatal("complete supported ACL layout refused")
			}
		})
	}
	negative := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short header", func(data []byte) []byte { return data[:11] }},
		{"truncated entry", func(data []byte) []byte { return data[:len(data)-1] }},
		{"negative offset", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[4:8], ^uint32(0)); return data }},
		{"header overlap", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[4:8], 4); return data }},
		{"oversized payload", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[8:12], ^uint32(0)); return data }},
		{"wrong magic", func(data []byte) []byte { data[12] ^= 1; return data }},
		{"extra entries", func(data []byte) []byte { return storeACLBuffer([]aclEntry{grant, grant}, 1) }},
		{"wrong entry count", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[48:52], 129); return data }},
		{"unsupported entry", func(data []byte) []byte { binary.LittleEndian.PutUint32(data[72:76], 3); return data }},
	}
	for _, vector := range negative {
		t.Run(vector.name, func(t *testing.T) {
			if _, err := parseACLResponse(vector.change(storeACLBuffer([]aclEntry{grant}, 1))); !errors.Is(err, ErrUnsafe) {
				t.Fatal("unsupported or incomplete native ACL layout admitted")
			}
		})
	}
}

func storeDarwinACLCommand(t *testing.T, anchor, path string, arguments ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	argv := append(append([]string{}, arguments...), path)
	command := exec.CommandContext(ctx, "/bin/chmod", argv...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	command.WaitDelay = time.Second
	capture := &storeActorCapture{limit: 65536}
	command.Stdout, command.Stderr = capture, capture
	group, setupErr := newStoreActorGroup(command)
	if setupErr != nil {
		t.Fatal("native ACL fixture process group failed")
	}
	command.Cancel = group.Terminate
	err := command.Start()
	if err == nil {
		if attachErr := group.Attach(command.Process); attachErr != nil {
			killErr := group.Terminate()
			waitErr := command.Wait()
			closeErr := group.Close()
			t.Fatal("native ACL process attachment failed; checked cleanup:", attachErr, killErr, waitErr, closeErr)
		}
		err = command.Wait()
	}
	groupErr := group.Close()
	output := capture.Bytes()
	// This owned log contains only synthetic fixture arguments and native setup output.
	exit := -1
	if command.ProcessState != nil {
		exit = command.ProcessState.ExitCode()
	}
	log := []byte(fmt.Sprintf("argv=%q\nexit=%d\n", append([]string{"/bin/chmod"}, argv...), exit))
	log = append(log, output...)
	logFile, createErr := os.CreateTemp(anchor, "acl-fixture-*.log")
	if createErr != nil {
		t.Fatal("native ACL fixture log failed")
	}
	_, writeErr := logFile.Write(log)
	closeErr := logFile.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("native ACL fixture log write/close failed")
	}
	if capture.truncated {
		t.Fatal("native ACL fixture output exceeded64KiB")
	}
	if err != nil || groupErr != nil {
		t.Fatal("native ACL fixture prerequisite or zero-process cleanup failed")
	}
}

func TestStoreDarwinNativeACLAncestorSevenVectors(t *testing.T) {
	current, err := user.Current()
	if err != nil || current.Username == "" || strings.ContainsAny(current.Username, ":,\n\r") {
		t.Fatal("native current-user ACL fixture prerequisite unavailable")
	}
	for _, vector := range []struct {
		name, entry string
		safe        bool
	}{
		{"everyone read/readattr/readextattr/readsecurity/search accepted", "everyone allow read,list,search,readattr,readextattr,readsecurity", true},
		{"everyone deny delete accepted", "everyone deny delete", true},
		{"current-owner add-file/add-directory/delete-child accepted", "user:" + current.Username + " allow add_file,add_subdirectory,delete_child", true},
		{"everyone add-file refused", "everyone allow add_file", false},
		{"everyone delete-child refused", "everyone allow delete_child", false},
		{"everyone write-security refused", "everyone allow writesecurity", false},
		{"everyone inheritance-only mutation grant refused", "everyone allow add_file,only_inherit,file_inherit,directory_inherit", false},
	} {
		t.Run(vector.name, func(t *testing.T) {
			location := storeFixtureLocation(t)
			path := filepath.Join(location.anchor, "acl-ancestor")
			if os.Mkdir(path, 0o700) != nil {
				t.Fatal("native ACL ancestor fixture failed")
			}
			storeDarwinACLCommand(t, location.anchor, path, "+a", vector.entry)
			file, err := os.Open(path)
			if err != nil {
				t.Fatal("native ACL fixture open failed")
			}
			check := inspectDarwinACL(file, false)
			closed := file.Close()
			if closed != nil {
				t.Fatal("native ACL fixture close failed")
			}
			if vector.safe && check != nil || !vector.safe && !errors.Is(check, ErrUnsafe) {
				t.Fatal("native ancestor ACL policy differed", check)
			}
			storeDarwinACLCommand(t, location.anchor, path, "-N")
		})
	}
}

func TestStoreDarwinNativeOwnedReceiverVectors(t *testing.T) {
	current, err := user.Current()
	if err != nil || current.Username == "" || strings.ContainsAny(current.Username, ":,\n\r") {
		t.Fatal("native current-user fixture prerequisite unavailable")
	}
	for _, vector := range []struct {
		name, entry string
		safe        bool
	}{
		{"no ACL", "", true},
		{"owner-only grant", "user:" + current.Username + " allow read,write", true},
		{"inherited owner-only grant", "user:" + current.Username + " allow read,write,inherited", true},
		{"other-principal read grant", "everyone allow read", false},
		{"other-principal mutation grant", "everyone allow write", false},
	} {
		t.Run(vector.name, func(t *testing.T) {
			location := storeFixtureLocation(t)
			path := filepath.Join(location.anchor, "acl-owned-record")
			if os.WriteFile(path, []byte("owned"), 0o600) != nil {
				t.Fatal("native ACL owned fixture failed")
			}
			if vector.entry != "" {
				storeDarwinACLCommand(t, location.anchor, path, "+a", vector.entry)
			}
			before, err := os.Stat(path)
			if err != nil || before.Mode().Perm() != 0o600 {
				t.Fatal("ACL fixture changed required mode bits")
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal("native ACL owned fixture open failed")
			}
			check := inspectDarwinACL(file, true)
			if file.Close() != nil {
				t.Fatal("native ACL owned fixture close failed")
			}
			if vector.safe && check != nil || !vector.safe && !errors.Is(check, ErrUnsafe) {
				t.Fatal("actual owned ACL receiver differed", check)
			}
			after, err := os.Stat(path)
			if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
				t.Fatal("ACL receiver repaired or replaced object")
			}
			if vector.entry != "" {
				storeDarwinACLCommand(t, location.anchor, path, "-N")
			}
		})
	}
	// The sixth native owned-receiver vector is the real pinned-parent rename case
	// in TestStoreUnixPinnedParentNeverBecomesMissingLeaf on Darwin.
}

func TestStoreDarwinControlledUnavailableReceiverAndUUID(t *testing.T) {
	location := storeFixtureLocation(t)
	file, err := os.Open(location.anchor)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if file.Close() != nil {
			t.Error("controlled receiver fixture close failed")
		}
	}()
	original := loadACL
	loadACL = func() (aclLibrary, error) { return aclLibrary{}, ErrUnsafe }
	requireStoreError(t, inspectDarwinACL(file, true), ErrUnsafe)
	loadACL = original
	defer func() { loadACL = original }()
	for _, result := range []int32{-1, 0} {
		api := aclLibrary{uuid: func(uint32, unsafe.Pointer) int32 { return result }}
		_, err := aclUUID(api, uint32(os.Geteuid()))
		requireStoreError(t, err, ErrUnsafe)
	}
	// These are controlled unavailable/zero-UUID branches, not native symbol failures.
}

func TestStoreDarwinUnknownMetadataFlagsRefuse(t *testing.T) {
	entry := aclEntry{principal: [16]byte{1}, flags: 1, rights: 1}
	for _, vector := range []struct {
		offset int
		value  uint32
	}{{52, 1}, {52, 1 << 18}, {72, 1<<9 | 1}} {
		data := storeACLBuffer([]aclEntry{entry}, 1)
		binary.LittleEndian.PutUint32(data[vector.offset:vector.offset+4], vector.value)
		if _, err := parseACLResponse(data); !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsupported ACL metadata semantics admitted")
		}
	}
}
