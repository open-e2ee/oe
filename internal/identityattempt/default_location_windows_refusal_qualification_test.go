//go:build windows && identity_default_qualification

package identityattempt

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() { defaultProbeRefusalObserver = observeWindowsDefaultRefusal }

type refusalIdentity struct {
	Kind       uint32 `json:"kind"`
	Volume     uint32 `json:"volume"`
	Object     uint64 `json:"object"`
	Attributes uint32 `json:"attributes"`
	Links      uint32 `json:"links"`
	Size       uint64 `json:"size"`
}

type refusalSnapshot struct {
	identity   refusalIdentity
	descriptor []byte
}

type refusalHeld struct {
	handle     windows.Handle
	file       *os.File
	index      int
	before     *refusalSnapshot
	comparison string
	attempted  bool
	closed     bool
}

type refusalFailure struct {
	Stage     string `json:"stage"`
	Code      string `json:"code"`
	Component int    `json:"component"`
}

type refusalCollector struct {
	started        time.Time
	budget         refusalBudget
	held           [32]refusalHeld
	opened         int
	buffer         [8192]uint64
	security       *windows.LazyProc
	first          refusalFailure
	original       refusalNativeError
	stopOptional   bool
	incomplete     bool
	outputFailed   bool
	logicalOverrun bool
	panicType      string
	writtenBytes   int
	writtenRecords int
	wrapped        int
	rosterCount    int
	visited        int
}

func (c *refusalCollector) note(stage, code string, index int) {
	if c.first.Code == "" {
		c.first = refusalFailure{stage, code, index}
	}
}

func (c *refusalCollector) check() error {
	if time.Since(c.started) >= 5*time.Second {
		c.logicalOverrun = true
	}
	if c.stopOptional || c.logicalOverrun {
		c.stopOptional, c.incomplete = true, true
		c.note("budget", "BOUND_REACHED", -1)
		return errRefusalBound
	}
	return nil
}

func (c *refusalCollector) emit(stage string, index int, phase string, detail any, err error, terminal bool) (complete bool) {
	defer func() {
		if value := recover(); value != nil {
			c.outputFailed = true
			c.recordPanic(value)
			complete = false
		}
	}()
	if c.outputFailed {
		return false
	}
	frame, encodeErr := c.budget.frame(map[string]any{
		"stage": stage, "component": index, "phase": phase,
		"detail": detail, "error": refusalErrorRecord(err),
		"errorScope": "new-observation-call", "dCredit": false,
	}, terminal)
	if encodeErr != nil {
		c.stopOptional, c.incomplete = true, true
		c.note("output", "BOUND_REACHED", index)
		return false
	}
	count, writeErr := os.Stdout.Write(frame)
	c.writtenBytes += count
	if writeErr != nil || count != len(frame) {
		c.outputFailed, c.stopOptional, c.incomplete = true, true, true
		c.note("output", "WRITE_INCOMPLETE", index)
		return false
	}
	c.writtenRecords++
	return true
}

func observeWindowsDefaultRefusal(location Location, nonce string, original error) {
	c := &refusalCollector{started: time.Now(), original: refusalErrorRecord(original)}
	defer c.finish()
	if !errors.Is(original, ErrUnsafe) {
		c.note("context", "INVALID_ORIGINAL_ERROR", -1)
		c.incomplete = true
		return
	}
	c.walk(location, nonce)
}

func (c *refusalCollector) walk(location Location, nonce string) {
	if location.validate() != nil ||
		len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" ||
		(runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		c.note("context", "INVALID_CONTEXT", -1)
		c.incomplete = true
		return
	}
	if refusalPathBound(location.anchor) != nil {
		c.note("path", "BOUND_REACHED", -1)
		c.incomplete = true
		return
	}
	volume := filepath.VolumeName(location.anchor)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(location.anchor, `\\`) {
		c.note("path", "INVALID_DRIVE_PATH", -1)
		c.incomplete = true
		return
	}
	root := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(location.anchor, root), string(filepath.Separator))
	if location.anchor == root {
		parts = nil
	}
	if len(parts)+1+len(location.managed) > 32 {
		c.note("path", "BOUND_REACHED", -1)
		c.incomplete = true
		return
	}
	paths := []string{root}
	for _, part := range append(parts, location.managed[:]...) {
		if c.check() != nil {
			return
		}
		if !validLeaf(part) {
			c.note("path", "INVALID_LEAF", len(paths))
			c.incomplete = true
			return
		}
		path := filepath.Join(paths[len(paths)-1], part)
		if refusalPathBound(path) != nil {
			c.note("path", "BOUND_REACHED", len(paths))
			c.incomplete = true
			return
		}
		paths = append(paths, path)
	}
	c.rosterCount = len(paths)
	if !c.emit("context", -1, "", map[string]any{
		"nonce": nonce, "pid": os.Getpid(), "architecture": runtime.GOARCH,
		"anchor": location.anchor, "managedNames": location.managed,
		"originalOpenError": c.original, "nativeErrorsAreNotOriginalOpenErrors": true,
		"components": len(paths), "desiredAccess": uint32(0x80020000), "shareMode": 3,
		"disposition": 3, "flags": uint32(0x02200000), "inheritanceSource": "nil-security-attributes",
	}, nil, false) {
		return
	}
	if c.check() != nil {
		return
	}
	principals, err := currentWindowsPrincipals()
	expired := c.check() != nil
	if !c.emit("principal-cache", -1, "", map[string]bool{"compoundOperationNoPerInternalDeadline": true}, err, false) {
		return
	}
	if expired {
		return
	}
	if err != nil {
		c.note("principal-cache", "GUARD_REFUSED", -1)
		return
	}
	if c.check() != nil {
		return
	}
	userSID := principals.user.String()
	expired = c.check() != nil
	if !c.emit("principal-sid", -1, "", map[string]string{"user": userSID}, nil, false) {
		return
	}
	if expired {
		return
	}
	if userSID == "" {
		c.note("principal-sid", "METADATA_FAILED", -1)
		c.incomplete = true
		return
	}
	wide, err := windows.UTF16PtrFromString(root)
	if err != nil {
		c.note("path", "UTF16_FAILED", -1)
		c.incomplete = true
		return
	}
	if c.check() != nil {
		return
	}
	drive := windows.GetDriveType(wide)
	expired = c.check() != nil
	if !c.emit("drive-type", 0, "", drive, nil, false) {
		return
	}
	if expired {
		return
	}
	if drive == windows.DRIVE_UNKNOWN || drive == windows.DRIVE_NO_ROOT_DIR || drive == windows.DRIVE_REMOTE {
		c.note("drive-type", "UNSUPPORTED_DRIVE", 0)
		return
	}
	c.security = windows.NewLazySystemDLL("advapi32.dll").NewProc("GetKernelObjectSecurity")
	if c.check() != nil {
		return
	}
	err = c.security.Find()
	expired = c.check() != nil
	if !c.emit("GetKernelObjectSecurity-resolve", -1, "", nil, err, false) {
		return
	}
	if expired {
		return
	}
	if err != nil {
		c.note("descriptor", "PROCEDURE_UNAVAILABLE", -1)
		c.incomplete = true
		return
	}
	managedStart := 1 + len(parts)
	for index, path := range paths {
		if c.check() != nil {
			return
		}
		if index >= managedStart {
			if !c.guard(&c.held[c.opened-1], index > managedStart, "parent-revalidation") {
				return
			}
		}
		wide, err := windows.UTF16PtrFromString(path)
		if err != nil {
			c.note("path", "UTF16_FAILED", index)
			c.incomplete = true
			return
		}
		if !c.emit("open-started", index, "", map[string]any{"path": path, "managed": index >= managedStart}, nil, false) {
			return
		}
		if c.check() != nil {
			return
		}
		handle, openErr := windows.CreateFile(wide, windows.GENERIC_READ|windows.READ_CONTROL,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		c.visited++
		var held *refusalHeld
		if openErr == nil {
			held = &c.held[c.opened]
			*held = refusalHeld{handle: handle, index: index, comparison: "INCOMPLETE"}
			c.opened++
		}
		expired = c.check() != nil
		if !c.emit("CreateFile", index, "", map[string]any{"handleReturned": held != nil}, openErr, false) {
			return
		}
		if expired {
			return
		}
		if openErr != nil {
			code := "OPEN_FAILED"
			if errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) || errors.Is(openErr, windows.ERROR_PATH_NOT_FOUND) {
				code = "MISSING"
			}
			c.note("CreateFile", code, index)
			return
		}
		if c.check() != nil {
			return
		}
		held.file = os.NewFile(uintptr(handle), path)
		expired = c.check() != nil
		if held.file == nil {
			c.note("os.NewFile", "WRAP_FAILED", index)
			c.incomplete = true
			return
		}
		c.wrapped++
		if expired {
			return
		}
		held.before = c.snapshot(held, 0)
		if held.before == nil {
			return
		}
		if !c.guard(held, index >= managedStart, "nativeFileStamp") {
			return
		}
	}
	c.note("walk", "NAMESPACE_STATE_DIFFERS", len(paths)-1)
}

func (c *refusalCollector) guard(held *refusalHeld, managed bool, stage string) bool {
	if c.check() != nil {
		return false
	}
	stamp, err := nativeFileStamp(held.file, true, managed)
	expired := c.check() != nil
	if !c.emit(stage, held.index, "", map[string]any{
		"compoundOperationNoPerInternalDeadline": true, "logicalOverrun": c.logicalOverrun,
		"managed": managed, "device": stamp.device, "object": stamp.object, "size": stamp.size,
	}, err, false) {
		return false
	}
	if expired {
		return false
	}
	if err != nil {
		c.note(stage, "GUARD_REFUSED", held.index)
		return false
	}
	return true
}

func (c *refusalCollector) snapshot(held *refusalHeld, phase int) *refusalSnapshot {
	label := "before"
	if phase == 1 {
		label = "after"
	}
	if c.check() != nil {
		return nil
	}
	kind, err := windows.GetFileType(held.handle)
	expired := c.check() != nil
	if !c.emit("GetFileType", held.index, label, kind, err, false) {
		return nil
	}
	if expired {
		return nil
	}
	if err != nil {
		c.note("GetFileType", "METADATA_FAILED", held.index)
		c.incomplete = true
		return nil
	}
	if c.check() != nil {
		return nil
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(held.handle, &info)
	expired = c.check() != nil
	identity := refusalIdentity{kind, info.VolumeSerialNumber, uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		info.FileAttributes, info.NumberOfLinks, uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)}
	var detail any
	if err == nil {
		detail = identity
	}
	if !c.emit("GetFileInformationByHandle", held.index, label, detail, err, false) {
		return nil
	}
	if expired {
		return nil
	}
	if err != nil {
		c.note("GetFileInformationByHandle", "METADATA_FAILED", held.index)
		c.incomplete = true
		return nil
	}
	if c.check() != nil {
		return nil
	}
	clear(c.buffer[:])
	var needed uint32
	ok, _, callErr := c.security.Call(uintptr(held.handle), uintptr(windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&c.buffer[0])), 65536, uintptr(unsafe.Pointer(&needed)))
	runtime.KeepAlive(c)
	expired = c.check() != nil
	var queryErr error
	if ok == 0 {
		queryErr = callErr
	}
	if !c.emit("GetKernelObjectSecurity", held.index, label, map[string]any{"success": ok != 0, "neededBytes": needed}, queryErr, false) {
		return nil
	}
	if expired {
		return nil
	}
	if ok == 0 || needed < 20 || needed > 65536 {
		c.note("GetKernelObjectSecurity", "METADATA_FAILED", held.index)
		c.incomplete = true
		return nil
	}
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&c.buffer[0])), 65536)
	data := buffer[:int(needed)]
	decoded, decodeErr := refusalDecode(data, c.check)
	if c.budget.snapshot(phase, len(data), len(decoded.ACEs)) != nil {
		c.note("descriptor", "BOUND_REACHED", held.index)
		c.stopOptional, c.incomplete = true, true
		return nil
	}
	hash := refusalHash(data)
	if !c.emit("descriptor", held.index, label, map[string]any{"sha256": hash, "bytes": len(data), "metadata": decoded}, decodeErr, false) {
		return nil
	}
	for offset, sequence := 0, 0; offset < len(data); sequence++ {
		if c.check() != nil {
			return nil
		}
		end := min(offset+1536, len(data))
		if !c.emit("descriptor-bytes", held.index, label, map[string]any{
			"sha256": hash, "sequence": sequence, "offset": offset, "totalBytes": len(data),
			"base64": base64.StdEncoding.EncodeToString(data[offset:end]),
		}, nil, false) {
			return nil
		}
		offset = end
	}
	for _, ace := range decoded.ACEs {
		if c.check() != nil {
			return nil
		}
		if !c.emit("ace", held.index, label, ace, nil, false) {
			return nil
		}
	}
	if decodeErr != nil {
		c.note("descriptor", "DECODE_INCOMPLETE", held.index)
		c.incomplete = true
		return nil
	}
	return &refusalSnapshot{identity: identity, descriptor: bytes.Clone(data)}
}

func (c *refusalCollector) recordPanic(value any) {
	c.panicType = fmt.Sprintf("%T", value)
	if len(c.panicType) > 128 {
		c.panicType = "TYPE_BOUND_REACHED"
	}
	c.stopOptional, c.incomplete = true, true
	c.note("observer", "PANIC_INVALIDATES_OBSERVATION", -1)
}

func (c *refusalCollector) finish() {
	if value := recover(); value != nil {
		c.recordPanic(value)
	}
	func() {
		defer func() {
			if value := recover(); value != nil {
				c.recordPanic(value)
			}
		}()
		for index := 0; index < c.opened; index++ {
			held := &c.held[index]
			if c.check() != nil {
				break
			}
			if held.file == nil || held.before == nil {
				continue
			}
			after := c.snapshot(held, 1)
			if after == nil {
				continue
			}
			held.comparison = "CHANGED"
			if held.before.identity == after.identity && bytes.Equal(held.before.descriptor, after.descriptor) {
				held.comparison = "UNCHANGED"
			}
			if held.comparison != "UNCHANGED" {
				c.incomplete = true
			}
		}
	}()
	attempted, closed := 0, 0
	for index := c.opened - 1; index >= 0; index-- {
		held := &c.held[index]
		var closeErr error
		panicked := false
		func() {
			defer func() {
				if value := recover(); value != nil {
					panicked = true
					c.recordPanic(value)
				}
			}()
			held.attempted = true
			attempted++
			if held.file != nil {
				closeErr = held.file.Close()
			} else {
				closeErr = windows.CloseHandle(held.handle)
			}
			if closeErr == nil {
				held.closed = true
				closed++
			}
		}()
		if !held.closed || held.comparison == "INCOMPLETE" {
			c.incomplete = true
		}
		c.emit("close", held.index, "terminal", map[string]any{
			"wrapped": held.file != nil, "attempted": held.attempted, "closed": held.closed,
			"comparison": held.comparison, "panic": panicked,
		}, closeErr, true)
	}
	c.emit("terminal", -1, "terminal", map[string]any{
		"firstObservation": c.first, "originalOpenError": c.original,
		"originalD01FailurePreserved": true, "collectionComplete": !c.incomplete,
		"opened": c.opened, "wrapped": c.wrapped, "closeAttempted": attempted,
		"closed": closed, "uncertainHandles": c.opened - closed,
		"components": c.rosterCount, "visited": c.visited, "notAttempted": c.rosterCount - c.visited,
		"panicType": c.panicType, "runtimeSafetyDefect": c.panicType != "",
		"outputFailed": c.outputFailed, "budgetBeforeTerminal": c.budget,
		"writtenRecordsBeforeTerminal": c.writtenRecords, "writtenBytesBeforeTerminal": c.writtenBytes,
		"elapsedMilliseconds": time.Since(c.started).Milliseconds(), "atomicSnapshot": false,
		"logicalOverrun": c.logicalOverrun, "compoundOperationNoPerInternalDeadline": true,
	}, nil, true)
}
