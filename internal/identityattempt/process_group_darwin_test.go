package identityattempt

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

var loadStoreActorSysctl = sync.OnceValues(func() (uintptr, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || unsafe.Sizeof(unix.KinfoProc{}) != 648 || unsafe.Sizeof(uintptr(0)) != 8 {
		return 0, ErrUnsafe
	}
	library, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return 0, err
	}
	symbol, err := purego.Dlsym(library, "sysctl")
	if err != nil {
		return 0, combine(err, purego.Dlclose(library))
	}
	// This test process retains one library reference while the symbol is live.
	return symbol, nil
})

func storeActorTerminal(pid int) (bool, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return false, fmt.Errorf("actor terminal census: %w", err)
	}
	if info.Proc.P_pid != int32(pid) || info.Eproc.Ppid != int32(os.Getpid()) || info.Eproc.Pgid != int32(pid) || info.Proc.P_stat <= 0 {
		return false, ErrRelease
	}
	// Public Darwin proc.h defines SZOMB as 5. This does not reap the child.
	return info.Proc.P_stat == 5, nil
}

func storeActorGroupCensus(pid int, requireLeader bool) (int, int, error) {
	symbol, err := loadStoreActorSysctl()
	if err != nil {
		return 0, 0, err
	}
	// CTL_KERN, KERN_PROC, KERN_PROC_PGRP, exact owned PGID.
	mib := [4]int32{1, 14, 2, int32(pid)}
	// The maintained actor graph has at most two members. The third detects overflow.
	var records [3]unix.KinfoProc
	size := unsafe.Sizeof(records)
	result, _, nativeErrno := purego.SyscallN(symbol,
		uintptr(unsafe.Pointer(&mib[0])), uintptr(len(mib)),
		uintptr(unsafe.Pointer(&records[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	runtime.KeepAlive(mib)
	runtime.KeepAlive(records)
	if int32(result) != 0 {
		return 0, 0, fmt.Errorf("actor group sysctl result %d: %w", int32(result), syscall.Errno(uint32(nativeErrno)))
	}
	width := unsafe.Sizeof(records[0])
	if size > unsafe.Sizeof(records) || size%width != 0 || size/width > 2 {
		return 0, 0, ErrRelease
	}
	count, live := int(size/width), 0
	leader := false
	for index := range count {
		record := &records[index]
		if record.Proc.P_pid <= 0 || record.Eproc.Pgid != int32(pid) || record.Proc.P_stat <= 0 {
			return 0, 0, ErrRelease
		}
		for previous := range index {
			if records[previous].Proc.P_pid == record.Proc.P_pid {
				return 0, 0, ErrRelease
			}
		}
		if record.Proc.P_pid == int32(pid) {
			leader = true
		}
		if record.Proc.P_stat != 5 {
			live++
		}
	}
	if requireLeader && !leader {
		return 0, 0, ErrRelease
	}
	return count, live, nil
}

func storeActorGroupNeedsSignal(pid int) (bool, error) {
	_, live, err := storeActorGroupCensus(pid, true)
	return live != 0, err
}

func storeActorGroupEmpty(pid int) (bool, error) {
	count, _, err := storeActorGroupCensus(pid, false)
	return count == 0 && err == nil, err
}
