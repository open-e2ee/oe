package identityattempt

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func storeActorTerminal(pid int) (bool, error) {
	var info unix.Siginfo
	err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
	if errors.Is(err, unix.EINTR) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("actor waitid: %w", err)
	}
	if info.Signo == 0 {
		return false, nil
	}
	// Linux CLD_EXITED, CLD_KILLED and CLD_DUMPED are 1, 2 and 3.
	if info.Signo != int32(unix.SIGCHLD) || info.Errno != 0 || info.Code < 1 || info.Code > 3 {
		return false, ErrRelease
	}
	return true, nil
}

func storeActorGroupNeedsSignal(_ int) (bool, error) { return true, nil }

func storeActorGroupEmpty(pid int) (bool, error) {
	err := unix.Kill(-pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("actor group probe: %w", err)
	}
	return false, nil
}
