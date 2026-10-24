//go:build darwin || linux

package identityattempt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func defaultConfigRoot() (string, error)  { return os.UserConfigDir() }
func managedDirectoryNames() [3]string    { return [3]string{"open-e2ee", "oe", "identity-attempts"} }
func nativeReplacePhase() string          { return "rename-returned" }
func nativeDirectoryBarrierPhase() string { return "parent-fsync-returned" }

// Darwin installs its required native ACL receiver during package initialization.
// Linux mode masks bound POSIX ACL grants; native qualification remains separate.
var unixACLReceiver = func(file *os.File, managed bool) error {
	if runtime.GOOS == "darwin" {
		return ErrUnsafe
	}
	return nil
}

var unixMountReceiver = func(file *os.File) error {
	var data unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &data) != nil {
		return ErrUnsafe
	}
	if runtime.GOOS == "linux" {
		switch uint64(data.Type) {
		case 0x6969, 0x517b, 0xff534d42:
			return ErrUnsafe
		}
	}
	return nil
}

func nativeFileStamp(file *os.File, directory, managed bool) (fileStamp, error) {
	if file == nil {
		return fileStamp{}, ErrUnsafe
	}
	var info unix.Stat_t
	if unix.Fstat(int(file.Fd()), &info) != nil {
		return fileStamp{}, ErrUnsafe
	}
	mode := uint32(info.Mode)
	if mode&unix.S_IFMT != unix.S_IFREG && (!directory || mode&unix.S_IFMT != unix.S_IFDIR) {
		return fileStamp{}, ErrUnsafe
	}
	if directory && mode&unix.S_IFMT != unix.S_IFDIR {
		return fileStamp{}, ErrUnsafe
	}
	if !directory && info.Nlink != 1 {
		return fileStamp{}, ErrUnsafe
	}
	if mode&(unix.S_ISUID|unix.S_ISGID) != 0 || managed && mode&unix.S_ISVTX != 0 {
		return fileStamp{}, ErrUnsafe
	}
	uid := uint32(os.Geteuid())
	if managed {
		wanted := uint32(0o600)
		if directory {
			wanted = 0o700
		}
		if info.Uid != uid || mode&0o777 != wanted {
			return fileStamp{}, ErrUnsafe
		}
	} else if info.Uid != 0 && info.Uid != uid || mode&0o022 != 0 {
		return fileStamp{}, ErrUnsafe
	}
	if err := unixACLReceiver(file, managed); err != nil {
		return fileStamp{}, err
	}
	return fileStamp{uint64(info.Dev), uint64(info.Ino), info.Size}, nil
}

func unixOpenDirectory(parent int, name, path string, managed bool) (*os.File, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, errMissing
		}
		return nil, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		if unix.Close(fd) != nil {
			return nil, combine(ErrUnsafe, ErrRelease)
		}
		return nil, ErrUnsafe
	}
	if _, err := nativeFileStamp(file, true, managed); err != nil {
		return nil, combine(err, releaseFile(file))
	}
	if err := unixMountReceiver(file); err != nil {
		return nil, combine(err, releaseFile(file))
	}
	return file, nil
}

func nativeOpenLocation(ctx context.Context, location Location, create bool) (*nativeDirectory, bool, error) {
	if err := phase(ctx); err != nil {
		return nil, false, err
	}
	if location.validate() != nil {
		return nil, false, ErrLocation
	}
	root, err := unixOpenDirectory(unix.AT_FDCWD, string(filepath.Separator), string(filepath.Separator), false)
	if err != nil {
		return nil, false, err
	}
	pins := []*os.File{root}
	fail := func(err error) (*nativeDirectory, bool, error) {
		for i := len(pins) - 1; i >= 0; i-- {
			err = combine(err, releaseFile(pins[i]))
		}
		return nil, false, err
	}
	current := root
	currentPath := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(location.anchor, string(filepath.Separator)), string(filepath.Separator))
	if location.anchor == string(filepath.Separator) {
		parts = nil
	}
	for index, part := range parts {
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		if !validLeaf(part) {
			return fail(ErrLocation)
		}
		parentPath := currentPath
		currentPath = filepath.Join(currentPath, part)
		next, err := unixOpenDirectory(int(current.Fd()), part, currentPath, false)
		if check := unixRevalidateDirectory(current, parentPath, false); check != nil {
			if next != nil {
				check = combine(check, releaseFile(next))
			}
			return fail(combine(err, check))
		}
		createdAnchor := false
		if soleMissing(err) && index != len(parts)-1 {
			return fail(ErrLocation)
		}
		if soleMissing(err) && create {
			if err := phase(ctx); err != nil {
				return fail(err)
			}
			if err := observe(ctx, location.observer, "before-selected-anchor-create"); err != nil {
				return fail(err)
			}
			mkdirErr := unix.Mkdirat(int(current.Fd()), part, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return fail(ErrPersistence)
			}
			createdAnchor = mkdirErr == nil
			if createdAnchor {
				if err := observe(ctx, location.observer, "before-created-directory-parent-flush"); err != nil {
					return fail(err)
				}
				if unix.Fsync(int(current.Fd())) != nil {
					return fail(ErrPersistence)
				}
			}
			if err := phase(ctx); err != nil {
				return fail(err)
			}
			next, err = unixOpenDirectory(int(current.Fd()), part, currentPath, createdAnchor)
			if check := unixRevalidateDirectory(current, parentPath, false); check != nil {
				if next != nil {
					check = combine(check, releaseFile(next))
				}
				return fail(combine(err, check))
			}
		}
		if err != nil {
			return fail(err)
		}
		pins = append(pins, next)
		current = next
		if createdAnchor {
			if err := observe(ctx, location.observer, "selected-anchor-created"); err != nil {
				return fail(err)
			}
		}
	}
	createdFinal := false
	for index, part := range location.managed {
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		if err := unixRevalidateDirectory(current, currentPath, index > 0); err != nil {
			return fail(err)
		}
		path := filepath.Join(currentPath, part)
		if create {
			if err := observe(ctx, location.observer, "before-managed-directory-create"); err != nil {
				return fail(err)
			}
			mkdirErr := unix.Mkdirat(int(current.Fd()), part, 0o700)
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return fail(ErrPersistence)
			}
			if index == len(location.managed)-1 {
				createdFinal = mkdirErr == nil
			}
			if mkdirErr == nil {
				if err := observe(ctx, location.observer, "before-created-directory-parent-flush"); err != nil {
					return fail(err)
				}
				if unix.Fsync(int(current.Fd())) != nil {
					return fail(ErrPersistence)
				}
			}
		}
		if err := phase(ctx); err != nil {
			return fail(err)
		}
		next, err := unixOpenDirectory(int(current.Fd()), part, path, true)
		if check := unixRevalidateDirectory(current, currentPath, index > 0); check != nil {
			if next != nil {
				check = combine(check, releaseFile(next))
			}
			return fail(combine(err, check))
		}
		if err != nil {
			return fail(err)
		}
		pins = append(pins, next)
		current, currentPath = next, path
	}
	return &nativeDirectory{file: current, path: currentPath, pins: pins[:len(pins)-1]}, createdFinal, nil
}

func (d *nativeDirectory) revalidate() error { return unixRevalidateDirectory(d.file, d.path, true) }

func unixRevalidateDirectory(file *os.File, path string, managed bool) error {
	before, err := nativeFileStamp(file, true, managed)
	if err != nil {
		return err
	}
	actual, err := os.Lstat(path)
	if err != nil || actual.Mode()&os.ModeSymlink != 0 {
		return ErrChanged
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, actual) {
		return ErrChanged
	}
	after, err := nativeFileStamp(file, true, managed)
	if err != nil {
		return err
	}
	if before.device != after.device || before.object != after.object {
		return ErrChanged
	}
	return nil
}

func (d *nativeDirectory) subdirectory(ctx context.Context, name string, create bool) (*nativeDirectory, error) {
	if err := phase(ctx); err != nil {
		return nil, err
	}
	if !validLeaf(name) {
		return nil, ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	if create {
		if err := phase(ctx); err != nil {
			return nil, err
		}
		if err := unix.Mkdirat(int(d.file.Fd()), name, 0o700); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return nil, ErrUncertain
			}
			return nil, ErrPersistence
		}
		if err := d.sync(ctx); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(d.path, name)
	file, err := unixOpenDirectory(int(d.file.Fd()), name, path, true)
	if check := d.revalidate(); check != nil {
		if file != nil {
			check = combine(check, releaseFile(file))
		}
		return nil, combine(err, check)
	}
	if err != nil {
		return nil, err
	}
	return &nativeDirectory{file: file, path: path}, nil
}

func (d *nativeDirectory) openFile(ctx context.Context, name string, create bool) (*os.File, error) {
	if err := phase(ctx); err != nil {
		return nil, err
	}
	if !validLeaf(name) {
		return nil, ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	flags := unix.O_RDWR | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), name, flags, 0o600)
	if err != nil {
		if check := d.revalidate(); check != nil {
			return nil, check
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, errMissing
		}
		if errors.Is(err, unix.EEXIST) {
			return nil, errExists
		}
		return nil, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), filepath.Join(d.path, name))
	if file == nil {
		if unix.Close(fd) != nil {
			return nil, combine(ErrUnsafe, ErrRelease)
		}
		return nil, ErrUnsafe
	}
	if _, err := nativeFileStamp(file, false, true); err != nil {
		return nil, combine(err, releaseFile(file))
	}
	return file, nil
}

func (d *nativeDirectory) names() ([]string, error) {
	if err := d.revalidate(); err != nil {
		return nil, err
	}
	file, err := unixOpenDirectory(int(d.file.Fd()), ".", d.path, true)
	if err != nil {
		return nil, err
	}
	names, readErr := file.Readdirnames(-1)
	if readErr != nil {
		readErr = ErrPersistence
	}
	return names, combine(readErr, releaseFile(file))
}

func (d *nativeDirectory) replace(ctx context.Context, source, destination string) error {
	if err := phase(ctx); err != nil {
		return err
	}
	if !validLeaf(source) || !validLeaf(destination) {
		return ErrFormat
	}
	if err := d.revalidate(); err != nil {
		return err
	}
	if err := phase(ctx); err != nil {
		return err
	}
	if unix.Renameat(int(d.file.Fd()), source, int(d.file.Fd()), destination) != nil {
		return ErrPersistence
	}
	return nil
}

func (d *nativeDirectory) sync(ctx context.Context) error {
	if err := phase(ctx); err != nil {
		return err
	}
	if err := d.revalidate(); err != nil {
		return err
	}
	if err := phase(ctx); err != nil {
		return err
	}
	if unix.Fsync(int(d.file.Fd())) != nil {
		return ErrPersistence
	}
	return nil
}

func nativeLock(ctx context.Context, file *os.File, exclusive bool) error {
	if err := boundedContext(ctx); err != nil {
		return err
	}
	flag := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		flag = unix.LOCK_EX | unix.LOCK_NB
	}
	for {
		if err := phase(ctx); err != nil {
			return ErrBusy
		}
		err := unix.Flock(int(file.Fd()), flag)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return ErrUnsafe
		}
		timer := time.NewTimer(acquisitionPoll)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ErrBusy
		case <-timer.C:
		}
	}
}

func nativeUnlock(file *os.File) error {
	if file == nil || unix.Flock(int(file.Fd()), unix.LOCK_UN) != nil {
		return ErrRelease
	}
	return nil
}
