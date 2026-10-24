package identityattempt

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
)

func freshTemporary(prefix string) (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", ErrPersistence
	}
	return prefix + hex.EncodeToString(entropy[:]) + ".tmp", nil
}

// commitBytes never removes a failed temporary or rolls back installed bytes.
func commitBytes(ctx context.Context, directory *nativeDirectory, destination, prefix string, data []byte, observer phaseObserver) error {
	if !validLeaf(destination) || !validLeaf(prefix+"x.tmp") {
		return ErrFormat
	}
	if err := observe(ctx, observer, "before-temp-create"); err != nil {
		return err
	}
	name, err := freshTemporary(prefix)
	if err != nil {
		return err
	}
	file, err := directory.openFile(ctx, name, true)
	if err != nil {
		return err
	}
	closeOnError := func(err error) error { return combine(err, releaseFile(file)) }
	if err = observe(ctx, observer, "temporary-created"); err != nil {
		return closeOnError(err)
	}
	if _, err = nativeFileStamp(file, false, true); err != nil {
		return closeOnError(err)
	}
	if err = observe(ctx, observer, "before-write"); err != nil {
		return closeOnError(err)
	}
	// The first partial write is a real write, also useful to native interruption tests.
	middle := len(data) / 2
	for index, part := range [][]byte{data[:middle], data[middle:]} {
		for len(part) != 0 {
			if err = phase(ctx); err != nil {
				return closeOnError(err)
			}
			n, writeErr := file.Write(part)
			if writeErr != nil || n <= 0 || n > len(part) {
				return closeOnError(ErrPersistence)
			}
			part = part[n:]
		}
		if index == 0 {
			if err = observe(ctx, observer, "partial-write-observed"); err != nil {
				return closeOnError(err)
			}
		}
	}
	if err = observe(ctx, observer, "complete-write-returned"); err != nil {
		return closeOnError(err)
	}
	if err = observe(ctx, observer, "before-file-flush"); err != nil {
		return closeOnError(err)
	}
	if file.Sync() != nil {
		return closeOnError(ErrPersistence)
	}
	if err = observe(ctx, observer, "file-flush-returned"); err != nil {
		return closeOnError(err)
	}
	if err = observe(ctx, observer, "before-file-close"); err != nil {
		return closeOnError(err)
	}
	closeErr := file.Close()
	file = nil
	if closeErr != nil {
		return ErrPersistence
	}
	if err = observe(ctx, observer, "checked-close-returned"); err != nil {
		return err
	}
	if err = observe(ctx, observer, "before-replace"); err != nil {
		return err
	}
	if err = directory.replace(ctx, name, destination); err != nil {
		return err
	}
	if err = observe(ctx, observer, nativeReplacePhase()); err != nil {
		return err
	}
	if err = observe(ctx, observer, "before-platform-barrier"); err != nil {
		return err
	}
	if err = directory.sync(ctx); err != nil {
		return err
	}
	if stage := nativeDirectoryBarrierPhase(); stage != "" {
		if err = observe(ctx, observer, stage); err != nil {
			return err
		}
	}
	if err = observe(ctx, observer, "before-post-open-security"); err != nil {
		return err
	}
	if err = observe(ctx, observer, "before-readback"); err != nil {
		return err
	}
	actual, err := readBounded(ctx, directory, destination, int64(len(data)))
	if err != nil {
		return err
	}
	if err = observe(ctx, observer, "before-canonical-compare"); err != nil {
		return err
	}
	if !bytes.Equal(actual, data) {
		return ErrPersistence
	}
	return observe(ctx, observer, "canonical-readback-returned")
}

func (l *Lease) read() (Envelope, error) {
	if err := l.guard(); err != nil {
		return Envelope{}, err
	}
	if err := l.namespace.currentReady(l.ioContext()); err != nil {
		return Envelope{}, err
	}
	if err := validateStableBinding(l.ioContext(), l.namespace.locks, l.stem+".lock", l.lock); err != nil {
		return Envelope{}, err
	}
	if err := checkOrphans(l.namespace.records, l.stem); err != nil {
		return Envelope{}, err
	}
	value, err := readRecord(l.ioContext(), l.namespace.records, l.stem, l.slot)
	if err == errMissing {
		return Envelope{}, ErrUncertain
	}
	return value, err
}

func (l *Lease) commit(value Envelope) error {
	if err := l.guard(); err != nil {
		return err
	}
	if err := l.namespace.currentReady(l.ioContext()); err != nil {
		return err
	}
	if err := validateStableBinding(l.ioContext(), l.namespace.locks, l.stem+".lock", l.lock); err != nil {
		return err
	}
	if value.Validate() != nil || !value.Slot().Equal(l.slot) {
		return ErrFormat
	}
	if err := checkOrphans(l.namespace.records, l.stem); err != nil {
		return err
	}
	limit, err := recordLimit(l.slot)
	if err != nil {
		return err
	}
	data, err := EncodeEnvelope(value)
	if err != nil || int64(len(data)) > limit {
		return ErrTooLarge
	}
	if err = commitBytes(l.ioContext(), l.namespace.records, l.stem+".json", "."+l.stem+".", data, l.observer); err != nil {
		return err
	}
	actual, err := readRecord(l.ioContext(), l.namespace.records, l.stem, l.slot)
	if err != nil {
		return err
	}
	if !actual.Equal(value) {
		return ErrPersistence
	}
	return nil
}

func (l *Lease) closeResources() error {
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	var result error
	if l.locked {
		result = nativeUnlock(l.lock)
		l.locked = false
	}
	if l.lock != nil {
		result = combine(result, releaseFile(l.lock))
		l.lock = nil
	}
	return combine(result, l.namespace.Close())
}

// Close checks all release operations. It never restores an earlier record.
func (l *Lease) Close() error {
	if l == nil {
		return ErrChanged
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if l.active {
		return ErrBusy
	}
	return l.closeResources()
}

// The native implementation owns OS file creation, locking and barriers.
var _ closeable = (*os.File)(nil)
