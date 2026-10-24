package identityattempt

import (
	"bytes"
	"context"
	"io"
	"os"
)

type fileStamp struct {
	device, object uint64
	size           int64
}

// recordLimit derives a storage bound without adding a schema ceiling.
func recordLimit(slot Slot) (int64, error) {
	if slot.Validate() != nil {
		return 0, ErrFormat
	}
	// These upper bounds preflight the accepted encoder's allocation arithmetic.
	// They do not encode a second slot or impose a public string length limit.
	lengths := []int{len(slot.ControlBase().String()), len(slot.OrganizationID()), len(slot.ProjectSlug()), len(slot.Environment()), len(slot.Kind())}
	if err := slotEncodingRepresentable(lengths); err != nil {
		return 0, err
	}
	maximum := uint64(^uint(0) >> 1)
	bound, err := MaximumEnvelopeEncodingBytes(slot)
	if err != nil || bound < 0 || uint64(bound) >= uint64(1<<63-1) || uint64(bound) >= maximum {
		return 0, ErrTooLarge
	}
	return int64(bound), nil
}

func slotEncodingRepresentable(lengths []int) error {
	maximum := uint64(^uint(0) >> 1)
	length := uint64(256)
	for _, size := range lengths {
		if size < 0 || uint64(size) > (maximum-length)/6 {
			return ErrTooLarge
		}
		length += uint64(size) * 6
	}
	if length > maximum-63832 {
		return ErrTooLarge
	}
	return nil
}

func readBounded(ctx context.Context, directory *nativeDirectory, name string, maximum int64) ([]byte, error) {
	if maximum < 0 || maximum == 1<<63-1 {
		return nil, ErrTooLarge
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	file, err := directory.openFile(ctx, name, false)
	if err != nil {
		return nil, err
	}
	data, readErr := readOpened(ctx, file, maximum)
	return data, combine(readErr, releaseFile(file))
}

func readOpened(ctx context.Context, file *os.File, maximum int64) ([]byte, error) {
	before, err := nativeFileStamp(file, false, true)
	if err != nil {
		return nil, err
	}
	if before.size < 0 || before.size > maximum {
		return nil, ErrTooLarge
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, ErrPersistence
	}
	if int64(len(data)) > maximum {
		return nil, ErrTooLarge
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	after, err := nativeFileStamp(file, false, true)
	if err != nil {
		return nil, err
	}
	if before != after || int64(len(data)) != before.size {
		return nil, ErrChanged
	}
	return data, nil
}

func readRecord(ctx context.Context, directory *nativeDirectory, stem string, slot Slot) (Envelope, error) {
	maximum, err := recordLimit(slot)
	if err != nil {
		return Envelope{}, err
	}
	actualStem, err := slot.FilenameStem()
	if err != nil || stem != actualStem {
		return Envelope{}, ErrFormat
	}
	data, err := readBounded(ctx, directory, stem+".json", maximum)
	if err != nil {
		return Envelope{}, err
	}
	value, err := DecodeEnvelope(data, slot)
	if err != nil {
		return Envelope{}, ErrFormat
	}
	canonical, err := EncodeEnvelope(value)
	if err != nil || !bytes.Equal(data, canonical) {
		return Envelope{}, ErrFormat
	}
	return value, nil
}

func checkReadyManifest(ctx context.Context, root *nativeDirectory) error {
	_, err := readReadyManifest(ctx, root)
	return err
}

func checkOrphans(directory *nativeDirectory, stem string) error {
	names, err := directory.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		if len(name) > len(stem)+2 && name[0] == '.' && name[1:len(stem)+1] == stem && name[len(stem)+1] == '.' {
			return ErrUncertain
		}
	}
	return nil
}
