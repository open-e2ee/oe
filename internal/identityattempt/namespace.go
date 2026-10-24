package identityattempt

import (
	"bytes"
	"context"
	"os"
	"sync"
	"time"
)

// FirstUse is a declaration, not evidence that deleted local state never existed.
type FirstUse uint8

const (
	NamespaceNeverUsed FirstUse = 1
	SlotNeverUsed      FirstUse = 2
)

type ObservationState uint8

const (
	AbsentNamespace ObservationState = iota + 1
	AbsentSlot
	Ready
)

type Observation struct {
	state    ObservationState
	envelope Envelope
}

func (v Observation) State() ObservationState { return v.state }
func (v Observation) Envelope() (Envelope, bool) {
	if v.state != Ready {
		return Envelope{}, false
	}
	value, err := v.envelope.Clone()
	return value, err == nil
}

// Store holds an immutable location. Native resources belong to individual operations.
type Store struct{ location Location }

type nativeDirectory struct {
	file *os.File
	path string
	pins []*os.File
}

func (d *nativeDirectory) Close() error {
	if d == nil {
		return nil
	}
	var result error
	if d.file != nil {
		result = releaseFile(d.file)
	}
	d.file = nil
	for i := len(d.pins) - 1; i >= 0; i-- {
		result = combine(result, releaseFile(d.pins[i]))
	}
	d.pins = nil
	return result
}

type namespace struct {
	root, locks, records *nativeDirectory
	rootLock             *os.File
	rootLocked           bool
	readyStamp           fileStamp
	readyPinned          bool
}

func (n *namespace) Close() error {
	if n == nil {
		return nil
	}
	var result error
	if n.rootLocked {
		result = nativeUnlock(n.rootLock)
		n.rootLocked = false
	}
	if n.rootLock != nil {
		result = combine(result, releaseFile(n.rootLock))
		n.rootLock = nil
	}
	result = combine(result, n.records.Close())
	result = combine(result, n.locks.Close())
	return combine(result, n.root.Close())
}

func Open(location Location) (*Store, error) {
	if location.validate() != nil {
		return nil, ErrLocation
	}
	ctx, cancel := context.WithTimeout(context.Background(), acquisitionLimit)
	defer cancel()
	n, err := openNamespace(ctx, location)
	if soleMissing(err) {
		return &Store{location}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := n.Close(); err != nil {
		return nil, err
	}
	return &Store{location}, nil
}

func BootstrapFirstUse(ctx context.Context, location Location, declaration FirstUse) (*Store, error) {
	if err := boundedContext(ctx); err != nil {
		return nil, err
	}
	if location.validate() != nil {
		return nil, ErrLocation
	}
	if declaration != NamespaceNeverUsed {
		return nil, ErrFirstUseRequired
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		return nil, ErrOperationIDUnretained
	}
	acquisition, stop := context.WithDeadline(ctx, remainingDeadline(ctx, acquisitionLimit))
	defer stop()
	root, created, err := nativeOpenLocation(acquisition, location, true)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, combine(ErrAlreadyInitialized, root.Close())
	}
	n := &namespace{root: root}
	fail := func(err error) (*Store, error) { return nil, combine(err, n.Close()) }
	if err := observe(ctx, location.observer, "root-directory-created"); err != nil {
		return fail(err)
	}
	n.rootLock, err = root.openFile(acquisition, "root.lock", true)
	if err != nil {
		return fail(err)
	}
	if err = nativeLock(acquisition, n.rootLock, true); err != nil {
		return fail(err)
	}
	n.rootLocked = true
	if err = syncStable(ctx, root, n.rootLock); err != nil {
		return fail(err)
	}
	if err = observe(ctx, location.observer, "root-lock-created"); err != nil {
		return fail(err)
	}
	n.locks, err = root.subdirectory(ctx, "locks", true)
	if err != nil {
		return fail(err)
	}
	n.records, err = root.subdirectory(ctx, "v1", true)
	if err != nil {
		return fail(err)
	}
	if err = root.sync(ctx); err != nil {
		return fail(err)
	}
	if err = observe(ctx, location.observer, "directories-created"); err != nil {
		return fail(err)
	}
	if err = commitBytes(ctx, root, "store.json", ".manifest.", []byte(readyManifest), manifestPhaseObserver{location.observer}); err != nil {
		return fail(err)
	}
	if err = observe(ctx, location.observer, "manifest-installed"); err != nil {
		return fail(err)
	}
	if err = checkReadyManifest(ctx, root); err != nil {
		return fail(err)
	}
	if err = observe(ctx, location.observer, "manifest-readback"); err != nil {
		return fail(err)
	}
	if err = n.Close(); err != nil {
		return nil, err
	}
	return &Store{location}, nil
}

func openNamespace(ctx context.Context, location Location) (*namespace, error) {
	if location.validate() != nil {
		return nil, ErrLocation
	}
	if err := phase(ctx); err != nil {
		return nil, err
	}
	root, _, err := nativeOpenLocation(ctx, location, false)
	if err != nil {
		return nil, err
	}
	n := &namespace{root: root}
	fail := func(err error) (*namespace, error) { return nil, combine(err, n.Close()) }
	n.rootLock, err = root.openFile(ctx, "root.lock", false)
	if soleMissing(err) {
		return fail(ErrUncertain)
	}
	if err != nil {
		return fail(err)
	}
	if err = nativeLock(ctx, n.rootLock, false); err != nil {
		return fail(err)
	}
	n.rootLocked = true
	if err = validateStableBinding(ctx, root, "root.lock", n.rootLock); err != nil {
		return fail(err)
	}
	n.readyStamp, err = readReadyManifest(ctx, root)
	if err != nil {
		return fail(err)
	}
	n.readyPinned = true
	for _, target := range []struct {
		name        string
		destination **nativeDirectory
	}{{"locks", &n.locks}, {"v1", &n.records}} {
		*target.destination, err = root.subdirectory(ctx, target.name, false)
		if soleMissing(err) {
			return fail(ErrUncertain)
		}
		if err != nil {
			return fail(err)
		}
	}
	names, err := root.names()
	if err != nil {
		return fail(err)
	}
	for _, name := range names {
		if name != "root.lock" && name != "store.json" && name != "locks" && name != "v1" {
			return fail(ErrUncertain)
		}
	}
	if err = n.currentReady(ctx); err != nil {
		return fail(err)
	}
	return n, nil
}

func validateStable(file *os.File) error {
	stamp, err := nativeFileStamp(file, false, true)
	if err != nil {
		return err
	}
	if stamp.size != 0 {
		return ErrUncertain
	}
	return nil
}

func syncStable(ctx context.Context, parent *nativeDirectory, file *os.File) error {
	if err := validateStable(file); err != nil {
		return err
	}
	if err := phase(ctx); err != nil {
		return err
	}
	if file.Sync() != nil {
		return ErrPersistence
	}
	if err := phase(ctx); err != nil {
		return err
	}
	return parent.sync(ctx)
}

func associatedAbsent(ctx context.Context, n *namespace, stem string) error {
	if err := checkOrphans(n.records, stem); err != nil {
		return err
	}
	file, err := n.records.openFile(ctx, stem+".json", false)
	if soleMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return combine(ErrUncertain, releaseFile(file))
}

func (s *Store) Inspect(ctx context.Context, slot Slot) (Observation, error) {
	if s == nil {
		return Observation{}, ErrLocation
	}
	if err := boundedContext(ctx); err != nil {
		return Observation{}, err
	}
	if _, err := recordLimit(slot); err != nil {
		return Observation{}, err
	}
	acquisition, stop := context.WithDeadline(ctx, remainingDeadline(ctx, acquisitionLimit))
	defer stop()
	n, err := openNamespace(acquisition, s.location)
	if soleMissing(err) {
		return Observation{state: AbsentNamespace}, nil
	}
	if err != nil {
		return Observation{}, err
	}
	stem, _ := slot.FilenameStem()
	lock, err := n.locks.openFile(acquisition, stem+".lock", false)
	if soleMissing(err) {
		stateErr := combine(associatedAbsent(ctx, n, stem), n.Close())
		if stateErr != nil {
			return Observation{}, stateErr
		}
		return Observation{state: AbsentSlot}, nil
	}
	if err != nil {
		return Observation{}, combine(err, n.Close())
	}
	locked := false
	finish := func(err error) error {
		if locked {
			err = combine(err, nativeUnlock(lock))
		}
		return combine(combine(err, releaseFile(lock)), n.Close())
	}
	if err = nativeLock(acquisition, lock, false); err != nil {
		return Observation{}, finish(err)
	}
	locked = true
	if err = validateStableBinding(ctx, n.locks, stem+".lock", lock); err != nil {
		return Observation{}, finish(err)
	}
	if err = checkOrphans(n.records, stem); err != nil {
		return Observation{}, finish(err)
	}
	value, err := readRecord(ctx, n.records, stem, slot)
	if soleMissing(err) {
		err = ErrUncertain
	}
	if err != nil {
		return Observation{}, finish(err)
	}
	if err := finish(nil); err != nil {
		return Observation{}, err
	}
	return Observation{Ready, value}, nil
}

func (s *Store) EnrollFirstUse(ctx context.Context, slot Slot, declaration FirstUse) (*Lease, error) {
	if declaration != SlotNeverUsed {
		return nil, ErrFirstUseRequired
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		return nil, ErrOperationIDUnretained
	}
	return s.enter(ctx, slot, true)
}

func (s *Store) BeginExisting(ctx context.Context, slot Slot) (*Lease, error) {
	return s.enter(ctx, slot, false)
}

func (s *Store) enter(ctx context.Context, slot Slot, enroll bool) (*Lease, error) {
	if s == nil {
		return nil, ErrLocation
	}
	if err := boundedContext(ctx); err != nil {
		return nil, err
	}
	if _, err := recordLimit(slot); err != nil {
		return nil, err
	}
	deadline := remainingDeadline(ctx, leaseLimit)
	acquisition, stop := context.WithDeadline(ctx, minTime(deadline, time.Now().Add(acquisitionLimit)))
	defer stop()
	n, err := openNamespace(acquisition, s.location)
	if soleMissing(err) {
		return nil, ErrFirstUseRequired
	}
	if err != nil {
		return nil, err
	}
	stem, _ := slot.FilenameStem()
	if enroll {
		existing, openErr := n.locks.openFile(acquisition, stem+".lock", false)
		if openErr == nil {
			return nil, combine(combine(ErrAlreadyInitialized, releaseFile(existing)), n.Close())
		}
		if !soleMissing(openErr) {
			return nil, combine(openErr, n.Close())
		}
		if err = associatedAbsent(ctx, n, stem); err != nil {
			return nil, combine(err, n.Close())
		}
	}
	lock, err := n.locks.openFile(acquisition, stem+".lock", enroll)
	if err == errExists {
		return nil, combine(ErrAlreadyInitialized, n.Close())
	}
	if soleMissing(err) {
		check := associatedAbsent(ctx, n, stem)
		if check == nil {
			check = ErrFirstUseRequired
		}
		return nil, combine(check, n.Close())
	}
	if err != nil {
		return nil, combine(err, n.Close())
	}
	leaseContext, cancel := context.WithDeadline(ctx, deadline)
	l := &Lease{namespace: n, lock: lock, slot: slot, stem: stem, deadline: deadline, ctx: leaseContext, cancel: cancel, observer: s.location.observer, permits: make(map[uint64]permitState)}
	if enroll {
		if err = observe(l.ctx, l.observer, "slot-lock-created"); err != nil {
			return nil, combine(err, l.closeResources())
		}
	}
	if err = nativeLock(acquisition, lock, true); err != nil {
		return nil, combine(err, l.closeResources())
	}
	l.locked = true
	if err = validateStableBinding(l.ctx, n.locks, stem+".lock", lock); err != nil {
		return nil, combine(err, l.closeResources())
	}
	if enroll {
		if err = syncStable(l.ctx, n.locks, lock); err != nil {
			return nil, combine(err, l.closeResources())
		}
		if err = observe(l.ctx, l.observer, "slot-lock-synced"); err != nil {
			return nil, combine(err, l.closeResources())
		}
		vacant, _ := NewVacantEnvelope(slot, 1)
		if err = l.commit(vacant); err != nil {
			return nil, combine(err, l.closeResources())
		}
		if err = observe(l.ctx, l.observer, "slot-vacant-readback"); err != nil {
			return nil, combine(err, l.closeResources())
		}
	} else {
		if _, err = l.read(); err != nil {
			return nil, combine(err, l.closeResources())
		}
	}
	return l, nil
}

// Lease owns one root shared lock and one stable exclusive slot lock.
// Its mutex prevents state phases from overlapping a tracked native/control call.
type Lease struct {
	mu                                  sync.Mutex
	namespace                           *namespace
	lock                                *os.File
	locked, closed, active, prepared    bool
	occupiedCallUsed, preparationJoined bool
	activeToken                         uint64
	slot                                Slot
	stem                                string
	deadline                            time.Time
	ctx                                 context.Context
	operationContext                    context.Context
	cancel                              context.CancelFunc
	observer                            phaseObserver
	permitSequence                      uint64
	permits                             map[uint64]permitState
}

// The ready marker's install is observed before the owning platform barrier.
type manifestPhaseObserver struct{ target phaseObserver }

func (o manifestPhaseObserver) Observe(stage string) error {
	if o.target == nil {
		return nil
	}
	if err := o.target.Observe(stage); err != nil {
		return err
	}
	if stage == nativeReplacePhase() {
		return o.target.Observe("ready-manifest-installed-before-final-barriers")
	}
	return nil
}

// A held stable descriptor must still name the existing lock at its managed leaf.
func validateStableBinding(ctx context.Context, parent *nativeDirectory, name string, held *os.File) error {
	if err := phase(ctx); err != nil {
		return err
	}
	before, err := nativeFileStamp(held, false, true)
	if err != nil {
		return err
	}
	if before.size != 0 {
		return ErrUncertain
	}
	current, err := parent.openFile(ctx, name, false)
	if soleMissing(err) {
		return ErrUncertain
	}
	if err != nil {
		return err
	}
	after, check := nativeFileStamp(current, false, true)
	if check == nil && before != after {
		check = ErrChanged
	}
	return combine(check, releaseFile(current))
}

func readReadyOpened(ctx context.Context, file *os.File) (fileStamp, error) {
	data, err := readOpened(ctx, file, int64(len(readyManifest)))
	if err != nil {
		return fileStamp{}, err
	}
	if !bytes.Equal(data, []byte(readyManifest)) {
		return fileStamp{}, ErrFormat
	}
	return nativeFileStamp(file, false, true)
}

func readReadyManifest(ctx context.Context, root *nativeDirectory) (fileStamp, error) {
	file, err := root.openFile(ctx, "store.json", false)
	if soleMissing(err) {
		return fileStamp{}, ErrUncertain
	}
	if err != nil {
		return fileStamp{}, err
	}
	stamp, check := readReadyOpened(ctx, file)
	return stamp, combine(check, releaseFile(file))
}

// currentReady reads current evidence without adding a durability barrier.
// The pinned identity belongs to this admission, not to any former process.
func (n *namespace) currentReady(ctx context.Context) error {
	if n == nil || !n.rootLocked || !n.readyPinned {
		return ErrChanged
	}
	if err := phase(ctx); err != nil {
		return err
	}
	if err := n.root.revalidate(); err != nil {
		return err
	}
	if err := validateStableBinding(ctx, n.root, "root.lock", n.rootLock); err != nil {
		return err
	}
	if err := n.locks.revalidate(); err != nil {
		return err
	}
	if err := n.records.revalidate(); err != nil {
		return err
	}
	names, err := n.root.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		if name != "root.lock" && name != "store.json" && name != "locks" && name != "v1" {
			return ErrUncertain
		}
	}
	stamp, err := readReadyManifest(ctx, n.root)
	if err != nil {
		return err
	}
	if stamp.device != n.readyStamp.device || stamp.object != n.readyStamp.object {
		return ErrChanged
	}
	return phase(ctx)
}

// qualifyReady establishes current visible bytes and new required barriers.
// It proves no earlier flush, move result, backup age or power-loss guarantee.
func (n *namespace) qualifyReady(ctx context.Context, observer phaseObserver) error {
	if n == nil || !n.rootLocked {
		return ErrChanged
	}
	if err := observe(ctx, observer, "ready-before-structure"); err != nil {
		return err
	}
	if err := n.currentReady(ctx); err != nil {
		return err
	}
	if err := observe(ctx, observer, "ready-before-open"); err != nil {
		return err
	}
	file, err := n.root.openFile(ctx, "store.json", false)
	if soleMissing(err) {
		return ErrUncertain
	}
	if err != nil {
		return err
	}
	fail := func(err error) error { return combine(err, releaseFile(file)) }
	if err := observe(ctx, observer, "ready-opened"); err != nil {
		return fail(err)
	}
	stamp, err := readReadyOpened(ctx, file)
	if err != nil {
		return fail(err)
	}
	if stamp.device != n.readyStamp.device || stamp.object != n.readyStamp.object {
		return fail(ErrChanged)
	}
	if err := observe(ctx, observer, "ready-canonical-read-returned"); err != nil {
		return fail(err)
	}
	if err := observe(ctx, observer, "ready-before-file-flush"); err != nil {
		return fail(err)
	}
	if file.Sync() != nil {
		return fail(ErrPersistence)
	}
	if err := observe(ctx, observer, "ready-file-flush-returned"); err != nil {
		return fail(err)
	}
	if err := observe(ctx, observer, "ready-before-file-close"); err != nil {
		return fail(err)
	}
	closeErr := file.Close()
	file = nil
	if closeErr != nil {
		return ErrRelease
	}
	if err := observe(ctx, observer, "ready-checked-close-returned"); err != nil {
		return err
	}
	if err := observe(ctx, observer, "ready-before-parent-barrier"); err != nil {
		return err
	}
	if err := n.root.sync(ctx); err != nil {
		return err
	}
	parentPhase := "ready-parent-check-returned"
	if nativeDirectoryBarrierPhase() != "" {
		parentPhase = "ready-parent-fsync-returned"
	}
	if err := observe(ctx, observer, parentPhase); err != nil {
		return err
	}
	if err := observe(ctx, observer, "ready-before-readback"); err != nil {
		return err
	}
	readback, err := n.root.openFile(ctx, "store.json", false)
	if soleMissing(err) {
		return ErrUncertain
	}
	if err != nil {
		return err
	}
	after, check := readReadyOpened(ctx, readback)
	if check == nil && (stamp.device != after.device || stamp.object != after.object) {
		check = ErrChanged
	}
	check = combine(check, releaseFile(readback))
	if check != nil {
		return check
	}
	return observe(ctx, observer, "ready-canonical-readback-returned")
}
