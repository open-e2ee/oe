package identityattempt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/open-e2ee/oe/internal/identity"
)

type storeActorRequest struct {
	Anchor, MarkerRoot, Nonce, Operation, Pause, ID, Cancellation, Expected, SlotWire string
	Start                                                                             bool
	Kind                                                                              Kind
}
type storeActorEvent struct {
	Stage, Code, Original, Cancellation string
	PID                                 int
}
type storeActorGroup interface {
	Attach(*os.Process) error
	Terminate() error
	Wait(context.Context) (error, error)
	Close() error
}
type storeActorProcess struct {
	command         *exec.Cmd
	input           io.WriteCloser
	output          *json.Decoder
	group           storeActorGroup
	ctx             context.Context
	cancel          context.CancelFunc
	finished        bool
	stream          io.Reader
	stdout, stderr  *storeActorCapture
	evidence, nonce string
}

type storeActorCapture struct {
	bytes.Buffer
	truncated bool
	drained   bool
	limit     int
}

func (c *storeActorCapture) Write(data []byte) (int, error) {
	count := len(data)
	limit := c.limit
	if limit == 0 {
		limit = 1048576
	}
	remaining := limit - c.Len()
	if len(data) > remaining {
		c.truncated = true
		data = data[:remaining]
	}
	_, err := c.Buffer.Write(data)
	return count, err
}

func (c *storeActorCapture) ReadFrom(reader io.Reader) (int64, error) {
	c.drained = false
	// Hide ReaderFrom so every byte passes through the bounded Write method.
	count, err := io.Copy(struct{ io.Writer }{c}, reader)
	c.drained = err == nil
	return count, err
}

func TestStoreActorCaptureReadFrom(t *testing.T) {
	for _, test := range []struct {
		name                   string
		limit, count, retained int
		truncated              bool
	}{
		{"default ceiling", 0, 1048577, 1048576, true},
		{"ACL ceiling", 65536, 65537, 65536, true},
		{"exact ceiling", 65536, 65536, 65536, false},
		{"empty EOF", 0, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture := &storeActorCapture{limit: test.limit}
			reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", test.count))}
			count, err := io.Copy(capture, reader)
			if err != nil || count != int64(test.count) || capture.Len() != test.retained || capture.truncated != test.truncated || !capture.drained {
				t.Fatal("capture lost its ceiling or EOF receipt", count, err, capture.Len(), capture.truncated, capture.drained)
			}
		})
	}
	t.Run("reader error is incomplete", func(t *testing.T) {
		failure := errors.New("capture reader failure")
		capture := &storeActorCapture{}
		reader := struct{ io.Reader }{io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(failure))}
		count, err := io.Copy(capture, reader)
		if !errors.Is(err, failure) || count != 3 || capture.String() != "abc" || capture.truncated || capture.drained {
			t.Fatal("capture converted a reader error to completed EOF", count, err, capture.drained)
		}
	})
}

func storeActorEvidenceRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("OE_IDENTITY_STORE_EVIDENCE_ROOT")
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(root) || canonical != filepath.Clean(root) || !strings.HasPrefix(filepath.Base(root), "ca8-store-evidence-") {
		t.Fatal("an explicitly owned native evidence root is required")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatal("native evidence directory unavailable")
	}
	return root
}

type storeActorObserver struct {
	selected string
	output   *json.Encoder
	input    *json.Decoder
}

func (o *storeActorObserver) Observe(stage string) error {
	if stage != o.selected {
		return nil
	}
	if o.output.Encode(storeActorEvent{Stage: stage, PID: os.Getpid()}) != nil {
		return ErrPersistence
	}
	var command string
	if o.input.Decode(&command) != nil || command != "continue" {
		return ErrPersistence
	}
	return nil
}

func actorEnvironment() []string {
	result := []string{"OE_IDENTITY_STORE_NATIVE_ACTOR=1", "OE_OPERATION_ID="}
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TMPDIR", "TMP", "TEMP"} {
		if value, present := os.LookupEnv(name); present {
			result = append(result, name+"="+value)
		}
	}
	return result
}

func startStoreActor(t *testing.T, location Location, request storeActorRequest) *storeActorProcess {
	t.Helper()
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal("fixture nonce failed")
	}
	request.Anchor, request.Nonce = location.anchor, hex.EncodeToString(entropy[:])
	request.MarkerRoot = location.anchor
	if _, err := os.Stat(location.anchor); os.IsNotExist(err) {
		request.MarkerRoot = filepath.Dir(location.anchor)
	}
	marker := filepath.Join(request.MarkerRoot, ".ca8-store-fixture."+request.Nonce)
	evidence := storeActorEvidenceRoot(t)
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("owned actor marker failed")
	}
	if _, err := file.WriteString(request.Nonce); err != nil {
		t.Fatal("owned actor marker failed")
	}
	if file.Close() != nil {
		t.Fatal("owned actor marker close failed")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("test executable unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, executable, "-test.run=^TestAttemptStoreNativeActor$", "-test.timeout=14s")
	command.Env = actorEnvironment()
	command.WaitDelay = time.Second
	group, err := newStoreActorGroup(command)
	if err != nil {
		cancel()
		t.Fatal("native process group setup failed")
	}
	command.Cancel = group.Terminate
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		cleanup := group.Close()
		t.Fatal("actor pipe failed; checked cleanup:", cleanup)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		cleanup := combine(releaseFile(input), group.Close())
		t.Fatal("actor pipe failed; checked cleanup:", cleanup)
	}
	stdout, stderr := &storeActorCapture{}, &storeActorCapture{}
	stream := bufio.NewReader(io.TeeReader(output, stdout))
	command.Stderr = stderr
	actor := &storeActorProcess{command: command, input: input, output: json.NewDecoder(stream), group: group, ctx: ctx, cancel: cancel, stream: stream, stdout: stdout, stderr: stderr, evidence: evidence, nonce: request.Nonce}
	if err := command.Start(); err != nil {
		cancel()
		cleanup := combine(releaseFile(input), group.Close())
		t.Fatal("native actor start failed; checked cleanup:", cleanup)
	}
	if err := group.Attach(command.Process); err != nil {
		killErr := command.Process.Kill()
		waitErr, custodyErr := group.Wait(ctx)
		cancel()
		cleanup := combine(releaseFile(input), group.Close())
		t.Fatal("native process group attachment failed; checked cleanup:", killErr, waitErr, custodyErr, cleanup)
	}
	t.Cleanup(func() { actor.finish(t, true) })
	if json.NewEncoder(input).Encode(request) != nil {
		actor.finish(t, true)
		t.Fatal("actor request failed")
	}
	return actor
}

func (p *storeActorProcess) next(t *testing.T) storeActorEvent {
	t.Helper()
	var event storeActorEvent
	if p.output.Decode(&event) != nil {
		p.finish(t, true)
		t.Fatal("native actor did not report the required event")
	}
	return event
}
func (p *storeActorProcess) continueActor(t *testing.T) {
	t.Helper()
	if json.NewEncoder(p.input).Encode("continue") != nil {
		t.Fatal("actor continuation failed")
	}
}
func (p *storeActorProcess) finish(t *testing.T, killed bool) {
	t.Helper()
	if p.finished {
		return
	}
	p.finished = true
	if killed && p.group.Terminate() != nil {
		t.Error("owned native group termination failed")
	}
	if p.input.Close() != nil {
		t.Error("owned actor input close failed")
	}
	_, drainErr := io.Copy(io.Discard, p.stream)
	err, custodyErr := p.group.Wait(p.ctx)
	if custodyErr != nil {
		t.Error("owned actor wait custody failed:", custodyErr)
	}
	if drainErr != nil {
		t.Error("owned actor stdout drain failed")
	}
	if !killed && err != nil {
		t.Error("native actor failed before normal completion")
	}
	cleanup := p.group.Close()
	if cleanup != nil {
		t.Error("owned native group close/zero-process check failed:", cleanup)
	}
	p.cancel()
	if p.command.ProcessState == nil {
		t.Error("owned actor has no completed reap; output receipt unavailable")
		return
	}
	if !p.stderr.drained {
		t.Error("owned actor stderr did not complete its drain")
	}
	if p.stdout.truncated || p.stderr.truncated {
		t.Error("owned actor output exceeded1MiB evidence ceiling")
	}
	exit := -1
	if p.command.ProcessState != nil {
		exit = p.command.ProcessState.ExitCode()
	}
	result, encodeErr := json.Marshal(struct {
		Argv                                                []string
		Exit                                                int
		Killed, ZeroGroup, StdoutTruncated, StderrTruncated bool
		StderrDrained                                       bool
	}{p.command.Args, exit, killed, cleanup == nil, p.stdout.truncated, p.stderr.truncated, p.stderr.drained})
	if encodeErr != nil {
		t.Error("actor result encoding failed")
	}
	for name, data := range map[string][]byte{"stdout.log": p.stdout.Bytes(), "stderr.log": p.stderr.Bytes(), "result.json": append(result, '\n')} {
		file, writeErr := os.OpenFile(filepath.Join(p.evidence, p.nonce+"."+name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if writeErr != nil {
			t.Error("actor evidence creation failed")
			continue
		}
		_, writeErr = file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Error("actor evidence write/close failed")
		}
	}
}

func actorOriginal(t *testing.T, envelope Envelope) (string, string) {
	t.Helper()
	attempt, err := envelope.RetainedAttempt()
	if err != nil || attempt == nil {
		return "", ""
	}
	var original string
	switch attempt.Kind() {
	case Selection:
		command, _ := attempt.SelectionCommand()
		original = string(command.OperationID)
	case KeysOnly:
		command, _ := attempt.KeysCommand()
		original = string(command.OperationID)
	case Lifecycle:
		command, _ := attempt.LifecycleCommand()
		original, _ = command.OperationID.ScalarString()
	}
	id, _ := attempt.CancellationID()
	return original, string(id)
}

func actorAttempt(t *testing.T, kind Kind, id string) Attempt {
	t.Helper()
	attempt := storeAttempt(t, kind)
	if id == "" {
		return attempt
	}
	var result Attempt
	var err error
	switch kind {
	case Selection:
		command, _ := attempt.SelectionCommand()
		command.OperationID = identity.SelectionOperationID(id)
		result, err = NewSelectionAttempt(command)
	case KeysOnly:
		command, _ := attempt.KeysCommand()
		command.OperationID = identity.SelectionOperationID(id)
		result, err = NewKeysAttempt(command)
	case Lifecycle:
		command, _ := attempt.LifecycleCommand()
		command.OperationID = recordText(t, id)
		result, err = NewLifecycleAttempt(command)
	}
	if err != nil {
		t.Fatal("actor command fixture invalid")
	}
	return result
}

func TestAttemptStoreNativeActor(t *testing.T) {
	if os.Getenv("OE_IDENTITY_STORE_NATIVE_ACTOR") != "1" {
		return
	}
	input, output := json.NewDecoder(io.LimitReader(os.Stdin, 65536)), json.NewEncoder(os.Stdout)
	var request storeActorRequest
	if input.Decode(&request) != nil || len(request.Nonce) != 32 || !filepath.IsAbs(request.Anchor) {
		t.Fatal("invalid native actor request")
	}
	if _, err := hex.DecodeString(request.Nonce); err != nil {
		t.Fatal("invalid native actor nonce")
	}
	if request.MarkerRoot != request.Anchor && request.MarkerRoot != filepath.Dir(request.Anchor) {
		t.Fatal("native actor marker is outside fixture scope")
	}
	marker, err := os.ReadFile(filepath.Join(request.MarkerRoot, ".ca8-store-fixture."+request.Nonce))
	if err != nil || string(marker) != request.Nonce {
		t.Fatal("native actor lacks owned fixture marker")
	}
	location := Location{anchor: request.Anchor, managed: managedDirectoryNames()}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	observer := &storeActorObserver{request.Pause, output, input}
	if request.Start {
		armed := &storeActorObserver{"armed", output, input}
		if armed.Observe("armed") != nil {
			t.Fatal("native actor start barrier failed")
		}
	}
	var slot Slot
	if request.Operation != "bootstrap" && request.Operation != "sleep" {
		slot = recordSlot(t, request.Kind)
	}
	if request.SlotWire != "" {
		slot, err = DecodeSlot([]byte(request.SlotWire))
		if err != nil {
			t.Fatal("native actor exact slot fixture invalid")
		}
	}
	if request.Operation == "bootstrap" {
		location.observer = observer
		_, err = BootstrapFirstUse(ctx, location, NamespaceNeverUsed)
	} else if request.Operation == "sleep" {
		if output.Encode(storeActorEvent{Stage: "grandchild-ready", PID: os.Getpid()}) != nil {
			t.Fatal("grandchild report failed")
		}
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		return
	} else {
		store, openErr := Open(location)
		if openErr != nil {
			err = openErr
		} else {
			var lease *Lease
			if request.Operation == "enroll" {
				store.location.observer = observer
				lease, err = store.EnrollFirstUse(ctx, slot, SlotNeverUsed)
			} else {
				lease, err = store.BeginExisting(ctx, slot)
			}
			if err == nil && lease != nil {
				current, readErr := lease.Read(ctx)
				err = readErr
				if err == nil {
					switch request.Operation {
					case "hold":
						err = observer.Observe("held")
					case "inherit":
						err = runStoreGrandchild(t, location, request, output, observer)
					case "retain":
						if request.Kind == Lifecycle {
							var permit *PreparationPermit
							permit, err = lease.ConfirmPreparation(ctx, current)
							if err == nil {
								var call *PreparationCall
								call, err = permit.Begin(ctx)
								if err == nil {
									err = call.Join()
								}
							}
						}
						lease.observer = observer
						if err == nil {
							_, err = lease.Retain(ctx, current, actorAttempt(t, request.Kind, request.ID))
						}
					case "confirm":
						lease.observer = observer
						action := SelectionApplyAction
						attempt, _ := current.RetainedAttempt()
						if request.Kind == KeysOnly {
							action = KeysReplaceAction
						}
						if request.Kind == Lifecycle {
							action = LifecycleApplyAction
						}
						if attempt != nil {
							if _, present := attempt.CancellationID(); present {
								if request.Kind == Selection {
									action = SelectionCancelAction
								} else {
									action = KeysCancelAction
								}
							}
						}
						_, err = lease.Confirm(ctx, current, action)
					case "prepare-confirm":
						lease.observer = observer
						_, err = lease.ConfirmPreparation(ctx, current)
					case "cancel":
						lease.observer = observer
						_, err = lease.AppendCancellation(ctx, current, identity.CancellationOperationID(request.Cancellation))
					case "settle":
						lease.observer = observer
						storeResolveSettled(t, lease, current)
					case "late":
						expected, decodeErr := DecodeEnvelope([]byte(request.Expected), current.Slot())
						if decodeErr != nil {
							t.Fatal("late result fixture invalid")
						}
						if request.Kind == Selection {
							_, err = lease.ResolveSelection(ctx, expected, storeSelectionReceipt(t, expected, "applied", identity.SelectionApply))
						} else {
							_, err = lease.ResolveKeys(ctx, expected, storeKeysReceipt(t, expected, "applied", identity.KeysReplace))
						}
					}
				}
				final, readErr := lease.Read(ctx)
				if readErr == nil {
					original, cancellation := actorOriginal(t, final)
					if output.Encode(storeActorEvent{Stage: "snapshot", Original: original, Cancellation: cancellation, PID: os.Getpid()}) != nil {
						t.Fatal("actor snapshot report failed")
					}
				}
				err = combine(err, lease.Close())
			}
		}
	}
	code := "ok"
	for _, candidate := range []*Failure{ErrChanged, ErrBusy, ErrUncertain, ErrAlreadyInitialized, ErrFirstUseRequired, ErrPersistence} {
		if errors.Is(err, candidate) {
			code = candidate.Code()
		}
	}
	if errors.Is(err, ErrRelease) {
		code = ErrRelease.Code()
	}
	if err != nil && code == "ok" {
		code = "unclassified-failure"
	}
	if output.Encode(storeActorEvent{Stage: "done", Code: code, PID: os.Getpid()}) != nil {
		t.Fatal("actor completion report failed")
	}
}

func runStoreGrandchild(t *testing.T, location Location, request storeActorRequest, output *json.Encoder, observer *storeActorObserver) (result error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		return ErrPersistence
	}
	command := exec.Command(executable, "-test.run=^TestAttemptStoreNativeActor$", "-test.timeout=12s")
	command.Env = actorEnvironment()
	input, err := command.StdinPipe()
	if err != nil {
		return ErrPersistence
	}
	reader, err := command.StdoutPipe()
	if err != nil {
		return combine(ErrPersistence, releaseFile(input))
	}
	command.Stderr = os.Stderr
	if command.Start() != nil {
		return combine(ErrPersistence, releaseFile(input))
	}
	defer func() {
		if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			result = combine(result, ErrRelease)
		}
		result = combine(result, releaseFile(input))
		if err := command.Wait(); err != nil {
			if _, ok := err.(*exec.ExitError); !ok {
				result = combine(result, ErrRelease)
			}
		}
	}()
	request.Operation, request.Pause, request.Start = "sleep", "", false
	if json.NewEncoder(input).Encode(request) != nil {
		return ErrPersistence
	}
	var ready storeActorEvent
	if json.NewDecoder(reader).Decode(&ready) != nil || ready.Stage != "grandchild-ready" {
		return ErrPersistence
	}
	if output.Encode(ready) != nil {
		return ErrPersistence
	}
	return observer.Observe("held")
}

func TestStoreNativeInterruptionMatrix(t *testing.T) {
	contexts := []string{"initial-vacant-selection", "initial-vacant-keys", "initial-vacant-lifecycle", "retain-selection", "retain-keys", "retain-lifecycle", "cancel-selection", "cancel-keys", "settle-selection", "settle-keys", "settle-lifecycle"}
	phases := []string{"temporary-created", "partial-write-observed", "complete-write-returned", "file-flush-returned", "checked-close-returned", "rename-returned", "parent-fsync-returned", "canonical-readback-returned"}
	if runtime.GOOS == "windows" {
		phases = []string{"temporary-created", "partial-write-observed", "complete-write-returned", "file-flush-returned", "checked-close-returned", "move-with-write-through-returned", "canonical-readback-returned"}
	}
	for _, name := range contexts {
		for _, point := range phases {
			if !t.Run(name+"/"+point, func(t *testing.T) {
				store, location := storeReady(t)
				kind := Selection
				if strings.HasSuffix(name, "keys") {
					kind = KeysOnly
				}
				if strings.HasSuffix(name, "lifecycle") {
					kind = Lifecycle
				}
				operation := strings.Split(name, "-")[0]
				if operation == "initial" {
					operation = "enroll"
				}
				slot := recordSlot(t, kind)
				var before []byte
				var next Envelope
				if operation == "enroll" {
					next, _ = NewVacantEnvelope(slot, 1)
				}
				if operation != "enroll" {
					lease, err := store.EnrollFirstUse(storeContext(t), slot, SlotNeverUsed)
					if err != nil {
						t.Fatal(err)
					}
					value, err := lease.Read(storeContext(t))
					if err != nil {
						t.Fatal(err)
					}
					if operation == "cancel" || operation == "settle" {
						value = storeRetain(t, lease)
					}
					before = recordEncoded(t, value)
					switch operation {
					case "retain":
						next, err = NewOccupiedEnvelope(slot, value.Revision()+1, storeAttempt(t, kind))
					case "cancel":
						attempt, _ := value.RetainedAttempt()
						enriched, appendErr := attempt.WithCancellation("cancel_001")
						if appendErr != nil {
							t.Fatal(appendErr)
						}
						next, err = NewOccupiedEnvelope(slot, value.Revision()+1, enriched)
					case "settle":
						next, err = NewVacantEnvelope(slot, value.Revision()+1)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := lease.Close(); err != nil {
						t.Fatal(err)
					}
				}
				actor := startStoreActor(t, location, storeActorRequest{Kind: kind, Operation: operation, Pause: point, Cancellation: "cancel_001"})
				if event := actor.next(t); event.Stage != point {
					t.Fatal("wrong native phase observed")
				}
				actor.finish(t, true)
				_, path := storePaths(t, location, slot)
				after, err := os.ReadFile(path)
				postReplace := point == "rename-returned" || point == "move-with-write-through-returned" || point == "parent-fsync-returned" || point == "canonical-readback-returned"
				if postReplace {
					if err != nil {
						t.Fatal("installed canonical record missing after process termination")
					}
					value, err := DecodeEnvelope(after, slot)
					if err != nil || !value.Equal(next) || !bytes.Equal(after, recordEncoded(t, next)) {
						t.Fatal("post-replace record did not become the exact intended next state")
					}
					lease, err := store.BeginExisting(storeContext(t), slot)
					if err != nil {
						t.Fatal(err)
					}
					actual, err := lease.Read(storeContext(t))
					if err != nil || !actual.Equal(value) {
						t.Fatal("post-kill state changed")
					}
					if err := lease.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					if before == nil {
						if !os.IsNotExist(err) {
							t.Fatal("pre-replace initial record appeared")
						}
					} else if err != nil || !bytes.Equal(before, after) {
						t.Fatal("pre-replace original changed")
					}
					_, err := store.BeginExisting(storeContext(t), slot)
					requireStoreError(t, err, ErrUncertain)
				}
			}) {
				return
			}
		}
	}
}

func TestStoreNativeBootstrapAndEnrollmentInterruptions(t *testing.T) {
	for _, point := range []string{"root-directory-created", "root-lock-created", "directories-created", "ready-manifest-installed-before-final-barriers", "manifest-readback"} {
		if !t.Run("bootstrap/"+point, func(t *testing.T) {
			location := storeFixtureLocation(t)
			actor := startStoreActor(t, location, storeActorRequest{Operation: "bootstrap", Pause: point})
			if actor.next(t).Stage != point {
				t.Fatal("wrong bootstrap phase")
			}
			actor.finish(t, true)
			_, err := Open(location)
			if point == "ready-manifest-installed-before-final-barriers" || point == "manifest-readback" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireStoreError(t, err, ErrUncertain)
			}
		}) {
			return
		}
	}
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		for _, point := range []string{"slot-lock-created", "slot-lock-synced", "slot-vacant-readback"} {
			if !t.Run(string(kind)+"/"+point, func(t *testing.T) {
				store, location := storeReady(t)
				actor := startStoreActor(t, location, storeActorRequest{Operation: "enroll", Kind: kind, Pause: point})
				if actor.next(t).Stage != point {
					t.Fatal("wrong slot phase")
				}
				actor.finish(t, true)
				lease, err := store.BeginExisting(storeContext(t), recordSlot(t, kind))
				if point != "slot-vacant-readback" {
					requireStoreError(t, err, ErrUncertain)
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				value, err := lease.Read(storeContext(t))
				attempt, _ := value.RetainedAttempt()
				if err != nil || attempt != nil || value.Revision() != 1 {
					t.Fatal("interrupted initial vacancy changed")
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			}) {
				return
			}
		}
	}
}

func TestStoreNativeContentionAndWinningOriginal(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		if !t.Run(string(kind), func(t *testing.T) {
			store, location := storeReady(t)
			lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			var actors []*storeActorProcess
			for index := range 5 {
				id := fmt.Sprintf("original_%03d", index)
				if kind == Lifecycle {
					id = fmt.Sprintf("lc1_%016x_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", index)
				}
				actors = append(actors, startStoreActor(t, location, storeActorRequest{Operation: "retain", Kind: kind, ID: id, Start: true}))
			}
			for _, actor := range actors {
				if actor.next(t).Stage != "armed" {
					t.Fatal("contender start barrier missing")
				}
			}
			for _, actor := range actors {
				actor.continueActor(t)
			}
			winners := 0
			var snapshots []storeActorEvent
			for _, actor := range actors {
				for count := 0; count < 3; count++ {
					event := actor.next(t)
					if event.Stage == "snapshot" {
						snapshots = append(snapshots, event)
						continue
					}
					if event.Stage != "done" {
						t.Fatal("unexpected contender event")
					}
					if event.Code == "ok" {
						winners++
					} else if event.Code != ErrChanged.Code() && event.Code != ErrBusy.Code() {
						t.Fatal("unexpected contention outcome")
					}
					break
				}
				actor.finish(t, false)
			}
			if winners != 1 {
				t.Fatal("native contenders did not elect one original")
			}
			finalLease, err := store.BeginExisting(storeContext(t), recordSlot(t, kind))
			if err != nil {
				t.Fatal(err)
			}
			final, err := finalLease.Read(storeContext(t))
			if err != nil {
				t.Fatal(err)
			}
			original, _ := actorOriginal(t, final)
			if original == "" {
				t.Fatal("native winner lost original")
			}
			for _, snapshot := range snapshots {
				if snapshot.Original != original {
					t.Fatal("contender changed or observed a different winner")
				}
			}
			if err := finalLease.Close(); err != nil {
				t.Fatal(err)
			}

		}) {
			return
		}
	}
}

func TestStoreNativeOwnerDeathAndNoInheritedLock(t *testing.T) {
	store, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	actor := startStoreActor(t, location, storeActorRequest{Operation: "inherit", Kind: Selection, Pause: "held"})
	child := actor.next(t)
	if child.Stage != "grandchild-ready" || child.PID == 0 {
		t.Fatal("grandchild did not start")
	}
	if actor.next(t).Stage != "held" {
		t.Fatal("owner lock not observed")
	}
	if actor.command.Process.Kill() != nil {
		t.Fatal("owner termination failed")
	}
	if !storeActorAlive(child.PID) {
		t.Fatal("inheritance fixture lost its live grandchild")
	}
	newLease, err := store.BeginExisting(storeContext(t), original.Slot())
	if err != nil {
		t.Fatal("grandchild retained a native lock or release did not occur within observed budget", err)
	}
	if err := newLease.Close(); err != nil {
		t.Fatal(err)
	}
	actor.finish(t, true)
}

func storeActorDone(t *testing.T, actor *storeActorProcess) storeActorEvent {
	t.Helper()
	for range 3 {
		event := actor.next(t)
		if event.Stage == "done" {
			actor.finish(t, false)
			return event
		}
		if event.Stage != "snapshot" {
			t.Fatal("unexpected native actor completion event")
		}
	}
	t.Fatal("native actor completion bound exceeded")
	return storeActorEvent{}
}

func TestStoreNativeBootstrapAndSlotElections(t *testing.T) {
	for _, operation := range []string{"bootstrap", "enroll"} {
		t.Run(operation, func(t *testing.T) {
			location := storeFixtureLocation(t)
			if operation == "enroll" {
				_, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed)
				if err != nil {
					t.Fatal(err)
				}
			}
			var actors []*storeActorProcess
			for range 2 {
				actors = append(actors, startStoreActor(t, location, storeActorRequest{Operation: operation, Kind: Selection, Start: true}))
			}
			for _, actor := range actors {
				if actor.next(t).Stage != "armed" {
					t.Fatal("election actor not armed")
				}
			}
			for _, actor := range actors {
				actor.continueActor(t)
			}
			winners := 0
			for _, actor := range actors {
				outcome := storeActorDone(t, actor)
				if outcome.Code == "ok" {
					winners++
				} else if outcome.Code != ErrAlreadyInitialized.Code() {
					t.Fatal("unexpected native election loser")
				}
			}
			if winners != 1 {
				t.Fatal("native first use did not elect exactly one creator")
			}
			store, err := Open(location)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "enroll" {
				lease, err := store.BeginExisting(storeContext(t), recordSlot(t, Selection))
				if err != nil {
					t.Fatal(err)
				}
				before, err := nativeFileStamp(lease.lock, false, true)
				if err != nil {
					t.Fatal(err)
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				lease, err = store.BeginExisting(storeContext(t), recordSlot(t, Selection))
				if err != nil {
					t.Fatal(err)
				}
				after, err := nativeFileStamp(lease.lock, false, true)
				if err != nil || before != after {
					t.Fatal("slot election replaced stable lock object")
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestStoreNativeIndependentAddressedSlots(t *testing.T) {
	store, location := storeReady(t)
	original := recordSlot(t, Selection)
	first, err := store.EnrollFirstUse(storeContext(t), original, SlotNeverUsed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	}()
	variants := []Slot{original, original, original, original, recordSlot(t, KeysOnly)}
	variants[0].base, err = identity.ParseControlBaseURL("https://control.example/other/api/cli")
	if err != nil {
		t.Fatal(err)
	}
	variants[1].organization = "org_other"
	variants[2].project = "other-project"
	variants[3].environment = "production"
	for _, slot := range variants {
		wire, err := EncodeSlot(slot)
		if err != nil {
			t.Fatal(err)
		}
		actor := startStoreActor(t, location, storeActorRequest{Operation: "enroll", Kind: slot.Kind(), SlotWire: string(wire)})
		if done := storeActorDone(t, actor); done.Code != "ok" {
			t.Fatal("independent slot blocked behind another slot", done.Code)
		}
	}
}

func TestStoreNativeCancellationWinnerAndLateOriginal(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly} {
		t.Run(string(kind), func(t *testing.T) {
			store, location, lease, original := storeOccupied(t, kind)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			var actors []*storeActorProcess
			for _, id := range []string{"cancel_001", "cancel_002"} {
				actors = append(actors, startStoreActor(t, location, storeActorRequest{Operation: "cancel", Kind: kind, Cancellation: id, Start: true}))
			}
			for _, actor := range actors {
				if actor.next(t).Stage != "armed" {
					t.Fatal("cancellation actor not armed")
				}
			}
			for _, actor := range actors {
				actor.continueActor(t)
			}
			winners := 0
			for _, actor := range actors {
				done := storeActorDone(t, actor)
				if done.Code == "ok" {
					winners++
				} else if done.Code != ErrChanged.Code() {
					t.Fatal("unexpected cancellation outcome", done.Code)
				}
			}
			if winners != 1 {
				t.Fatal("cancellation did not elect one durable ID")
			}
			lease, err := store.BeginExisting(storeContext(t), original.Slot())
			if err != nil {
				t.Fatal(err)
			}
			enriched, err := lease.Read(storeContext(t))
			if err != nil {
				t.Fatal(err)
			}
			attempt, _ := enriched.RetainedAttempt()
			id, present := attempt.CancellationID()
			if !present || id != "cancel_001" && id != "cancel_002" || enriched.Revision() != original.Revision()+1 {
				t.Fatal("durable cancellation winner changed")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			late := startStoreActor(t, location, storeActorRequest{Operation: "late", Kind: kind, Expected: string(recordEncoded(t, original))})
			if done := storeActorDone(t, late); done.Code != ErrChanged.Code() {
				t.Fatal("late original result cleared enrichment", done.Code)
			}
			observation, err := store.Inspect(storeContext(t), original.Slot())
			actual, ready := observation.Envelope()
			if err != nil || !ready || !actual.Equal(enriched) {
				t.Fatal("late original changed exact enriched record")
			}
		})
	}
}

func TestStoreNativeLateOldResultAgainstReoccupiedSlot(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly} {
		t.Run(string(kind), func(t *testing.T) {
			store, location, lease, original := storeOccupied(t, kind)
			settled := storeResolveSettled(t, lease, original)
			vacant, err := settled.Envelope()
			if err != nil || vacant.Revision() != original.Revision()+1 {
				t.Fatal("settlement fixture failed")
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			lease, err = store.BeginExisting(storeContext(t), original.Slot())
			if err != nil {
				t.Fatal(err)
			}
			newAttempt := actorAttempt(t, kind, "original_later")
			newer, err := lease.Retain(storeContext(t), vacant, newAttempt)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			late := startStoreActor(t, location, storeActorRequest{Operation: "late", Kind: kind, Expected: string(recordEncoded(t, original))})
			if done := storeActorDone(t, late); done.Code != ErrChanged.Code() {
				t.Fatal("late old result resolved a later original")
			}
			observation, err := store.Inspect(storeContext(t), original.Slot())
			actual, ready := observation.Envelope()
			if err != nil || !ready || !actual.Equal(newer) {
				t.Fatal("later original was altered")
			}
		})
	}
}

func TestStoreNativeAcquisitionTimeoutCreatesNothing(t *testing.T) {
	store, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	actor := startStoreActor(t, location, storeActorRequest{Operation: "hold", Kind: Selection, Pause: "held"})
	if actor.next(t).Stage != "held" {
		t.Fatal("native lock holder not observed")
	}
	before, err := os.ReadDir(filepath.Join(location.path(), "v1"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = store.BeginExisting(ctx, original.Slot())
	requireStoreError(t, err, ErrBusy)
	if time.Since(start) > acquisitionLimit+time.Second {
		t.Fatal("native acquisition did not return within observed budget")
	}
	after, err := os.ReadDir(filepath.Join(location.path(), "v1"))
	if err != nil || len(before) != len(after) {
		t.Fatal("acquisition timeout created state")
	}
	for index := range before {
		if before[index].Name() != after[index].Name() {
			t.Fatal("acquisition timeout changed record names")
		}
	}
	actor.continueActor(t)
	if done := storeActorDone(t, actor); done.Code != "ok" {
		t.Fatal("native winner was disturbed")
	}
}

func TestStoreNativeSelectedAnchorConcurrentAndInterrupted(t *testing.T) {
	t.Run("concurrent-final-anchor", func(t *testing.T) {
		location := storeFixtureLocation(t)
		location.anchor = filepath.Join(location.anchor, "selected-config")
		// Marker creation needs an existing fixture parent, not the absent selected anchor.
		// This case uses the explicit native actor marker directory carried separately.
		first := startStoreActor(t, location, storeActorRequest{Operation: "bootstrap", Pause: "selected-anchor-created"})
		if first.next(t).Stage != "selected-anchor-created" {
			t.Fatal("new selected anchor not observed")
		}
		second := startStoreActor(t, location, storeActorRequest{Operation: "bootstrap"})
		if done := storeActorDone(t, second); done.Code != "ok" {
			t.Fatal("concurrent safe existing anchor did not permit namespace election")
		}
		first.continueActor(t)
		if done := storeActorDone(t, first); done.Code != ErrAlreadyInitialized.Code() {
			t.Fatal("first anchor creator replaced namespace winner")
		}
	})
	t.Run("anchor-exit-no-admission", func(t *testing.T) {
		location := storeFixtureLocation(t)
		location.anchor = filepath.Join(location.anchor, "selected-config")
		actor := startStoreActor(t, location, storeActorRequest{Operation: "bootstrap", Pause: "selected-anchor-created"})
		if actor.next(t).Stage != "selected-anchor-created" {
			t.Fatal("new selected anchor not observed")
		}
		actor.finish(t, true)
		store, err := Open(location)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.BeginExisting(storeContext(t), recordSlot(t, Selection)); !errors.Is(err, ErrFirstUseRequired) {
			t.Fatal("anchor alone granted admission")
		}
		if _, err := BootstrapFirstUse(storeContext(t), location, NamespaceNeverUsed); err != nil {
			t.Fatal("truthful explicit bootstrap could not use safe existing anchor", err)
		}
	})
}

func TestStoreNativeReadyRepeatInterruptionMatrix(t *testing.T) {
	for _, name := range storeReadyContexts() {
		for _, point := range []string{"ready-file-flush-returned", "ready-checked-close-returned", storeReadyParentPoint(), "ready-canonical-readback-returned"} {
			if !t.Run(name+"/"+point, func(t *testing.T) {
				fixture := storeReadyCase(t, name)
				if err := fixture.lease.Close(); err != nil {
					t.Fatal(err)
				}
				manifest := filepath.Join(fixture.location.path(), "store.json")
				before, err := os.Stat(manifest)
				if err != nil {
					t.Fatal(err)
				}
				operation := "confirm"
				if fixture.preparation {
					operation = "prepare-confirm"
				}
				actor := startStoreActor(t, fixture.location, storeActorRequest{Operation: operation, Kind: fixture.expected.Slot().Kind(), Pause: point})
				if actor.next(t).Stage != point {
					t.Fatal("wrong repeated ready native boundary")
				}
				actor.finish(t, true)
				after, err := os.Stat(manifest)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("ready interruption replaced manifest")
				}
				data, err := os.ReadFile(manifest)
				if err != nil || string(data) != readyManifest {
					t.Fatal("ready interruption altered manifest bytes")
				}
				lease, err := fixture.store.BeginExisting(storeContext(t), fixture.expected.Slot())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := lease.Close(); err != nil {
						t.Error(err)
					}
				}()
				actual, err := lease.Read(storeContext(t))
				if err != nil || !actual.Equal(fixture.expected) {
					t.Fatal("ready interruption altered full original/cancellation context")
				}
				fresh := fixture
				fresh.lease = lease
				if minted, err := fresh.confirm(storeContext(t)); err != nil || !minted {
					t.Fatal("complete current state could not receive a new qualification", err)
				}
				// A new successful qualification proves no former barrier or prior move return.
			}) {
				return
			}
		}
	}
}

func TestStoreNativeVisibleReadyAfterFormerBarrierInterruption(t *testing.T) {
	for _, preparation := range []bool{false, true} {
		if !t.Run(map[bool]string{false: "occupied", true: "preparation"}[preparation], func(t *testing.T) {
			location := storeFixtureLocation(t)
			actor := startStoreActor(t, location, storeActorRequest{Operation: "bootstrap", Pause: "ready-manifest-installed-before-final-barriers"})
			if actor.next(t).Stage != "ready-manifest-installed-before-final-barriers" {
				t.Fatal("actual manifest install boundary not observed")
			}
			actor.finish(t, true)
			store, err := Open(location)
			if err != nil {
				t.Fatal("complete visible canonical namespace refused", err)
			}
			kind := Selection
			if preparation {
				kind = Lifecycle
			}
			lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := lease.Close(); err != nil {
					t.Error(err)
				}
			}()
			value, err := lease.Read(storeContext(t))
			if err != nil {
				t.Fatal(err)
			}
			if !preparation {
				value = storeRetain(t, lease)
			}
			fixture := storeReadyFixture{store: store, location: location, lease: lease, expected: value, preparation: preparation, action: SelectionApplyAction}
			minted, err := fixture.confirm(storeContext(t))
			if err != nil || !minted {
				t.Fatal("new current qualification failed", err)
			}
			// This observes a running kernel after process exit. It is not a power-loss test.
		}) {
			return
		}
	}
}
