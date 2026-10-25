//go:build identity_default_qualification

package identityattempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

var defaultProbeProof = flag.String("identity-default-proof", "", "owned disposable qualification evidence directory")
var defaultProbeNonce = flag.String("identity-default-nonce", "", "owned disposable qualification nonce")
var defaultProbeActor = flag.String("identity-default-actor", "", "fixed same-binary qualification action")

var defaultProbeRefusalObserver func(Location, string, error)

type defaultProbeMarker struct {
	Nonce        string `json:"nonce"`
	Identity     string `json:"identity"`
	Home         string `json:"home,omitempty"`
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	BinarySHA256 string `json:"binarySHA256"`
	GithubHosted bool   `json:"githubHosted"`
}

type defaultProbeEvent struct {
	PID                 int    `json:"pid"`
	Action              string `json:"action"`
	Code                string `json:"code"`
	EnvelopeSHA256      string `json:"envelopeSHA256,omitempty"`
	OriginalID          string `json:"originalId,omitempty"`
	ElapsedMilliseconds int64  `json:"elapsedMilliseconds"`
}

type defaultProbeObject struct {
	Device uint64 `json:"device"`
	Object uint64 `json:"object"`
	Bytes  int64  `json:"fileBytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

func defaultProbeSave(t *testing.T, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(data) > 1048576 {
		t.Fatal("bounded default proof encoding failed")
	}
	file, err := os.OpenFile(filepath.Join(*defaultProbeProof, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("new default proof file unavailable")
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("default proof write or close failed")
	}
}

func defaultProbeLocation(t *testing.T) Location {
	t.Helper()
	proof := *defaultProbeProof
	canonical, err := filepath.EvalSymlinks(proof)
	if err != nil || !filepath.IsAbs(proof) || canonical != filepath.Clean(proof) || !strings.HasPrefix(filepath.Base(proof), "ca8-default-proof-") {
		t.Fatal("an explicitly owned disposable proof directory is required")
	}
	if len(*defaultProbeNonce) != 32 || strings.Trim(*defaultProbeNonce, "0123456789abcdef") != "" {
		t.Fatal("disposable nonce unavailable")
	}
	file, err := os.Open(filepath.Join(proof, "disposable.json"))
	if err != nil {
		t.Fatal("disposable host marker unavailable")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	var marker defaultProbeMarker
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if readErr != nil || closeErr != nil || len(data) > 4096 || decoder.Decode(&marker) != nil ||
		!marker.GithubHosted || marker.Nonce != *defaultProbeNonce || marker.OS != runtime.GOOS || marker.Architecture != runtime.GOARCH {
		t.Fatal("actual disposable identity/architecture marker does not match")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		t.Fatal("disposable marker contains trailing data")
	}
	if os.Getenv("OE_OPERATION_ID") != "" {
		t.Fatal("a disposable default probe cannot inherit an operation ID")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("actual probe executable unavailable")
	}
	binary, err := os.Open(executable)
	if err != nil {
		t.Fatal("actual probe binary unavailable")
	}
	hash := sha256.New()
	count, hashErr := io.Copy(hash, io.LimitReader(binary, 134217729))
	closeErr = binary.Close()
	if hashErr != nil || closeErr != nil || count > 134217728 || hex.EncodeToString(hash.Sum(nil)) != marker.BinarySHA256 {
		t.Fatal("actual probe executable differs from the owned binary")
	}
	location, err := DefaultLocation()
	if err != nil {
		t.Fatal("actual default location prerequisite failed", err)
	}
	principal := defaultQualificationPlatform(t, location)
	if principal["identity"] != marker.Identity {
		t.Fatal("actual OS identity differs from the created disposable caller")
	}
	if marker.Home != "" && principal["home"] != marker.Home {
		t.Fatal("inherited HOME differs from the actual account record")
	}
	return location
}

func defaultProbeAnchorInventory(t *testing.T, location Location) string {
	t.Helper()
	entries, err := os.ReadDir(location.anchor)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatal("actual default anchor inventory unavailable")
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name()+":"+entry.Type().String())
	}
	encoded, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func defaultProbeReadObject(t *testing.T, directory *nativeDirectory, leaf string) (defaultProbeObject, []byte) {
	t.Helper()
	file, err := directory.openFile(storeContext(t), leaf, false)
	if err != nil {
		t.Fatal("native synthetic object open failed", err)
	}
	stamp, stampErr := nativeFileStamp(file, false, true)
	if stampErr != nil || stamp.size < 0 || stamp.size > 2097152 {
		closeErr := file.Close()
		t.Fatal("current bounded native object policy refused", stampErr, closeErr)
	}
	data := make([]byte, int(stamp.size))
	_, readErr := io.ReadFull(file, data)
	after, afterErr := nativeFileStamp(file, false, true)
	closeErr := file.Close()
	if readErr != nil || afterErr != nil || closeErr != nil || after != stamp {
		t.Fatal("bounded native object read changed or failed", readErr, afterErr, closeErr)
	}
	hash := sha256.Sum256(data)
	return defaultProbeObject{stamp.device, stamp.object, stamp.size, hex.EncodeToString(hash[:])}, data
}

func defaultProbeImage(t *testing.T, location Location, witness bool) map[string]defaultProbeObject {
	t.Helper()
	root, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal("actual default namespace native read failed", err)
	}
	defer func() {
		if root.Close() != nil {
			t.Fatal("default namespace handle close failed")
		}
	}()
	result := map[string]defaultProbeObject{}
	for _, name := range []string{"", "locks", "v1"} {
		directory := root
		if name != "" {
			directory, err = root.subdirectory(storeContext(t), name, false)
			if err != nil {
				t.Fatal(err)
			}
		}
		stamp, err := nativeFileStamp(directory.file, true, true)
		if err != nil {
			t.Fatal("native default directory policy refused", err)
		}
		result[name+"/"] = defaultProbeObject{Device: stamp.device, Object: stamp.object}
		if name != "" {
			defer func() {
				if directory.Close() != nil {
					t.Fatal("default child directory close failed")
				}
			}()
		}
		names, err := directory.names()
		if err != nil || len(names) > 8 {
			t.Fatal("default object inventory failed")
		}
		for _, leaf := range names {
			if name == "" && (leaf == "locks" || leaf == "v1") {
				continue
			}
			stem, err := recordSlot(t, Selection).FilenameStem()
			if err != nil {
				t.Fatal(err)
			}
			allowed := name == "" && (leaf == "root.lock" || leaf == "store.json" || witness && leaf == "store.json.d06-witness") ||
				name == "locks" && leaf == stem+".lock" || name == "v1" && leaf == stem+".json"
			if !allowed {
				t.Fatal("unexpected object in owned synthetic namespace")
			}
			object, _ := defaultProbeReadObject(t, directory, leaf)
			result[filepath.ToSlash(filepath.Join(name, leaf))] = object
		}
	}
	return result
}

type defaultProbeCopy struct {
	Source defaultProbeObject `json:"source"`
	Copy   defaultProbeObject `json:"copy"`
	Bytes  int64              `json:"bytes"`
}

// Only the actual ordinary controller copies these fixed synthetic objects.
// Every leased writer and all four fixed actor processes finish before this call.
func defaultProbeHandoff(t *testing.T, location Location, expected map[string]defaultProbeObject, actors []defaultProbeEvent) {
	t.Helper()
	if len(expected) != 7 || len(actors) != 4 || actors[0].Action != "busy" || actors[1].Action != "retain" || actors[2].Action != "read" || actors[3].Action != "uncertain" {
		t.Fatal("the complete closed actor sequence is required before evidence copy")
	}
	destination := filepath.Join(*defaultProbeProof, "D06-handoff")
	if os.Mkdir(destination, 0700) != nil {
		t.Fatal("new standard-user handoff directory unavailable")
	}
	for _, name := range []string{"locks", "v1"} {
		if os.Mkdir(filepath.Join(destination, name), 0700) != nil {
			t.Fatal("new standard-user handoff child unavailable")
		}
	}
	root, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal("synthetic handoff namespace open failed", err)
	}
	defer func() {
		if root.Close() != nil {
			t.Fatal("handoff namespace close failed")
		}
	}()
	stem, err := recordSlot(t, Selection).FilenameStem()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]defaultProbeCopy{}
	var total int64
	for _, group := range []struct {
		directory string
		leaves    []string
	}{
		{"", []string{"root.lock", "store.json.d06-witness"}},
		{"locks", []string{stem + ".lock"}}, {"v1", []string{stem + ".json"}},
	} {
		directory := root
		if group.directory != "" {
			directory, err = root.subdirectory(storeContext(t), group.directory, false)
			if err != nil {
				t.Fatal("handoff native child open failed", err)
			}
			defer func() {
				if directory.Close() != nil {
					t.Fatal("handoff child close failed")
				}
			}()
		}
		for _, leaf := range group.leaves {
			name := filepath.ToSlash(filepath.Join(group.directory, leaf))
			source, data := defaultProbeReadObject(t, directory, leaf)
			total += int64(len(data))
			if source != expected[name] || total > 16777216 {
				t.Fatal("handoff differs from the qualified bounded synthetic image")
			}
			file, err := os.OpenFile(filepath.Join(destination, group.directory, leaf), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
			if err != nil {
				t.Fatal("new synthetic handoff file unavailable", err)
			}
			closed := false
			defer func() {
				if !closed && file.Close() != nil {
					t.Error("handoff file cleanup failed")
				}
			}()
			count, writeErr := file.Write(data)
			syncErr := file.Sync()
			stamp := defaultQualificationEvidenceStamp(t, file)
			readback := make([]byte, len(data))
			readCount, readErr := file.ReadAt(readback, 0)
			after := defaultQualificationEvidenceStamp(t, file)
			closeErr := file.Close()
			closed = true
			if writeErr != nil || syncErr != nil || count != len(data) || readErr != nil || readCount != len(data) || !bytes.Equal(readback, data) || stamp != after || closeErr != nil {
				t.Fatal("synthetic handoff write, native identity, readback or close failed", writeErr, syncErr, readErr, closeErr)
			}
			copy := defaultProbeObject{stamp.device, stamp.object, stamp.size, source.SHA256}
			if copy.Bytes != source.Bytes {
				t.Fatal("synthetic handoff size differs")
			}
			files[name] = defaultProbeCopy{Source: source, Copy: copy, Bytes: int64(len(data))}
		}
	}
	if len(files) != 4 || !reflect.DeepEqual(expected, defaultProbeImage(t, location, true)) {
		t.Fatal("handoff changed or omitted original damaged evidence")
	}
	defaultProbeSave(t, "D06-handoff.json", map[string]any{"originalPath": location.path(), "copyDirectory": "D06-handoff", "files": files, "bytes": total,
		"closedActors": actors, "leasedWritersClosed": true, "originalPreserved": true, "copyBeforeControllerExit": true,
		"policy": "Admin verifies copied native identities and hashes only after all owned Jobs or sessions reach zero. No privileged original reads."})
}

func defaultProbeChild(t *testing.T, action string) defaultProbeEvent {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestIdentityDefaultQualificationActor$", "-test.timeout=27s",
		"-identity-default-proof="+*defaultProbeProof, "-identity-default-nonce="+*defaultProbeNonce, "-identity-default-actor="+action)
	command.Env = os.Environ()
	command.WaitDelay = time.Second
	stdout := &storeActorCapture{limit: 16777216}
	stderr := &storeActorCapture{limit: 16777216}
	command.Stdout, command.Stderr = stdout, stderr
	started := time.Now()
	executionErr := command.Run()
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	for name, data := range map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes()} {
		file, err := os.OpenFile(filepath.Join(*defaultProbeProof, action+"."+name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("actor raw proof file unavailable")
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal("actor raw proof write or close failed")
		}
	}
	stdoutHash := sha256.Sum256(stdout.Bytes())
	defaultProbeSave(t, action+"-process.json", map[string]any{"pid": pid, "elapsedMilliseconds": time.Since(started).Milliseconds(), "exited": command.ProcessState != nil && command.ProcessState.Exited(),
		"stdoutSHA256": hex.EncodeToString(stdoutHash[:]), "stdoutBytes": stdout.Len(), "stderrBytes": stderr.Len(), "stdoutTruncated": stdout.truncated, "stderrTruncated": stderr.truncated})
	if executionErr != nil || command.ProcessState == nil || !command.ProcessState.Exited() || stdout.truncated || stderr.truncated || ctx.Err() != nil {
		t.Fatal("bounded actual default actor failed", executionErr)
	}
	var event defaultProbeEvent
	data, err := os.ReadFile(filepath.Join(*defaultProbeProof, action+".json"))
	if err != nil || len(data) > 1048576 || json.Unmarshal(data, &event) != nil || event.PID != command.Process.Pid || event.Action != action {
		t.Fatal("actual default actor evidence unavailable")
	}
	return event
}

func TestIdentityDefaultQualification(t *testing.T) {
	location := defaultProbeLocation(t)
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	var store *Store
	var closedActors []defaultProbeEvent
	if !t.Run("D01", func(t *testing.T) {
		if _, err := os.Lstat(location.path()); !os.IsNotExist(err) {
			t.Fatal("a fresh disposable default namespace is required")
		}
		before := defaultProbeAnchorInventory(t, location)
		var err error
		store, err = Open(location)
		if err != nil {
			if errors.Is(err, ErrUnsafe) && defaultProbeRefusalObserver != nil {
				defaultProbeRefusalObserver(location, *defaultProbeNonce, err)
			}
			t.Fatal(err)
		}
		observed, err := store.Inspect(ctx, recordSlot(t, Selection))
		if err != nil || observed.State() != AbsentNamespace || before != defaultProbeAnchorInventory(t, location) {
			t.Fatal("default read created state or lost absence", err)
		}
	}) {
		return
	}
	if !t.Run("D02", func(t *testing.T) {
		for _, truth := range []FirstUse{0, SlotNeverUsed} {
			if _, err := BootstrapFirstUse(ctx, location, truth); !errors.Is(err, ErrFirstUseRequired) {
				t.Fatal("wrong namespace declaration accepted")
			}
			if _, err := os.Lstat(location.path()); !os.IsNotExist(err) {
				t.Fatal("wrong namespace declaration created state")
			}
		}
		var err error
		store, err = BootstrapFirstUse(ctx, location, NamespaceNeverUsed)
		if err != nil {
			t.Fatal(err)
		}
		before := defaultProbeImage(t, location, false)
		for _, truth := range []FirstUse{0, NamespaceNeverUsed} {
			if _, err := store.EnrollFirstUse(ctx, recordSlot(t, Selection), truth); !errors.Is(err, ErrFirstUseRequired) {
				t.Fatal("wrong slot declaration accepted")
			}
		}
		if !reflect.DeepEqual(before, defaultProbeImage(t, location, false)) {
			t.Fatal("invalid slot declaration changed state")
		}
	}) {
		return
	}
	if !t.Run("D03", func(t *testing.T) {
		lease, err := store.EnrollFirstUse(ctx, recordSlot(t, Selection), SlotNeverUsed)
		if err != nil {
			t.Fatal(err)
		}
		value, readErr := lease.Read(ctx)
		closeErr := lease.Close()
		if readErr != nil || closeErr != nil || value.Revision() != 1 {
			t.Fatal("native first use failed", readErr, closeErr)
		}
		attempt, err := value.RetainedAttempt()
		if err != nil || attempt != nil {
			t.Fatal("first use invented an operation")
		}
		defaultProbeSave(t, "D03-native.json", defaultProbeImage(t, location, false))
	}) {
		return
	}
	if !t.Run("D04", func(t *testing.T) {
		lease, err := store.BeginExisting(ctx, recordSlot(t, Selection))
		if err != nil {
			t.Fatal(err)
		}
		closed := false
		defer func() {
			if !closed && lease.Close() != nil {
				t.Error("default busy-owner lease close failed")
			}
		}()
		before := defaultProbeImage(t, location, false)
		event := defaultProbeChild(t, "busy")
		closedActors = append(closedActors, event)
		closeErr := lease.Close()
		closed = true
		if event.Code != ErrBusy.Code() || event.ElapsedMilliseconds > 3000 || closeErr != nil || !reflect.DeepEqual(before, defaultProbeImage(t, location, false)) {
			t.Fatal("same-user exclusion lost native state or its acquisition bound")
		}
	}) {
		return
	}
	if !t.Run("D05", func(t *testing.T) {
		retained := defaultProbeChild(t, "retain")
		read := defaultProbeChild(t, "read")
		closedActors = append(closedActors, retained, read)
		if retained.Code != "retain" || read.Code != "read" || retained.EnvelopeSHA256 != read.EnvelopeSHA256 ||
			retained.OriginalID != "original_001" || read.OriginalID != retained.OriginalID {
			t.Fatal("actual process restart changed the retained command")
		}
	}) {
		return
	}
	if !t.Run("D06", func(t *testing.T) {
		before := defaultProbeImage(t, location, false)
		if os.Rename(filepath.Join(location.path(), "store.json"), filepath.Join(location.path(), "store.json.d06-witness")) != nil {
			t.Fatal("owned witness displacement failed")
		}
		event := defaultProbeChild(t, "uncertain")
		closedActors = append(closedActors, event)
		after := defaultProbeImage(t, location, true)
		witness := after["store.json.d06-witness"]
		delete(after, "store.json.d06-witness")
		original := before["store.json"]
		delete(before, "store.json")
		if event.Code != ErrUncertain.Code() || witness != original || !reflect.DeepEqual(before, after) {
			t.Fatal("witness loss replaced or changed original evidence")
		}
		defaultProbeSave(t, "D06-preserved.json", map[string]any{"originalPath": location.path(), "witness": "store.json.d06-witness", "objects": after, "witnessObject": witness,
			"policy": "Preserve exact synthetic bytes before any whole fixture-profile teardown. Never reset first use."})
		expected := make(map[string]defaultProbeObject, len(after)+1)
		for name, object := range after {
			expected[name] = object
		}
		expected["store.json.d06-witness"] = witness
		defaultProbeHandoff(t, location, expected, closedActors)
	}) {
		return
	}
	defaultProbeSave(t, "D-result.json", map[string]any{"success": true, "cases": []string{"D01", "D02", "D03", "D04", "D05", "D06"}, "identity": defaultQualificationPlatform(t, location), "namespacePreserved": true})
}

func TestIdentityDefaultQualificationActor(t *testing.T) {
	location := defaultProbeLocation(t)
	action := *defaultProbeActor
	if action != "busy" && action != "retain" && action != "read" && action != "uncertain" {
		t.Fatal("a fixed default actor action is required")
	}
	started := time.Now()
	event := defaultProbeEvent{PID: os.Getpid(), Action: action}
	store, err := Open(location)
	if action == "uncertain" {
		if !errors.Is(err, ErrUncertain) || errors.Is(err, ErrRelease) {
			t.Fatal("damaged default namespace did not refuse cleanly", err)
		}
		event.Code = ErrUncertain.Code()
	} else {
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		lease, err := store.BeginExisting(ctx, recordSlot(t, Selection))
		if action == "busy" {
			if !errors.Is(err, ErrBusy) || errors.Is(err, ErrRelease) {
				t.Fatal("competing default lease was not cleanly busy", err)
			}
			event.Code = ErrBusy.Code()
		} else {
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			defer func() {
				if !closed && lease.Close() != nil {
					t.Error("default actor lease close failed")
				}
			}()
			value, err := lease.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if action == "retain" {
				value, err = lease.Retain(ctx, value, recordAttempt(t, Selection))
				if err != nil {
					t.Fatal(err)
				}
			}
			attempt, err := value.RetainedAttempt()
			if err != nil || attempt == nil || !attempt.Equal(recordAttempt(t, Selection)) {
				t.Fatal("retained complete command did not survive restart")
			}
			command, err := attempt.SelectionCommand()
			if err != nil {
				t.Fatal(err)
			}
			event.OriginalID = string(command.OperationID)
			data, err := EncodeEnvelope(value)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			event.EnvelopeSHA256, event.Code = hex.EncodeToString(digest[:]), action
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
		}
	}
	event.ElapsedMilliseconds = time.Since(started).Milliseconds()
	defaultProbeSave(t, action+".json", event)
}
