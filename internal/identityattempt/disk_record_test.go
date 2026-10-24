package identityattempt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

func storeReplaceRecord(t *testing.T, location Location, value Envelope, data []byte) {
	t.Helper()
	_, path := storePaths(t, location, value.Slot())
	if os.WriteFile(path, data, 0o600) != nil {
		t.Fatal("owned record fixture write failed")
	}
}

func TestStoreDiskCanonicalVariantsAndExactPureBoundary(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		variants := []string{"vacant", "occupied"}
		if kind != Lifecycle {
			variants = append(variants, "cancelled")
		}
		for _, variant := range variants {
			t.Run(fmt.Sprintf("%s/%s", kind, variant), func(t *testing.T) {
				store, location := storeReady(t)
				lease, err := store.EnrollFirstUse(storeContext(t), recordSlot(t, kind), SlotNeverUsed)
				if err != nil {
					t.Fatal(err)
				}
				value, err := lease.Read(storeContext(t))
				if err != nil {
					t.Fatal(err)
				}
				if variant != "vacant" {
					value = storeRetain(t, lease)
				}
				if variant == "cancelled" {
					value, err = lease.AppendCancellation(storeContext(t), value, "cancel_001")
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
				positive, err := store.Inspect(storeContext(t), value.Slot())
				if err != nil {
					t.Fatal(err)
				}
				actual, ready := positive.Envelope()
				if !ready || !actual.Equal(value) {
					t.Fatal("canonical round trip changed")
				}
				canonical := recordEncoded(t, value)
				for _, transformed := range [][]byte{
					append([]byte(" "), canonical...), bytes.TrimSuffix(canonical, []byte("\n")), append(slices.Clone(canonical), '\n'),
					bytes.ReplaceAll(canonical, []byte("\n"), []byte("\r\n")), recordReverseObjectOrder(t, canonical),
					bytes.Replace(canonical, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1e0`), 1),
					bytes.Replace(canonical, []byte(fmt.Sprintf(`"revision":%d`, value.Revision())), []byte(fmt.Sprintf(`"revision":%d.0`, value.Revision())), 1),
					bytes.Replace(canonical, []byte(`"org_1"`), []byte(`"\u006frg_1"`), 1),
					bytes.Replace(canonical, []byte(`"schemaVersion"`), []byte(`"schema\u0056ersion"`), 1),
				} {
					if _, err := DecodeEnvelope(transformed, value.Slot()); err != nil {
						t.Fatal("positive pure decoder fixture narrowed")
					}
					storeReplaceRecord(t, location, value, transformed)
					_, err := store.BeginExisting(storeContext(t), value.Slot())
					if err == nil {
						t.Fatal("noncanonical disk bytes accepted")
					}
				}
				storeReplaceRecord(t, location, value, canonical)
				lease, err = store.BeginExisting(storeContext(t), value.Slot())
				if err != nil {
					t.Fatal(err)
				}
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStoreDiskMalformedAndWrongSlotRefuseWithoutRewrite(t *testing.T) {
	_, location, lease, value := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	canonical := recordEncoded(t, value)
	for _, malformed := range [][]byte{
		nil, {0xff}, canonical[:len(canonical)/2],
		bytes.Replace(canonical, []byte(`"revision":2`), []byte(`"revision":9007199254740992`), 1),
		bytes.Replace(canonical, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":2`), 1),
		bytes.Replace(canonical, []byte(`"revision":2`), []byte(`"revision":2,"revision":2`), 1),
		bytes.Replace(canonical, []byte(`"revision"`), []byte(`"Revision"`), 1),
		bytes.Replace(canonical, []byte(`"attempt":`), []byte(`"unknown":`), 1),
		bytes.Replace(canonical, []byte(`"command":`), []byte(`"cancellationId":null,"command":`), 1),
		bytes.Replace(canonical, []byte(`"sandbox"`), []byte(`"production"`), 1),
		bytes.Replace(canonical, []byte(`"org_1"`), []byte(`"org_other"`), 1),
	} {
		storeReplaceRecord(t, location, value, malformed)
		store, err := Open(location)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.BeginExisting(storeContext(t), value.Slot()); err == nil {
			t.Fatal("invalid record admitted")
		}
		_, path := storePaths(t, location, value.Slot())
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, malformed) {
			t.Fatal("invalid bytes repaired automatically")
		}
	}
}

// The values extend the already-accepted exact-bound fixtures through the disk receiver.
func storeMaximumEnvelope(t *testing.T, kind Kind) Envelope {
	t.Helper()
	maximum := identity.SafeInteger(identity.MaximumSafeInteger)
	slot := recordSlot(t, kind)
	if kind == Lifecycle {
		attempt, err := NewLifecycleAttempt(identity.LifecycleAttempt{OperationID: identity.TextFromUnits(slices.Repeat([]uint16{0xd800}, 128)), TargetKind: "subject", ExpectedLifecycleVersion: maximum, State: "suspended"})
		if err != nil {
			t.Fatal(err)
		}
		value, err := NewOccupiedEnvelope(slot, maximum, attempt)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	slot.environment = "production"
	kidLength := 255
	if kind == KeysOnly {
		kidLength = 128
	}
	keys := make([]identity.SigningPublicKey, 32)
	for index := range keys {
		keys[index] = identity.SigningPublicKey{Kty: "EC", Curve: "P-256", X: recordCoordinate, Y: recordCoordinate, Kid: recordText(t, strings.Repeat("k", kidLength-2)+fmt.Sprintf("%02d", index)), Algorithm: new("ES256"), Use: new("sig"), Operations: new([]string{"verify"}), Extractable: new(true)}
		if keys[index].Validate() != nil || kind == KeysOnly && (identity.ReplacementKeys{keys[index]}).Validate() != nil {
			t.Fatal("maximum fixture has invalid individual keys")
		}
	}
	precondition := recordDecode[identity.Precondition](t, recordPrecondition)
	precondition.PublishableKey = strings.Repeat("p", 255)
	precondition.RecoveryGeneration = maximum
	precondition.Scope.EnvironmentKind = "production"
	precondition.Scope.EnvironmentID = identity.TextFromUnits(slices.Repeat([]uint16{0xd800}, 256))
	precondition.Scope.ProjectID = identity.TextFromUnits(slices.Repeat([]uint16{0xdc00}, 256))
	precondition.Scope.RelayScopeID = recordText(t, strings.Repeat("r", 255))
	var attempt Attempt
	var err error
	if kind == KeysOnly {
		attempt, err = NewKeysAttempt(identity.KeysCommand{OperationID: identity.SelectionOperationID(strings.Repeat("o", 96)), ExpectedConfigurationVersion: maximum, Keys: keys, Precondition: precondition})
	} else {
		target := recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
		target.Mode = "provider-bound"
		target.Issuer = new(recordText(t, "https://auth.example.com/"+strings.Repeat("a", 255-len("https://auth.example.com/"))))
		target.Audience = new(recordText(t, strings.Repeat("a", 255)))
		target.SubjectClaim = new("s" + strings.Repeat("a", 63))
		target.Keys = &keys
		attempt, err = NewSelectionAttempt(identity.SelectionCommand{OperationID: identity.SelectionOperationID(strings.Repeat("o", 96)), ExpectedConfigurationVersion: maximum, Target: target, Precondition: precondition})
	}
	if err != nil {
		t.Fatal(err)
	}
	attempt, err = attempt.WithCancellation(identity.CancellationOperationID(strings.Repeat("c", 96)))
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOccupiedEnvelope(slot, maximum, attempt)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestStoreDiskExactMaximumKindsAndHistoricalUTF16(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			value := storeMaximumEnvelope(t, kind)
			data := recordEncoded(t, value)
			bound, err := recordLimit(value.Slot())
			if err != nil || int64(len(data)) != bound {
				t.Fatal("maximum fixture did not reach its actual bound")
			}
			store, location := storeReady(t)
			lease, err := store.EnrollFirstUse(storeContext(t), value.Slot(), SlotNeverUsed)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			storeReplaceRecord(t, location, value, data)
			lease, err = store.BeginExisting(storeContext(t), value.Slot())
			if err != nil {
				t.Fatal(err)
			}
			actual, err := lease.Read(storeContext(t))
			if err != nil || !actual.Equal(value) {
				t.Fatal("maximum canonical record changed")
			}
			_, err = lease.Retain(storeContext(t), value, storeAttempt(t, kind))
			requireStoreError(t, err, ErrChanged)
			if kind == Lifecycle {
				_, err := lease.Confirm(storeContext(t), value, LifecycleResumeAction)
				requireStoreError(t, err, ErrContinuationUnsupported)
			}
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStoreDiskBoundPlusOneAndRepresentability(t *testing.T) {
	_, location, lease, value := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	bound, err := recordLimit(value.Slot())
	if err != nil {
		t.Fatal(err)
	}
	_, path := storePaths(t, location, value.Slot())
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if file.Truncate(bound+1) != nil || file.Close() != nil {
		t.Fatal("oversize fixture failed")
	}
	store, err := Open(location)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.BeginExisting(storeContext(t), value.Slot())
	requireStoreError(t, err, ErrTooLarge)
	for _, lengths := range [][]int{{int(^uint(0) >> 1)}, {-1}, {int(^uint(0)>>1) / 6, 63832}} {
		requireStoreError(t, slotEncodingRepresentable(lengths), ErrTooLarge)
	}
	if err := slotEncodingRepresentable([]int{1, 1024, 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := recordLimit(Slot{}); !errors.Is(err, ErrFormat) {
		t.Fatal("invalid slot bound admitted")
	}
	// OOM is not simulated as a schema error. Native growth races belong to the process roster.
}

func TestStoreDiskRecursiveClosureAndPrivacyCanaries(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			store, location, lease, value := storeOccupied(t, kind)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			canonical := recordEncoded(t, value)
			recordObjectMutations(t, bytes.TrimSpace(canonical), func(bad []byte) {
				storeReplaceRecord(t, location, value, append(bad, '\n'))
				_, err := store.BeginExisting(storeContext(t), value.Slot())
				if err == nil || strings.Contains(err.Error(), "VALUE") {
					t.Fatal("recursive field/privacy refusal failed")
				}
			})
			storeReplaceRecord(t, location, value, canonical)
			for _, name := range []string{"subject", "accountAddress", "profileFingerprint", "assertion", "credential", "session", "locator", "privateKey", "inputDigest", "d"} {
				canary := "PRIVATE_DISK_CANARY_" + name
				var attempt Attempt
				original, _ := value.RetainedAttempt()
				wire, err := original.MarshalJSON()
				if err != nil {
					t.Fatal(err)
				}
				bad := append([]byte(`{"`+name+`":"`+canary+`",`), wire[1:]...)
				if err := attempt.UnmarshalJSON(bad); err == nil || strings.Contains(err.Error(), canary) {
					t.Fatal("private DTO field entered a typed attempt or its failure")
				}
				if attempt.Validate() == nil {
					t.Fatal("failed DTO receiver retained valid authority")
				}
				_, path := storePaths(t, location, value.Slot())
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, canonical) || bytes.Contains(after, []byte(canary)) {
					t.Fatal("private canary reached actual canonical disk")
				}
			}
		})
	}
}

func TestStoreDiskMissingAttemptAndWrongAssociation(t *testing.T) {
	store, location, lease, original := storeOccupied(t, Selection)
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	canonical := recordEncoded(t, original)
	missing := bytes.Replace(canonical, []byte(`,"attempt":`), []byte(`,"other":`), 1)
	storeReplaceRecord(t, location, original, missing)
	_, err := store.BeginExisting(storeContext(t), original.Slot())
	requireStoreError(t, err, ErrFormat)
	storeReplaceRecord(t, location, original, canonical)
	root, _, err := nativeOpenLocation(storeContext(t), location, false)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.subdirectory(storeContext(t), "v1", false)
	if err != nil {
		t.Fatal(err)
	}
	stem, _ := original.Slot().FilenameStem()
	_, err = readRecord(storeContext(t), directory, stem+"wrong", original.Slot())
	requireStoreError(t, err, ErrFormat)
	other := original.Slot()
	other.organization = "org_other"
	_, err = readRecord(storeContext(t), directory, stem, other)
	requireStoreError(t, err, ErrFormat)
	if directory.Close() != nil || root.Close() != nil {
		t.Fatal("association fixture close failed")
	}
}

// This gate schedules real owned-file changes between native stat and read phases.
// It changes no file/lock/reader return value or transaction arbitration.
type storeReadPhaseContext struct {
	context.Context
	calls, selected int
	action          func() error
	failure         error
}

func (c *storeReadPhaseContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	c.calls++
	if c.calls == c.selected {
		c.failure = c.action()
	}
	return c.failure
}

func TestStoreNativeReadGrowthAndLengthChange(t *testing.T) {
	for _, change := range []string{"grow-before-read", "shrink-after-read"} {
		t.Run(change, func(t *testing.T) {
			_, location, lease, value := storeOccupied(t, Selection)
			if err := lease.Close(); err != nil {
				t.Fatal(err)
			}
			_, path := storePaths(t, location, value.Slot())
			reader, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			writer, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if reader.Close() != nil || writer.Close() != nil {
					t.Error("read-race fixture close failed")
				}
			}()
			limit, err := recordLimit(value.Slot())
			if err != nil {
				t.Fatal(err)
			}
			selected := 1
			size := limit + 1
			if change == "shrink-after-read" {
				selected, size = 2, 0
			}
			ctx := &storeReadPhaseContext{Context: storeContext(t), selected: selected, action: func() error { return writer.Truncate(size) }}
			_, err = readOpened(ctx, reader, limit)
			if ctx.failure != nil {
				t.Fatal("native read-change fixture was not established")
			}
			if change == "grow-before-read" {
				requireStoreError(t, err, ErrTooLarge)
			} else {
				requireStoreError(t, err, ErrChanged)
			}
			if ctx.calls < selected {
				t.Fatal("controlled native scheduling point not reached")
			}
		})
	}
}
