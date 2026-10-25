//go:build identity_default_qualification

package identityattempt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func refusalCodecFixture() []byte {
	data := make([]byte, 60)
	data[0] = 1
	binary.LittleEndian.PutUint16(data[2:4], 0x8004)
	binary.LittleEndian.PutUint32(data[4:8], 20)
	binary.LittleEndian.PutUint32(data[16:20], 32)
	copy(data[20:32], []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})
	data[32] = 2
	binary.LittleEndian.PutUint16(data[34:36], 28)
	binary.LittleEndian.PutUint16(data[36:38], 1)
	data[41] = 0x10
	binary.LittleEndian.PutUint16(data[42:44], 20)
	binary.LittleEndian.PutUint32(data[44:48], 0x001f01ff)
	copy(data[48:60], []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	return data
}

func TestDefaultRefusalCodecReportsWithoutPolicy(t *testing.T) {
	data := refusalCodecFixture()
	decoded, err := refusalDecode(data, nil)
	if err != nil || decoded.Owner != "S-1-5-18" || !decoded.DACLPresent || decoded.DACLNull || decoded.ACECount != 1 {
		t.Fatal("valid descriptor metadata differs", err)
	}
	ace := decoded.ACEs[0]
	if ace.SID != "S-1-1-0" || ace.Mask == nil || *ace.Mask != 0x001f01ff || ace.Flags != 0x10 || ace.SHA256 != refusalHash(data[40:60]) {
		t.Fatal("raw effective grant metadata differs")
	}
	for _, kind := range []byte{1, 5, 0x11, 0xff} {
		data[40] = kind
		decoded, err = refusalDecode(data, nil)
		if err != nil {
			t.Fatal("bounded ACE metadata refused", kind, err)
		}
		if kind != 1 && (decoded.ACEs[0].Mask != nil || decoded.ACEs[0].SID != "") {
			t.Fatal("unknown ACE layout gained an interpreted SID or mask")
		}
	}
	binary.LittleEndian.PutUint32(data[16:20], 0)
	decoded, err = refusalDecode(data[:32], nil)
	if err != nil || !decoded.DACLNull || !decoded.DACLPresent {
		t.Fatal("null DACL facts were lost")
	}
}

func TestDefaultRefusalCodecRejectsMalformedSpans(t *testing.T) {
	vectors := []struct {
		name   string
		change func([]byte) []byte
	}{
		{"short-header", func(b []byte) []byte { return b[:19] }},
		{"absolute", func(b []byte) []byte { b[3] = 0; return b }},
		{"owner-overflow", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], ^uint32(0)); return b }},
		{"owner-header", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], 4); return b }},
		{"owner-misaligned", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], 21); return b }},
		{"owner-overlap", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], 48); return b }},
		{"owner-count", func(b []byte) []byte { b[21] = 16; return b }},
		{"owner-span", func(b []byte) []byte { b[21] = 15; return b }},
		{"dacl-overflow", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], ^uint32(0)); return b }},
		{"dacl-header", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 16); return b }},
		{"dacl-misaligned", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 33); return b }},
		{"dacl-short", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[34:36], 7); return b }},
		{"dacl-span", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[34:36], 65535); return b }},
		{"ace-limit", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[36:38], 129); return b }},
		{"ace-count", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[36:38], 2); return b }},
		{"ace-zero", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[42:44], 0); return b }},
		{"ace-alignment", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[42:44], 18); return b }},
		{"ace-span", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[42:44], 24); return b }},
		{"ace-sid-header", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[42:44], 12); return b }},
		{"ace-sid-revision", func(b []byte) []byte { b[48] = 2; return b }},
		{"ace-sid-span", func(b []byte) []byte { b[49] = 2; return b }},
		{"ace-sid-tail", func(b []byte) []byte {
			b = append(b, 0, 0, 0, 0)
			binary.LittleEndian.PutUint16(b[34:36], 32)
			binary.LittleEndian.PutUint16(b[42:44], 24)
			return b
		}},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			if _, err := refusalDecode(vector.change(refusalCodecFixture()), nil); err == nil {
				t.Fatal("malformed native span accepted")
			}
		})
	}
	if _, err := refusalSpan(make([]byte, 20), ^uint32(0), 8); err == nil {
		t.Fatal("overflowed span accepted")
	}
	if _, err := refusalDecode(make([]byte, 65537), nil); err == nil {
		t.Fatal("oversized descriptor accepted")
	}
}

func TestDefaultRefusalCodecCancellation(t *testing.T) {
	stop := errors.New("observation deadline")
	for _, bound := range []int{1, 8, 10, 14} {
		steps := 0
		_, err := refusalDecode(refusalCodecFixture(), func() error {
			steps++
			if steps == bound {
				return stop
			}
			return nil
		})
		if !errors.Is(err, stop) || steps != bound {
			t.Fatal("decoder ignored its bounded step", bound, steps, err)
		}
	}
}

func TestDefaultRefusalEvidenceReserves(t *testing.T) {
	var budget refusalBudget
	for range refusalRecordsLimit - refusalFinalRecords {
		if _, err := budget.frame(0, false); err != nil {
			t.Fatal(err)
		}
	}
	before := budget
	if _, err := budget.frame(0, false); !errors.Is(err, errRefusalBound) || budget != before {
		t.Fatal("ordinary frame consumed the terminal reserve")
	}
	for range refusalFinalRecords {
		frame, err := budget.frame(0, true)
		if err != nil || !bytes.Equal(frame, []byte(refusalFramePrefix+"0\n")) {
			t.Fatal("terminal reserve unavailable", err)
		}
	}
	if _, err := budget.frame(0, true); !errors.Is(err, errRefusalBound) {
		t.Fatal("record limit ignored")
	}
	budget = refusalBudget{Payload: refusalPayloadLimit - refusalFinalBytes}
	before = budget
	if _, err := budget.frame(0, false); !errors.Is(err, errRefusalBound) || budget != before {
		t.Fatal("payload reserve consumed")
	}
	if _, err := budget.frame(0, true); err != nil {
		t.Fatal("terminal payload unavailable", err)
	}
	budget = refusalBudget{}
	if _, err := budget.frame(strings.Repeat("x", 4094), false); err != nil {
		t.Fatal("exact record boundary refused", err)
	}
	before = budget
	if _, err := budget.frame(strings.Repeat("x", 4095), false); !errors.Is(err, errRefusalBound) || budget != before {
		t.Fatal("oversized record charged or accepted")
	}
	budget = refusalBudget{Framed: refusalFramedLimit - 1}
	if _, err := budget.frame(0, true); !errors.Is(err, errRefusalBound) {
		t.Fatal("framed output limit ignored")
	}
	budget = refusalBudget{}
	if err := budget.snapshot(0, 65536, 128); err != nil {
		t.Fatal(err)
	}
	before = budget
	if err := budget.snapshot(0, 20, 0); !errors.Is(err, errRefusalBound) || budget != before {
		t.Fatal("first phase consumed final descriptor capacity")
	}
	if err := budget.snapshot(1, 65536, 128); err != nil {
		t.Fatal("final descriptor reserve unavailable", err)
	}
	budget = refusalBudget{}
	for range 2 {
		if err := budget.snapshot(0, 20, 128); err != nil {
			t.Fatal(err)
		}
	}
	if err := budget.snapshot(0, 20, 1); !errors.Is(err, errRefusalBound) {
		t.Fatal("ACE reserve consumed")
	}
	if err := budget.snapshot(1, 20, 128); err != nil {
		t.Fatal("final ACE reserve unavailable", err)
	}
	for _, invalid := range [][3]int{{-1, 20, 0}, {2, 20, 0}, {0, 19, 0}, {0, 65537, 0}, {0, 20, -1}, {0, 20, 129}} {
		before = budget
		if err := budget.snapshot(invalid[0], invalid[1], invalid[2]); err == nil || budget != before {
			t.Fatal("invalid snapshot charged or accepted", invalid)
		}
	}
}

func TestDefaultRefusalPathEvidenceBound(t *testing.T) {
	for _, path := range []string{strings.Repeat("a", 1023), strings.Repeat("😀", 511)} {
		if err := refusalPathBound(path); err != nil {
			t.Fatal("exact path bound refused", err)
		}
	}
	for _, path := range []string{strings.Repeat("a", 1024), strings.Repeat("😀", 512), "a\x00b", "\xff"} {
		if err := refusalPathBound(path); err == nil {
			t.Fatal("invalid path bound accepted")
		}
	}
}

func FuzzDefaultRefusalDescriptorSpans(f *testing.F) {
	f.Add(refusalCodecFixture())
	f.Add([]byte{})
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65537 {
			return
		}
		decoded, err := refusalDecode(data, nil)
		if err == nil && (len(decoded.ACEs) > 128 || len(data) > 65536) {
			t.Fatal("decoder escaped its bounds")
		}
	})
}

func TestDefaultRefusalErrorEvidenceKeepsOriginalScope(t *testing.T) {
	original := refusalErrorRecord(ErrUnsafe)
	if !original.Present || original.StoreCode != "STORE_UNSAFE" || original.Win32Code != nil {
		t.Fatal("original store error gained an inferred native error")
	}
	observed := refusalErrorRecord(fmt.Errorf("observation: %w", syscall.Errno(5)))
	if !observed.Present || observed.StoreCode != "" || observed.Win32Code == nil || *observed.Win32Code != 5 {
		t.Fatal("new wrapped native error was lost")
	}
	if zero := refusalErrorRecord(nil); zero.Present || zero.Win32Code != nil || zero.StoreCode != "" {
		t.Fatal("successful operation gained an error")
	}
	var budget refusalBudget
	before := budget
	if _, err := budget.frame(make(chan int), false); err == nil || budget != before {
		t.Fatal("failed JSON encoding consumed evidence capacity")
	}
}
