package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

func mustText(t *testing.T, value string) ContractText {
	t.Helper()
	v, e := Text(value)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func mustDecode[T any](t *testing.T, data string) T {
	t.Helper()
	var v T
	if e := json.Unmarshal([]byte(data), &v); e != nil {
		t.Fatalf("positive fixture refused: %v", e)
	}
	return v
}
func rejectJSON[T any](t *testing.T, data []byte) {
	t.Helper()
	var v T
	e := json.Unmarshal(data, &v)
	if e == nil {
		t.Fatal("invalid fixture accepted")
	}
	if strings.Contains(e.Error(), "CANARY") {
		t.Fatal("private input in error")
	}
}
func roundTrip[T any](t *testing.T, value T) T {
	t.Helper()
	data, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var out T
	if json.Unmarshal(data, &out) != nil {
		t.Fatal("encoded valid value refused")
	}
	again, e := json.Marshal(out)
	if e != nil || !bytes.Equal(data, again) {
		t.Fatal("nonstable encoding")
	}
	return out
}

func TestContractTextPreservesExactCodeUnits(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		units      []uint16
	}{
		{"empty", `""`, []uint16{}}, {"literal", `"a😀"`, []uint16{'a', 0xd83d, 0xde00}},
		{"escaped pair", `"\ud83d\ude00"`, []uint16{0xd83d, 0xde00}},
		{"unpaired high", `"\ud800"`, []uint16{0xd800}}, {"unpaired low", `"\udc00"`, []uint16{0xdc00}},
		{"mixed", `"\ud800x\udc00"`, []uint16{0xd800, 'x', 0xdc00}},
		{"escapes", `"\"\\\/\b\f\n\r\t\u0000"`, []uint16{'"', '\\', '/', 8, 12, 10, 13, 9, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := mustDecode[ContractText](t, tc.wire)
			if !slices.Equal(v.Units(), tc.units) || v.Len() != len(tc.units) {
				t.Fatal("code units changed")
			}
			out := roundTrip(t, v)
			if !out.Equal(v) {
				t.Fatal("round trip changed text")
			}
			units := v.Units()
			if len(units) > 0 {
				units[0] ^= 1
				if !slices.Equal(v.Units(), tc.units) {
					t.Fatal("units alias escaped")
				}
			}
		})
	}
	a := TextFromUnits([]uint16{0xd800})
	b := TextFromUnits([]uint16{0xd801})
	if a.Equal(b) {
		t.Fatal("distinct unpaired units merged")
	}
	if _, ok := a.ScalarString(); ok {
		t.Fatal("unpaired text became scalar")
	}
	units := []uint16{'a'}
	v := TextFromUnits(units)
	units[0] = 'b'
	if !textLiteral(v, "a") {
		t.Fatal("constructor retained mutable units")
	}
	if _, e := Text(string([]byte{0xff})); e == nil {
		t.Fatal("invalid Go UTF-8 accepted")
	}
	for _, data := range [][]byte{[]byte(`null`), []byte(`1`), []byte(`"\uZZZZ"`), []byte{'"', 0xff, '"'}, []byte(`"x" {}`)} {
		rejectJSON[ContractText](t, data)
	}
}
func TestSafeIntegerUsesJavaScriptNumberSemantics(t *testing.T) {
	for _, wire := range []string{"0", "-0", "1.0", "1e0", "9007199254740991", "9007199254740991.1"} {
		roundTrip(t, mustDecode[SafeInteger](t, wire))
	}
	for _, wire := range []string{"null", "-1", "1.5", "9007199254740992", "1e400", "true", "\"1\""} {
		rejectJSON[SafeInteger](t, []byte(wire))
	}
	if _, e := json.Marshal(SafeInteger(MaximumSafeInteger + 1)); !errors.Is(e, ErrIdentityValue) {
		t.Fatal("invalid constructed number encoded")
	}
}

// This fixture walk changes wire bytes without replacing typed policy parsers.
func assertRecursiveClosure(t *testing.T, data []byte, decode func([]byte) error) {
	t.Helper()
	if decode(data) != nil {
		t.Fatal("closure positive failed")
	}
	var walk func([]byte, func([]byte) []byte)
	walk = func(current []byte, replace func([]byte) []byte) {
		trimmed := bytes.TrimSpace(current)
		if len(trimmed) == 0 {
			return
		}
		if trimmed[0] == '{' {
			var object map[string]json.RawMessage
			if json.Unmarshal(trimmed, &object) != nil {
				t.Fatal("bad test object")
			}
			extra := append([]byte(`{"PRIVATE_CANARY":true,`), trimmed[1:]...)
			if len(object) == 0 {
				extra = []byte(`{"PRIVATE_CANARY":true}`)
			}
			if decode(replace(extra)) == nil {
				t.Fatal("unknown nested field accepted")
			}
			for name, value := range object {
				key, _ := json.Marshal(name)
				duplicate := append(append(append([]byte{'{'}, key...), ':'), value...)
				duplicate = append(duplicate, ',')
				duplicate = append(duplicate, trimmed[1:]...)
				if decode(replace(duplicate)) == nil {
					t.Fatal("duplicate nested field accepted")
				}
				changed := map[string]json.RawMessage{}
				for k, v := range object {
					changed[k] = v
				}
				delete(changed, name)
				changed[strings.ToUpper(name)] = value
				encoded, _ := json.Marshal(changed)
				if strings.ToUpper(name) != name && decode(replace(encoded)) == nil {
					t.Fatal("wrong-case nested field accepted")
				}
				walk(value, func(child []byte) []byte {
					copy := map[string]json.RawMessage{}
					for k, v := range object {
						copy[k] = v
					}
					copy[name] = child
					out, _ := json.Marshal(copy)
					return replace(out)
				})
			}
		} else if trimmed[0] == '[' {
			var values []json.RawMessage
			if json.Unmarshal(trimmed, &values) != nil {
				t.Fatal("bad array")
			}
			for i, v := range values {
				walk(v, func(child []byte) []byte {
					copy := slices.Clone(values)
					copy[i] = child
					out, _ := json.Marshal(copy)
					return replace(out)
				})
			}
		}
	}
	walk(data, func(v []byte) []byte { return v })
}
func TestStrictRootBytesAndDuplicateEscapes(t *testing.T) {
	decode := func(data []byte) error { var v LifecycleInputTarget; return json.Unmarshal(data, &v) }
	good := []byte(`{"kind":"account","accountAddress":"a"}`)
	assertRecursiveClosure(t, good, decode)
	for _, wire := range []string{`{"kind":"account","\u006bind":"account","accountAddress":"a"}`, `{"kind":"account","accountAddress":"a"} {}`, `null`, `[]`, `{"kind":"account","accountAddress":null}`} {
		if decode([]byte(wire)) == nil {
			t.Fatal("strict root accepted")
		}
	}
	bad := append([]byte(`{"kind":"account","accountAddress":"`), 0xff)
	bad = append(bad, []byte(`"}`)...)
	if decode(bad) == nil {
		t.Fatal("invalid UTF8 accepted")
	}
}
