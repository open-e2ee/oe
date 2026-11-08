package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	oldScope     = `"relayScopeId":"signal_relay_scope"`
	renamedScope = `"signalRelayScopeId":"signal_relay_scope"`
	otherScope   = `"signalRelayScopeId":"other_scope"`
)

// TestScopeReadersAcceptBothConsoleNames covers each identity reader of the
// Console rename of relayScopeId to signalRelayScopeId. Each reader keeps its
// closed decoding, and each encoding still writes relayScopeId, because oe
// sends the scope back in each precondition.
func TestScopeReadersAcceptBothConsoleNames(t *testing.T) {
	readers := []struct {
		name string
		wire string
		read func([]byte) (string, []byte, error)
	}{
		{"Scope", scopeWire, func(data []byte) (string, []byte, error) {
			var v Scope
			if err := json.Unmarshal(data, &v); err != nil {
				return "", nil, err
			}
			encoded, err := json.Marshal(v)
			return v.SignalProtocolRelayScopeID.webString(), encoded, err
		}},
		{"AdmissionReadiness", admissionReadinessWire(t), func(data []byte) (string, []byte, error) {
			var v AdmissionReadiness
			if err := json.Unmarshal(data, &v); err != nil {
				return "", nil, err
			}
			encoded, err := json.Marshal(v)
			return v.SignalProtocolRelayScopeID.webString(), encoded, err
		}},
	}
	for _, reader := range readers {
		t.Run(reader.name, func(t *testing.T) {
			if !strings.Contains(reader.wire, oldScope) {
				t.Fatalf("the %s fixture has no %s", reader.name, oldScope)
			}
			for _, test := range []struct {
				name, wire string
			}{
				{"the old name only", reader.wire},
				{"the new name only", strings.Replace(reader.wire, oldScope, renamedScope, 1)},
				{"both names", strings.Replace(reader.wire, oldScope, oldScope+","+renamedScope, 1)},
			} {
				scope, encoded, err := reader.read([]byte(test.wire))
				if err != nil || scope != "signal_relay_scope" {
					t.Fatalf("%s: read %s = %q, %v", test.name, test.wire, scope, err)
				}
				if !strings.Contains(string(encoded), `"relayScopeId":`) || strings.Contains(string(encoded), "signalRelayScopeId") {
					t.Fatalf("%s: the encoding changed its wire name: %s", test.name, encoded)
				}
			}
			for _, wire := range []string{
				strings.Replace(reader.wire, oldScope, oldScope+","+otherScope, 1),
				strings.Replace(reader.wire, oldScope, `"signalRelayScopeId":""`, 1),
				strings.Replace(reader.wire, oldScope, renamedScope+`,"unknown":1`, 1),
			} {
				if _, _, err := reader.read([]byte(wire)); !errors.Is(err, ErrIdentityValue) {
					t.Fatalf("read %s = %v, want ErrIdentityValue", wire, err)
				}
			}
		})
	}
}

// TestCurrentContextAcceptsTheNewScopeName proves that the nested readers
// work in the full Console response, which compares the two scope values.
func TestCurrentContextAcceptsTheNewScopeName(t *testing.T) {
	renamed := strings.ReplaceAll(currentWire, oldScope, renamedScope)
	if strings.Contains(renamed, oldScope) {
		t.Fatal("the fixture still has the old name")
	}
	current := mustDecode[CurrentContext](t, renamed)
	if !current.Equal(mustDecode[CurrentContext](t, currentWire)) {
		t.Fatal("the new name decodes to another context")
	}
	rejectJSON[CurrentContext](t, []byte(strings.Replace(renamed, renamedScope, otherScope, 1)))
}

// admissionReadinessWire is the admissionReadiness object of completeWire.
func admissionReadinessWire(t *testing.T) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(completeWire), &fields); err != nil {
		t.Fatal(err)
	}
	return string(fields["admissionReadiness"])
}
