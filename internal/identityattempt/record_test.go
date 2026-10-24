package identityattempt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

const recordPrecondition = `{"publishableKey":"pk_public","recoveryGeneration":3,"scope":{"environmentId":"env","environmentKind":"sandbox","projectId":"opaque","protocolProfile":"signal","relayScopeId":"scope"}}`
const recordPreconditionGolden = `{"publishableKey":"pk_public","recoveryGeneration":3,"scope":{"environmentId":"\u0065\u006e\u0076","environmentKind":"sandbox","projectId":"\u006f\u0070\u0061\u0071\u0075\u0065","protocolProfile":"signal","relayScopeId":"\u0073\u0063\u006f\u0070\u0065"}}`
const recordCoordinate = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const recordKey = `{"kty":"EC","crv":"P-256","x":"` + recordCoordinate + `","y":"` + recordCoordinate + `","kid":"key_1"}`
const recordKeyGolden = `{"kty":"EC","crv":"P-256","x":"` + recordCoordinate + `","y":"` + recordCoordinate + `","kid":"\u006b\u0065\u0079\u005f\u0031"}`
const recordSelectionWire = `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":` + recordPrecondition + `}`
const recordKeysWire = `{"operationId":"original_001","expectedConfigurationVersion":1,"keys":[` + recordKey + `],"precondition":` + recordPrecondition + `}`
const recordLifecycleWire = `{"operationId":"old_1","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`
const recordConfiguredWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://auth.example.com","audience":"chat","subjectClaim":"sub","keys":[` + recordKey + `]}`
const recordClerkWire = `{"mode":"provider-bound","algorithms":["RS256"],"issuer":"https://clerk.example.com","audience":"chat","subjectClaim":"sub","provider":"clerk","authorizedParties":["https://a.example.com","https://b.example.com"],"allowMissingAuthorizedParty":false}`
const recordFirebaseWire = `{"mode":"provider-bound","algorithms":["RS256"],"issuer":"https://securetoken.google.com/project-1","audience":"project-1","subjectClaim":"sub","provider":"firebase"}`

func recordText(t *testing.T, value string) identity.ContractText {
	t.Helper()
	text, err := identity.Text(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func recordDecode[T any](t *testing.T, wire string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(wire), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func recordSlot(t *testing.T, kind Kind) Slot {
	t.Helper()
	base, err := identity.ParseControlBaseURL("https://control.example/api/cli")
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewSlot(base, "org_1", "chat", "sandbox", kind)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func recordAttempt(t *testing.T, kind Kind) Attempt {
	t.Helper()
	var value Attempt
	var err error
	switch kind {
	case Selection:
		value, err = NewSelectionAttempt(recordDecode[identity.SelectionCommand](t, recordSelectionWire))
	case KeysOnly:
		value, err = NewKeysAttempt(recordDecode[identity.KeysCommand](t, recordKeysWire))
	case Lifecycle:
		value, err = NewLifecycleAttempt(recordDecode[identity.LifecycleAttempt](t, recordLifecycleWire))
	default:
		t.Fatal("invalid test kind")
	}
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func recordOccupied(t *testing.T, kind Kind) Envelope {
	t.Helper()
	value, err := NewOccupiedEnvelope(recordSlot(t, kind), 7, recordAttempt(t, kind))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func recordEncoded(t *testing.T, value Envelope) []byte {
	t.Helper()
	wire, err := EncodeEnvelope(value)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestEnvelopeVacantGoldenAndRequiredNull(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			value, err := NewVacantEnvelope(recordSlot(t, kind), 1)
			if err != nil {
				t.Fatal(err)
			}
			golden := `{"schemaVersion":1,"revision":1,"slot":["open-e2ee.identity-attempt-slot",1,"https://control.example/api/cli","org_1","chat","sandbox","` + string(kind) + `"],"attempt":null}` + "\n"
			wire := recordEncoded(t, value)
			if string(wire) != golden || bytes.Count(wire, []byte("\n")) != 1 {
				t.Fatalf("vacant encoding differs: %s", wire)
			}
			decoded, err := DecodeEnvelope(wire, value.Slot())
			if err != nil || !decoded.Equal(value) || decoded.Revision() != 1 {
				t.Fatal("vacant envelope lost its public association")
			}
			attempt, err := decoded.RetainedAttempt()
			if err != nil || attempt != nil {
				t.Fatal("vacancy became an attempt")
			}
			if _, err := DecodeEnvelope(bytes.Replace(wire, []byte(`,"attempt":null`), nil, 1), value.Slot()); !errors.Is(err, ErrEnvelope) {
				t.Fatal("missing attempt became vacancy")
			}
		})
	}
}

func TestEnvelopeOccupiedGoldensAndRoundTrip(t *testing.T) {
	selection := `{"operationId":"original_001","expectedConfigurationVersion":1,"target":{"mode":"device-owned"},"precondition":` + recordPreconditionGolden + `}`
	keys := `{"operationId":"original_001","expectedConfigurationVersion":1,"keys":[` + recordKeyGolden + `],"precondition":` + recordPreconditionGolden + `}`
	lifecycle := `{"operationId":"\u006f\u006c\u0064\u005f\u0031","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`
	for _, input := range []struct {
		name, command string
		kind          Kind
		cancel        bool
	}{
		{"selection", selection, Selection, false},
		{"selection-cancel", selection, Selection, true},
		{"keys", keys, KeysOnly, false},
		{"keys-cancel", keys, KeysOnly, true},
		{"lifecycle", lifecycle, Lifecycle, false},
	} {
		t.Run(input.name, func(t *testing.T) {
			attempt := recordAttempt(t, input.kind)
			cancel := ""
			if input.cancel {
				var err error
				attempt, err = attempt.WithCancellation("cancel_001")
				if err != nil {
					t.Fatal(err)
				}
				cancel = `,"cancellationId":"cancel_001"`
			}
			value, err := NewOccupiedEnvelope(recordSlot(t, input.kind), 7, attempt)
			if err != nil {
				t.Fatal(err)
			}
			golden := `{"schemaVersion":1,"revision":7,"slot":["open-e2ee.identity-attempt-slot",1,"https://control.example/api/cli","org_1","chat","sandbox","` + string(input.kind) + `"],"attempt":{"kind":"` + string(input.kind) + `","command":` + input.command + cancel + `}}` + "\n"
			wire := recordEncoded(t, value)
			if string(wire) != golden {
				t.Fatalf("occupied encoding differs: %s", wire)
			}
			decoded, err := DecodeEnvelope(wire, value.Slot())
			if err != nil || !decoded.Equal(value) || decoded.Validate() != nil {
				t.Fatal("occupied envelope did not round-trip")
			}
			compact, err := value.MarshalJSON()
			if err != nil || !bytes.Equal(append(compact, '\n'), wire) {
				t.Fatal("record encoder changed the owned JSON value")
			}
		})
	}
}

func TestEnvelopeStrictTopReceiverAndExpectedSlot(t *testing.T) {
	value := recordOccupied(t, Selection)
	wire := recordEncoded(t, value)
	for _, data := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`true`), []byte(`1`), []byte(`"record"`), []byte(`{}`),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":null`), 1),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":0`), 1),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":2`), 1),
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":"1"`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":0`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":-0`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":-1`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":1.5`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":9007199254740992`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":1e9999`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":"7"`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":true`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":null`), 1),
		bytes.Replace(wire, []byte(`"slot":[`), []byte(`"slot":null,"discarded":[`), 1),
		bytes.Replace(wire, []byte(`"attempt":{`), []byte(`"attempt":42,"discarded":{`), 1),
		bytes.Replace(wire, []byte(`"schemaVersion"`), []byte(`"SchemaVersion"`), 1),
		bytes.Replace(wire, []byte(`{"schemaVersion":1`), []byte(`{"schemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(wire, []byte(`{"schemaVersion":1`), []byte(`{"\u0073chemaVersion":1,"schemaVersion":1`), 1),
		bytes.Replace(wire, []byte(`org_1`), []byte(`\ud800`), 1),
		bytes.Replace(wire, []byte(`org_1`), []byte{0xff}, 1),
		append(bytes.Clone(wire), []byte(`{}`)...),
		wire[:len(wire)-3],
	} {
		decoded, err := DecodeEnvelope(data, value.Slot())
		if !errors.Is(err, ErrEnvelope) || decoded.Validate() == nil {
			t.Fatal("invalid envelope escaped the strict receiver")
		}
	}
	for _, change := range []func(Slot) Slot{
		func(s Slot) Slot { s.organization = "other"; return s },
		func(s Slot) Slot { s.project = "other"; return s },
		func(s Slot) Slot { s.environment = "production"; return s },
		func(s Slot) Slot { s.kind = KeysOnly; return s },
		func(s Slot) Slot { s.base, _ = identity.ParseControlBaseURL("https://control.example/other"); return s },
	} {
		if _, err := DecodeEnvelope(wire, change(value.Slot())); !errors.Is(err, ErrEnvelope) {
			t.Fatal("expected public slot mismatch accepted")
		}
	}
	if _, err := DecodeEnvelope(wire, Slot{}); !errors.Is(err, ErrEnvelope) {
		t.Fatal("invalid expected slot accepted")
	}
	prior := value
	if json.Unmarshal(wire, &prior) == nil || !prior.Equal(value) {
		t.Fatal("generic JSON decode bypassed the required expected slot or changed its receiver")
	}
}

func TestAttemptStrictVariantAndFailedReceiver(t *testing.T) {
	selection, _ := recordAttempt(t, Selection).MarshalJSON()
	keys, _ := recordAttempt(t, KeysOnly).MarshalJSON()
	lifecycle, _ := recordAttempt(t, Lifecycle).MarshalJSON()
	for _, data := range [][]byte{
		[]byte(`null`), []byte(`{}`), []byte(`[]`), []byte(`"selection"`),
		bytes.Replace(selection, []byte(`"kind":"selection",`), nil, 1),
		[]byte(`{"kind":"selection"}`),
		bytes.Replace(selection, []byte(`"selection"`), []byte(`null`), 1),
		bytes.Replace(selection, []byte(`"selection"`), []byte(`"Selection"`), 1),
		bytes.Replace(selection, []byte(`"selection"`), []byte(`"other"`), 1),
		bytes.Replace(selection, []byte(`"selection"`), []byte(`"\ud800"`), 1),
		[]byte(`{"kind":"selection","command":null}`),
		[]byte(`{"kind":"keys-only","command":null}`),
		[]byte(`{"kind":"lifecycle","command":null}`),
		bytes.Replace(selection, []byte(`"selection"`), []byte(`"keys-only"`), 1),
		bytes.Replace(keys, []byte(`"keys-only"`), []byte(`"selection"`), 1),
		bytes.Replace(lifecycle, []byte(`"lifecycle"`), []byte(`"selection"`), 1),
		append(bytes.Clone(selection[:len(selection)-1]), []byte(`,"cancellationId":null}`)...),
		append(bytes.Clone(selection[:len(selection)-1]), []byte(`,"cancellationId":1}`)...),
		append(bytes.Clone(selection[:len(selection)-1]), []byte(`,"cancellationId":"short"}`)...),
		append(bytes.Clone(lifecycle[:len(lifecycle)-1]), []byte(`,"cancellationId":"cancel_001"}`)...),
		bytes.Replace(selection, []byte(`"kind"`), []byte(`"Kind"`), 1),
		append(bytes.Clone(selection), []byte(`null`)...),
	} {
		prior := recordAttempt(t, KeysOnly)
		value, err := prior.Clone()
		if err != nil || value.UnmarshalJSON(data) == nil || !value.Equal(prior) {
			t.Fatal("invalid variant changed the receiver")
		}
	}
	var nilAttempt *Attempt
	if !errors.Is(nilAttempt.UnmarshalJSON(selection), ErrEnvelope) {
		t.Fatal("nil attempt receiver accepted")
	}
}

// recordObjectMutations edits every object boundary without parsing domain policy.
func recordObjectMutations(t *testing.T, data []byte, reject func([]byte)) {
	t.Helper()
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) == nil && fields != nil {
		reject(append([]byte(`{"__privateCanary":"VALUE",`), data[1:]...))
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			value := fields[name]
			key, _ := json.Marshal(name)
			reject(append(append(append(append([]byte{'{'}, key...), ':'), value...), append([]byte{','}, data[1:]...)...))
			escaped := []byte(fmt.Sprintf(`"\u%04x%s"`, name[0], name[1:]))
			reject(append(append(append(append([]byte{'{'}, escaped...), ':'), value...), append([]byte{','}, data[1:]...)...))
			delete(fields, name)
			if name != "cancellationId" {
				missing, _ := json.Marshal(fields)
				reject(missing)
			}
			fields[strings.ToUpper(name[:1])+name[1:]] = value
			wrongCase, _ := json.Marshal(fields)
			reject(wrongCase)
			delete(fields, strings.ToUpper(name[:1])+name[1:])
			fields[name] = json.RawMessage(`null`)
			if name != "attempt" {
				null, _ := json.Marshal(fields)
				reject(null)
			}
			fields[name] = value
			recordObjectMutations(t, value, func(changed []byte) {
				fields[name] = changed
				parent, _ := json.Marshal(fields)
				fields[name] = value
				reject(parent)
			})
		}
		return
	}
	var elements []json.RawMessage
	if json.Unmarshal(data, &elements) == nil && elements != nil {
		for i, value := range elements {
			recordObjectMutations(t, value, func(changed []byte) {
				elements[i] = changed
				parent, _ := json.Marshal(elements)
				elements[i] = value
				reject(parent)
			})
		}
	}
}

func TestEnvelopeDelegatesRecursiveClosureToActualOwners(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		t.Run(string(kind), func(t *testing.T) {
			value := recordOccupied(t, kind)
			recordObjectMutations(t, bytes.TrimSpace(recordEncoded(t, value)), func(bad []byte) {
				if _, err := DecodeEnvelope(bad, value.Slot()); !errors.Is(err, ErrEnvelope) {
					t.Fatal("recursive duplicate, case, unknown, missing or null field accepted")
				}
			})
		})
	}
}

func TestEnvelopeSemanticObjectOrderAndNumericOwner(t *testing.T) {
	value := recordOccupied(t, Selection)
	wire := recordEncoded(t, value)
	for _, variant := range [][]byte{
		bytes.Replace(wire, []byte(`"schemaVersion":1`), []byte(`"schemaVersion":1.0`), 1),
		bytes.Replace(wire, []byte(`"revision":7`), []byte(`"revision":7e0`), 1),
		bytes.Replace(wire, []byte(`"expectedConfigurationVersion":1`), []byte(`"expectedConfigurationVersion":1e0`), 1),
		bytes.Replace(wire, []byte(`"recoveryGeneration":3`), []byte(`"recoveryGeneration":3.0`), 1),
	} {
		decoded, err := DecodeEnvelope(variant, value.Slot())
		if err != nil || !decoded.Equal(value) || !bytes.Equal(recordEncoded(t, decoded), wire) {
			t.Fatal("record narrowed identity-owned numeric semantics")
		}
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	reordered := []byte(`{"attempt":` + string(object["attempt"]) + `,"slot":` + string(object["slot"]) + `,"revision":7,"schemaVersion":1}`)
	decoded, err := DecodeEnvelope(reordered, value.Slot())
	if err != nil || !decoded.Equal(value) {
		t.Fatal("object property order changed semantic equality")
	}
	limit, err := MaximumEnvelopeEncodingBytes(value.Slot())
	if err != nil {
		t.Fatal(err)
	}
	spaced := append(bytes.Repeat([]byte(" \n"), limit), wire...)
	decoded, err = DecodeEnvelope(spaced, value.Slot())
	if err != nil || !decoded.Equal(value) {
		t.Fatal("canonical output bound became an unapproved input ceiling")
	}
}

func recordReverseObjectOrder(t *testing.T, data []byte) []byte {
	t.Helper()
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) == nil && fields != nil {
		names := make([]string, 0, len(fields))
		for name := range fields {
			names = append(names, name)
		}
		slices.Sort(names)
		slices.Reverse(names)
		var members [][]byte
		for _, name := range names {
			key, _ := json.Marshal(name)
			members = append(members, append(append(key, ':'), recordReverseObjectOrder(t, fields[name])...))
		}
		return append(append([]byte{'{'}, bytes.Join(members, []byte{','})...), '}')
	}
	var elements []json.RawMessage
	if json.Unmarshal(data, &elements) == nil && elements != nil {
		for i := range elements {
			elements[i] = recordReverseObjectOrder(t, elements[i])
		}
		encoded, err := json.Marshal(elements)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	return bytes.Clone(data)
}

func TestEnvelopeAllObjectOrdersKeepArrayOrder(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		value := recordOccupied(t, kind)
		encoded := recordEncoded(t, value)
		reordered := recordReverseObjectOrder(t, bytes.TrimSpace(encoded))
		decoded, err := DecodeEnvelope(reordered, value.Slot())
		if err != nil || !decoded.Equal(value) || !bytes.Equal(encoded, recordEncoded(t, decoded)) {
			t.Fatal("nested object property order changed the complete semantic value")
		}
	}
}

func TestEnvelopeCompleteEqualityIncludesContextRevisionAndCancellation(t *testing.T) {
	original := recordDecode[identity.SelectionCommand](t, recordSelectionWire)
	for _, mutate := range []func(*identity.SelectionCommand){
		func(v *identity.SelectionCommand) { v.OperationID = "changed_001" },
		func(v *identity.SelectionCommand) { v.ExpectedConfigurationVersion++ },
		func(v *identity.SelectionCommand) {
			v.Target = recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
		},
		func(v *identity.SelectionCommand) { v.Precondition.PublishableKey = "pk_other" },
		func(v *identity.SelectionCommand) { v.Precondition.RecoveryGeneration++ },
		func(v *identity.SelectionCommand) { v.Precondition.Scope.EnvironmentID = recordText(t, "other") },
		func(v *identity.SelectionCommand) { v.Precondition.Scope.ProjectID = recordText(t, "other_opaque") },
		func(v *identity.SelectionCommand) { v.Precondition.Scope.RelayScopeID = recordText(t, "other") },
	} {
		changed, err := original.Clone()
		if err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		a, err := NewSelectionAttempt(changed)
		if err != nil || a.Equal(recordAttempt(t, Selection)) {
			t.Fatal("valid original field difference disappeared")
		}
	}
	value := recordOccupied(t, Selection)
	differentRevision, err := NewOccupiedEnvelope(value.Slot(), 8, recordAttempt(t, Selection))
	if err != nil || value.Equal(differentRevision) {
		t.Fatal("revision difference disappeared")
	}
	vacant, err := NewVacantEnvelope(value.Slot(), value.Revision())
	if err != nil || value.Equal(vacant) {
		t.Fatal("occupancy difference disappeared")
	}
	winner, err := recordAttempt(t, Selection).WithCancellation("cancel_001")
	if err != nil {
		t.Fatal(err)
	}
	enriched, err := NewOccupiedEnvelope(value.Slot(), value.Revision(), winner)
	if err != nil || value.Equal(enriched) {
		t.Fatal("cancellation presence difference disappeared")
	}
	other, err := recordAttempt(t, Selection).WithCancellation("cancel_002")
	if err != nil || other.Equal(winner) {
		t.Fatal("cancellation identity difference disappeared")
	}
	for _, input := range []identity.LifecycleAttempt{
		{OperationID: recordText(t, "other_1"), TargetKind: "subject", State: "suspended"},
		{OperationID: recordText(t, "old_1"), TargetKind: "account", State: "suspended"},
		{OperationID: recordText(t, "old_1"), TargetKind: "subject", ExpectedLifecycleVersion: 1, State: "suspended"},
		{OperationID: recordText(t, "old_1"), TargetKind: "subject", State: "active"},
	} {
		changed, err := NewLifecycleAttempt(input)
		if err != nil || changed.Equal(recordAttempt(t, Lifecycle)) {
			t.Fatal("lifecycle command difference disappeared")
		}
	}
}

func TestAttemptOrderedArraysOptionalPresenceAndUTF16(t *testing.T) {
	command := recordDecode[identity.SelectionCommand](t, recordSelectionWire)
	command.Target = recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
	second := recordDecode[identity.SigningPublicKey](t, strings.Replace(recordKey, "key_1", "key_2", 1))
	*command.Target.Keys = append(*command.Target.Keys, second)
	original, err := NewSelectionAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(*command.Target.Keys)
	reversed, err := NewSelectionAttempt(command)
	if err != nil || original.Equal(reversed) {
		t.Fatal("configured key order disappeared")
	}
	slices.Reverse(*command.Target.Keys)
	for _, mutate := range []func(*identity.SigningPublicKey){
		func(v *identity.SigningPublicKey) { v.Algorithm = new("ES256") },
		func(v *identity.SigningPublicKey) { v.Use = new("sig") },
		func(v *identity.SigningPublicKey) { v.Operations = new([]string{"verify"}) },
		func(v *identity.SigningPublicKey) { v.Extractable = new(true) },
	} {
		copy, err := command.Clone()
		if err != nil {
			t.Fatal(err)
		}
		mutate(&(*copy.Target.Keys)[0])
		changed, err := NewSelectionAttempt(copy)
		if err != nil || original.Equal(changed) {
			t.Fatal("optional key field presence disappeared")
		}
	}
	keys := recordDecode[identity.KeysCommand](t, recordKeysWire)
	keys.Keys = append(keys.Keys, second)
	before, err := NewKeysAttempt(keys)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(keys.Keys)
	after, err := NewKeysAttempt(keys)
	if err != nil || before.Equal(after) {
		t.Fatal("replacement key order disappeared")
	}
	command.Target = recordDecode[identity.SelectionTarget](t, recordClerkWire)
	clerk, err := NewSelectionAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(*command.Target.AuthorizedParties)
	partyOrder, err := NewSelectionAttempt(command)
	if err != nil || clerk.Equal(partyOrder) {
		t.Fatal("authorized-party order disappeared")
	}
	slices.Reverse(*command.Target.AuthorizedParties)
	command.Target.AllowMissingAuthorizedParty = nil
	absentFalse, err := NewSelectionAttempt(command)
	if err != nil || clerk.Equal(absentFalse) {
		t.Fatal("explicit false presence disappeared")
	}
	command.Target.Audience = nil
	withoutAudience, err := NewSelectionAttempt(command)
	if err != nil || withoutAudience.Equal(absentFalse) {
		t.Fatal("optional audience presence disappeared")
	}
	command.Target = recordDecode[identity.SelectionTarget](t, recordClerkWire)
	command.Target.AllowMissingAuthorizedParty = new(true)
	explicitTrue, err := NewSelectionAttempt(command)
	if err != nil || clerk.Equal(explicitTrue) {
		t.Fatal("explicit boolean value difference disappeared")
	}
	for _, units := range [][]uint16{{0xd800}, {0xdc00}, {'e', 0x301}, {0xe9}, {0xd83d, 0xde00}} {
		lifecycle := identity.LifecycleAttempt{OperationID: identity.TextFromUnits(units), TargetKind: "account", State: "active"}
		attempt, err := NewLifecycleAttempt(lifecycle)
		if err != nil {
			t.Fatal("narrowed the existing historical operation text contract")
		}
		value, err := NewOccupiedEnvelope(recordSlot(t, Lifecycle), 1, attempt)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEnvelope(recordEncoded(t, value), value.Slot())
		if err != nil || !decoded.Equal(value) {
			t.Fatal("UTF-16 code units changed")
		}
		retained, err := decoded.RetainedAttempt()
		if err != nil {
			t.Fatal(err)
		}
		got, err := retained.LifecycleCommand()
		if err != nil || !slices.Equal(got.OperationID.Units(), units) {
			t.Fatal("historical operation text lost code units")
		}
	}
	composed, err := NewLifecycleAttempt(identity.LifecycleAttempt{OperationID: recordText(t, "é"), TargetKind: "account", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := NewLifecycleAttempt(identity.LifecycleAttempt{OperationID: recordText(t, "e\u0301"), TargetKind: "account", State: "active"})
	if err != nil || composed.Equal(decomposed) {
		t.Fatal("Unicode normalization merged distinct contract code units")
	}
}

func TestAttemptAndEnvelopeDefensiveCopies(t *testing.T) {
	command := recordDecode[identity.SelectionCommand](t, recordSelectionWire)
	command.Target = recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
	(*command.Target.Keys)[0].Operations = new([]string{"verify"})
	attempt, err := NewSelectionAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOccupiedEnvelope(recordSlot(t, Selection), 7, attempt)
	if err != nil {
		t.Fatal(err)
	}
	wire := recordEncoded(t, value)
	(*command.Target.Algorithms)[0] = "changed"
	(*(*command.Target.Keys)[0].Operations)[0] = "changed"
	(*command.Target.Keys)[0].Kid = recordText(t, "changed")
	command.Precondition.Scope.ProjectID = recordText(t, "changed")
	if !bytes.Equal(wire, recordEncoded(t, value)) {
		t.Fatal("constructor retained caller-owned nested storage")
	}
	copy, err := value.RetainedAttempt()
	if err != nil {
		t.Fatal(err)
	}
	extracted, err := copy.SelectionCommand()
	if err != nil {
		t.Fatal(err)
	}
	(*extracted.Target.Algorithms)[0] = "changed"
	(*(*extracted.Target.Keys)[0].Operations)[0] = "changed"
	if !bytes.Equal(wire, recordEncoded(t, value)) {
		t.Fatal("command getter exposed nested storage")
	}
	if err := copy.UnmarshalJSON([]byte(`{"kind":"selection","command":` + recordSelectionWire + `}`)); err != nil || !bytes.Equal(wire, recordEncoded(t, value)) {
		t.Fatal("attempt getter exposed the retained receiver")
	}
	cloned, err := value.Clone()
	if err != nil || !cloned.Equal(value) {
		t.Fatal("clone changed the complete record")
	}
	wire[0] = 'x'
	if recordEncoded(t, value)[0] != '{' || !cloned.Equal(value) {
		t.Fatal("encoded bytes exposed record storage")
	}
	for _, kind := range []Kind{KeysOnly, Lifecycle} {
		v := recordAttempt(t, kind)
		if _, err := v.SelectionCommand(); !errors.Is(err, ErrEnvelope) {
			t.Fatal("wrong command getter accepted")
		}
	}
	if _, err := recordAttempt(t, Selection).KeysCommand(); !errors.Is(err, ErrEnvelope) {
		t.Fatal("wrong keys getter accepted")
	}
	if _, err := recordAttempt(t, Selection).LifecycleCommand(); !errors.Is(err, ErrEnvelope) {
		t.Fatal("wrong lifecycle getter accepted")
	}
	keysInput := recordDecode[identity.KeysCommand](t, recordKeysWire)
	keysAttempt, err := NewKeysAttempt(keysInput)
	if err != nil {
		t.Fatal(err)
	}
	keysBefore, err := keysAttempt.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	keysInput.Keys[0].Kid = recordText(t, "changed")
	keysCopy, err := keysAttempt.KeysCommand()
	if err != nil {
		t.Fatal(err)
	}
	keysCopy.Keys[0].Kid = recordText(t, "getter_changed")
	keysAfter, err := keysAttempt.MarshalJSON()
	if err != nil || !bytes.Equal(keysBefore, keysAfter) {
		t.Fatal("keys constructor or getter exposed retained slice storage")
	}
	lifecycle := recordAttempt(t, Lifecycle)
	lifecycleCopy, err := lifecycle.LifecycleCommand()
	if err != nil {
		t.Fatal(err)
	}
	units := lifecycleCopy.OperationID.Units()
	units[0] = 'x'
	if !lifecycle.Equal(recordAttempt(t, Lifecycle)) {
		t.Fatal("lifecycle getter exposed contract text storage")
	}
}

func TestAttemptCancellationIsDetachedAndImmutable(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly} {
		t.Run(string(kind), func(t *testing.T) {
			original := recordAttempt(t, kind)
			winner, err := original.WithCancellation("cancel_001")
			if err != nil {
				t.Fatal(err)
			}
			if _, present := original.CancellationID(); present {
				t.Fatal("enrichment changed the original")
			}
			id, present := winner.CancellationID()
			if !present || id != "cancel_001" {
				t.Fatal("winning cancellation identity disappeared")
			}
			repeated, err := winner.WithCancellation("cancel_001")
			if err != nil || !repeated.Equal(winner) {
				t.Fatal("same cancellation identity changed the value")
			}
			if _, err := winner.WithCancellation("cancel_002"); !errors.Is(err, ErrEnvelope) {
				t.Fatal("winning cancellation identity was replaced")
			}
			for _, id := range []identity.CancellationOperationID{"", "short", identity.CancellationOperationID(strings.Repeat("a", 97)), "cancel space"} {
				if _, err := original.WithCancellation(id); !errors.Is(err, ErrEnvelope) {
					t.Fatal("invalid cancellation identity accepted")
				}
			}
			if _, err := original.WithCancellation("original_001"); err != nil {
				t.Fatal("codec invented an inequality absent from the ID owner")
			}
		})
	}
	if _, err := recordAttempt(t, Lifecycle).WithCancellation("cancel_001"); !errors.Is(err, ErrEnvelope) {
		t.Fatal("lifecycle acquired a cancellation field")
	}
}

func TestEnvelopeSlotKindEnvironmentAndRevisionBounds(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		for _, revision := range []identity.SafeInteger{0, 1, identity.SafeInteger(identity.MaximumSafeInteger), identity.SafeInteger(identity.MaximumSafeInteger + 1)} {
			valid := revision > 0 && uint64(revision) <= identity.MaximumSafeInteger
			vacant, e1 := NewVacantEnvelope(recordSlot(t, kind), revision)
			occupied, e2 := NewOccupiedEnvelope(recordSlot(t, kind), revision, recordAttempt(t, kind))
			if (e1 == nil) != valid || (e2 == nil) != valid {
				t.Fatal("revision bound changed")
			}
			if valid {
				for _, v := range []Envelope{vacant, occupied} {
					decoded, err := DecodeEnvelope(recordEncoded(t, v), v.Slot())
					if err != nil || !decoded.Equal(v) {
						t.Fatal("valid boundary revision changed")
					}
				}
			}
		}
		for _, other := range []Kind{Selection, KeysOnly, Lifecycle} {
			_, err := NewOccupiedEnvelope(recordSlot(t, kind), 1, recordAttempt(t, other))
			if (err == nil) != (kind == other) {
				t.Fatal("slot and attempt kind association changed")
			}
		}
	}
	for _, kind := range []Kind{Selection, KeysOnly} {
		s := recordSlot(t, kind)
		s.environment = "production"
		if _, err := NewOccupiedEnvelope(s, 1, recordAttempt(t, kind)); !errors.Is(err, ErrEnvelope) {
			t.Fatal("precondition environment mismatch accepted")
		}
	}
	for _, v := range []Envelope{{}, {slot: recordSlot(t, Selection), revision: 1, attempt: new(Attempt{})}} {
		if v.Validate() == nil || v.Equal(v) {
			t.Fatal("invalid envelope established equality")
		}
		if _, err := EncodeEnvelope(v); !errors.Is(err, ErrEnvelope) {
			t.Fatal("invalid envelope encoded")
		}
		if _, err := v.Clone(); !errors.Is(err, ErrEnvelope) {
			t.Fatal("invalid envelope cloned")
		}
	}
	if (Attempt{}).Equal(Attempt{}) {
		t.Fatal("zero attempts established equality")
	}
	if _, err := NewSelectionAttempt(identity.SelectionCommand{}); err != ErrEnvelope {
		t.Fatal("invalid selection escaped its owner")
	}
	if _, err := NewKeysAttempt(identity.KeysCommand{}); err != ErrEnvelope {
		t.Fatal("invalid keys escaped their owner")
	}
	if _, err := NewLifecycleAttempt(identity.LifecycleAttempt{}); err != ErrEnvelope {
		t.Fatal("invalid lifecycle escaped its owner")
	}
	if _, err := NewVacantEnvelope(Slot{}, 1); err != ErrEnvelope {
		t.Fatal("vacant constructor accepted an invalid slot")
	}
	if _, err := NewOccupiedEnvelope(Slot{}, 1, recordAttempt(t, Selection)); err != ErrEnvelope {
		t.Fatal("occupied constructor accepted an invalid slot")
	}
	if _, err := NewOccupiedEnvelope(recordSlot(t, Selection), 1, Attempt{}); err != ErrEnvelope {
		t.Fatal("occupied constructor accepted an invalid attempt")
	}
}

func TestEnvelopePrivacyWhitelistAndFixedErrors(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		value := recordOccupied(t, kind)
		wire := recordEncoded(t, value)
		for _, field := range []string{"subject", "accountAddress", "profileFingerprint", "assertion", "credential", "session", "locator", "privateKey", "inputDigest", "d", "precondition"} {
			canary := "PRIVATE_RECORD_CANARY_" + field
			bad := append([]byte(`{"`+field+`":"`+canary+`",`), wire[1:]...)
			decoded, err := DecodeEnvelope(bad, value.Slot())
			if err != ErrEnvelope || strings.Contains(err.Error(), canary) || decoded.Validate() == nil {
				t.Fatal("private input escaped through the envelope or error")
			}
			if bytes.Contains(wire, []byte(canary)) {
				t.Fatal("private input entered the original record")
			}
		}
	}
	lifecycle := recordOccupied(t, Lifecycle)
	if bytes.Contains(recordEncoded(t, lifecycle), []byte(`"precondition"`)) {
		t.Fatal("lifecycle duplicated a selection precondition")
	}
}

func TestEnvelopeCompleteSupportedTargetsAndPreparedID(t *testing.T) {
	for _, target := range []string{`{"mode":"device-owned"}`, recordConfiguredWire, strings.Replace(recordConfiguredWire, "custom-token", "provider-bound", 1), recordClerkWire, recordFirebaseWire} {
		command := recordDecode[identity.SelectionCommand](t, recordSelectionWire)
		command.Target = recordDecode[identity.SelectionTarget](t, target)
		attempt, err := NewSelectionAttempt(command)
		if err != nil {
			t.Fatal(err)
		}
		value, err := NewOccupiedEnvelope(recordSlot(t, Selection), 1, attempt)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeEnvelope(recordEncoded(t, value), value.Slot())
		if err != nil || !decoded.Equal(value) {
			t.Fatal("supported target did not round-trip")
		}
	}
	id := recordText(t, "lc1_"+strings.Repeat("a", 16)+"_"+strings.Repeat("A", 22)+"_"+strings.Repeat("A", 43))
	if identity.ValidatePreparedOperationID(id) != nil {
		t.Fatal("prepared fixture does not satisfy its actual owner")
	}
	command := identity.LifecycleAttempt{OperationID: id, TargetKind: "account", ExpectedLifecycleVersion: 1, State: "active"}
	attempt, err := NewLifecycleAttempt(command)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewOccupiedEnvelope(recordSlot(t, Lifecycle), 1, attempt)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelope(recordEncoded(t, value), value.Slot())
	if err != nil || !decoded.Equal(value) {
		t.Fatal("prepared identity changed in persistence encoding")
	}
}

func TestEnvelopeCanonicalEncodingBoundsAndExactSlotContribution(t *testing.T) {
	for _, kind := range []Kind{Selection, KeysOnly, Lifecycle} {
		value := recordOccupied(t, kind)
		limit, err := MaximumEnvelopeEncodingBytes(value.Slot())
		if err != nil || len(recordEncoded(t, value)) > limit {
			t.Fatal("canonical encoding exceeded its derived bound")
		}
		larger := value.Slot()
		larger.organization = strings.Repeat("é😀", 2048)
		largerLimit, err := MaximumEnvelopeEncodingBytes(larger)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := EncodeSlot(value.Slot())
		b, _ := EncodeSlot(larger)
		if largerLimit-limit != len(b)-len(a) {
			t.Fatal("bound did not use the exact encoded expected slot")
		}
	}
	if _, err := MaximumEnvelopeEncodingBytes(Slot{}); !errors.Is(err, ErrEnvelope) {
		t.Fatal("invalid slot produced an encoding bound")
	}
	lifecycle, err := NewLifecycleAttempt(identity.LifecycleAttempt{OperationID: identity.TextFromUnits(slices.Repeat([]uint16{0xd800}, 128)), TargetKind: "subject", ExpectedLifecycleVersion: identity.SafeInteger(identity.MaximumSafeInteger), State: "suspended"})
	if err != nil {
		t.Fatal(err)
	}
	lifecycleEnvelope, err := NewOccupiedEnvelope(recordSlot(t, Lifecycle), identity.SafeInteger(identity.MaximumSafeInteger), lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleLimit, err := MaximumEnvelopeEncodingBytes(lifecycleEnvelope.Slot())
	if err != nil || len(recordEncoded(t, lifecycleEnvelope)) != lifecycleLimit {
		t.Fatal("maximum lifecycle fixture did not reach its exact encoding bound")
	}
	for _, replacement := range []bool{false, true} {
		keys := make([]identity.SigningPublicKey, 32)
		kidUnits := 255
		if replacement {
			kidUnits = 128
		}
		for i := range keys {
			keys[i] = identity.SigningPublicKey{Kty: "EC", Curve: "P-256", X: recordCoordinate, Y: recordCoordinate, Kid: recordText(t, strings.Repeat("k", kidUnits-2)+fmt.Sprintf("%02d", i)), Algorithm: new("ES256"), Use: new("sig"), Operations: new([]string{"verify"}), Extractable: new(true)}
			if keys[i].Validate() != nil || replacement && (identity.ReplacementKeys{keys[i]}).Validate() != nil {
				t.Fatal("bound fixture contains an invalid individual key")
			}
		}
		precondition := recordDecode[identity.Precondition](t, recordPrecondition)
		precondition.PublishableKey = strings.Repeat("p", 255)
		precondition.RecoveryGeneration = identity.SafeInteger(identity.MaximumSafeInteger)
		precondition.Scope.EnvironmentKind = "production"
		precondition.Scope.EnvironmentID = identity.TextFromUnits(slices.Repeat([]uint16{0xd800}, 256))
		precondition.Scope.ProjectID = identity.TextFromUnits(slices.Repeat([]uint16{0xdc00}, 256))
		precondition.Scope.RelayScopeID = recordText(t, strings.Repeat("r", 255))
		kind := Selection
		var attempt Attempt
		var err error
		if replacement {
			kind = KeysOnly
			attempt, err = NewKeysAttempt(identity.KeysCommand{OperationID: identity.SelectionOperationID(strings.Repeat("o", 96)), ExpectedConfigurationVersion: identity.SafeInteger(identity.MaximumSafeInteger), Keys: keys, Precondition: precondition})
		} else {
			target := recordDecode[identity.SelectionTarget](t, recordConfiguredWire)
			target.Mode = "provider-bound"
			target.Issuer = new(recordText(t, "https://auth.example.com/"+strings.Repeat("a", 255-len("https://auth.example.com/"))))
			target.Audience = new(recordText(t, strings.Repeat("a", 255)))
			target.SubjectClaim = new("s" + strings.Repeat("a", 63))
			target.Keys = &keys
			attempt, err = NewSelectionAttempt(identity.SelectionCommand{OperationID: identity.SelectionOperationID(strings.Repeat("o", 96)), ExpectedConfigurationVersion: identity.SafeInteger(identity.MaximumSafeInteger), Target: target, Precondition: precondition})
		}
		if err != nil {
			t.Fatal(err)
		}
		attempt, err = attempt.WithCancellation(identity.CancellationOperationID(strings.Repeat("c", 96)))
		if err != nil {
			t.Fatal(err)
		}
		s := recordSlot(t, kind)
		s.environment = "production"
		value, err := NewOccupiedEnvelope(s, identity.SafeInteger(identity.MaximumSafeInteger), attempt)
		if err != nil {
			t.Fatal(err)
		}
		limit, err := MaximumEnvelopeEncodingBytes(s)
		if err != nil || len(recordEncoded(t, value)) != limit {
			t.Fatal("maximum configured or replacement fixture did not reach its exact encoding bound")
		}
	}
}
