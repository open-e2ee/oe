package identityattempt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/open-e2ee/oe/internal/identity"
)

var ErrEnvelope = errors.New("The identity attempt envelope is invalid.")

// Attempt retains only an identity-owned safe command and optional cancellation.
type Attempt struct {
	kind         Kind
	selection    *identity.SelectionCommand
	keys         *identity.KeysCommand
	lifecycle    *identity.LifecycleAttempt
	cancellation *identity.CancellationOperationID
}

func NewSelectionAttempt(command identity.SelectionCommand) (Attempt, error) {
	copy, err := command.Clone()
	if err != nil {
		return Attempt{}, ErrEnvelope
	}
	return Attempt{kind: Selection, selection: &copy}, nil
}

func NewKeysAttempt(command identity.KeysCommand) (Attempt, error) {
	copy, err := command.Clone()
	if err != nil {
		return Attempt{}, ErrEnvelope
	}
	return Attempt{kind: KeysOnly, keys: &copy}, nil
}

func NewLifecycleAttempt(command identity.LifecycleAttempt) (Attempt, error) {
	copy, err := command.Clone()
	if err != nil {
		return Attempt{}, ErrEnvelope
	}
	return Attempt{kind: Lifecycle, lifecycle: &copy}, nil
}

func (v Attempt) Validate() error {
	if v.cancellation != nil && v.cancellation.Validate() != nil {
		return ErrEnvelope
	}
	switch v.kind {
	case Selection:
		if v.selection != nil && v.keys == nil && v.lifecycle == nil && v.selection.Validate() == nil {
			return nil
		}
	case KeysOnly:
		if v.keys != nil && v.selection == nil && v.lifecycle == nil && v.keys.Validate() == nil {
			return nil
		}
	case Lifecycle:
		if v.lifecycle != nil && v.selection == nil && v.keys == nil && v.cancellation == nil && v.lifecycle.Validate() == nil {
			return nil
		}
	}
	return ErrEnvelope
}

func (v Attempt) Kind() Kind { return v.kind }

func (v Attempt) SelectionCommand() (identity.SelectionCommand, error) {
	if v.Validate() != nil || v.kind != Selection {
		return identity.SelectionCommand{}, ErrEnvelope
	}
	copy, err := v.selection.Clone()
	if err != nil {
		return identity.SelectionCommand{}, ErrEnvelope
	}
	return copy, nil
}

func (v Attempt) KeysCommand() (identity.KeysCommand, error) {
	if v.Validate() != nil || v.kind != KeysOnly {
		return identity.KeysCommand{}, ErrEnvelope
	}
	copy, err := v.keys.Clone()
	if err != nil {
		return identity.KeysCommand{}, ErrEnvelope
	}
	return copy, nil
}

func (v Attempt) LifecycleCommand() (identity.LifecycleAttempt, error) {
	if v.Validate() != nil || v.kind != Lifecycle {
		return identity.LifecycleAttempt{}, ErrEnvelope
	}
	copy, err := v.lifecycle.Clone()
	if err != nil {
		return identity.LifecycleAttempt{}, ErrEnvelope
	}
	return copy, nil
}

func (v Attempt) CancellationID() (identity.CancellationOperationID, bool) {
	if v.cancellation == nil {
		return "", false
	}
	return *v.cancellation, true
}

func (v Attempt) Clone() (Attempt, error) {
	if v.Validate() != nil {
		return Attempt{}, ErrEnvelope
	}
	var copy Attempt
	var err error
	switch v.kind {
	case Selection:
		copy, err = NewSelectionAttempt(*v.selection)
	case KeysOnly:
		copy, err = NewKeysAttempt(*v.keys)
	case Lifecycle:
		copy, err = NewLifecycleAttempt(*v.lifecycle)
	}
	if err != nil {
		return Attempt{}, ErrEnvelope
	}
	if v.cancellation != nil {
		copy.cancellation = new(*v.cancellation)
	}
	return copy, nil
}

// WithCancellation returns a detached value. It commits no revision or dispatch.
func (v Attempt) WithCancellation(id identity.CancellationOperationID) (Attempt, error) {
	if v.Validate() != nil || id.Validate() != nil || v.kind == Lifecycle || v.cancellation != nil && *v.cancellation != id {
		return Attempt{}, ErrEnvelope
	}
	copy, err := v.Clone()
	if err != nil {
		return Attempt{}, ErrEnvelope
	}
	copy.cancellation = new(id)
	return copy, nil
}

func (v Attempt) Equal(other Attempt) bool {
	if v.Validate() != nil || other.Validate() != nil || v.kind != other.kind || (v.cancellation == nil) != (other.cancellation == nil) {
		return false
	}
	if v.cancellation != nil && *v.cancellation != *other.cancellation {
		return false
	}
	switch v.kind {
	case Selection:
		return v.selection.Equal(*other.selection)
	case KeysOnly:
		return v.keys.Equal(*other.keys)
	case Lifecycle:
		return v.lifecycle.Equal(*other.lifecycle)
	}
	return false
}

func (v Attempt) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrEnvelope
	}
	var command any
	switch v.kind {
	case Selection:
		command = v.selection
	case KeysOnly:
		command = v.keys
	case Lifecycle:
		command = v.lifecycle
	}
	data, err := json.Marshal(struct {
		Kind           Kind                              `json:"kind"`
		Command        any                               `json:"command"`
		CancellationID *identity.CancellationOperationID `json:"cancellationId,omitempty"`
	}{v.kind, command, v.cancellation})
	if err != nil {
		return nil, ErrEnvelope
	}
	return data, nil
}

// recordFields owns only the two record objects. Nested values use their owners.
func recordFields(data []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, ErrEnvelope
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrEnvelope
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, names := range [][]string{required, optional} {
		for _, name := range names {
			allowed[name] = true
		}
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for d.More() {
		token, err = d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] {
			return nil, ErrEnvelope
		}
		if _, exists := fields[name]; exists {
			return nil, ErrEnvelope
		}
		var raw json.RawMessage
		if d.Decode(&raw) != nil {
			return nil, ErrEnvelope
		}
		fields[name] = raw
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrEnvelope
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrEnvelope
	}
	for _, name := range required {
		if _, exists := fields[name]; !exists {
			return nil, ErrEnvelope
		}
	}
	return fields, nil
}

func (v *Attempt) UnmarshalJSON(data []byte) error {
	if v == nil {
		return ErrEnvelope
	}
	fields, err := recordFields(data, []string{"kind", "command"}, []string{"cancellationId"})
	if err != nil {
		return ErrEnvelope
	}
	kind, err := slotText(fields["kind"])
	if err != nil {
		return ErrEnvelope
	}
	var candidate Attempt
	switch Kind(kind) {
	case Selection:
		var command identity.SelectionCommand
		if command.UnmarshalJSON(fields["command"]) != nil {
			return ErrEnvelope
		}
		candidate, err = NewSelectionAttempt(command)
	case KeysOnly:
		var command identity.KeysCommand
		if command.UnmarshalJSON(fields["command"]) != nil {
			return ErrEnvelope
		}
		candidate, err = NewKeysAttempt(command)
	case Lifecycle:
		var command identity.LifecycleAttempt
		if command.UnmarshalJSON(fields["command"]) != nil {
			return ErrEnvelope
		}
		candidate, err = NewLifecycleAttempt(command)
	default:
		return ErrEnvelope
	}
	if err != nil {
		return ErrEnvelope
	}
	if raw, present := fields["cancellationId"]; present {
		var id identity.CancellationOperationID
		if id.UnmarshalJSON(raw) != nil {
			return ErrEnvelope
		}
		candidate, err = candidate.WithCancellation(id)
		if err != nil {
			return ErrEnvelope
		}
	}
	*v = candidate
	return nil
}

// Envelope is a detached public record. It grants no persistence or authority.
type Envelope struct {
	revision identity.SafeInteger
	slot     Slot
	attempt  *Attempt
}

func NewVacantEnvelope(slot Slot, revision identity.SafeInteger) (Envelope, error) {
	value := Envelope{revision: revision, slot: slot}
	if value.Validate() != nil {
		return Envelope{}, ErrEnvelope
	}
	return value, nil
}

func NewOccupiedEnvelope(slot Slot, revision identity.SafeInteger, attempt Attempt) (Envelope, error) {
	copy, err := attempt.Clone()
	if err != nil {
		return Envelope{}, ErrEnvelope
	}
	value := Envelope{revision: revision, slot: slot, attempt: &copy}
	if value.Validate() != nil {
		return Envelope{}, ErrEnvelope
	}
	return value, nil
}

func (v Envelope) Validate() error {
	if v.slot.Validate() != nil || v.revision == 0 || v.revision.Validate() != nil {
		return ErrEnvelope
	}
	if v.attempt == nil {
		return nil
	}
	if v.attempt.Validate() != nil || v.slot.Kind() != v.attempt.Kind() {
		return ErrEnvelope
	}
	if v.attempt.kind == Selection && v.attempt.selection.Precondition.Scope.EnvironmentKind != v.slot.Environment() || v.attempt.kind == KeysOnly && v.attempt.keys.Precondition.Scope.EnvironmentKind != v.slot.Environment() {
		return ErrEnvelope
	}
	return nil
}

func (v Envelope) Slot() Slot                     { return v.slot }
func (v Envelope) Revision() identity.SafeInteger { return v.revision }

func (v Envelope) RetainedAttempt() (*Attempt, error) {
	if v.Validate() != nil {
		return nil, ErrEnvelope
	}
	if v.attempt == nil {
		return nil, nil
	}
	copy, err := v.attempt.Clone()
	if err != nil {
		return nil, ErrEnvelope
	}
	return &copy, nil
}

func (v Envelope) Clone() (Envelope, error) {
	if v.Validate() != nil {
		return Envelope{}, ErrEnvelope
	}
	if v.attempt == nil {
		return NewVacantEnvelope(v.slot, v.revision)
	}
	return NewOccupiedEnvelope(v.slot, v.revision, *v.attempt)
}

func (v Envelope) Equal(other Envelope) bool {
	if v.Validate() != nil || other.Validate() != nil || v.revision != other.revision || !v.slot.Equal(other.slot) || (v.attempt == nil) != (other.attempt == nil) {
		return false
	}
	return v.attempt == nil || v.attempt.Equal(*other.attempt)
}

func (v Envelope) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrEnvelope
	}
	data, err := json.Marshal(struct {
		SchemaVersion int                  `json:"schemaVersion"`
		Revision      identity.SafeInteger `json:"revision"`
		Slot          Slot                 `json:"slot"`
		Attempt       *Attempt             `json:"attempt"`
	}{1, v.revision, v.slot, v.attempt})
	if err != nil {
		return nil, ErrEnvelope
	}
	return data, nil
}

// UnmarshalJSON refuses decoding without the caller's expected public slot.
func (v *Envelope) UnmarshalJSON([]byte) error { return ErrEnvelope }

func EncodeEnvelope(value Envelope) ([]byte, error) {
	data, err := value.MarshalJSON()
	if err != nil {
		return nil, ErrEnvelope
	}
	return append(data, '\n'), nil
}

func DecodeEnvelope(data []byte, expectedSlot Slot) (Envelope, error) {
	if expectedSlot.Validate() != nil {
		return Envelope{}, ErrEnvelope
	}
	fields, err := recordFields(data, []string{"schemaVersion", "revision", "slot", "attempt"}, nil)
	if err != nil {
		return Envelope{}, ErrEnvelope
	}
	var schema, revision identity.SafeInteger
	var slot Slot
	if schema.UnmarshalJSON(fields["schemaVersion"]) != nil || schema != 1 || revision.UnmarshalJSON(fields["revision"]) != nil || slot.UnmarshalJSON(fields["slot"]) != nil || !slot.Equal(expectedSlot) {
		return Envelope{}, ErrEnvelope
	}
	if bytes.Equal(bytes.TrimSpace(fields["attempt"]), []byte("null")) {
		return NewVacantEnvelope(slot, revision)
	}
	var attempt Attempt
	if attempt.UnmarshalJSON(fields["attempt"]) != nil {
		return Envelope{}, ErrEnvelope
	}
	return NewOccupiedEnvelope(slot, revision, attempt)
}

// MaximumEnvelopeEncodingBytes bounds this encoder, not all valid JSON spellings.
func MaximumEnvelopeEncodingBytes(expectedSlot Slot) (int, error) {
	slot, err := EncodeSlot(expectedSlot)
	if err != nil {
		return 0, ErrEnvelope
	}
	// ContractText emits six bytes per code unit. Safe integers use at most 16 digits.
	const initialKey = len(`{"kty":"EC","crv":"P-256","x":"","y":"","kid":"","alg":"ES256","use":"sig","key_ops":["verify"],"ext":true}`) + 86 + 6*255
	const replacementKey = initialKey - 6*255 + 6*128
	const initialKeys = 2 + 32*initialKey + 31
	const replacementKeys = 2 + 32*replacementKey + 31
	const precondition = len(`{"publishableKey":"","recoveryGeneration":0,"scope":{"environmentId":"","environmentKind":"production","projectId":"","protocolProfile":"signal","relayScopeId":""}}`) + 255 + 15 + 6*(256+256+255)
	const configured = len(`{"mode":"provider-bound","algorithms":["ES256"],"issuer":"","audience":"","subjectClaim":"","keys":[]}`) + 6*(255+255) + 64 + initialKeys - 2
	const clerk = len(`{"mode":"provider-bound","algorithms":["RS256"],"issuer":"","audience":"","subjectClaim":"sub","provider":"clerk","authorizedParties":[],"allowMissingAuthorizedParty":false}`) + 6*(512+512) + 16*(2+6*512) + 15
	const selection = len(`{"operationId":"","expectedConfigurationVersion":0,"target":null,"precondition":null}`) + 96 + 15 + max(configured, clerk) - 4 + precondition - 4
	const keys = len(`{"operationId":"","expectedConfigurationVersion":0,"keys":[],"precondition":null}`) + 96 + 15 + replacementKeys - 2 + precondition - 4
	const lifecycle = len(`{"operationId":"","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`) + 6*128 + 15
	var attempt int
	switch expectedSlot.Kind() {
	case Selection:
		attempt = len(`{"kind":"selection","command":null,"cancellationId":""}`) + selection - 4 + 96
	case KeysOnly:
		attempt = len(`{"kind":"keys-only","command":null,"cancellationId":""}`) + keys - 4 + 96
	case Lifecycle:
		attempt = len(`{"kind":"lifecycle","command":null}`) + lifecycle - 4
	}
	fixed := len(`{"schemaVersion":1,"revision":0,"slot":null,"attempt":null}`) + 15 - 4 + attempt - 4 + 1
	if len(slot) > int(^uint(0)>>1)-fixed {
		return 0, ErrEnvelope
	}
	return len(slot) + fixed, nil
}
