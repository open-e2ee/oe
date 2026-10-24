package identity

import (
	"encoding/json"
	"slices"
)

type SelectionOperationID string
type CancellationOperationID string
type SelectionReadID struct{ value ContractText }

func (v SelectionOperationID) Validate() error {
	if !matches(`^[A-Za-z0-9_-]{8,96}$`, string(v)) {
		return ErrIdentityValue
	}
	return nil
}
func (v CancellationOperationID) Validate() error { return SelectionOperationID(v).Validate() }
func (v SelectionOperationID) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrIdentityValue
	}
	return json.Marshal(string(v))
}
func (v *SelectionOperationID) UnmarshalJSON(data []byte) error {
	var t ContractText
	if t.UnmarshalJSON(data) != nil || !asciiText(t, `^[A-Za-z0-9_-]{8,96}$`) {
		return ErrIdentityValue
	}
	*v = SelectionOperationID(t.webString())
	return nil
}
func (v CancellationOperationID) MarshalJSON() ([]byte, error) {
	return SelectionOperationID(v).MarshalJSON()
}
func (v *CancellationOperationID) UnmarshalJSON(data []byte) error {
	var id SelectionOperationID
	if id.UnmarshalJSON(data) != nil {
		return ErrIdentityValue
	}
	*v = CancellationOperationID(id)
	return nil
}
func NewSelectionReadID(value ContractText) (SelectionReadID, error) {
	if !textBound(value, 1, 255) {
		return SelectionReadID{}, ErrIdentityValue
	}
	return SelectionReadID{TextFromUnits(value.Units())}, nil
}
func (v SelectionReadID) Text() ContractText { return TextFromUnits(v.value.Units()) }
func (v SelectionReadID) MarshalJSON() ([]byte, error) {
	if !textBound(v.value, 1, 255) {
		return nil, ErrIdentityValue
	}
	return v.value.MarshalJSON()
}
func (v *SelectionReadID) UnmarshalJSON(data []byte) error {
	var t ContractText
	if t.UnmarshalJSON(data) != nil {
		return ErrIdentityValue
	}
	value, e := NewSelectionReadID(t)
	if e != nil {
		return e
	}
	*v = value
	return nil
}

type SelectionCommand struct {
	OperationID                  SelectionOperationID `json:"operationId"`
	ExpectedConfigurationVersion SafeInteger          `json:"expectedConfigurationVersion"`
	Target                       SelectionTarget      `json:"target"`
	Precondition                 Precondition         `json:"precondition"`
}

func (v SelectionCommand) Validate() error {
	if v.OperationID.Validate() != nil || !positive(v.ExpectedConfigurationVersion) || v.Target.Validate() != nil || v.Precondition.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type KeysCommand struct {
	OperationID                  SelectionOperationID `json:"operationId"`
	ExpectedConfigurationVersion SafeInteger          `json:"expectedConfigurationVersion"`
	Keys                         ReplacementKeys      `json:"keys"`
	Precondition                 Precondition         `json:"precondition"`
}

func (v KeysCommand) Validate() error {
	if v.OperationID.Validate() != nil || !positive(v.ExpectedConfigurationVersion) || v.Keys.Validate() != nil || v.Precondition.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type OperationResult struct {
	Kind                 *string      `json:"kind,omitempty"`
	OperationID          ContractText `json:"operationId"`
	State                string       `json:"state"`
	ConfigurationVersion SafeInteger  `json:"configurationVersion"`
	AdmissionRevision    SafeInteger  `json:"admissionRevision"`
	Reason               *string      `json:"reason,omitempty"`
}

func (v OperationResult) Validate() error {
	if v.Kind != nil && !slices.Contains([]string{"migration-install", "migration-retire", "keys-only"}, *v.Kind) || !textBound(v.OperationID, 1, 255) || !slices.Contains([]string{"prepared", "fenced", "configuration_committed", "applied", "aborting", "aborted", "refused", "deleted", "unchanged"}, v.State) || !positive(v.ConfigurationVersion) || v.AdmissionRevision.Validate() != nil || v.Reason != nil && !slices.Contains([]string{"migration_required", "authority_in_use"}, *v.Reason) {
		return ErrIdentityValue
	}
	return nil
}

type SelectionResult OperationResult
type KeysResult OperationResult

func (v SelectionResult) Validate() error {
	if OperationResult(v).Validate() != nil || v.Kind != nil {
		return ErrIdentityValue
	}
	return nil
}
func (v KeysResult) Validate() error {
	if OperationResult(v).Validate() != nil || v.Kind == nil || *v.Kind != "keys-only" {
		return ErrIdentityValue
	}
	return nil
}

type NativeCapabilities struct {
	Clerk    string `json:"clerk"`
	Firebase string `json:"firebase"`
}

func (v NativeCapabilities) Validate() error {
	states := []string{"closed", "owned_acceptance", "available"}
	if !slices.Contains(states, v.Clerk) || !slices.Contains(states, v.Firebase) {
		return ErrIdentityValue
	}
	return nil
}

type PreviewRequest struct {
	Kind                         string           `json:"kind"`
	ExpectedConfigurationVersion SafeInteger      `json:"expectedConfigurationVersion"`
	Target                       *SelectionTarget `json:"target,omitempty"`
	Keys                         *ReplacementKeys `json:"keys,omitempty"`
}

func (v PreviewRequest) Validate() error {
	if !positive(v.ExpectedConfigurationVersion) {
		return ErrIdentityValue
	}
	if v.Kind == "selection" && v.Target != nil && v.Keys == nil {
		return v.Target.Validate()
	}
	if v.Kind == "keys-only" && v.Keys != nil && v.Target == nil {
		return v.Keys.Validate()
	}
	return ErrIdentityValue
}

type PreviewResult struct {
	Kind                         string             `json:"kind"`
	ExpectedConfigurationVersion SafeInteger        `json:"expectedConfigurationVersion"`
	Target                       *SelectionTarget   `json:"target,omitempty"`
	Keys                         *ReplacementKeys   `json:"keys,omitempty"`
	Current                      CurrentContext     `json:"current"`
	NativeCapabilities           NativeCapabilities `json:"nativeCapabilities"`
}

func (v PreviewResult) Validate() error {
	request := PreviewRequest{Kind: v.Kind, ExpectedConfigurationVersion: v.ExpectedConfigurationVersion, Target: v.Target, Keys: v.Keys}
	if request.Validate() != nil || v.Current.Validate() != nil || v.NativeCapabilities.Validate() != nil || v.Current.Configuration.ConfigurationVersion != v.ExpectedConfigurationVersion {
		return ErrIdentityValue
	}
	return nil
}

type SelectionReceiptSource string

const (
	SelectionApply  SelectionReceiptSource = "select"
	SelectionStatus SelectionReceiptSource = "status"
	SelectionCancel SelectionReceiptSource = "cancel"
	KeysReplace     SelectionReceiptSource = "replace"
)

type SelectionReceipt struct {
	original     SelectionCommand
	cancellation *CancellationOperationID
	source       SelectionReceiptSource
	result       SelectionResult
}
type KeysReceipt struct {
	original     KeysCommand
	cancellation *CancellationOperationID
	source       SelectionReceiptSource
	result       KeysResult
}

func cancellationEqual(a, b *CancellationOperationID) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func validSelectionMetadata(source SelectionReceiptSource, cancellation *CancellationOperationID, keys bool) bool {
	if cancellation != nil && cancellation.Validate() != nil {
		return false
	}
	if source == SelectionCancel {
		return cancellation != nil
	}
	if source == SelectionStatus {
		return true
	}
	return cancellation == nil && (source == SelectionApply && !keys || source == KeysReplace && keys)
}

// Receipt factories accept caller metadata, not a wire observationSource.
// Actual transport ownership must establish that metadata before calling them.
func NewSelectionReceipt(original SelectionCommand, cancellation *CancellationOperationID, source SelectionReceiptSource, result SelectionResult) (SelectionReceipt, error) {
	if original.Validate() != nil || result.Validate() != nil || !validSelectionMetadata(source, cancellation, false) || !textLiteral(result.OperationID, string(original.OperationID)) {
		return SelectionReceipt{}, ErrIdentityValue
	}
	command, e := original.Clone()
	if e != nil {
		return SelectionReceipt{}, e
	}
	received, e := result.Clone()
	if e != nil {
		return SelectionReceipt{}, e
	}
	var cancel *CancellationOperationID
	if cancellation != nil {
		cancel = new(*cancellation)
	}
	return SelectionReceipt{command, cancel, source, received}, nil
}
func NewKeysReceipt(original KeysCommand, cancellation *CancellationOperationID, source SelectionReceiptSource, result KeysResult) (KeysReceipt, error) {
	if original.Validate() != nil || result.Validate() != nil || !validSelectionMetadata(source, cancellation, true) || !textLiteral(result.OperationID, string(original.OperationID)) {
		return KeysReceipt{}, ErrIdentityValue
	}
	command, e := original.Clone()
	if e != nil {
		return KeysReceipt{}, e
	}
	received, e := result.Clone()
	if e != nil {
		return KeysReceipt{}, e
	}
	var cancel *CancellationOperationID
	if cancellation != nil {
		cancel = new(*cancellation)
	}
	return KeysReceipt{command, cancel, source, received}, nil
}
func (v SelectionReceipt) Result() (SelectionResult, error) { return v.result.Clone() }
func (v KeysReceipt) Result() (KeysResult, error)           { return v.result.Clone() }
func (v SelectionReceipt) MarshalJSON() ([]byte, error)     { return nil, ErrIdentityValue }
func (v *SelectionReceipt) UnmarshalJSON([]byte) error      { return ErrIdentityValue }
func (v KeysReceipt) MarshalJSON() ([]byte, error)          { return nil, ErrIdentityValue }
func (v *KeysReceipt) UnmarshalJSON([]byte) error           { return ErrIdentityValue }
func operationDisposition(state string) ReceiptDisposition {
	if slices.Contains([]string{"applied", "aborted", "refused", "deleted", "unchanged"}, state) {
		return ReceiptSettled
	}
	return ReceiptPending
}
func ClassifySelectionReceipt(expected SelectionCommand, cancellation *CancellationOperationID, receipt SelectionReceipt) ReceiptDisposition {
	if expected.Validate() != nil || !expected.Equal(receipt.original) || !cancellationEqual(cancellation, receipt.cancellation) || receipt.result.Validate() != nil || !validSelectionMetadata(receipt.source, receipt.cancellation, false) || !textLiteral(receipt.result.OperationID, string(expected.OperationID)) {
		return ReceiptMismatch
	}
	return operationDisposition(receipt.result.State)
}
func ClassifyKeysReceipt(expected KeysCommand, cancellation *CancellationOperationID, receipt KeysReceipt) ReceiptDisposition {
	if expected.Validate() != nil || !expected.Equal(receipt.original) || !cancellationEqual(cancellation, receipt.cancellation) || receipt.result.Validate() != nil || !validSelectionMetadata(receipt.source, receipt.cancellation, true) || !textLiteral(receipt.result.OperationID, string(expected.OperationID)) {
		return ReceiptMismatch
	}
	return operationDisposition(receipt.result.State)
}

func (v SelectionCommand) MarshalJSON() ([]byte, error) {
	type wire SelectionCommand
	return encodeChecked(wire(v), v.Validate)
}
func (v *SelectionCommand) UnmarshalJSON(data []byte) error {
	type wire SelectionCommand
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := SelectionCommand(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v SelectionCommand) Clone() (SelectionCommand, error)  { return cloneValue(v) }
func (v SelectionCommand) Equal(other SelectionCommand) bool { return equalValue(v, other) }

func (v KeysCommand) MarshalJSON() ([]byte, error) {
	type wire KeysCommand
	return encodeChecked(wire(v), v.Validate)
}
func (v *KeysCommand) UnmarshalJSON(data []byte) error {
	type wire KeysCommand
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := KeysCommand(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v KeysCommand) Clone() (KeysCommand, error)  { return cloneValue(v) }
func (v KeysCommand) Equal(other KeysCommand) bool { return equalValue(v, other) }

func (v OperationResult) MarshalJSON() ([]byte, error) {
	type wire OperationResult
	return encodeChecked(wire(v), v.Validate)
}
func (v *OperationResult) UnmarshalJSON(data []byte) error {
	type wire OperationResult
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := OperationResult(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v OperationResult) Clone() (OperationResult, error)  { return cloneValue(v) }
func (v OperationResult) Equal(other OperationResult) bool { return equalValue(v, other) }

func (v SelectionResult) MarshalJSON() ([]byte, error) {
	type wire SelectionResult
	return encodeChecked(wire(v), v.Validate)
}
func (v *SelectionResult) UnmarshalJSON(data []byte) error {
	type wire SelectionResult
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := SelectionResult(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v SelectionResult) Clone() (SelectionResult, error)  { return cloneValue(v) }
func (v SelectionResult) Equal(other SelectionResult) bool { return equalValue(v, other) }

func (v KeysResult) MarshalJSON() ([]byte, error) {
	type wire KeysResult
	return encodeChecked(wire(v), v.Validate)
}
func (v *KeysResult) UnmarshalJSON(data []byte) error {
	type wire KeysResult
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := KeysResult(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v KeysResult) Clone() (KeysResult, error)  { return cloneValue(v) }
func (v KeysResult) Equal(other KeysResult) bool { return equalValue(v, other) }

func (v NativeCapabilities) MarshalJSON() ([]byte, error) {
	type wire NativeCapabilities
	return encodeChecked(wire(v), v.Validate)
}
func (v *NativeCapabilities) UnmarshalJSON(data []byte) error {
	type wire NativeCapabilities
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := NativeCapabilities(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v NativeCapabilities) Clone() (NativeCapabilities, error)  { return cloneValue(v) }
func (v NativeCapabilities) Equal(other NativeCapabilities) bool { return equalValue(v, other) }

func (v PreviewRequest) MarshalJSON() ([]byte, error) {
	type wire PreviewRequest
	return encodeChecked(wire(v), v.Validate)
}
func (v *PreviewRequest) UnmarshalJSON(data []byte) error {
	type wire PreviewRequest
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := PreviewRequest(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v PreviewRequest) Clone() (PreviewRequest, error)  { return cloneValue(v) }
func (v PreviewRequest) Equal(other PreviewRequest) bool { return equalValue(v, other) }

func (v PreviewResult) MarshalJSON() ([]byte, error) {
	type wire PreviewResult
	return encodeChecked(wire(v), v.Validate)
}
func (v *PreviewResult) UnmarshalJSON(data []byte) error {
	type wire PreviewResult
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := PreviewResult(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v PreviewResult) Clone() (PreviewResult, error)  { return cloneValue(v) }
func (v PreviewResult) Equal(other PreviewResult) bool { return equalValue(v, other) }
