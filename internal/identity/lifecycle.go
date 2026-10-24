package identity

import (
	"encoding/json"
	"slices"
)

type LifecycleInputTarget struct {
	Kind           string        `json:"kind"`
	AccountAddress *ContractText `json:"accountAddress,omitempty"`
	Subject        *ContractText `json:"subject,omitempty"`
	ProfileSource  *string       `json:"profileSource,omitempty"`
}

func (v LifecycleInputTarget) Validate() error {
	if v.Kind == "account" && v.AccountAddress != nil && textBound(*v.AccountAddress, 1, 256) && v.Subject == nil && v.ProfileSource == nil {
		return nil
	}
	if v.Kind == "subject" && v.AccountAddress == nil && v.Subject != nil && textBound(*v.Subject, 1, 1024) && v.ProfileSource != nil && slices.Contains([]string{"installed", "migration-target"}, *v.ProfileSource) {
		return nil
	}
	return ErrIdentityValue
}

type LifecyclePublicTarget struct {
	Kind string `json:"kind"`
}

func (v LifecyclePublicTarget) Validate() error {
	if !targetKind(v.Kind) {
		return ErrIdentityValue
	}
	return nil
}
func targetKind(value string) bool     { return value == "account" || value == "subject" }
func lifecycleState(value string) bool { return value == "active" || value == "suspended" }
func ValidatePreparedOperationID(value ContractText) error {
	if !asciiText(value, `^lc1_[0-9a-f]{16}_[A-Za-z0-9_-]{21}[AQgw]_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`) {
		return ErrIdentityValue
	}
	return nil
}
func ValidateResumeOperationID(value ContractText) error {
	if !asciiText(value, `^[A-Za-z0-9_-]{1,128}$`) {
		return ErrIdentityValue
	}
	return nil
}
func ValidatePreparationNonce(value string) error {
	if !matches(`^[A-Za-z0-9_-]{21}[AQgw]$`, value) {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleAttempt struct {
	OperationID              ContractText `json:"operationId"`
	TargetKind               string       `json:"targetKind"`
	ExpectedLifecycleVersion SafeInteger  `json:"expectedLifecycleVersion"`
	State                    string       `json:"state"`
}

func (v LifecycleAttempt) Validate() error {
	if !textBound(v.OperationID, 1, 128) || !targetKind(v.TargetKind) || !lifecycleState(v.State) || v.ExpectedLifecycleVersion.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleOperation struct {
	Scope           Scope                 `json:"scope"`
	Target          LifecyclePublicTarget `json:"target"`
	OperationID     ContractText          `json:"operationId"`
	ExpectedVersion SafeInteger           `json:"expectedVersion"`
}

func (v LifecycleOperation) Validate() error {
	if v.Scope.Validate() != nil || v.Target.Validate() != nil || !textBound(v.OperationID, 1, 128) || v.ExpectedVersion.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleReference struct {
	Scope       Scope                 `json:"scope"`
	Target      LifecyclePublicTarget `json:"target"`
	OperationID ContractText          `json:"operationId"`
	Version     SafeInteger           `json:"version"`
}

func (v LifecycleReference) Validate() error {
	if v.Scope.Validate() != nil || v.Target.Validate() != nil || !textBound(v.OperationID, 1, 128) || !positive(v.Version) {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleHead struct {
	Scope       Scope                 `json:"scope"`
	Target      LifecyclePublicTarget `json:"target"`
	OperationID ContractText          `json:"operationId"`
	Version     SafeInteger           `json:"version"`
	State       string                `json:"state"`
}

func (v LifecycleHead) Validate() error {
	reference := LifecycleReference{v.Scope, v.Target, v.OperationID, v.Version}
	if reference.Validate() != nil || !lifecycleState(v.State) {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleStatus struct {
	Operation          LifecycleOperation  `json:"operation"`
	Version            *SafeInteger        `json:"version" nullable:"true"`
	State              string              `json:"state"`
	CurrentHead        *LifecycleHead      `json:"currentHead" nullable:"true"`
	EffectiveState     string              `json:"effectiveState"`
	Status             string              `json:"status"`
	SupersededBy       *LifecycleReference `json:"supersededBy" nullable:"true"`
	RequiredMailboxes  SafeInteger         `json:"requiredMailboxes"`
	PreparedMailboxes  SafeInteger         `json:"preparedMailboxes"`
	ActivatedMailboxes SafeInteger         `json:"activatedMailboxes"`
}

func (v LifecycleStatus) Validate() error {
	if v.Operation.Validate() != nil || v.Version != nil && !positive(*v.Version) || !lifecycleState(v.State) || !lifecycleState(v.EffectiveState) || v.CurrentHead != nil && v.CurrentHead.Validate() != nil || v.SupersededBy != nil && v.SupersededBy.Validate() != nil || !slices.Contains([]string{"pending_owners", "pending_prepare", "pending_activation", "pending_service_ready", "converged", "refused", "superseded", "superseded_by_deletion"}, v.Status) {
		return ErrIdentityValue
	}
	if v.RequiredMailboxes.Validate() != nil || v.PreparedMailboxes.Validate() != nil || v.ActivatedMailboxes.Validate() != nil || v.ActivatedMailboxes > v.PreparedMailboxes || v.PreparedMailboxes > v.RequiredMailboxes || v.Status == "superseded" && v.SupersededBy == nil {
		return ErrIdentityValue
	}
	return nil
}

type BoundAccountApplication struct {
	Kind             string           `json:"kind"`
	EffectiveState   string           `json:"effectiveState"`
	CurrentOperation *LifecycleStatus `json:"currentOperation" nullable:"true"`
}

func (v BoundAccountApplication) Validate() error {
	if v.Kind != "bound-account" || !lifecycleState(v.EffectiveState) || v.CurrentOperation != nil && v.CurrentOperation.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type LifecycleApplication struct {
	kind  string
	bound *BoundAccountApplication
}

func UnboundSubjectApplication() LifecycleApplication {
	return LifecycleApplication{kind: "unbound-subject"}
}
func BoundLifecycleApplication(state string, current *LifecycleStatus) (LifecycleApplication, error) {
	value := BoundAccountApplication{Kind: "bound-account", EffectiveState: state, CurrentOperation: current}
	if value.Validate() != nil {
		return LifecycleApplication{}, ErrIdentityValue
	}
	copied, e := value.Clone()
	if e != nil {
		return LifecycleApplication{}, e
	}
	return LifecycleApplication{kind: "bound-account", bound: &copied}, nil
}
func (v LifecycleApplication) Kind() string { return v.kind }
func (v LifecycleApplication) Bound() (*BoundAccountApplication, error) {
	if v.kind != "bound-account" || v.bound == nil {
		return nil, ErrIdentityValue
	}
	copy, e := v.bound.Clone()
	return &copy, e
}
func (v LifecycleApplication) Validate() error {
	if v.kind == "unbound-subject" && v.bound == nil {
		return nil
	}
	if v.kind == "bound-account" && v.bound != nil {
		return v.bound.Validate()
	}
	return ErrIdentityValue
}
func (v LifecycleApplication) MarshalJSON() ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrIdentityValue
	}
	if v.bound != nil {
		return json.Marshal(v.bound)
	}
	return json.Marshal(struct {
		Kind string `json:"kind"`
	}{"unbound-subject"})
}
func (v *LifecycleApplication) UnmarshalJSON(data []byte) error {
	if checkJSON(data) != nil {
		return ErrIdentityValue
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return ErrIdentityValue
	}
	var kind string
	if json.Unmarshal(fields["kind"], &kind) != nil {
		return ErrIdentityValue
	}
	if kind == "bound-account" {
		var value BoundAccountApplication
		if json.Unmarshal(data, &value) != nil {
			return ErrIdentityValue
		}
		*v = LifecycleApplication{kind: kind, bound: &value}
		return nil
	}
	var value struct {
		Kind string `json:"kind"`
	}
	if decodeClosed(data, &value) != nil || value.Kind != "unbound-subject" {
		return ErrIdentityValue
	}
	*v = UnboundSubjectApplication()
	return nil
}

type TargetObservation struct {
	OperationID     ContractText          `json:"operationId"`
	Scope           Scope                 `json:"scope"`
	Target          LifecyclePublicTarget `json:"target"`
	ObservedVersion SafeInteger           `json:"observedVersion"`
	ObservedState   string                `json:"observedState"`
	CurrentHead     *LifecycleHead        `json:"currentHead" nullable:"true"`
	Application     LifecycleApplication  `json:"application"`
}

func (v TargetObservation) Validate() error {
	if !textBound(v.OperationID, 1, 128) || v.Scope.Validate() != nil || v.Target.Validate() != nil || v.ObservedVersion.Validate() != nil || !lifecycleState(v.ObservedState) || v.CurrentHead != nil && v.CurrentHead.Validate() != nil || v.Application.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type Preparation struct {
	OperationID              ContractText          `json:"operationId"`
	PreparedOperationID      ContractText          `json:"preparedOperationId"`
	Scope                    Scope                 `json:"scope"`
	ExpectedLifecycleVersion SafeInteger           `json:"expectedLifecycleVersion"`
	State                    string                `json:"state"`
	Target                   LifecyclePublicTarget `json:"target"`
}

func (v Preparation) Validate() error {
	if !textBound(v.OperationID, 1, 128) || ValidatePreparedOperationID(v.PreparedOperationID) != nil || v.Scope.Validate() != nil || v.ExpectedLifecycleVersion.Validate() != nil || !lifecycleState(v.State) || v.Target.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}
func (v Preparation) Attempt() (LifecycleAttempt, error) {
	if v.Validate() != nil {
		return LifecycleAttempt{}, ErrIdentityValue
	}
	return LifecycleAttempt{TextFromUnits(v.PreparedOperationID.Units()), v.Target.Kind, v.ExpectedLifecycleVersion, v.State}, nil
}

type ReceiptSource string

const (
	LifecycleStatusSource ReceiptSource = "status"
	LifecycleApplySource  ReceiptSource = "apply"
	LifecycleResumeSource ReceiptSource = "resume"
)

type ReceiptDisposition string

const (
	ReceiptMismatch             ReceiptDisposition = "mismatch"
	ReceiptPending              ReceiptDisposition = "pending"
	ReceiptContinuationRequired ReceiptDisposition = "continuation_required"
	ReceiptSettled              ReceiptDisposition = "settled"
)

type LifecycleReceipt struct {
	original LifecycleAttempt
	scope    Scope
	source   ReceiptSource
	result   LifecycleStatus
}

func validLifecycleSource(v ReceiptSource) bool {
	return v == LifecycleStatusSource || v == LifecycleApplySource || v == LifecycleResumeSource
}
func lifecycleAssociation(expected LifecycleAttempt, scope Scope, result LifecycleStatus) bool {
	return expected.Validate() == nil && scope.Validate() == nil && result.Validate() == nil && expected.OperationID.Equal(result.Operation.OperationID) && expected.TargetKind == result.Operation.Target.Kind && expected.State == result.State && expected.ExpectedLifecycleVersion == result.Operation.ExpectedVersion && scope.Equal(result.Operation.Scope)
}
func NewLifecycleReceipt(original LifecycleAttempt, scope Scope, source ReceiptSource, result LifecycleStatus) (LifecycleReceipt, error) {
	if !validLifecycleSource(source) || !lifecycleAssociation(original, scope, result) {
		return LifecycleReceipt{}, ErrIdentityValue
	}
	command, e := original.Clone()
	if e != nil {
		return LifecycleReceipt{}, e
	}
	association, e := scope.Clone()
	if e != nil {
		return LifecycleReceipt{}, e
	}
	received, e := result.Clone()
	if e != nil {
		return LifecycleReceipt{}, e
	}
	return LifecycleReceipt{command, association, source, received}, nil
}
func (v LifecycleReceipt) Result() (LifecycleStatus, error) { return v.result.Clone() }
func (v LifecycleReceipt) MarshalJSON() ([]byte, error)     { return nil, ErrIdentityValue }
func (v *LifecycleReceipt) UnmarshalJSON([]byte) error      { return ErrIdentityValue }
func ClassifyLifecycleReceipt(expected LifecycleAttempt, scope Scope, receipt LifecycleReceipt) ReceiptDisposition {
	if !validLifecycleSource(receipt.source) || !expected.Equal(receipt.original) || !scope.Equal(receipt.scope) || !lifecycleAssociation(expected, scope, receipt.result) {
		return ReceiptMismatch
	}
	if receipt.result.Status == "converged" {
		if receipt.source == LifecycleStatusSource {
			return ReceiptContinuationRequired
		}
		return ReceiptSettled
	}
	if slices.Contains([]string{"refused", "superseded", "superseded_by_deletion"}, receipt.result.Status) {
		return ReceiptSettled
	}
	return ReceiptPending
}

func (v LifecycleInputTarget) MarshalJSON() ([]byte, error) {
	type wire LifecycleInputTarget
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleInputTarget) UnmarshalJSON(data []byte) error {
	type wire LifecycleInputTarget
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleInputTarget(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleInputTarget) Clone() (LifecycleInputTarget, error)  { return cloneValue(v) }
func (v LifecycleInputTarget) Equal(other LifecycleInputTarget) bool { return equalValue(v, other) }

func (v LifecyclePublicTarget) MarshalJSON() ([]byte, error) {
	type wire LifecyclePublicTarget
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecyclePublicTarget) UnmarshalJSON(data []byte) error {
	type wire LifecyclePublicTarget
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecyclePublicTarget(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecyclePublicTarget) Clone() (LifecyclePublicTarget, error)  { return cloneValue(v) }
func (v LifecyclePublicTarget) Equal(other LifecyclePublicTarget) bool { return equalValue(v, other) }

func (v LifecycleAttempt) MarshalJSON() ([]byte, error) {
	type wire LifecycleAttempt
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleAttempt) UnmarshalJSON(data []byte) error {
	type wire LifecycleAttempt
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleAttempt(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleAttempt) Clone() (LifecycleAttempt, error)  { return cloneValue(v) }
func (v LifecycleAttempt) Equal(other LifecycleAttempt) bool { return equalValue(v, other) }

func (v LifecycleOperation) MarshalJSON() ([]byte, error) {
	type wire LifecycleOperation
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleOperation) UnmarshalJSON(data []byte) error {
	type wire LifecycleOperation
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleOperation(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleOperation) Clone() (LifecycleOperation, error)  { return cloneValue(v) }
func (v LifecycleOperation) Equal(other LifecycleOperation) bool { return equalValue(v, other) }

func (v LifecycleReference) MarshalJSON() ([]byte, error) {
	type wire LifecycleReference
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleReference) UnmarshalJSON(data []byte) error {
	type wire LifecycleReference
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleReference(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleReference) Clone() (LifecycleReference, error)  { return cloneValue(v) }
func (v LifecycleReference) Equal(other LifecycleReference) bool { return equalValue(v, other) }

func (v LifecycleHead) MarshalJSON() ([]byte, error) {
	type wire LifecycleHead
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleHead) UnmarshalJSON(data []byte) error {
	type wire LifecycleHead
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleHead(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleHead) Clone() (LifecycleHead, error)  { return cloneValue(v) }
func (v LifecycleHead) Equal(other LifecycleHead) bool { return equalValue(v, other) }

func (v LifecycleStatus) MarshalJSON() ([]byte, error) {
	type wire LifecycleStatus
	return encodeChecked(wire(v), v.Validate)
}
func (v *LifecycleStatus) UnmarshalJSON(data []byte) error {
	type wire LifecycleStatus
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := LifecycleStatus(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v LifecycleStatus) Clone() (LifecycleStatus, error)  { return cloneValue(v) }
func (v LifecycleStatus) Equal(other LifecycleStatus) bool { return equalValue(v, other) }

func (v BoundAccountApplication) MarshalJSON() ([]byte, error) {
	type wire BoundAccountApplication
	return encodeChecked(wire(v), v.Validate)
}
func (v *BoundAccountApplication) UnmarshalJSON(data []byte) error {
	type wire BoundAccountApplication
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := BoundAccountApplication(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v BoundAccountApplication) Clone() (BoundAccountApplication, error) { return cloneValue(v) }
func (v BoundAccountApplication) Equal(other BoundAccountApplication) bool {
	return equalValue(v, other)
}

func (v TargetObservation) MarshalJSON() ([]byte, error) {
	type wire TargetObservation
	return encodeChecked(wire(v), v.Validate)
}
func (v *TargetObservation) UnmarshalJSON(data []byte) error {
	type wire TargetObservation
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := TargetObservation(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v TargetObservation) Clone() (TargetObservation, error)  { return cloneValue(v) }
func (v TargetObservation) Equal(other TargetObservation) bool { return equalValue(v, other) }

func (v Preparation) MarshalJSON() ([]byte, error) {
	type wire Preparation
	return encodeChecked(wire(v), v.Validate)
}
func (v *Preparation) UnmarshalJSON(data []byte) error {
	type wire Preparation
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := Preparation(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v Preparation) Clone() (Preparation, error)  { return cloneValue(v) }
func (v Preparation) Equal(other Preparation) bool { return equalValue(v, other) }
