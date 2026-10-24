package identity

import "slices"

type Scope struct {
	EnvironmentID   ContractText `json:"environmentId"`
	EnvironmentKind string       `json:"environmentKind"`
	ProjectID       ContractText `json:"projectId"`
	ProtocolProfile string       `json:"protocolProfile"`
	RelayScopeID    ContractText `json:"relayScopeId"`
}

func (v Scope) Validate() error {
	if !textBound(v.EnvironmentID, 1, 256) || !textBound(v.ProjectID, 1, 256) || !textBound(v.RelayScopeID, 1, 256) || !slices.Contains([]string{"sandbox", "production"}, v.EnvironmentKind) || v.ProtocolProfile != "signal" {
		return ErrIdentityValue
	}
	return nil
}

type Precondition struct {
	PublishableKey     string      `json:"publishableKey"`
	RecoveryGeneration SafeInteger `json:"recoveryGeneration"`
	Scope              Scope       `json:"scope"`
}

func (v Precondition) Validate() error {
	if v.Scope.Validate() != nil || !matches(`^[A-Za-z0-9_-]{1,255}$`, v.PublishableKey) || !asciiText(v.Scope.RelayScopeID, `^[A-Za-z0-9_-]{1,255}$`) || !positive(v.RecoveryGeneration) {
		return ErrIdentityValue
	}
	return nil
}

type Inventory struct {
	EverAdmitted       bool          `json:"everAdmitted"`
	BindingCount       SafeInteger   `json:"bindingCount"`
	HistoryCount       SafeInteger   `json:"historyCount"`
	PendingOperationID *ContractText `json:"pendingOperationId" nullable:"true"`
}

func (v Inventory) Validate() error {
	if v.BindingCount.Validate() != nil || v.HistoryCount.Validate() != nil || v.PendingOperationID != nil && !textBound(*v.PendingOperationID, 1, 255) {
		return ErrIdentityValue
	}
	return nil
}

type IdentityRecovery struct {
	RequiredAssurance string `json:"requiredAssurance"`
}

func (v IdentityRecovery) Validate() error {
	if !slices.Contains([]string{"recent", "step-up"}, v.RequiredAssurance) {
		return ErrIdentityValue
	}
	return nil
}

type RecoveryPolicy struct {
	Kind              string  `json:"kind"`
	RequiredAssurance *string `json:"requiredAssurance,omitempty"`
}

func (v RecoveryPolicy) Validate() error {
	if v.Kind == "none" && v.RequiredAssurance == nil {
		return nil
	}
	if v.Kind == "provider" && v.RequiredAssurance != nil && slices.Contains([]string{"recent", "step-up"}, *v.RequiredAssurance) {
		return nil
	}
	return ErrIdentityValue
}

type MigrationConfiguration struct {
	Version               SafeInteger      `json:"version"`
	SourceProfile         InstalledProfile `json:"sourceProfile"`
	TargetProfile         InstalledProfile `json:"targetProfile"`
	PreparationTTLSeconds SafeInteger      `json:"preparationTtlSeconds"`
	RollbackWindowSeconds SafeInteger      `json:"rollbackWindowSeconds"`
	ManifestID            *string          `json:"manifestId,omitempty"`
	Revision              *SafeInteger     `json:"revision,omitempty"`
	SourceRecovery        *RecoveryPolicy  `json:"sourceRecovery,omitempty"`
	TargetRecovery        *RecoveryPolicy  `json:"targetRecovery,omitempty"`
}

func (v MigrationConfiguration) Validate() error {
	if v.SourceProfile.Validate() != nil || v.TargetProfile.Validate() != nil || v.PreparationTTLSeconds < 60 || v.PreparationTTLSeconds > 86400 || v.RollbackWindowSeconds < 60 || v.RollbackWindowSeconds > 2592000 {
		return ErrIdentityValue
	}
	if v.ManifestID != nil && !matches(`^[A-Za-z0-9_-]{1,128}$`, *v.ManifestID) || v.Revision != nil && !positive(*v.Revision) {
		return ErrIdentityValue
	}
	switch v.Version {
	case 1:
		if (v.ManifestID == nil) != (v.Revision == nil) || v.SourceRecovery != nil || v.TargetRecovery != nil || v.SourceProfile.Mode == "device-owned" || v.TargetProfile.Mode == "device-owned" {
			return ErrIdentityValue
		}
		if v.SourceProfile.Issuer.Equal(*v.TargetProfile.Issuer) && optionalTextEqual(v.SourceProfile.Audience, v.TargetProfile.Audience) {
			return ErrIdentityValue
		}
	case 2:
		if v.ManifestID == nil || v.Revision == nil || v.SourceRecovery == nil || v.TargetRecovery == nil || v.SourceRecovery.Validate() != nil || v.TargetRecovery.Validate() != nil {
			return ErrIdentityValue
		}
		sourceDevice := v.SourceProfile.Mode == "device-owned"
		targetDevice := v.TargetProfile.Mode == "device-owned"
		if sourceDevice == targetDevice || sourceDevice != (v.SourceRecovery.Kind == "none") || targetDevice != (v.TargetRecovery.Kind == "none") {
			return ErrIdentityValue
		}
	default:
		return ErrIdentityValue
	}
	return nil
}

type CompleteMigration struct {
	ManifestID    ContractText           `json:"manifestId"`
	Revision      SafeInteger            `json:"revision"`
	Configuration MigrationConfiguration `json:"configuration"`
}

func (v CompleteMigration) Validate() error {
	if !textBound(v.ManifestID, 1, 255) || v.Revision.Validate() != nil || v.Configuration.Validate() != nil {
		return ErrIdentityValue
	}
	if v.Configuration.ManifestID == nil {
		if v.Revision != 0 || !asciiText(v.ManifestID, `^legacy_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`) {
			return ErrIdentityValue
		}
	} else if !textLiteral(v.ManifestID, *v.Configuration.ManifestID) || v.Revision != *v.Configuration.Revision {
		return ErrIdentityValue
	}
	return nil
}

type ReadinessGeneration struct {
	Kind              string       `json:"kind"`
	ReceiptEpoch      *SafeInteger `json:"receiptEpoch,omitempty"`
	AdmissionRevision SafeInteger  `json:"admissionRevision"`
	PolicyFingerprint string       `json:"policyFingerprint"`
}

func (v ReadinessGeneration) Validate() error {
	if v.AdmissionRevision.Validate() != nil || !matches(`^[A-Za-z0-9_-]{43}$`, v.PolicyFingerprint) {
		return ErrIdentityValue
	}
	if v.Kind == "provision" && v.ReceiptEpoch == nil {
		return nil
	}
	if v.Kind == "cutover" && v.ReceiptEpoch != nil && *v.ReceiptEpoch >= 1 && *v.ReceiptEpoch <= 1024 {
		return nil
	}
	return ErrIdentityValue
}

type ReadinessEvidence struct {
	State            string      `json:"state"`
	CheckedAtSeconds SafeInteger `json:"checkedAtSeconds"`
}

func (v ReadinessEvidence) Validate() error {
	if !slices.Contains([]string{"current", "unknown"}, v.State) || v.CheckedAtSeconds.Validate() != nil {
		return ErrIdentityValue
	}
	return nil
}

type AdmissionReadiness struct {
	RelayScopeID     ContractText         `json:"relayScopeId"`
	Evidence         ReadinessEvidence    `json:"evidence"`
	State            string               `json:"state"`
	SourceGeneration *ReadinessGeneration `json:"sourceGeneration" nullable:"true"`
	Reason           *string              `json:"reason" nullable:"true"`
}

func (v AdmissionReadiness) Validate() error {
	if !textBound(v.RelayScopeID, 1, 255) || v.Evidence.Validate() != nil || v.SourceGeneration != nil && v.SourceGeneration.Validate() != nil {
		return ErrIdentityValue
	}
	reason := ""
	if v.Reason != nil {
		reason = *v.Reason
	}
	if v.State == "unknown" {
		if v.Evidence.State != "unknown" || v.SourceGeneration != nil || !slices.Contains([]string{"not_enabled", "evidence_unavailable", "changed_during_read", "owner_disagreement"}, reason) {
			return ErrIdentityValue
		}
		return nil
	}
	if v.Evidence.State != "current" {
		return ErrIdentityValue
	}
	switch v.State {
	case "absent":
		if v.SourceGeneration != nil || reason != "missing_authority" {
			return ErrIdentityValue
		}
	case "unready":
		if reason != "not_ready" {
			return ErrIdentityValue
		}
	case "pending":
		if !slices.Contains([]string{"operation_pending", "release_pending"}, reason) {
			return ErrIdentityValue
		}
	case "ready":
		if v.SourceGeneration == nil || v.Reason != nil {
			return ErrIdentityValue
		}
	default:
		return ErrIdentityValue
	}
	return nil
}

type MixedModeMigration struct {
	Available bool `json:"available"`
}

func (v MixedModeMigration) Validate() error {
	if v.Available {
		return ErrIdentityValue
	}
	return nil
}

type ProviderValidation struct {
	State string `json:"state"`
}

func (v ProviderValidation) Validate() error {
	if v.State != "not_checked" {
		return ErrIdentityValue
	}
	return nil
}

type ApplicationIntegration struct {
	State string `json:"state"`
}

func (v ApplicationIntegration) Validate() error {
	if v.State != "unverified" {
		return ErrIdentityValue
	}
	return nil
}

type CompleteConfiguration struct {
	ConfigurationVersion          SafeInteger            `json:"configurationVersion"`
	AdmissionRevision             SafeInteger            `json:"admissionRevision"`
	VerificationPolicyFingerprint string                 `json:"verificationPolicyFingerprint"`
	IdentityProfile               InstalledProfile       `json:"identityProfile"`
	Inventory                     Inventory              `json:"inventory"`
	IdentityRecovery              *IdentityRecovery      `json:"identityRecovery" nullable:"true"`
	IdentityMigration             *CompleteMigration     `json:"identityMigration" nullable:"true"`
	MixedModeMigration            MixedModeMigration     `json:"mixedModeMigration"`
	Selection                     *OperationResult       `json:"selection" nullable:"true"`
	ProviderValidation            ProviderValidation     `json:"providerValidation"`
	ApplicationIntegration        ApplicationIntegration `json:"applicationIntegration"`
	AdmissionReadiness            AdmissionReadiness     `json:"admissionReadiness"`
	SelectionOperation            *OperationResult       `json:"selectionOperation" nullable:"true"`
}

func (v CompleteConfiguration) Validate() error {
	if !positive(v.ConfigurationVersion) || v.AdmissionRevision.Validate() != nil || !matches(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`, v.VerificationPolicyFingerprint) || v.IdentityProfile.Validate() != nil || v.Inventory.Validate() != nil || v.MixedModeMigration.Validate() != nil || v.ProviderValidation.Validate() != nil || v.ApplicationIntegration.Validate() != nil || v.AdmissionReadiness.Validate() != nil {
		return ErrIdentityValue
	}
	if v.IdentityRecovery != nil && v.IdentityRecovery.Validate() != nil || v.Selection != nil && v.Selection.Validate() != nil || v.SelectionOperation != nil && v.SelectionOperation.Validate() != nil {
		return ErrIdentityValue
	}
	if v.IdentityMigration != nil && (v.IdentityMigration.Validate() != nil || !v.IdentityMigration.Configuration.SourceProfile.Equal(v.IdentityProfile)) {
		return ErrIdentityValue
	}
	g := v.AdmissionReadiness.SourceGeneration
	if g != nil && (g.AdmissionRevision != v.AdmissionRevision || g.PolicyFingerprint != v.VerificationPolicyFingerprint) {
		return ErrIdentityValue
	}
	return nil
}

type CurrentContext struct {
	Configuration CompleteConfiguration `json:"configuration"`
	Precondition  Precondition          `json:"precondition"`
}

func (v CurrentContext) Validate() error {
	if v.Configuration.Validate() != nil || v.Precondition.Validate() != nil || !v.Configuration.AdmissionReadiness.RelayScopeID.Equal(v.Precondition.Scope.RelayScopeID) {
		return ErrIdentityValue
	}
	return nil
}

func (v Scope) MarshalJSON() ([]byte, error) {
	type wire Scope
	return encodeChecked(wire(v), v.Validate)
}
func (v *Scope) UnmarshalJSON(data []byte) error {
	type wire Scope
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := Scope(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v Scope) Clone() (Scope, error)  { return cloneValue(v) }
func (v Scope) Equal(other Scope) bool { return equalValue(v, other) }

func (v Precondition) MarshalJSON() ([]byte, error) {
	type wire Precondition
	return encodeChecked(wire(v), v.Validate)
}
func (v *Precondition) UnmarshalJSON(data []byte) error {
	type wire Precondition
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := Precondition(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v Precondition) Clone() (Precondition, error)  { return cloneValue(v) }
func (v Precondition) Equal(other Precondition) bool { return equalValue(v, other) }

func (v Inventory) MarshalJSON() ([]byte, error) {
	type wire Inventory
	return encodeChecked(wire(v), v.Validate)
}
func (v *Inventory) UnmarshalJSON(data []byte) error {
	type wire Inventory
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := Inventory(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v Inventory) Clone() (Inventory, error)  { return cloneValue(v) }
func (v Inventory) Equal(other Inventory) bool { return equalValue(v, other) }

func (v IdentityRecovery) MarshalJSON() ([]byte, error) {
	type wire IdentityRecovery
	return encodeChecked(wire(v), v.Validate)
}
func (v *IdentityRecovery) UnmarshalJSON(data []byte) error {
	type wire IdentityRecovery
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := IdentityRecovery(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v IdentityRecovery) Clone() (IdentityRecovery, error)  { return cloneValue(v) }
func (v IdentityRecovery) Equal(other IdentityRecovery) bool { return equalValue(v, other) }

func (v RecoveryPolicy) MarshalJSON() ([]byte, error) {
	type wire RecoveryPolicy
	return encodeChecked(wire(v), v.Validate)
}
func (v *RecoveryPolicy) UnmarshalJSON(data []byte) error {
	type wire RecoveryPolicy
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := RecoveryPolicy(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v RecoveryPolicy) Clone() (RecoveryPolicy, error)  { return cloneValue(v) }
func (v RecoveryPolicy) Equal(other RecoveryPolicy) bool { return equalValue(v, other) }

func (v MigrationConfiguration) MarshalJSON() ([]byte, error) {
	type wire MigrationConfiguration
	return encodeChecked(wire(v), v.Validate)
}
func (v *MigrationConfiguration) UnmarshalJSON(data []byte) error {
	type wire MigrationConfiguration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := MigrationConfiguration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v MigrationConfiguration) Clone() (MigrationConfiguration, error)  { return cloneValue(v) }
func (v MigrationConfiguration) Equal(other MigrationConfiguration) bool { return equalValue(v, other) }

func (v CompleteMigration) MarshalJSON() ([]byte, error) {
	type wire CompleteMigration
	return encodeChecked(wire(v), v.Validate)
}
func (v *CompleteMigration) UnmarshalJSON(data []byte) error {
	type wire CompleteMigration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := CompleteMigration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v CompleteMigration) Clone() (CompleteMigration, error)  { return cloneValue(v) }
func (v CompleteMigration) Equal(other CompleteMigration) bool { return equalValue(v, other) }

func (v ReadinessGeneration) MarshalJSON() ([]byte, error) {
	type wire ReadinessGeneration
	return encodeChecked(wire(v), v.Validate)
}
func (v *ReadinessGeneration) UnmarshalJSON(data []byte) error {
	type wire ReadinessGeneration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := ReadinessGeneration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v ReadinessGeneration) Clone() (ReadinessGeneration, error)  { return cloneValue(v) }
func (v ReadinessGeneration) Equal(other ReadinessGeneration) bool { return equalValue(v, other) }

func (v ReadinessEvidence) MarshalJSON() ([]byte, error) {
	type wire ReadinessEvidence
	return encodeChecked(wire(v), v.Validate)
}
func (v *ReadinessEvidence) UnmarshalJSON(data []byte) error {
	type wire ReadinessEvidence
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := ReadinessEvidence(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v ReadinessEvidence) Clone() (ReadinessEvidence, error)  { return cloneValue(v) }
func (v ReadinessEvidence) Equal(other ReadinessEvidence) bool { return equalValue(v, other) }

func (v AdmissionReadiness) MarshalJSON() ([]byte, error) {
	type wire AdmissionReadiness
	return encodeChecked(wire(v), v.Validate)
}
func (v *AdmissionReadiness) UnmarshalJSON(data []byte) error {
	type wire AdmissionReadiness
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := AdmissionReadiness(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v AdmissionReadiness) Clone() (AdmissionReadiness, error)  { return cloneValue(v) }
func (v AdmissionReadiness) Equal(other AdmissionReadiness) bool { return equalValue(v, other) }

func (v MixedModeMigration) MarshalJSON() ([]byte, error) {
	type wire MixedModeMigration
	return encodeChecked(wire(v), v.Validate)
}
func (v *MixedModeMigration) UnmarshalJSON(data []byte) error {
	type wire MixedModeMigration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := MixedModeMigration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v MixedModeMigration) Clone() (MixedModeMigration, error)  { return cloneValue(v) }
func (v MixedModeMigration) Equal(other MixedModeMigration) bool { return equalValue(v, other) }

func (v ProviderValidation) MarshalJSON() ([]byte, error) {
	type wire ProviderValidation
	return encodeChecked(wire(v), v.Validate)
}
func (v *ProviderValidation) UnmarshalJSON(data []byte) error {
	type wire ProviderValidation
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := ProviderValidation(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v ProviderValidation) Clone() (ProviderValidation, error)  { return cloneValue(v) }
func (v ProviderValidation) Equal(other ProviderValidation) bool { return equalValue(v, other) }

func (v ApplicationIntegration) MarshalJSON() ([]byte, error) {
	type wire ApplicationIntegration
	return encodeChecked(wire(v), v.Validate)
}
func (v *ApplicationIntegration) UnmarshalJSON(data []byte) error {
	type wire ApplicationIntegration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := ApplicationIntegration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v ApplicationIntegration) Clone() (ApplicationIntegration, error)  { return cloneValue(v) }
func (v ApplicationIntegration) Equal(other ApplicationIntegration) bool { return equalValue(v, other) }

func (v CompleteConfiguration) MarshalJSON() ([]byte, error) {
	type wire CompleteConfiguration
	return encodeChecked(wire(v), v.Validate)
}
func (v *CompleteConfiguration) UnmarshalJSON(data []byte) error {
	type wire CompleteConfiguration
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := CompleteConfiguration(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v CompleteConfiguration) Clone() (CompleteConfiguration, error)  { return cloneValue(v) }
func (v CompleteConfiguration) Equal(other CompleteConfiguration) bool { return equalValue(v, other) }

func (v CurrentContext) MarshalJSON() ([]byte, error) {
	type wire CurrentContext
	return encodeChecked(wire(v), v.Validate)
}
func (v *CurrentContext) UnmarshalJSON(data []byte) error {
	type wire CurrentContext
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := CurrentContext(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v CurrentContext) Clone() (CurrentContext, error)  { return cloneValue(v) }
func (v CurrentContext) Equal(other CurrentContext) bool { return equalValue(v, other) }
