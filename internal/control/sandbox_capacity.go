package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"slices"
	"time"
)

// SandboxCapacity keeps unknown observations as null and counts as exact decimals.
type SandboxCapacity struct {
	SchemaVersion              int                          `json:"schemaVersion"`
	ContractVersion            string                       `json:"contractVersion"`
	Environment                string                       `json:"environment"`
	BillingProjectHandle       string                       `json:"billingProjectHandle"`
	SignalProtocolRelayScopeID string                       `json:"signalRelayScopeId"`
	RecoveryGeneration         int64                        `json:"recoveryGeneration"`
	ActivationRevision         *int64                       `json:"activationRevision"`
	CapacityRevision           *int64                       `json:"capacityRevision"`
	State                      string                       `json:"state"`
	Basis                      string                       `json:"basis"`
	Limit                      *int64                       `json:"limit"`
	LimitSource                *string                      `json:"limitSource"`
	RegisteredAccounts         *string                      `json:"registeredAccounts"`
	ReservedAccounts           *string                      `json:"reservedAccounts"`
	AvailableSlots             *string                      `json:"availableSlots"`
	OverCapacity               *bool                        `json:"overCapacity"`
	ObservedAtMilliseconds     *int64                       `json:"observedAtMilliseconds"`
	PendingLimit               *SandboxCapacityPendingLimit `json:"pendingLimit"`
}

type SandboxCapacityPendingLimit struct {
	RegisteredTestAccounts int64  `json:"registeredTestAccounts"`
	AppliesAtMilliseconds  int64  `json:"appliesAtMilliseconds"`
	ControlOperationID     string `json:"controlOperationId"`
}

type ProjectCapacity struct {
	Project     string          `json:"project"`
	Environment string          `json:"environment"`
	Capacity    SandboxCapacity `json:"capacity"`
}

var errSandboxCapacity = errors.New("the Sandbox account capacity response is invalid")
var capacityDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// ProjectCapacity reads the separate account contract without a monthly usage fallback.
func (c *Client) ProjectCapacity(ctx context.Context, credential CredentialRequest, project, environment string) (ProjectCapacity, error) {
	if environment != "sandbox" {
		return ProjectCapacity{}, errors.New("account capacity is available only in Sandbox")
	}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, projectPath(project, "sandbox-account-capacity")+"?environment=sandbox", credential, nil, &raw); err != nil {
		return ProjectCapacity{}, err
	}
	var result ProjectCapacity
	if err := capacityObject(raw, &result, "project", "environment", "capacity"); err != nil {
		return ProjectCapacity{}, errSandboxCapacity
	}
	if result.Project != project || result.Environment != "sandbox" {
		return ProjectCapacity{}, errSandboxCapacity
	}
	return result, nil
}

func (value *SandboxCapacity) UnmarshalJSON(data []byte) error {
	type wire SandboxCapacity
	var decoded wire
	if err := capacityObject(data, &decoded, "schemaVersion", "contractVersion", "environment", "billingProjectHandle", "signalRelayScopeId", "recoveryGeneration", "activationRevision", "capacityRevision", "state", "basis", "limit", "limitSource", "registeredAccounts", "reservedAccounts", "availableSlots", "overCapacity", "observedAtMilliseconds", "pendingLimit"); err != nil {
		return errSandboxCapacity
	}
	candidate := SandboxCapacity(decoded)
	if !candidate.valid() {
		return errSandboxCapacity
	}
	*value = candidate
	return nil
}

func (value *SandboxCapacityPendingLimit) UnmarshalJSON(data []byte) error {
	type wire SandboxCapacityPendingLimit
	var decoded wire
	if err := capacityObject(data, &decoded, "registeredTestAccounts", "appliesAtMilliseconds", "controlOperationId"); err != nil ||
		!capacityInteger(decoded.RegisteredTestAccounts) || !capacityInteger(decoded.AppliesAtMilliseconds) || !capacityIdentifier(decoded.ControlOperationID) {
		return errSandboxCapacity
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || bytes.Equal(fields["registeredTestAccounts"], []byte("null")) || bytes.Equal(fields["appliesAtMilliseconds"], []byte("null")) {
		return errSandboxCapacity
	}
	*value = SandboxCapacityPendingLimit(decoded)
	return nil
}

// capacityObject requires every field once, including nullable observations.
func capacityObject(data []byte, target any, fields ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errSandboxCapacity
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err = decoder.Token()
		field, ok := token.(string)
		if err != nil || !ok || seen[field] || !slices.Contains(fields, field) {
			return errSandboxCapacity
		}
		seen[field] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return errSandboxCapacity
		}
	}
	if _, err = decoder.Token(); err != nil || len(seen) != len(fields) {
		return errSandboxCapacity
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errSandboxCapacity
	}
	return json.Unmarshal(data, target)
}

func capacityInteger(value int64) bool     { return value >= 0 && value <= 9_007_199_254_740_991 }
func capacityIdentifier(value string) bool { return len(value) > 0 && len(value) <= 255 }
func (value SandboxCapacity) valid() bool {
	if value.SchemaVersion != 1 || value.ContractVersion != "sandbox_registered_accounts_v1" || value.Environment != "sandbox" ||
		value.Basis != "currently_registered_canonical_accounts" || !capacityIdentifier(value.BillingProjectHandle) || !capacityIdentifier(value.SignalProtocolRelayScopeID) ||
		!capacityInteger(value.RecoveryGeneration) || value.RecoveryGeneration < 1 {
		return false
	}
	for _, number := range []*int64{value.ActivationRevision, value.CapacityRevision, value.Limit, value.ObservedAtMilliseconds} {
		if number != nil && !capacityInteger(*number) {
			return false
		}
	}
	for _, count := range []*string{value.RegisteredAccounts, value.ReservedAccounts, value.AvailableSlots} {
		if count != nil && !capacityDecimal.MatchString(*count) {
			return false
		}
	}
	if value.LimitSource != nil && !slices.Contains([]string{"sandbox_default", "legacy_allowance", "override"}, *value.LimitSource) {
		return false
	}
	switch value.State {
	case "ready", "active":
		if value.RegisteredAccounts == nil || value.ReservedAccounts == nil || value.Limit == nil || value.LimitSource == nil || value.ActivationRevision == nil || value.CapacityRevision == nil || value.ObservedAtMilliseconds == nil || value.AvailableSlots == nil || value.OverCapacity == nil {
			return false
		}
		registered, _ := new(big.Int).SetString(*value.RegisteredAccounts, 10)
		reserved, _ := new(big.Int).SetString(*value.ReservedAccounts, 10)
		occupied := new(big.Int).Add(registered, reserved)
		limit := big.NewInt(*value.Limit)
		available := new(big.Int).Sub(limit, occupied)
		if available.Sign() < 0 {
			available.SetInt64(0)
		}
		return *value.AvailableSlots == available.String() && *value.OverCapacity == (occupied.Cmp(limit) > 0)
	case "inactive", "partial", "unknown":
		return value.AvailableSlots == nil && value.OverCapacity == nil
	default:
		return false
	}
}

// At retains known counts but removes availability when the observation expires.
func (value SandboxCapacity) At(now time.Time) SandboxCapacity {
	if value.State == "active" || value.State == "ready" {
		if value.ObservedAtMilliseconds == nil || *value.ObservedAtMilliseconds > now.UnixMilli()+30_000 || *value.ObservedAtMilliseconds < now.UnixMilli()-60_000 {
			value.State, value.AvailableSlots, value.OverCapacity = "unknown", nil, nil
		}
	}
	return value
}
