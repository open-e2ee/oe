package identity

import (
	"bytes"
	"encoding/json"
	"errors"
)

type Draft struct {
	Target    Profile `json:"target"`
	Assertion string  `json:"assertion,omitempty"`
}

// Check contains only a closed public verdict, never claims or error bodies.
type Check struct {
	State                  string `json:"state"`
	ProfileMode            string `json:"profileMode"`
	Environment            string `json:"environment"`
	Configuration          string `json:"configuration"`
	InstalledConfiguration string `json:"installedConfiguration"`
	DeviceAdmission        string `json:"deviceAdmission"`
	MemberBinding          string `json:"memberBinding"`
	EncryptedExchange      string `json:"encryptedExchange"`
	Lifecycle              string `json:"lifecycle"`
	ExpiresAt              *int64 `json:"expiresAt,omitempty"`
	Reason                 string `json:"reason,omitempty"`
}

var ErrResult = errors.New("the identity check returned an invalid result")

func (c *Check) UnmarshalJSON(data []byte) error {
	type wire Check
	var value wire
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return ErrResult
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 10 {
		return ErrResult
	}
	for _, name := range []string{"state", "profileMode", "environment", "configuration", "installedConfiguration", "deviceAdmission", "memberBinding", "encryptedExchange", "lifecycle"} {
		if fields[name] == nil {
			return ErrResult
		}
	}
	if value.Configuration != "draft" || value.InstalledConfiguration != "unverified" || value.DeviceAdmission != "unverified" ||
		value.MemberBinding != "unverified" || value.EncryptedExchange != "unverified" || value.Lifecycle != "unverified" {
		return ErrResult
	}
	switch value.State {
	case "accepted_at_check":
		if (value.ProfileMode != "custom-token" && value.ProfileMode != "provider-bound") || fields["reason"] != nil ||
			value.ExpiresAt == nil || *value.ExpiresAt < 0 || *value.ExpiresAt > 9_007_199_254_740_991 {
			return ErrResult
		}
	case "not_applicable":
		if value.ProfileMode != "device-owned" || value.Reason != "device_owned_identity" || fields["expiresAt"] != nil {
			return ErrResult
		}
	default:
		return ErrResult
	}
	*c = Check(value)
	return nil
}

func (c Check) Matches(p Profile, environment string) bool {
	if c.Environment != environment || c.ProfileMode != p.Mode || (environment != "sandbox" && environment != "production") ||
		c.Configuration != "draft" || c.InstalledConfiguration != "unverified" || c.DeviceAdmission != "unverified" ||
		c.MemberBinding != "unverified" || c.EncryptedExchange != "unverified" || c.Lifecycle != "unverified" {
		return false
	}
	return (c.State == "not_applicable" && c.ProfileMode == "device-owned" && c.ExpiresAt == nil && c.Reason == "device_owned_identity") ||
		(c.State == "accepted_at_check" && c.ProfileMode != "device-owned" && c.ExpiresAt != nil && *c.ExpiresAt >= 0 && *c.ExpiresAt <= 9_007_199_254_740_991 && c.Reason == "")
}

func (c Check) Data() map[string]any {
	d := map[string]any{"state": c.State, "profileMode": c.ProfileMode, "environment": c.Environment, "configuration": "draft",
		"installedConfiguration": "unverified", "deviceAdmission": "unverified", "memberBinding": "unverified", "encryptedExchange": "unverified", "lifecycle": "unverified"}
	if c.ExpiresAt != nil {
		d["expiresAt"] = *c.ExpiresAt
	}
	if c.Reason != "" {
		d["reason"] = c.Reason
	}
	return d
}
