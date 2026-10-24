package identity

import (
	"encoding/json"
	"regexp"
	"slices"
	"unicode"

	whatwg "github.com/nationallibraryofnorway/whatwg-url/url"
)

func matches(pattern, value string) bool {
	ok, e := regexp.MatchString(pattern, value)
	return e == nil && ok
}

type InstalledPublicKey struct {
	Kty         string          `json:"kty"`
	Curve       string          `json:"crv"`
	X           ContractText    `json:"x"`
	Y           ContractText    `json:"y"`
	Kid         ContractText    `json:"kid"`
	Algorithm   *ContractText   `json:"alg,omitempty"`
	Use         *ContractText   `json:"use,omitempty"`
	Operations  *[]ContractText `json:"key_ops,omitempty"`
	Extractable *bool           `json:"ext,omitempty"`
}

func (v InstalledPublicKey) Validate() error {
	if v.Kty != "EC" || v.Curve != "P-256" || v.Operations != nil && *v.Operations == nil {
		return ErrIdentityValue
	}
	return nil
}

type SigningPublicKey struct {
	Kty         string       `json:"kty"`
	Curve       string       `json:"crv"`
	X           string       `json:"x"`
	Y           string       `json:"y"`
	Kid         ContractText `json:"kid"`
	Algorithm   *string      `json:"alg,omitempty"`
	Use         *string      `json:"use,omitempty"`
	Operations  *[]string    `json:"key_ops,omitempty"`
	Extractable *bool        `json:"ext,omitempty"`
}

func (v SigningPublicKey) Validate() error { return v.validateWrite(false) }
func (v SigningPublicKey) validateWrite(replacement bool) error {
	limit := 255
	if replacement {
		limit = 128
	}
	if v.Kty != "EC" || v.Curve != "P-256" || !textBound(v.Kid, 1, limit) {
		return ErrIdentityValue
	}
	coordinate := `^[A-Za-z0-9_-]{43}$`
	if replacement {
		coordinate = `^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`
	}
	if !matches(coordinate, v.X) || !matches(coordinate, v.Y) {
		return ErrIdentityValue
	}
	if v.Algorithm != nil && *v.Algorithm != "ES256" || v.Use != nil && *v.Use != "sig" || v.Extractable != nil && !*v.Extractable {
		return ErrIdentityValue
	}
	if v.Operations != nil && (len(*v.Operations) != 1 || (*v.Operations)[0] != "verify") {
		return ErrIdentityValue
	}
	if replacement {
		for _, r := range v.Kid.webString() {
			if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
				return ErrIdentityValue
			}
		}
	}
	return nil
}

type InstalledProfile struct {
	Mode                        string                `json:"mode"`
	Algorithms                  *[]string             `json:"algorithms,omitempty"`
	Issuer                      *ContractText         `json:"issuer,omitempty"`
	Audience                    *ContractText         `json:"audience,omitempty"`
	SubjectClaim                *ContractText         `json:"subjectClaim,omitempty"`
	Keys                        *[]InstalledPublicKey `json:"keys,omitempty"`
	Provider                    *string               `json:"provider,omitempty"`
	AuthorizedParties           *[]ContractText       `json:"authorizedParties,omitempty"`
	AllowMissingAuthorizedParty *bool                 `json:"allowMissingAuthorizedParty,omitempty"`
}

type SelectionTarget struct {
	Mode                        string              `json:"mode"`
	Algorithms                  *[]string           `json:"algorithms,omitempty"`
	Issuer                      *ContractText       `json:"issuer,omitempty"`
	Audience                    *ContractText       `json:"audience,omitempty"`
	SubjectClaim                *string             `json:"subjectClaim,omitempty"`
	Keys                        *[]SigningPublicKey `json:"keys,omitempty"`
	Provider                    *string             `json:"provider,omitempty"`
	AuthorizedParties           *[]ContractText     `json:"authorizedParties,omitempty"`
	AllowMissingAuthorizedParty *bool               `json:"allowMissingAuthorizedParty,omitempty"`
}

type ReplacementKeys []SigningPublicKey

func algorithm(v InstalledProfile, want string) bool {
	return v.Algorithms != nil && len(*v.Algorithms) == 1 && (*v.Algorithms)[0] == want
}
func noNativeFields(v InstalledProfile) bool {
	return v.Provider == nil && v.AuthorizedParties == nil && v.AllowMissingAuthorizedParty == nil
}
func (v InstalledProfile) Validate() error {
	if v.Provider != nil {
		return v.validateNative()
	}
	if !noNativeFields(v) || v.Issuer == nil || v.Audience == nil {
		return ErrIdentityValue
	}
	if v.Mode == "device-owned" {
		if !algorithm(v, "EdDSA") || v.SubjectClaim != nil || v.Keys != nil {
			return ErrIdentityValue
		}
		return nil
	}
	if !slices.Contains([]string{"custom-token", "provider-bound"}, v.Mode) || !algorithm(v, "ES256") || v.SubjectClaim == nil || v.Keys == nil || len(*v.Keys) < 1 {
		return ErrIdentityValue
	}
	for _, k := range *v.Keys {
		if k.Validate() != nil {
			return ErrIdentityValue
		}
	}
	return nil
}
func (v SelectionTarget) Validate() error {
	noNative := v.Provider == nil && v.AuthorizedParties == nil && v.AllowMissingAuthorizedParty == nil
	if v.Mode == "device-owned" {
		if v.Algorithms != nil || v.Issuer != nil || v.Audience != nil || v.SubjectClaim != nil || v.Keys != nil || !noNative {
			return ErrIdentityValue
		}
		return nil
	}
	if v.Provider != nil {
		if v.SubjectClaim == nil || v.Keys != nil {
			return ErrIdentityValue
		}
		subject, e := Text(*v.SubjectClaim)
		if e != nil {
			return ErrIdentityValue
		}
		p := InstalledProfile{Mode: v.Mode, Algorithms: v.Algorithms, Issuer: v.Issuer, Audience: v.Audience, SubjectClaim: &subject, Provider: v.Provider, AuthorizedParties: v.AuthorizedParties, AllowMissingAuthorizedParty: v.AllowMissingAuthorizedParty}
		return p.validateNative()
	}
	if !noNative || !slices.Contains([]string{"custom-token", "provider-bound"}, v.Mode) || v.Algorithms == nil || len(*v.Algorithms) != 1 || (*v.Algorithms)[0] != "ES256" || v.Issuer == nil || v.Audience == nil || v.SubjectClaim == nil || v.Keys == nil {
		return ErrIdentityValue
	}
	if !textBound(*v.Issuer, 1, 255) || !externalHTTPS(*v.Issuer) || !textBound(*v.Audience, 1, 255) || !matches(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`, *v.SubjectClaim) {
		return ErrIdentityValue
	}
	if slices.Contains([]string{"iss", "aud", "iat", "nbf", "exp", "jti", "token_use", "purpose", "assurance"}, *v.SubjectClaim) {
		return ErrIdentityValue
	}
	return validateKeys(*v.Keys, false, 32)
}

func validateKeys(keys []SigningPublicKey, replacement bool, maximum int) error {
	if len(keys) < 1 || len(keys) > maximum {
		return ErrIdentityValue
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if key.validateWrite(replacement) != nil {
			return ErrIdentityValue
		}
		data, _ := key.Kid.MarshalJSON()
		id := string(data)
		if seen[id] {
			return ErrIdentityValue
		}
		seen[id] = true
	}
	return nil
}
func (v ReplacementKeys) Validate() error { return validateKeys(v, true, 32) }

// ValidateMigrationKeys retains the separate migration write limit.
func ValidateMigrationKeys(v []SigningPublicKey) error { return validateKeys(v, false, 16) }
func (v InstalledProfile) validateNative() error {
	if v.Mode != "provider-bound" || v.Provider == nil || !algorithm(v, "RS256") || v.Issuer == nil || v.SubjectClaim == nil || !textLiteral(*v.SubjectClaim, "sub") || v.Keys != nil {
		return ErrIdentityValue
	}
	nativeText := func(t ContractText) bool { return textBound(t, 1, 512) && !containsNUL(t) }
	if !nativeText(*v.Issuer) {
		return ErrIdentityValue
	}
	switch *v.Provider {
	case "firebase":
		if v.Audience == nil || !nativeText(*v.Audience) || !asciiText(*v.Audience, `^[a-z][a-z0-9-]{4,28}[a-z0-9]$`) || v.AuthorizedParties != nil || v.AllowMissingAuthorizedParty != nil || !textLiteral(*v.Issuer, "https://securetoken.google.com/"+v.Audience.webString()) {
			return ErrIdentityValue
		}
	case "clerk":
		if !nativeOrigin(*v.Issuer, true) || v.Audience != nil && !nativeText(*v.Audience) || v.AuthorizedParties == nil || len(*v.AuthorizedParties) < 1 || len(*v.AuthorizedParties) > 16 {
			return ErrIdentityValue
		}
		seen := map[string]bool{}
		for _, party := range *v.AuthorizedParties {
			if !nativeText(party) || !nativeOrigin(party, false) {
				return ErrIdentityValue
			}
			data, _ := party.MarshalJSON()
			if seen[string(data)] {
				return ErrIdentityValue
			}
			seen[string(data)] = true
		}
		if v.AllowMissingAuthorizedParty != nil && *v.AllowMissingAuthorizedParty && v.Audience == nil {
			return ErrIdentityValue
		}
	default:
		return ErrIdentityValue
	}
	return nil
}

// URL parsing uses scalar input only. The retained ContractText is unchanged.
func externalHTTPS(value ContractText) bool {
	parsed, err := whatwg.Parse(value.webString())
	return err == nil && parsed.Scheme() == "https" && parsed.Username() == "" && parsed.Password() == "" && parsed.Hash() == ""
}
func nativeOrigin(value ContractText, publicOnly bool) bool {
	original, scalar := value.ScalarString()
	if !scalar {
		return false
	}
	parsed, err := whatwg.Parse(value.webString())
	if err != nil || parsed.Username() != "" || parsed.Password() != "" || parsed.Scheme()+"://"+parsed.Host() != original {
		return false
	}
	if publicOnly {
		host := parsed.Hostname()
		return parsed.Scheme() == "https" && parsed.Port() == "" && len(host) <= 253 && matches(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`, host) && !matches(`(?:^|\.)(?:localhost|local|localdomain|internal|invalid|test|example|home|lan|onion|alt)$`, host)
	}
	return parsed.Scheme() == "https" || parsed.Scheme() == "http" && parsed.Hostname() == "localhost"
}

func (v InstalledPublicKey) MarshalJSON() ([]byte, error) {
	type wire InstalledPublicKey
	return encodeChecked(wire(v), v.Validate)
}
func (v *InstalledPublicKey) UnmarshalJSON(data []byte) error {
	type wire InstalledPublicKey
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := InstalledPublicKey(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v InstalledPublicKey) Clone() (InstalledPublicKey, error)  { return cloneValue(v) }
func (v InstalledPublicKey) Equal(other InstalledPublicKey) bool { return equalValue(v, other) }

func (v InstalledProfile) MarshalJSON() ([]byte, error) {
	type wire InstalledProfile
	return encodeChecked(wire(v), v.Validate)
}
func (v *InstalledProfile) UnmarshalJSON(data []byte) error {
	type wire InstalledProfile
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := InstalledProfile(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v InstalledProfile) Clone() (InstalledProfile, error)  { return cloneValue(v) }
func (v InstalledProfile) Equal(other InstalledProfile) bool { return equalValue(v, other) }

func (v SelectionTarget) MarshalJSON() ([]byte, error) {
	type wire SelectionTarget
	return encodeChecked(wire(v), v.Validate)
}
func (v *SelectionTarget) UnmarshalJSON(data []byte) error {
	type wire SelectionTarget
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := SelectionTarget(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v SelectionTarget) Clone() (SelectionTarget, error)  { return cloneValue(v) }
func (v SelectionTarget) Equal(other SelectionTarget) bool { return equalValue(v, other) }

func (v ReplacementKeys) MarshalJSON() ([]byte, error) {
	type wire ReplacementKeys
	return encodeChecked(wire(v), v.Validate)
}
func (v *ReplacementKeys) UnmarshalJSON(data []byte) error {
	type wire ReplacementKeys
	var value wire
	if checkJSON(data) != nil || json.Unmarshal(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := ReplacementKeys(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v ReplacementKeys) Clone() (ReplacementKeys, error)  { return cloneValue(v) }
func (v ReplacementKeys) Equal(other ReplacementKeys) bool { return equalValue(v, other) }

func (v SigningPublicKey) MarshalJSON() ([]byte, error) {
	type wire SigningPublicKey
	return encodeChecked(wire(v), v.Validate)
}
func (v *SigningPublicKey) UnmarshalJSON(data []byte) error {
	type wire SigningPublicKey
	var value wire
	if decodeClosed(data, &value) != nil {
		return ErrIdentityValue
	}
	candidate := SigningPublicKey(value)
	if candidate.Validate() != nil {
		return ErrIdentityValue
	}
	*v = candidate
	return nil
}
func (v SigningPublicKey) Clone() (SigningPublicKey, error)  { return cloneValue(v) }
func (v SigningPublicKey) Equal(other SigningPublicKey) bool { return equalValue(v, other) }
