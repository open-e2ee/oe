// Package identity owns public draft profiles and redacted check results.
package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"slices"
	"unicode/utf16"
)

var (
	ErrInvalid     = errors.New("the public identity profile is invalid")
	ErrUnsupported = errors.New("this identity profile is not supported by the draft check")
)

type PublicKey struct {
	Kid         string   `json:"kid"`
	Kty         string   `json:"kty"`
	Curve       string   `json:"crv"`
	X           string   `json:"x"`
	Y           string   `json:"y"`
	Algorithm   string   `json:"alg,omitempty"`
	Use         string   `json:"use,omitempty"`
	Operations  []string `json:"key_ops,omitempty"`
	Extractable *bool    `json:"ext,omitempty"`
}

type Profile struct {
	Mode         string      `json:"mode"`
	Algorithms   []string    `json:"algorithms,omitempty"`
	Issuer       string      `json:"issuer,omitempty"`
	Audience     string      `json:"audience,omitempty"`
	SubjectClaim string      `json:"subjectClaim,omitempty"`
	Keys         []PublicKey `json:"keys,omitempty"`
}

var subjectClaim = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)

func profileText(value string) bool { return value != "" && len(utf16.Encode([]rune(value))) <= 255 }

// Load reads a bounded public file. Errors contain no path or field values.
func Load(path string) (Profile, error) {
	f, err := os.Open(path)
	if err != nil {
		return Profile{}, ErrInvalid
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 100_000 {
		return Profile{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, 100_001))
	if err != nil {
		return Profile{}, ErrInvalid
	}
	return Parse(data)
}

// Parse excludes credentials before the existing Console verifier sees input.
func Parse(data []byte) (Profile, error) {
	var fields map[string]json.RawMessage
	if len(data) > 100_000 || json.Unmarshal(data, &fields) != nil || fields == nil {
		return Profile{}, ErrInvalid
	}
	if _, native := fields["provider"]; native {
		return Profile{}, ErrUnsupported
	}
	for name := range fields {
		if !slices.Contains([]string{"mode", "algorithms", "issuer", "audience", "subjectClaim", "keys"}, name) {
			return Profile{}, ErrInvalid
		}
	}
	var p Profile
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return Profile{}, ErrInvalid
	}
	if p.Mode == "device-owned" {
		if len(fields) != 1 || fields["mode"] == nil {
			return Profile{}, ErrInvalid
		}
		return p, nil
	}
	if p.Mode != "custom-token" && p.Mode != "provider-bound" {
		return Profile{}, ErrUnsupported
	}
	if len(fields) != 6 || len(p.Algorithms) != 1 || p.Algorithms[0] != "ES256" {
		return Profile{}, ErrUnsupported
	}
	u, err := url.Parse(p.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !profileText(p.Issuer) || !profileText(p.Audience) || !subjectClaim.MatchString(p.SubjectClaim) ||
		slices.Contains([]string{"iss", "aud", "iat", "nbf", "exp", "jti", "token_use", "purpose", "assurance"}, p.SubjectClaim) || len(p.Keys) == 0 || len(p.Keys) > 32 {
		return Profile{}, ErrInvalid
	}
	seen := make(map[string]bool)
	var rawKeys []map[string]json.RawMessage
	if json.Unmarshal(fields["keys"], &rawKeys) != nil {
		return Profile{}, ErrInvalid
	}
	for i, key := range p.Keys {
		for name, value := range rawKeys[i] {
			if !slices.Contains([]string{"kid", "kty", "crv", "x", "y", "alg", "use", "key_ops", "ext"}, name) || bytes.Equal(value, []byte("null")) {
				return Profile{}, ErrInvalid
			}
		}
		if (rawKeys[i]["alg"] != nil && key.Algorithm != "ES256") || (rawKeys[i]["use"] != nil && key.Use != "sig") ||
			(rawKeys[i]["key_ops"] != nil && !slices.Equal(key.Operations, []string{"verify"})) {
			return Profile{}, ErrInvalid
		}
		if !profileText(key.Kid) || seen[key.Kid] || key.Kty != "EC" || key.Curve != "P-256" || key.X == "" || key.Y == "" ||
			(key.Algorithm != "" && key.Algorithm != "ES256") || (key.Use != "" && key.Use != "sig") ||
			(len(key.Operations) != 0 && !slices.Equal(key.Operations, []string{"verify"})) || (key.Extractable != nil && !*key.Extractable) {
			return Profile{}, ErrInvalid
		}
		for _, coordinate := range []string{key.X, key.Y} {
			decoded, err := base64.RawURLEncoding.DecodeString(coordinate)
			if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != coordinate {
				return Profile{}, ErrInvalid
			}
		}
		seen[key.Kid] = true
	}
	return p, nil
}
