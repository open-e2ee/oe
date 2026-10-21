package identity

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const publicDraft = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"production","subjectClaim":"sub","keys":[{"kid":"one","kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`

func TestPublicProfilesExcludeSecretsAndUnsupportedContracts(t *testing.T) {
	p, err := Parse([]byte(publicDraft))
	if err != nil || p.Mode != "custom-token" || p.Keys[0].Kid != "one" {
		t.Fatalf("public profile: %v", err)
	}
	device, err := Parse([]byte(`{"mode":"device-owned"}`))
	if err != nil || device.Mode != "device-owned" {
		t.Fatalf("device-owned: %v", err)
	}
	for _, data := range []string{
		`{"mode":"device-owned","issuer":"https://secret.example"}`,
		`{"mode":"device-owned","keys":[]}`,
		strings.Replace(publicDraft, `"kid":"one"`, `"d":"PRIVATE_CANARY","kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"kid":"`+strings.Repeat("x", 256)+`"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"kid":"`+strings.Repeat("😀", 128)+`"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"alg":null,"kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"alg":"","kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"use":"enc","kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"key_ops":[],"kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"ext":false,"kid":"one"`, 1),
		strings.Replace(publicDraft, `"kid":"one"`, `"Kid":"one"`, 1),
		strings.Replace(publicDraft, `"ES256"`, `"RS256"`, 1),
		strings.Replace(publicDraft, `"sub"`, `"iss"`, 1),
		strings.Replace(publicDraft, `https://members.example`, `http://members.example`, 1),
		strings.Replace(publicDraft, `https://members.example`, `https://user:PRIVATE_CANARY@members.example`, 1),
		strings.Replace(publicDraft, `"crv":"P-256"`, `"crv":"P-384"`, 1),
		strings.Replace(publicDraft, `"x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"x":"PRIVATE_CANARY"`, 1),
		publicDraft + `{}`,
		strings.Repeat(" ", 100_001),
		`null`, `[]`, `{`,
		`{"mode":"provider-bound","provider":"clerk"}`,
	} {
		_, err := Parse([]byte(data))
		if err == nil || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("malformed public profile accepted or leaked its input")
		}
	}
}

func TestLoadBoundsPublicFilesAndSanitizesPaths(t *testing.T) {
	p := filepath.Join(t.TempDir(), "PRIVATE_PATH_CANARY.json")
	if _, err := Load(p); err == nil || strings.Contains(err.Error(), "CANARY") {
		t.Fatal("missing path leaked")
	}
	if err := os.WriteFile(p, []byte(publicDraft), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 100_001)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("oversized profile accepted")
	}
}

func TestCheckDTORefusesOverclaimsAndInapplicableFields(t *testing.T) {
	base := map[string]any{"state": "accepted_at_check", "profileMode": "custom-token", "environment": "production", "configuration": "draft", "installedConfiguration": "unverified",
		"deviceAdmission": "unverified", "memberBinding": "unverified", "encryptedExchange": "unverified", "lifecycle": "unverified", "expiresAt": float64(100)}
	data, _ := json.Marshal(base)
	var result Check
	if json.Unmarshal(data, &result) != nil || !result.Matches(Profile{Mode: "custom-token"}, "production") {
		t.Fatal("valid historical result refused")
	}
	if result.Matches(Profile{Mode: "custom-token"}, "sandbox") {
		t.Fatal("crossed environment accepted")
	}
	for _, change := range []map[string]any{
		{"state": "ready"}, {"installedConfiguration": "verified"}, {"deviceAdmission": "verified"}, {"memberBinding": "verified"},
		{"encryptedExchange": "verified"}, {"lifecycle": "verified"}, {"expiresAt": nil}, {"expiresAt": 100.5},
		{"expiresAt": -1}, {"expiresAt": float64(9_007_199_254_740_992)}, {"reason": "CANARY"}, {"rawAssertion": "PRIVATE_CANARY"},
	} {
		candidate := maps.Clone(base)
		maps.Copy(candidate, change)
		data, _ := json.Marshal(candidate)
		if json.Unmarshal(data, &result) == nil {
			t.Errorf("invalid discriminated result accepted")
		}
	}
	delete(base, "expiresAt")
	base["state"], base["profileMode"], base["reason"] = "not_applicable", "device-owned", "device_owned_identity"
	data, _ = json.Marshal(base)
	if json.Unmarshal(data, &result) != nil || !result.Matches(Profile{Mode: "device-owned"}, "production") {
		t.Fatal("device-owned verdict refused")
	}
	base["expiresAt"] = nil
	data, _ = json.Marshal(base)
	if json.Unmarshal(data, &result) == nil {
		t.Fatal("device-owned accepted an expiry field")
	}
}
