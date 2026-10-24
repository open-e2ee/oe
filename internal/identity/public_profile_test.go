package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const keyWire = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one"}`
const configuredWire = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + keyWire + `]}`
const deviceInstalledWire = `{"mode":"device-owned","algorithms":["EdDSA"],"issuer":"","audience":""}`
const clerkWire = `{"mode":"provider-bound","provider":"clerk","algorithms":["RS256"],"issuer":"https://accounts.vendor.com","subjectClaim":"sub","authorizedParties":["https://app.example","http://localhost:3000"],"allowMissingAuthorizedParty":false}`
const firebaseWire = `{"mode":"provider-bound","provider":"firebase","algorithms":["RS256"],"issuer":"https://securetoken.google.com/sample-project","audience":"sample-project","subjectClaim":"sub"}`

func TestProfilesSeparateInstalledAndWriteContracts(t *testing.T) {
	for _, wire := range []string{configuredWire, deviceInstalledWire, clerkWire, firebaseWire} {
		v := mustDecode[InstalledProfile](t, wire)
		if !v.Equal(roundTrip(t, v)) {
			t.Fatal("installed profile changed")
		}
		assertRecursiveClosure(t, []byte(wire), func(data []byte) error { var v InstalledProfile; return json.Unmarshal(data, &v) })
	}
	for _, wire := range []string{configuredWire, `{"mode":"device-owned"}`, clerkWire, firebaseWire} {
		v := mustDecode[SelectionTarget](t, wire)
		if !v.Equal(roundTrip(t, v)) {
			t.Fatal("target changed")
		}
	}
	installed := strings.Replace(configuredWire, `"kid":"key-one"`, `"kid":"","alg":"","use":"","key_ops":[],"ext":false`, 1)
	installed = strings.Replace(installed, `"x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"x":"\ud800"`, 1)
	v := mustDecode[InstalledProfile](t, installed)
	out := roundTrip(t, v)
	if !v.Equal(out) || out.Keys == nil || (*out.Keys)[0].Operations == nil || len(*(*out.Keys)[0].Operations) != 0 || (*out.Keys)[0].Extractable == nil || *(*out.Keys)[0].Extractable {
		t.Fatal("installed optional field lost")
	}
	rejectJSON[SelectionTarget](t, []byte(installed))
	duplicateKeys := strings.Replace(configuredWire, keyWire, keyWire+","+keyWire, 1)
	mustDecode[InstalledProfile](t, duplicateKeys)
	rejectJSON[SelectionTarget](t, []byte(duplicateKeys))
	long := strings.Replace(configuredWire, `"kid":"key-one"`, `"kid":"`+strings.Repeat("x", 256)+`"`, 1)
	mustDecode[InstalledProfile](t, long)
	rejectJSON[SelectionTarget](t, []byte(long))
	rejectJSON[SelectionTarget](t, []byte(deviceInstalledWire))
	rejectJSON[InstalledProfile](t, []byte(`{"mode":"device-owned"}`))
}
func TestPublicProfilePresenceAndDefensiveCopy(t *testing.T) {
	absent := mustDecode[InstalledProfile](t, clerkWire)
	present := mustDecode[InstalledProfile](t, strings.Replace(clerkWire, `"subjectClaim"`, `"audience":"members","subjectClaim"`, 1))
	if absent.Equal(present) {
		t.Fatal("audience absence lost")
	}
	withoutFalse := mustDecode[InstalledProfile](t, strings.Replace(clerkWire, `,"allowMissingAuthorizedParty":false`, "", 1))
	if absent.Equal(withoutFalse) {
		t.Fatal("false presence lost")
	}
	copied, e := absent.Clone()
	if e != nil {
		t.Fatal(e)
	}
	(*copied.AuthorizedParties)[0] = mustText(t, "https://changed.example")
	if absent.Equal(copied) || !textLiteral((*absent.AuthorizedParties)[0], "https://app.example") {
		t.Fatal("copy aliased parties")
	}
	reverse := absent
	parties := []ContractText{(*absent.AuthorizedParties)[1], (*absent.AuthorizedParties)[0]}
	reverse.AuthorizedParties = &parties
	if absent.Equal(reverse) {
		t.Fatal("party order ignored")
	}
	for _, wire := range []string{strings.Replace(clerkWire, `"allowMissingAuthorizedParty":false`, `"allowMissingAuthorizedParty":true`, 1), strings.Replace(clerkWire, `"allowMissingAuthorizedParty":false`, `"allowMissingAuthorizedParty":null`, 1), strings.Replace(firebaseWire, "sample-project\",\"subjectClaim", "other-project\",\"subjectClaim", 1), strings.Replace(clerkWire, "accounts.vendor.com", "accounts.internal", 1), strings.Replace(clerkWire, "http://localhost:3000", "http://127.0.0.1:3000", 1)} {
		rejectJSON[InstalledProfile](t, []byte(wire))
	}
}
func TestWriteKeyBoundsRemainDistinct(t *testing.T) {
	initial := strings.Replace(configuredWire, "key-one", strings.Repeat("x", 255), 1)
	mustDecode[SelectionTarget](t, initial)
	key129 := strings.Replace(keyWire, "key-one", strings.Repeat("x", 129), 1)
	rejectJSON[ReplacementKeys](t, []byte("["+key129+"]"))
	for _, kid := range []string{`a\u0000b`, `a\u200db`} {
		wire := strings.Replace(keyWire, `key-one`, kid, 1)
		rejectJSON[ReplacementKeys](t, []byte("["+wire+"]"))
		mustDecode[SelectionTarget](t, strings.Replace(configuredWire, keyWire, wire, 1))
	}
	unpaired := strings.Replace(keyWire, "key-one", `\ud800`, 1)
	mustDecode[ReplacementKeys](t, "["+unpaired+"]")
	noncanonical := strings.Replace(keyWire, `"x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"`, 1)
	mustDecode[SelectionTarget](t, strings.Replace(configuredWire, keyWire, noncanonical, 1))
	rejectJSON[ReplacementKeys](t, []byte("["+noncanonical+"]"))
	for _, count := range []int{1, 16, 17, 32, 33} {
		keys := []SigningPublicKey{}
		for i := 0; i < count; i++ {
			key := mustDecode[SigningPublicKey](t, keyWire)
			key.Kid = mustText(t, fmt.Sprintf("key-%d", i))
			if key.Validate() != nil || (ReplacementKeys{key}).Validate() != nil {
				t.Fatal("count fixture must contain valid individual write and replacement keys")
			}
			keys = append(keys, key)
		}
		if (ValidateMigrationKeys(keys) == nil) != (count <= 16) {
			t.Fatal("migration write bound changed")
		}
		if (ReplacementKeys(keys).Validate() == nil) != (count <= 32) {
			t.Fatal("replacement bound changed")
		}
	}
	rejectJSON[ReplacementKeys](t, []byte("[]"))
	rejectJSON[ReplacementKeys](t, []byte("["+keyWire+","+keyWire+"]"))
}
func TestProfileURLConstraintVectors(t *testing.T) {
	for _, issuer := range []string{"https://members.example", "https:members.example", "https://members.example/#", "HTTPS://members.example", " https://members.example ", `https://members.example/\ud800`} {
		wire := strings.Replace(configuredWire, "https://members.example", issuer, 1)
		mustDecode[SelectionTarget](t, wire)
	}
	for _, issuer := range []string{"http://members.example", "https://user:pass@members.example", "https://members.example/#fragment", "https://members.example:65536", "https://"} {
		rejectJSON[SelectionTarget](t, []byte(strings.Replace(configuredWire, "https://members.example", issuer, 1)))
	}
}
func TestExistingDraftStillHasItsOriginalBoundary(t *testing.T) {
	if _, e := Parse([]byte(clerkWire)); !errors.Is(e, ErrUnsupported) {
		t.Fatal("existing draft accepted native profile")
	}
	if _, e := Parse([]byte(`{"mode":"device-owned"}`)); e != nil {
		t.Fatal("existing device draft changed")
	}
}

// These vectors are definitions only. Root's finite parser experiment has a separate owner.
func TestMaintainedURLPredicatesKeepFinitePolicyVectors(t *testing.T) {
	cases := []struct {
		name string
		wire string
		want [3]bool
	}{
		{"prior14-special-https", `"https:members.example"`, [3]bool{true, false, false}},
		{"prior14-edge-whitespace", `" https://members.example "`, [3]bool{true, false, false}},
		{"prior14-unpaired-path", `"https://members.example/\ud800"`, [3]bool{true, false, false}},
		{"prior14-unicode-host", `"https://b\u00fccher.vendor.com"`, [3]bool{true, false, false}},
		{"prior14-empty-fragment", `"https://members.example/#"`, [3]bool{true, false, false}},
		{"prior14-empty-userinfo", `"https://@members.example"`, [3]bool{true, false, false}},
		{"prior14-hex-ipv4", `"https://0x7f000001"`, [3]bool{true, false, false}},
		{"prior14-short-ipv4", `"https://127.1"`, [3]bool{true, false, false}},
		{"prior14-canonical-ipv4", `"https://127.0.0.1"`, [3]bool{true, false, true}},
		{"prior14-unicode-party", `"https://b\u00fccher.vendor.com"`, [3]bool{true, false, false}},
		{"prior14-invalid-punycode", `"https://xn--a.vendor.com"`, [3]bool{false, false, false}},
		{"prior14-ipv6-origin", `"https://[::ffff:127.0.0.1]"`, [3]bool{true, false, false}},
		{"prior14-default-port", `"https://accounts.vendor.com:443"`, [3]bool{true, false, false}},
		{"prior14-localhost-party", `"http://localhost:3000"`, [3]bool{false, false, true}},
		{"qualified-wpt-4", `"https://:@test"`, [3]bool{true, false, false}},
		{"qualified-wpt-17", `"http://f:b/c"`, [3]bool{false, false, false}},
		{"qualified-idna-16", `"https://xn--a"`, [3]bool{false, false, false}},
		{"qualified-policy-0", `"https://tenant.clerk.accounts.dev"`, [3]bool{true, true, true}},
		{"qualified-policy-1", `"http://localhost:5179"`, [3]bool{false, false, true}},
		{"qualified-policy-2", `"https:example.com"`, [3]bool{true, false, false}},
		{"qualified-policy-3", `"https://example.com/#"`, [3]bool{true, false, false}},
		{"qualified-policy-4", `"https://user:pass@example.com"`, [3]bool{false, false, false}},
		{"qualified-policy-5", `"https://fa\u1e9e.de"`, [3]bool{true, false, false}},
		{"qualified-policy-6", `"https://fa\u00df.de"`, [3]bool{true, false, false}},
		{"qualified-policy-7", `"https://127.1"`, [3]bool{true, false, false}},
		{"qualified-policy-8", `"https://0x7f000001"`, [3]bool{true, false, false}},
		{"qualified-policy-9", `"https://example.com/\ud800"`, [3]bool{true, false, false}},
		{"qualified-policy-10", `"https://xn--zca.com"`, [3]bool{true, true, true}},
		{"qualified-policy-11", `"https://example.com"`, [3]bool{true, true, true}},
		{"qualified-policy-12", `"https://example.com:443"`, [3]bool{true, false, false}},
		{"qualified-policy-13", `"https://[::1]"`, [3]bool{true, false, true}},
		{"qualified-policy-14", `"http://LOCALHOST"`, [3]bool{false, false, false}},
		{"qualified-policy-15", `"https://tenant.clerk.accounts.dev/"`, [3]bool{true, false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := mustDecode[ContractText](t, tc.wire)
			configured := mustDecode[SelectionTarget](t, configuredWire)
			configured.Issuer = &value
			issuer := mustDecode[InstalledProfile](t, clerkWire)
			issuer.Issuer = &value
			party := mustDecode[InstalledProfile](t, clerkWire)
			parties := []ContractText{value}
			party.AuthorizedParties = &parties
			actual := [3]bool{configured.Validate() == nil, issuer.Validate() == nil, party.Validate() == nil}
			if actual != tc.want {
				t.Fatal("URL predicate decision changed")
			}
		})
	}
}
func TestURLValidationPreservesOriginalContractTextAndEncoding(t *testing.T) {
	for _, wire := range []string{`"\thttps://fa\u00df.de:443/a/../\ud800#"`, `"https://0x7f000001"`, `"https://@members.example/#"`} {
		value := mustDecode[ContractText](t, wire)
		target := mustDecode[SelectionTarget](t, configuredWire)
		target.Issuer = &value
		before, e := json.Marshal(target)
		if e != nil {
			t.Fatal(e)
		}
		if target.Validate() != nil {
			t.Fatal("accepted issuer refused")
		}
		after, e := json.Marshal(target)
		if e != nil || string(before) != string(after) || !target.Issuer.Equal(value) {
			t.Fatal("URL validation rewrote retained data")
		}
		decoded := roundTrip(t, target)
		if !decoded.Issuer.Equal(value) {
			t.Fatal("URL input scalar replaced retained code units")
		}
	}
	value := mustText(t, "https://0x7f000001")
	profile := mustDecode[InstalledProfile](t, clerkWire)
	parties := []ContractText{value}
	profile.AuthorizedParties = &parties
	if profile.Validate() == nil || !(*profile.AuthorizedParties)[0].Equal(value) {
		t.Fatal("noncanonical party was normalized into authority")
	}
}
