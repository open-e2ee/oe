package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

const identityConfigKey = `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"key-one","alg":"ES256","use":"sig","key_ops":["verify"],"ext":true}`
const identityConfigExternal = `{"mode":"custom-token","algorithms":["ES256"],"issuer":"https://members.example","audience":"members","subjectClaim":"sub","keys":[` + identityConfigKey + `]}`
const identityConfigClerk = `{"mode":"provider-bound","provider":"clerk","algorithms":["RS256"],"issuer":"https://members.clerk.accounts.dev","subjectClaim":"sub","authorizedParties":["https://chat.example","http://localhost:3000"],"audience":"members","allowMissingAuthorizedParty":true}`
const identityConfigFirebase = `{"mode":"provider-bound","provider":"firebase","algorithms":["RS256"],"issuer":"https://securetoken.google.com/my-project","audience":"my-project","subjectClaim":"sub"}`

func configIdentityFixture[T any](t *testing.T, wire string) T {
	t.Helper()
	var value T
	if err := json.Unmarshal([]byte(wire), &value); err != nil {
		t.Fatal("invalid qualified identity fixture", err)
	}
	return value
}

func configIdentityValue(t *testing.T, wire string) map[string]any {
	t.Helper()
	var base map[string]any
	data, err := json.Marshal(New("typed-chat"))
	if err != nil || json.Unmarshal(data, &base) != nil {
		t.Fatal("invalid base config")
	}
	var target any
	if json.Unmarshal([]byte(wire), &target) != nil {
		t.Fatal("invalid fixture JSON")
	}
	base["environments"].(map[string]any)["sandbox"].(map[string]any)["identity"] = target
	return base
}

func completeConfigIdentity(t *testing.T, profile string) identity.CompleteConfiguration {
	t.Helper()
	fingerprint := strings.Repeat("A", 43)
	return configIdentityFixture[identity.CompleteConfiguration](t, `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"`+fingerprint+`","identityProfile":`+profile+`,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"`+fingerprint+`"},"reason":null},"selectionOperation":null}`)
}

func TestPublicIdentityConfigQualifiedVariantsLoadAndRoundTrip(t *testing.T) {
	variants := map[string]string{
		"device-owned":              `{"mode":"device-owned"}`,
		"custom-token":              identityConfigExternal,
		"configured-provider-bound": strings.Replace(identityConfigExternal, `"custom-token"`, `"provider-bound"`, 1),
		"clerk":                     identityConfigClerk,
		"firebase":                  identityConfigFirebase,
	}
	for name, wire := range variants {
		t.Run(name, func(t *testing.T) {
			input := configIdentityValue(t, wire)
			value, err := validate(input)
			if err != nil {
				t.Fatal("valid public variant refused", err)
			}
			target, err := value.IdentityFor("sandbox")
			expected := configIdentityFixture[identity.SelectionTarget](t, wire)
			if err != nil || target == nil || !target.Equal(expected) {
				t.Fatal("typed policy changed")
			}
			path := writeConfig(t, header+"export default defineConfig("+mustConfigIdentityJSON(t, input)+");\n")
			loaded, err := Load(path)
			if err != nil {
				t.Fatal("actual loader refused qualified variant", err)
			}
			again, err := loaded.IdentityFor("sandbox")
			if err != nil || again == nil || !again.Equal(expected) {
				t.Fatal("actual config load lost public policy")
			}
			if err := Create(path, loaded); err != nil {
				t.Fatal(err)
			}
			roundTrip, err := Load(path)
			if err != nil || !reflect.DeepEqual(roundTrip, loaded) {
				t.Fatal("created public config did not round-trip", err)
			}
		})
	}
}

func mustConfigIdentityJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPublicIdentityConfigRejectsClosedVariantAndSecretInputs(t *testing.T) {
	invalid := map[string]string{
		"null":                   `null`,
		"device-extra":           `{"mode":"device-owned","issuer":"PRIVATE_SENTINEL"}`,
		"unknown-provider":       strings.Replace(identityConfigClerk, `"clerk"`, `"other"`, 1),
		"native-keys":            strings.TrimSuffix(identityConfigFirebase, "}") + `,"keys":[` + identityConfigKey + `]}`,
		"private-key":            strings.Replace(identityConfigExternal, `"kty":"EC"`, `"d":"PRIVATE_SENTINEL","kty":"EC"`, 1),
		"private-property-name":  strings.TrimSuffix(identityConfigExternal, "}") + `,"PRIVATE_SENTINEL":"hidden"}`,
		"private-enum-value":     strings.Replace(identityConfigExternal, `"ES256"`, `"PRIVATE_SENTINEL"`, 1),
		"key-source":             strings.TrimSuffix(identityConfigExternal, "}") + `,"jwksUrl":"https://private.example/PRIVATE_SENTINEL"}`,
		"key-null":               strings.Replace(identityConfigExternal, `"ext":true`, `"ext":null`, 1),
		"key-false":              strings.Replace(identityConfigExternal, `"ext":true`, `"ext":false`, 1),
		"key-order-invalid":      strings.Replace(identityConfigExternal, `["verify"]`, `["sign","verify"]`, 1),
		"issuer-credential":      strings.Replace(identityConfigExternal, `https://members.example`, `https://PRIVATE_SENTINEL@members.example`, 1),
		"reserved-subject":       strings.Replace(identityConfigExternal, `"sub"`, `"exp"`, 1),
		"firebase-issuer":        strings.Replace(identityConfigFirebase, `securetoken.google.com/my-project`, `securetoken.google.com/another-project`, 1),
		"clerk-parties-null":     strings.Replace(identityConfigClerk, `["https://chat.example","http://localhost:3000"]`, `null`, 1),
		"clerk-audience-missing": strings.Replace(identityConfigClerk, `,"audience":"members"`, ``, 1),
	}
	for name, wire := range invalid {
		t.Run(name, func(t *testing.T) {
			value, err := validate(configIdentityValue(t, wire))
			if err == nil {
				t.Fatal("unsafe or unsupported identity accepted", value)
			}
			failure := requireCode(t, err, "CONFIG_INVALID")
			data, encodeErr := json.Marshal(failure.Data)
			if encodeErr != nil || strings.Contains(failure.Message+string(data), "PRIVATE_SENTINEL") {
				t.Fatal("invalid identity values leaked")
			}
		})
	}
}

func TestPublicIdentitySchemaErrorsKeepOnlyTheEnvironmentIdentityPath(t *testing.T) {
	for _, environment := range []string{"sandbox", "production"} {
		raw := configIdentityValue(t, identityConfigExternal)
		environments := raw["environments"].(map[string]any)
		entry := environments["sandbox"].(map[string]any)
		if environment == "production" {
			environments["production"] = entry
			environments["sandbox"] = map[string]any{}
		}
		entry["identity"] = map[string]any{"mode": "PRIVATE_SENTINEL", "PRIVATE_SENTINEL": "hidden"}
		_, err := validate(raw)
		failure := requireCode(t, err, "CONFIG_INVALID")
		data, encodeErr := json.Marshal(failure.Data)
		if encodeErr != nil || strings.Contains(failure.Message+string(data), "PRIVATE_SENTINEL") {
			t.Fatal("identity schema failure exposed a value or unknown field")
		}
		if !strings.Contains(string(data), "environments."+environment+".identity") {
			t.Fatal("identity schema failure lost its safe location")
		}
	}
}

func TestPublicIdentityAbsenceAndRelayDefaultsRemainExact(t *testing.T) {
	raw := configIdentityFixture[map[string]any](t, `{"product":"signal-relay","project":"typed-chat","relay":{"deliveryRetention":"7d","attachmentRetention":"7d"},"environments":{"sandbox":{}}}`)
	value, err := validate(raw)
	if err != nil || !value.Relay.RelayReceipts {
		t.Fatal("old defaults changed", err)
	}
	target, err := value.IdentityFor("sandbox")
	if err != nil || target != nil {
		t.Fatal("absence invented device-owned identity")
	}
	data := mustConfigIdentityJSON(t, value)
	if strings.Contains(data, `"identity"`) {
		t.Fatal("old serialized config gained identity")
	}
	if _, err := value.IdentityFor("production"); err == nil {
		t.Fatal("missing Production section invented identity")
	}
	raw["identity"] = map[string]any{"mode": "device-owned"}
	if _, err := validate(raw); err == nil {
		t.Fatal("shared identity default accepted")
	}
}

func TestPublicIdentityReturnedPolicyIsDetached(t *testing.T) {
	value, err := validate(configIdentityValue(t, identityConfigExternal))
	if err != nil {
		t.Fatal(err)
	}
	target, err := value.IdentityFor("sandbox")
	if err != nil || target == nil || target.Keys == nil {
		t.Fatal("fixture target missing")
	}
	(*target.Keys)[0].Kid = identity.TextFromUnits([]uint16{'x'})
	original, err := value.IdentityFor("sandbox")
	expected := configIdentityFixture[identity.SelectionTarget](t, identityConfigExternal)
	if err != nil || original == nil || !original.Equal(expected) {
		t.Fatal("caller changed retained config policy")
	}
}

func TestPublicIdentityProjectionKeepsHistoricalReceiverBreadth(t *testing.T) {
	for _, name := range []string{"overlong-issuer", "legacy-coordinate"} {
		t.Run(name, func(t *testing.T) {
			profile := identityConfigExternal
			if name == "overlong-issuer" {
				profile = strings.Replace(profile, "https://members.example", "https://members.example/"+strings.Repeat("x", 256), 1)
			} else {
				profile = strings.Replace(profile, strings.Repeat("A", 43), "historical-coordinate", 1)
			}
			complete := completeConfigIdentity(t, profile)
			before, err := complete.Clone()
			if err != nil {
				t.Fatal("historical installed receiver refused", err)
			}
			if _, err := ProjectInstalledIdentity(complete); err == nil {
				t.Fatal("historical value was silently made writable")
			}
			if !complete.Equal(before) {
				t.Fatal("projection changed installed evidence")
			}
		})
	}
	for _, profile := range []string{identityConfigExternal, identityConfigClerk, identityConfigFirebase} {
		complete := completeConfigIdentity(t, profile)
		got, err := ProjectInstalledIdentity(complete)
		expected := configIdentityFixture[identity.SelectionTarget](t, profile)
		if err != nil || !got.Equal(expected) {
			t.Fatal("representable public policy changed", err)
		}
	}
}

func TestPublicIdentityProjectionDeviceAndValidMigrationDisposition(t *testing.T) {
	device := `{"mode":"device-owned","algorithms":["EdDSA"],"issuer":"device-authority","audience":"device-audience"}`
	complete := completeConfigIdentity(t, device)
	target, err := ProjectInstalledIdentity(complete)
	if err != nil || !target.Equal(identity.SelectionTarget{Mode: "device-owned"}) {
		t.Fatal("device selection projection changed", err)
	}
	complete = completeConfigIdentity(t, identityConfigExternal)
	destination := strings.Replace(identityConfigExternal, "https://members.example", "https://other.example", 1)
	migration := `{"manifestId":"legacy_` + strings.Repeat("A", 43) + `","revision":0,"configuration":{"version":1,"sourceProfile":` + identityConfigExternal + `,"targetProfile":` + destination + `,"preparationTtlSeconds":60,"rollbackWindowSeconds":60}}`
	value := configIdentityFixture[identity.CompleteMigration](t, migration)
	complete.IdentityMigration = &value
	if complete.Validate() != nil {
		t.Fatal("migration fixture is invalid")
	}
	if _, err := ProjectInstalledIdentity(complete); err == nil {
		t.Fatal("active migration was converted into a selection write")
	}
}
