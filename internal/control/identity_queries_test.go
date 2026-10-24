package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

const observationWire = `{"operationId":"read_target","scope":` + scopeWire + `,"target":{"kind":"subject"},"observedVersion":0,"observedState":"active","currentHead":null,"application":{"kind":"unbound-subject"}}`
const preparedID = "lc1_0123456789abcdef_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestIdentityQueriesPreserveLiteralSelectorsAndClosedBodies(t *testing.T) {
	for _, name := range []string{"current", "keys-read", "target", "preview-selection", "preview-keys"} {
		t.Run(name, func(t *testing.T) {
			kind := identityattempt.Selection
			if name == "keys-read" || name == "preview-keys" {
				kind = identityattempt.KeysOnly
			}
			if name == "target" {
				kind = identityattempt.Lifecycle
			}
			target := identityDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
			keys := identityDecode[identity.ReplacementKeys](t, `[`+keyWire+`]`)
			calls := 0
			client := identityFixture(t, kind, func(r *http.Request) (*http.Response, error) {
				calls++
				action := r.URL.Query().Get("action")
				if name == "current" {
					if r.Method != "GET" || action != "current" {
						t.Error("current selectors changed")
					}
					return identityResponse(200, currentWire), nil
				}
				if r.GetBody != nil {
					t.Error("identity request grants transport replay")
				}
				if r.Method != "POST" {
					t.Error("query method changed")
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]json.RawMessage
				if json.Unmarshal(data, &body) != nil {
					t.Fatal("request is not JSON")
				}
				var literal string
				if json.Unmarshal(body["action"], &literal) != nil || literal != action {
					t.Error("body and URL selectors differ")
				}
				switch name {
				case "keys-read":
					if action != "keys-read" || len(body) != 1 {
						t.Error("current keys read acquired an operation")
					}
					return identityResponse(200, currentWire), nil
				case "target":
					if action != "target" || len(body) != 2 || body["subject"] != nil {
						t.Error("target body changed")
					}
					return identityResponse(200, observationWire), nil
				default:
					if action != "preview" || len(body) != 4 || body["precondition"] != nil {
						t.Error("preview acquired dispatch context")
					}
					preview := identity.PreviewResult{Kind: string(kind), ExpectedConfigurationVersion: 1,
						Current: identityDecode[identity.CurrentContext](t, currentWire), NativeCapabilities: identity.NativeCapabilities{Clerk: "closed", Firebase: "available"}}
					if kind == identityattempt.Selection {
						preview.Target = &target
					} else {
						preview.Keys = &keys
					}
					wire, err := json.Marshal(preview)
					if err != nil {
						t.Fatal(err)
					}
					return identityResponse(200, string(wire)), nil
				}
			})
			credential := CredentialRequest{AccessToken: "token"}
			var err error
			switch name {
			case "current":
				_, err = client.Current(context.Background(), credential)
			case "keys-read":
				_, err = client.KeysCurrent(context.Background(), credential)
			case "target":
				subject, _ := identity.Text("private_subject_CANARY")
				profile := "installed"
				_, err = client.LifecycleTarget(context.Background(), credential, identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile})
			default:
				input := identity.PreviewRequest{Kind: string(kind), ExpectedConfigurationVersion: 1}
				if kind == identityattempt.Selection {
					input.Target = &target
				} else {
					input.Keys = &keys
				}
				_, err = client.Preview(context.Background(), credential, input)
			}
			if err != nil || calls != 1 {
				t.Fatalf("qualified query failed: %v", err)
			}
		})
	}
}

func TestIdentityQueriesRejectWrongEnvironmentAndTargetKind(t *testing.T) {
	for _, wire := range []string{
		strings.Replace(observationWire, `"kind":"subject"`, `"kind":"account"`, 1),
		strings.Replace(observationWire, `"environmentKind":"sandbox"`, `"environmentKind":"production"`, 1),
		strings.Replace(observationWire, `"application":{"kind":"unbound-subject"}`, `"application":null`, 1),
	} {
		client := identityFixture(t, identityattempt.Lifecycle, func(*http.Request) (*http.Response, error) {
			return identityResponse(200, wire), nil
		})
		subject, _ := identity.Text("private_CANARY")
		profile := "installed"
		_, err := client.LifecycleTarget(context.Background(), CredentialRequest{AccessToken: "token"}, identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile})
		identityCode(t, err, "IDENTITY_RESULT_INVALID")
	}
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		return identityResponse(200, strings.Replace(currentWire, `"environmentKind":"sandbox"`, `"environmentKind":"production"`, 1)), nil
	})
	_, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
	identityCode(t, err, "IDENTITY_RESULT_INVALID")
}

func TestIdentityPreviewCorrelatesWholeTargetAndOrderedKeys(t *testing.T) {
	for _, kind := range []identityattempt.Kind{identityattempt.Selection, identityattempt.KeysOnly} {
		for _, change := range []string{"kind", "version", "target-or-order"} {
			t.Run(string(kind)+"/"+change, func(t *testing.T) {
				target := identityDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
				keys := identityDecode[identity.ReplacementKeys](t, `[`+keyWire+`,`+strings.Replace(keyWire, "key-one", "key-two", 1)+`]`)
				input := identity.PreviewRequest{Kind: string(kind), ExpectedConfigurationVersion: 1}
				if kind == identityattempt.Selection {
					input.Target = &target
				} else {
					input.Keys = &keys
				}
				result := identity.PreviewResult{Kind: input.Kind, ExpectedConfigurationVersion: 1, Target: input.Target, Keys: input.Keys,
					Current: identityDecode[identity.CurrentContext](t, currentWire), NativeCapabilities: identity.NativeCapabilities{Clerk: "closed", Firebase: "closed"}}
				switch change {
				case "kind":
					if kind == identityattempt.Selection {
						result.Kind = "keys-only"
						result.Target = nil
						result.Keys = &keys
					} else {
						result.Kind = "selection"
						result.Keys = nil
						result.Target = &target
					}
				case "version":
					result.ExpectedConfigurationVersion = 2
					result.Current.Configuration.ConfigurationVersion = 2
				case "target-or-order":
					if kind == identityattempt.Selection {
						altered := identityDecode[identity.SelectionTarget](t, configuredWire)
						result.Target = &altered
					} else {
						swapped := identity.ReplacementKeys{keys[1], keys[0]}
						result.Keys = &swapped
					}
				}
				wire, err := json.Marshal(result)
				if err != nil {
					t.Fatal("perturbation fixture is invalid", err)
				}
				client := identityFixture(t, kind, func(*http.Request) (*http.Response, error) {
					return identityResponse(200, string(wire)), nil
				})
				_, err = client.Preview(context.Background(), CredentialRequest{AccessToken: "token"}, input)
				identityCode(t, err, "IDENTITY_RESULT_INVALID")
			})
		}
	}
}

func TestIdentityAddressedCurrentIsDetachedAndNotSerializable(t *testing.T) {
	client := identityFixture(t, identityattempt.Selection, func(*http.Request) (*http.Response, error) {
		return identityResponse(200, currentWire), nil
	})
	current, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
	if err != nil {
		t.Fatal(err)
	}
	value, err := current.Context()
	if err != nil {
		t.Fatal(err)
	}
	value.Precondition.PublishableKey = "pk_changed"
	again, err := current.Context()
	if err != nil || again.Precondition.PublishableKey != "pk_public" {
		t.Fatal("addressed reply aliases caller state")
	}
	if _, err := json.Marshal(current); err == nil {
		t.Fatal("address provenance serialized")
	}
	if json.Unmarshal([]byte(currentWire), &AddressedCurrent{}) == nil {
		t.Fatal("wire manufactured provenance")
	}
	if _, err := (AddressedCurrent{}).Context(); err == nil {
		t.Fatal("zero provenance accepted")
	}
	other := client.slot
	base, _ := identity.ParseControlBaseURL("https://other.example/api/cli")
	other, _ = identityattempt.NewSlot(base, other.OrganizationID(), other.ProjectSlug(), other.Environment(), other.Kind())
	if current.matches(other) {
		t.Fatal("another address accepted current evidence")
	}
}

func TestIdentityInvalidQueryAndPreparationPermitHaveNoRequest(t *testing.T) {
	calls := 0
	client := identityFixture(t, identityattempt.Lifecycle, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, currentWire), nil
	})
	_, err := client.LifecycleTarget(context.Background(), CredentialRequest{AccessToken: "token"}, identity.LifecycleInputTarget{})
	identityCode(t, err, "IDENTITY_INPUT_INVALID")
	_, err = client.Preview(context.Background(), CredentialRequest{AccessToken: "token"}, identity.PreviewRequest{})
	identityCode(t, err, "IDENTITY_INPUT_INVALID")
	_, err = client.KeysCurrent(context.Background(), CredentialRequest{AccessToken: "token"})
	identityCode(t, err, "IDENTITY_INPUT_INVALID")
	for _, permit := range []*identityattempt.PreparationPermit{nil, {}} {
		_, err = client.LifecyclePrepare(context.Background(), CredentialRequest{AccessToken: "token"}, AddressedCurrent{}, permit, LifecyclePreparationInput{})
		if err == nil {
			t.Fatal("manufactured preparation admitted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid query or permit reached HTTP")
	}
}
