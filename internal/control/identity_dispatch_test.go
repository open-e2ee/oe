package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

const selectionID = "oe_0123456789abcdef0123456789abcdef"
const cancellationID = "oe_fedcba9876543210fedcba9876543210"
const selectionResultWire = `{"operationId":"` + selectionID + `","state":"prepared","configurationVersion":2,"admissionRevision":0}`
const keysResultWire = `{"kind":"keys-only","operationId":"` + selectionID + `","state":"prepared","configurationVersion":2,"admissionRevision":0}`
const lifecycleResultWire = `{"operation":{"scope":` + scopeWire + `,"target":{"kind":"subject"},"operationId":"` + preparedID + `","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"pending_owners","supersededBy":null,"requiredMailboxes":2,"preparedMailboxes":0,"activatedMailboxes":0}`

// identityDispatchCall is one mutation or status call by operation ID.
type identityDispatchCall struct {
	action string
	reply  string
	// body is the exact request body, without the action selector.
	body map[string]string
	run  func(*identityHTTP, AddressedCurrent) error
}

func identityDispatchCalls(t *testing.T) map[string]identityDispatchCall {
	t.Helper()
	precondition := identityDecode[identity.Precondition](t, preconditionWire)
	target := identityDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
	keys := identityDecode[identity.ReplacementKeys](t, `[`+keyWire+`]`)
	attempt := identityDecode[identity.LifecycleAttempt](t, `{"operationId":"`+preparedID+`","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	subject, _ := identity.Text("private_CANARY")
	profile := "installed"
	lifecycleTarget := identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile}
	prepared, _ := identity.Text(preparedID)
	credential := CredentialRequest{AccessToken: "token"}
	ctx := context.Background()
	quoted := func(value string) string { return `"` + value + `"` }
	return map[string]identityDispatchCall{
		"selection-apply": {"select", selectionResultWire,
			map[string]string{"operationId": quoted(selectionID), "expectedConfigurationVersion": "1", "target": `{"mode":"device-owned"}`, "precondition": preconditionWire},
			func(c *identityHTTP, _ AddressedCurrent) error {
				_, err := c.SelectionApply(ctx, credential, identity.SelectionCommand{OperationID: selectionID, ExpectedConfigurationVersion: 1, Target: target, Precondition: precondition})
				return err
			}},
		"selection-status": {"selection-operation", selectionResultWire,
			map[string]string{"selectionOperationId": quoted(selectionID), "precondition": preconditionWire},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.SelectionStatus(ctx, credential, current, selectionID)
				return err
			}},
		"selection-cancel": {"selection-cancel", selectionResultWire,
			map[string]string{"operationId": quoted(cancellationID), "selectionOperationId": quoted(selectionID), "precondition": preconditionWire},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.SelectionCancel(ctx, credential, current, cancellationID, selectionID)
				return err
			}},
		"keys-replace": {"keys-replace", keysResultWire,
			map[string]string{"operationId": quoted(selectionID), "expectedConfigurationVersion": "1", "keys": `[` + keyWire + `]`, "precondition": preconditionWire},
			func(c *identityHTTP, _ AddressedCurrent) error {
				_, err := c.KeysReplace(ctx, credential, identity.KeysCommand{OperationID: selectionID, ExpectedConfigurationVersion: 1, Keys: keys, Precondition: precondition})
				return err
			}},
		"keys-status": {"keys-read", keysResultWire,
			map[string]string{"selectionOperationId": quoted(selectionID), "precondition": preconditionWire},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.KeysStatus(ctx, credential, current, selectionID)
				return err
			}},
		"keys-cancel": {"keys-cancel", keysResultWire,
			map[string]string{"operationId": quoted(cancellationID), "selectionOperationId": quoted(selectionID), "precondition": preconditionWire},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.KeysCancel(ctx, credential, current, cancellationID, selectionID)
				return err
			}},
		"lifecycle-operation": {"operation", lifecycleResultWire,
			map[string]string{"lifecycleOperationId": quoted(preparedID)},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.LifecycleOperation(ctx, credential, current, prepared)
				return err
			}},
		"lifecycle-apply": {"apply", lifecycleResultWire,
			map[string]string{"operationId": quoted(preparedID), "target": `{"kind":"subject","subject":"private_CANARY","profileSource":"installed"}`,
				"state": `"suspended"`, "expectedLifecycleVersion": "0"},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.LifecycleApply(ctx, credential, current, attempt, lifecycleTarget)
				return err
			}},
		"lifecycle-resume": {"resume", lifecycleResultWire,
			map[string]string{"operationId": quoted(preparedID)},
			func(c *identityHTTP, current AddressedCurrent) error {
				_, err := c.LifecycleResume(ctx, credential, current, prepared)
				return err
			}},
	}
}

// identityAddressedCurrent reads current evidence through the client so a
// test holds receiver provenance for its own address.
func identityAddressedCurrent(t *testing.T, client *identityHTTP, current *bool) AddressedCurrent {
	t.Helper()
	*current = true
	value, err := client.Current(context.Background(), CredentialRequest{AccessToken: "token"})
	*current = false
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func compactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestIdentityDispatchSendsOneExactCommandByOperationID(t *testing.T) {
	for name, call := range identityDispatchCalls(t) {
		t.Run(name, func(t *testing.T) {
			calls, current := 0, false
			client := identityFixture(t, func(r *http.Request) (*http.Response, error) {
				if current {
					return identityResponse(200, currentWire), nil
				}
				calls++
				if r.Method != "POST" || r.URL.Query().Get("action") != call.action || r.GetBody != nil {
					t.Error("dispatch selector, method or replay grant changed")
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				var body map[string]json.RawMessage
				if json.Unmarshal(data, &body) != nil {
					t.Fatal("request is not JSON")
				}
				if compactJSON(t, body["action"]) != `"`+call.action+`"` || len(body) != len(call.body)+1 {
					t.Errorf("body fields changed: %s", data)
				}
				for field, want := range call.body {
					if body[field] == nil || compactJSON(t, body[field]) != compactJSON(t, []byte(want)) {
						t.Errorf("field %s changed: %s", field, body[field])
					}
				}
				return identityResponse(200, call.reply), nil
			})
			if err := call.run(client, identityAddressedCurrent(t, client, &current)); err != nil || calls != 1 {
				t.Fatalf("exact dispatch failed after %d calls: %v", calls, err)
			}
		})
	}
}

func TestIdentityDispatchRejectsAResultForAnotherOperation(t *testing.T) {
	for name, call := range identityDispatchCalls(t) {
		t.Run(name, func(t *testing.T) {
			reply := strings.Replace(call.reply, selectionID, "oe_ffffffffffffffffffffffffffffffff", 1)
			reply = strings.Replace(reply, preparedID, "lc1_ffffffffffffffff_AAAAAAAAAAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1)
			current := false
			client := identityFixture(t, func(*http.Request) (*http.Response, error) {
				if current {
					return identityResponse(200, currentWire), nil
				}
				return identityResponse(200, reply), nil
			})
			identityCode(t, call.run(client, identityAddressedCurrent(t, client, &current)), "IDENTITY_RESULT_INVALID")
		})
	}
}

// A cancel result names the selection operation, never the cancellation.
func TestIdentityCancelResultNamesTheSelectionOperation(t *testing.T) {
	calls := identityDispatchCalls(t)
	for _, name := range []string{"selection-cancel", "keys-cancel"} {
		call := calls[name]
		current := false
		client := identityFixture(t, func(*http.Request) (*http.Response, error) {
			if current {
				return identityResponse(200, currentWire), nil
			}
			return identityResponse(200, strings.Replace(call.reply, selectionID, cancellationID, 1)), nil
		})
		identityCode(t, call.run(client, identityAddressedCurrent(t, client, &current)), "IDENTITY_RESULT_INVALID")
	}
}

func TestIdentityLifecycleApplyResultMatchesThePreparedAttempt(t *testing.T) {
	call := identityDispatchCalls(t)["lifecycle-apply"]
	for _, reply := range []string{
		strings.Replace(call.reply, `"state":"suspended"`, `"state":"active"`, 1),
		strings.Replace(call.reply, `"expectedVersion":0`, `"expectedVersion":1`, 1),
		strings.Replace(call.reply, `"environmentKind":"sandbox"`, `"environmentKind":"production"`, 1),
	} {
		current := false
		client := identityFixture(t, func(*http.Request) (*http.Response, error) {
			if current {
				return identityResponse(200, currentWire), nil
			}
			return identityResponse(200, reply), nil
		})
		identityCode(t, call.run(client, identityAddressedCurrent(t, client, &current)), "IDENTITY_RESULT_INVALID")
	}
}

func TestIdentityDispatchRefusesInvalidInputBeforeHTTP(t *testing.T) {
	calls := 0
	client := identityFixture(t, func(*http.Request) (*http.Response, error) {
		calls++
		return identityResponse(200, `{}`), nil
	})
	credential := CredentialRequest{AccessToken: "token"}
	ctx := context.Background()
	precondition := identityDecode[identity.Precondition](t, preconditionWire)
	production := identityDecode[identity.Precondition](t, strings.Replace(preconditionWire, `"environmentKind":"sandbox"`, `"environmentKind":"production"`, 1))
	target := identityDecode[identity.SelectionTarget](t, `{"mode":"device-owned"}`)
	keys := identityDecode[identity.ReplacementKeys](t, `[`+keyWire+`]`)
	attempt := identityDecode[identity.LifecycleAttempt](t, `{"operationId":"`+preparedID+`","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	subject, _ := identity.Text("private_CANARY")
	profile := "installed"
	lifecycleTarget := identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile}
	prepared, _ := identity.Text(preparedID)
	short, _ := identity.Text("bad id")
	var zero AddressedCurrent
	for name, run := range map[string]func() error{
		"selection-apply-id": func() error {
			_, err := client.SelectionApply(ctx, credential, identity.SelectionCommand{OperationID: "short", ExpectedConfigurationVersion: 1, Target: target, Precondition: precondition})
			return err
		},
		"selection-apply-environment": func() error {
			_, err := client.SelectionApply(ctx, credential, identity.SelectionCommand{OperationID: selectionID, ExpectedConfigurationVersion: 1, Target: target, Precondition: production})
			return err
		},
		"selection-status": func() error { _, err := client.SelectionStatus(ctx, credential, zero, selectionID); return err },
		"selection-cancel": func() error {
			_, err := client.SelectionCancel(ctx, credential, zero, cancellationID, selectionID)
			return err
		},
		"keys-replace-id": func() error {
			_, err := client.KeysReplace(ctx, credential, identity.KeysCommand{OperationID: "short", ExpectedConfigurationVersion: 1, Keys: keys, Precondition: precondition})
			return err
		},
		"keys-replace-environment": func() error {
			_, err := client.KeysReplace(ctx, credential, identity.KeysCommand{OperationID: selectionID, ExpectedConfigurationVersion: 1, Keys: keys, Precondition: production})
			return err
		},
		"keys-status": func() error { _, err := client.KeysStatus(ctx, credential, zero, selectionID); return err },
		"keys-cancel": func() error {
			_, err := client.KeysCancel(ctx, credential, zero, cancellationID, selectionID)
			return err
		},
		"lifecycle-operation": func() error { _, err := client.LifecycleOperation(ctx, credential, zero, prepared); return err },
		"lifecycle-apply": func() error {
			_, err := client.LifecycleApply(ctx, credential, zero, attempt, lifecycleTarget)
			return err
		},
		"lifecycle-resume":    func() error { _, err := client.LifecycleResume(ctx, credential, zero, prepared); return err },
		"lifecycle-resume-id": func() error { _, err := client.LifecycleResume(ctx, credential, zero, short); return err },
	} {
		identityCode(t, run(), "IDENTITY_INPUT_INVALID")
		if calls != 0 {
			t.Fatal("invalid input reached HTTP", name)
		}
	}
	// With real current evidence, an ID that is not a valid operation ID or
	// an apply that was not prepared still reaches no HTTP.
	current := false
	read := identityFixture(t, func(*http.Request) (*http.Response, error) {
		if current {
			return identityResponse(200, currentWire), nil
		}
		calls++
		return identityResponse(200, `{}`), nil
	})
	evidence := identityAddressedCurrent(t, read, &current)
	unprepared := attempt
	unprepared.OperationID, _ = identity.Text("fresh_read_001")
	account := lifecycleTarget
	account.Kind = "account"
	for name, run := range map[string]func() error{
		"selection-status-id": func() error { _, err := read.SelectionStatus(ctx, credential, evidence, "short"); return err },
		"selection-cancel-id": func() error {
			_, err := read.SelectionCancel(ctx, credential, evidence, "short", selectionID)
			return err
		},
		"keys-status-id": func() error { _, err := read.KeysStatus(ctx, credential, evidence, "x"); return err },
		"lifecycle-operation-id": func() error {
			_, err := read.LifecycleOperation(ctx, credential, evidence, short)
			return err
		},
		"lifecycle-apply-unprepared": func() error {
			_, err := read.LifecycleApply(ctx, credential, evidence, unprepared, lifecycleTarget)
			return err
		},
		"lifecycle-apply-target-kind": func() error {
			_, err := read.LifecycleApply(ctx, credential, evidence, attempt, account)
			return err
		},
	} {
		identityCode(t, run(), "IDENTITY_INPUT_INVALID")
		if calls != 0 {
			t.Fatal("invalid input reached HTTP", name)
		}
	}
}

func TestIdentityFactoryRejectsAChangedPublicAssociation(t *testing.T) {
	base, _ := identity.ParseControlBaseURL("https://console.example/api/cli")
	client, err := New(base.String(), &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"https://other.example/api/cli", "https://console.example/other-prefix"} {
		changed, _ := identity.ParseControlBaseURL(raw)
		address, err := NewIdentityAddress(changed, "sample", "sandbox")
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Identity(address)
		identityCode(t, err, "IDENTITY_CONTEXT_CHANGED")
	}
	if _, err := client.Identity(IdentityAddress{}); err == nil {
		t.Fatal("zero address accepted")
	}
	for _, input := range [][2]string{{"Sample", "sandbox"}, {"sample", "staging"}, {"", "sandbox"}, {strings.Repeat("a", 64), "sandbox"}} {
		if _, err := NewIdentityAddress(base, input[0], input[1]); err == nil {
			t.Fatal("invalid address accepted", input)
		}
	}
}

func TestIdentityPreparationInputOwnsAllTransientBounds(t *testing.T) {
	subject, _ := identity.Text("private_CANARY")
	profile := "installed"
	valid := LifecyclePreparationInput{Target: identity.LifecycleInputTarget{Kind: "subject", Subject: &subject, ProfileSource: &profile},
		State: "suspended", ExpectedLifecycleVersion: 0, Nonce: "AAAAAAAAAAAAAAAAAAAAAA"}
	if err := valid.validate(); err != nil {
		t.Fatal("positive transient fixture invalid", err)
	}
	for _, mutate := range []func(*LifecyclePreparationInput){
		func(v *LifecyclePreparationInput) {
			v.Nonce = "A"
		},
		func(v *LifecyclePreparationInput) {
			v.State = "deleted"
		},
		func(v *LifecyclePreparationInput) {
			v.ExpectedLifecycleVersion = identity.SafeInteger(identity.MaximumSafeInteger + 1)
		},
		func(v *LifecyclePreparationInput) {
			v.Target.Kind = "account"
		},
		func(v *LifecyclePreparationInput) {
			v.Target.ProfileSource = nil
		},
	} {
		copy := valid
		mutate(&copy)
		identityCode(t, copy.validate(), "IDENTITY_INPUT_INVALID")
	}
}
