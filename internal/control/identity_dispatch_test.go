package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
	"github.com/open-e2ee/oe/internal/identityattempt"
)

// These tests prove admission refusal only. Real permit success and lifecycle
// preparation use the external identityattempt_test composition owner.
func TestIdentityNineMethodsRefuseManufacturedPermitsBeforeHTTP(t *testing.T) {
	for _, permit := range []*identityattempt.DispatchPermit{nil, {}} {
		for _, name := range []string{"selection-apply", "selection-status", "selection-cancel", "keys-replace", "keys-status", "keys-cancel", "lifecycle-operation", "lifecycle-apply", "lifecycle-resume"} {
			t.Run(name, func(t *testing.T) {
				calls := 0
				kind := identityattempt.Selection
				if name[0:4] == "keys" {
					kind = identityattempt.KeysOnly
				}
				if name[0:4] == "life" {
					kind = identityattempt.Lifecycle
				}
				client := identityFixture(t, kind, func(*http.Request) (*http.Response, error) {
					calls++
					return identityResponse(200, `{}`), nil
				})
				credential := CredentialRequest{AccessToken: "token"}
				ctx := context.Background()
				var err error
				switch name {
				case "selection-apply":
					_, err = client.SelectionApply(ctx, credential, permit)
				case "selection-status":
					_, err = client.SelectionStatus(ctx, credential, permit)
				case "selection-cancel":
					_, err = client.SelectionCancel(ctx, credential, permit)
				case "keys-replace":
					_, err = client.KeysReplace(ctx, credential, permit)
				case "keys-status":
					_, err = client.KeysStatus(ctx, credential, permit)
				case "keys-cancel":
					_, err = client.KeysCancel(ctx, credential, permit)
				case "lifecycle-operation":
					_, err = client.LifecycleOperation(ctx, credential, AddressedCurrent{}, permit)
				case "lifecycle-apply":
					_, err = client.LifecycleApply(ctx, credential, AddressedCurrent{}, permit, identity.LifecycleInputTarget{})
				case "lifecycle-resume":
					_, err = client.LifecycleResume(ctx, credential, AddressedCurrent{}, permit)
				}
				if err == nil || calls != 0 {
					t.Fatal("manufactured occupied permit reached dispatch")
				}
			})
		}
	}
}

func TestIdentityLifecycleReplyRejectsZeroAndWireManufacture(t *testing.T) {
	if _, err := (LifecycleReply{}).Receipt(); err == nil {
		t.Fatal("zero reply supplied receipt")
	}
	if _, err := (LifecycleReply{}).Scope(); err == nil {
		t.Fatal("zero reply supplied scope")
	}
	if _, err := json.Marshal(LifecycleReply{}); err == nil {
		t.Fatal("reply provenance serialized")
	}
	if json.Unmarshal([]byte(`{}`), &LifecycleReply{}) == nil {
		t.Fatal("wire manufactured reply provenance")
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
		slot, err := identityattempt.NewSlot(changed, "org_actual", "sample", "sandbox", identityattempt.Selection)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Identity(slot)
		identityCode(t, err, "IDENTITY_CONTEXT_CHANGED")
	}
	if _, err := client.Identity(identityattempt.Slot{}); err == nil {
		t.Fatal("zero slot accepted")
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

func TestIdentityOpaqueReplyRetainsActualSourceAndScope(t *testing.T) {
	client := identityFixture(t, identityattempt.Lifecycle, nil)
	command := identityDecode[identity.LifecycleAttempt](t, `{"operationId":"`+preparedID+`","targetKind":"subject","expectedLifecycleVersion":0,"state":"suspended"}`)
	status := identityDecode[identity.LifecycleStatus](t, `{"operation":{"scope":`+scopeWire+`,"target":{"kind":"subject"},"operationId":"`+preparedID+`","expectedVersion":0},"version":1,"state":"suspended","currentHead":null,"effectiveState":"active","status":"pending_owners","supersededBy":null,"requiredMailboxes":2,"preparedMailboxes":0,"activatedMailboxes":0}`)
	for _, source := range []identity.ReceiptSource{identity.LifecycleStatusSource, identity.LifecycleApplySource, identity.LifecycleResumeSource} {
		receipt, err := identity.NewLifecycleReceipt(command, status.Operation.Scope, source, status)
		if err != nil {
			t.Fatal("source fixture invalid", err)
		}
		reply := LifecycleReply{receipt: receipt, scope: status.Operation.Scope, slot: client.slot}
		actual, err := reply.Receipt()
		if err != nil {
			t.Fatal(err)
		}
		scope, err := reply.Scope()
		if err != nil || !scope.Equal(status.Operation.Scope) || identity.ClassifyLifecycleReceipt(command, scope, actual) != identity.ReceiptPending {
			t.Fatal("reply lost owning receipt or independent scope")
		}
		scope.EnvironmentKind = "production"
		again, err := reply.Scope()
		if err != nil || again.EnvironmentKind != "sandbox" {
			t.Fatal("reply scope aliased")
		}
	}
}
