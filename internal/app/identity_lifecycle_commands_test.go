package app

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

func TestPublicLifecycleTargetAndDryRunRemainPrivateReadOnly(t *testing.T) {
	for _, action := range []string{"target", "suspend", "activate"} {
		t.Run(action, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.dependencies.In = strings.NewReader(publicTargetWire)
			args := []string{"identity", "lifecycle", action, "--target-stdin"}
			if action != "target" {
				args = append(args, "--dry-run")
			}
			exit, out, stderr := f.run(t, args...)
			if exit != 0 || f.count("current") != 1 || f.count("target") != 1 {
				t.Fatal("target read did not qualify", exit, out, stderr)
			}
			if strings.Contains(out+stderr, "PRIVATE_TARGET_SENTINEL") || strings.Contains(out, `"operationId"`) || strings.Contains(out, `"scope"`) {
				t.Fatal("private target or internal context escaped")
			}
			result := decodeEvent(t, []byte(out))
			if result.Data["applicationKind"] != "unbound-subject" || result.Data["serviceReadiness"] != "unverified" {
				t.Fatal("unbound target acquired Account service authority")
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicLifecycleAuthorityPrecedesPrivateInput(t *testing.T) {
	for _, action := range []string{"target", "suspend", "activate"} {
		t.Run(action, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.denyCurrent = true
			f.dependencies.In = unreadable{t}
			exit, out, stderr := f.run(t, "identity", "lifecycle", action, "--target-stdin")
			if exit != exitFailure || f.count("target") != 0 || !strings.Contains(out, `"code":"IDENTITY_CONTROL_DENIED"`) {
				t.Fatal("authority refusal did not precede private input", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
}

func TestPublicLifecycleClosedInputAndAvailabilityBounds(t *testing.T) {
	invalid := map[string]string{
		"null":           `null`,
		"unknown-field":  `{"kind":"subject","subject":"PRIVATE_TARGET_SENTINEL","profileSource":"installed","token":"PRIVATE_TOKEN_SENTINEL"}`,
		"null-subject":   `{"kind":"subject","subject":null,"profileSource":"installed"}`,
		"unknown-source": `{"kind":"subject","subject":"PRIVATE_TARGET_SENTINEL","profileSource":"other"}`,
		"crossed-target": `{"kind":"account","accountAddress":"PRIVATE_TARGET_SENTINEL","subject":"other","profileSource":"installed"}`,
		"trailing-data":  publicTargetWire + `{}`,
		"limit-plus-one": strings.Repeat(" ", 100001),
	}
	for name, wire := range invalid {
		t.Run(name, func(t *testing.T) {
			f := publicIdentityTestFixture(t, "")
			f.dependencies.In = strings.NewReader(wire)
			exit, out, stderr := f.run(t, "identity", "lifecycle", "suspend", "--target-stdin", "--dry-run")
			if exit != exitUsage || f.count("target") != 0 || strings.Contains(out+stderr, "PRIVATE_") {
				t.Fatal("invalid private target reached read or output", exit, out, stderr)
			}
			f.requireNoMutation(t)
		})
	}
	for _, wire := range []string{
		publicTargetWire,
		`{"kind":"account","accountAddress":"PRIVATE_ACCOUNT_SENTINEL"}`,
		`{"kind":"subject","subject":"PRIVATE_TARGET_SENTINEL","profileSource":"migration-target"}`,
	} {
		padding := 100000 - len(wire)
		value, err := readIdentityTarget(strings.NewReader(wire + strings.Repeat(" ", padding)))
		if err != nil || value.Validate() != nil {
			t.Fatal("exact private input availability bound refused", err)
		}
	}
}

func TestPublicLifecycleTargetEvidenceExcludesOnlyFreshReadCorrelation(t *testing.T) {
	approved := executionDecode[identity.TargetObservation](t, publicObservationWire)
	current, _ := approved.Clone()
	current.OperationID = identity.TextFromUnits([]uint16{'r', 'e', 'a', 'd', '_', 't', 'w', 'o'})
	if !sameIdentityTargetEvidence(approved, current) {
		t.Fatal("independent read correlation became target authority")
	}
	for _, name := range []string{"scope", "target", "version", "state", "head-presence", "application-kind", "application-state", "application-operation"} {
		t.Run(name, func(t *testing.T) {
			left, _ := approved.Clone()
			right, _ := approved.Clone()
			right.OperationID = current.OperationID
			switch name {
			case "scope":
				right.Scope.ProjectID = identity.TextFromUnits([]uint16{'o', 't', 'h', 'e', 'r'})
			case "target":
				right.Target.Kind = "account"
			case "version":
				right.ObservedVersion = 1
			case "state":
				right.ObservedState = "suspended"
			case "head-presence":
				right.CurrentHead = &identity.LifecycleHead{Scope: right.Scope, Target: right.Target, OperationID: identity.TextFromUnits([]uint16{'e', 'x', 'a', 'c', 't'}), Version: 1, State: "active"}
			case "application-kind":
				right.Application, _ = identity.BoundLifecycleApplication("active", nil)
			case "application-state":
				left.Application, _ = identity.BoundLifecycleApplication("active", nil)
				right.Application, _ = identity.BoundLifecycleApplication("suspended", nil)
			case "application-operation":
				left.Application, _ = identity.BoundLifecycleApplication("active", nil)
				status := publicLifecycleResult(t, "converged")
				right.Application, _ = identity.BoundLifecycleApplication("active", &status)
			}
			if left.Validate() != nil || right.Validate() != nil {
				t.Fatal("invalid evidence mutation fixture")
			}
			if sameIdentityTargetEvidence(left, right) {
				t.Fatal("approved target evidence changed silently", name)
			}
			leftBefore, _ := json.Marshal(left)
			rightBefore, _ := json.Marshal(right)
			_ = sameIdentityTargetEvidence(left, right)
			leftAfter, _ := json.Marshal(left)
			rightAfter, _ := json.Marshal(right)
			if string(leftBefore) != string(leftAfter) || string(rightBefore) != string(rightAfter) {
				t.Fatal("comparison rewrote observed evidence")
			}
		})
	}
}

func TestPublicLifecycleBoundObservationDoesNotLeakAccountInput(t *testing.T) {
	observation := executionDecode[identity.TargetObservation](t, publicObservationWire)
	observation.Application, _ = identity.BoundLifecycleApplication("suspended", nil)
	if observation.Application.Kind() != "bound-account" {
		t.Fatal("bound observation fixture failed")
	}
	bound, err := observation.Application.Bound()
	if err != nil || bound.EffectiveState != "suspended" {
		t.Fatal("effective Account state was lost")
	}
	observation.ObservedState = "active"
	if observation.ObservedState == bound.EffectiveState {
		t.Fatal("target and Account states were conflated")
	}
}

func TestPublicLifecycleReadErrorsContainNoInputBytes(t *testing.T) {
	_, err := readIdentityTarget(io.LimitReader(strings.NewReader(`{"kind":"PRIVATE_TARGET_SENTINEL"}`), 100000))
	if err == nil || strings.Contains(err.Error(), "PRIVATE_TARGET_SENTINEL") {
		t.Fatal("private parser error leaked input")
	}
}
