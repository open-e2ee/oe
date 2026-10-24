package identity

import (
	"encoding/json"
	"strings"
	"testing"
)

const fingerprintWire = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const scopeWire = `{"environmentId":"env","environmentKind":"sandbox","projectId":"project","protocolProfile":"signal","relayScopeId":"relay_scope"}`
const preconditionWire = `{"publishableKey":"pk_public","recoveryGeneration":1,"scope":` + scopeWire + `}`
const completeWire = `{"configurationVersion":1,"admissionRevision":0,"verificationPolicyFingerprint":"` + fingerprintWire + `","identityProfile":` + configuredWire + `,"inventory":{"everAdmitted":false,"bindingCount":0,"historyCount":0,"pendingOperationId":null},"identityRecovery":null,"identityMigration":null,"mixedModeMigration":{"available":false},"selection":null,"providerValidation":{"state":"not_checked"},"applicationIntegration":{"state":"unverified"},"admissionReadiness":{"relayScopeId":"relay_scope","evidence":{"state":"current","checkedAtSeconds":0},"state":"ready","sourceGeneration":{"kind":"provision","admissionRevision":0,"policyFingerprint":"` + fingerprintWire + `"},"reason":null},"selectionOperation":null}`
const currentWire = `{"configuration":` + completeWire + `,"precondition":` + preconditionWire + `}`

func TestCompleteConfigurationHasNoLegacyFallback(t *testing.T) {
	v := mustDecode[CurrentContext](t, currentWire)
	if !v.Equal(roundTrip(t, v)) {
		t.Fatal("complete context changed")
	}
	assertRecursiveClosure(t, []byte(currentWire), func(data []byte) error { var v CurrentContext; return json.Unmarshal(data, &v) })
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(completeWire), &fields) != nil {
		t.Fatal("bad fixture")
	}
	for name := range fields {
		t.Run("missing "+name, func(t *testing.T) {
			copy := map[string]json.RawMessage{}
			for k, v := range fields {
				if k != name {
					copy[k] = v
				}
			}
			wire, _ := json.Marshal(copy)
			rejectJSON[CompleteConfiguration](t, wire)
		})
	}
	for _, change := range []struct{ old, new string }{
		{`"configurationVersion":1`, `"configurationVersion":0`}, {`"admissionRevision":0`, `"admissionRevision":-1`},
		{`"available":false`, `"available":true`}, {`"not_checked"`, `"verified"`}, {`"unverified"`, `"ready"`},
		{`"identityMigration":null`, `"identityMigration":{"manifestId":"summary","revision":1}`},
		{`"relayScopeId":"relay_scope","evidence"`, `"relayScopeId":"other_scope","evidence"`},
		{`"policyFingerprint":"` + fingerprintWire + `"`, `"policyFingerprint":"BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`},
	} {
		rejectJSON[CurrentContext](t, []byte(strings.Replace(currentWire, change.old, change.new, 1)))
	}
	if _, e := json.Marshal(CompleteConfiguration{}); e == nil {
		t.Fatal("invalid constructed config encoded")
	}
}
func TestAllReadinessDiscriminants(t *testing.T) {
	for _, state := range []string{"absent", "unready", "pending", "ready", "unknown"} {
		t.Run(state, func(t *testing.T) {
			v := mustDecode[CompleteConfiguration](t, completeWire)
			r := &v.AdmissionReadiness
			r.State = state
			switch state {
			case "absent":
				r.SourceGeneration = nil
				r.Reason = new("missing_authority")
			case "unready":
				r.Reason = new("not_ready")
			case "pending":
				r.Reason = new("release_pending")
			case "unknown":
				r.SourceGeneration = nil
				r.Evidence.State = "unknown"
				r.Reason = new("owner_disagreement")
			}
			if v.Validate() != nil {
				t.Fatal("valid readiness refused")
			}
			roundTrip(t, v)
			broken, e := v.Clone()
			if e != nil {
				t.Fatal(e)
			}
			broken.AdmissionReadiness.Evidence.State = "bad"
			if broken.Validate() == nil {
				t.Fatal("wrong evidence accepted")
			}
		})
	}
	v := mustDecode[CompleteConfiguration](t, completeWire)
	v.AdmissionReadiness.SourceGeneration.Kind = "cutover"
	v.AdmissionReadiness.SourceGeneration.ReceiptEpoch = new(SafeInteger(1024))
	roundTrip(t, v)
	*v.AdmissionReadiness.SourceGeneration.ReceiptEpoch = 1025
	if v.Validate() == nil {
		t.Fatal("receipt epoch overflow accepted")
	}
	v = mustDecode[CompleteConfiguration](t, completeWire)
	v.AdmissionReadiness.SourceGeneration.AdmissionRevision = 1
	if v.Validate() == nil {
		t.Fatal("generation revision mismatch accepted")
	}
}
func TestCompleteMigrationReferencesAndSourceEquality(t *testing.T) {
	source := mustDecode[InstalledProfile](t, configuredWire)
	target := mustDecode[InstalledProfile](t, strings.Replace(configuredWire, "members.example", "target.example", 1))
	configuration := MigrationConfiguration{Version: 1, SourceProfile: source, TargetProfile: target, PreparationTTLSeconds: 60, RollbackWindowSeconds: 2592000}
	migration := CompleteMigration{ManifestID: mustText(t, "legacy_"+fingerprintWire), Revision: 0, Configuration: configuration}
	roundTrip(t, migration)
	migration.Revision = 1
	if migration.Validate() == nil {
		t.Fatal("legacy revision accepted")
	}
	migration.Revision = 0
	configuration.ManifestID = new("manifest_v1")
	configuration.Revision = new(SafeInteger(1))
	migration.Configuration = configuration
	migration.ManifestID = mustText(t, "manifest_v1")
	migration.Revision = 1
	roundTrip(t, migration)
	v := mustDecode[CompleteConfiguration](t, completeWire)
	v.IdentityMigration = &migration
	roundTrip(t, v)
	v.IdentityMigration.Configuration.SourceProfile = target
	if v.Validate() == nil {
		t.Fatal("migration source differs from installed profile")
	}
	configuration = MigrationConfiguration{Version: 2, SourceProfile: source, TargetProfile: mustDecode[InstalledProfile](t, deviceInstalledWire), PreparationTTLSeconds: 86400, RollbackWindowSeconds: 60, ManifestID: new("manifest_v2"), Revision: new(SafeInteger(2)), SourceRecovery: &RecoveryPolicy{Kind: "provider", RequiredAssurance: new("step-up")}, TargetRecovery: &RecoveryPolicy{Kind: "none"}}
	migration = CompleteMigration{ManifestID: mustText(t, "manifest_v2"), Revision: 2, Configuration: configuration}
	roundTrip(t, migration)
	migration.Configuration.SourceRecovery.Kind = "none"
	migration.Configuration.SourceRecovery.RequiredAssurance = nil
	if migration.Validate() == nil {
		t.Fatal("recovery/device correspondence ignored")
	}
}
func TestScopeAndPublicPreconditionBounds(t *testing.T) {
	v := mustDecode[Precondition](t, preconditionWire)
	v.Scope.EnvironmentID = TextFromUnits([]uint16{0xd800})
	roundTrip(t, v)
	v.Scope.RelayScopeID = TextFromUnits([]uint16{0xd800})
	if v.Validate() == nil {
		t.Fatal("precondition accepted non-ASCII scope ID")
	}
	if v.Scope.Validate() != nil {
		t.Fatal("lifecycle text bound narrowed to precondition bound")
	}
	v = mustDecode[Precondition](t, preconditionWire)
	v.RecoveryGeneration = 0
	if v.Validate() == nil {
		t.Fatal("zero recovery accepted")
	}
	for _, n := range []int{1, 255, 256} {
		v := mustDecode[Precondition](t, preconditionWire)
		v.PublishableKey = strings.Repeat("p", n)
		if (v.Validate() == nil) != (n <= 255) {
			t.Fatal("public identifier bound changed")
		}
	}
	copied, e := mustDecode[CurrentContext](t, currentWire).Clone()
	if e != nil {
		t.Fatal(e)
	}
	copied.Precondition.Scope.EnvironmentID = mustText(t, "changed")
	if copied.Equal(mustDecode[CurrentContext](t, currentWire)) {
		t.Fatal("scope association ignored")
	}
}
