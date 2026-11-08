package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// v2Sample is sample in the deprecated config-v2.json form.
const v2Sample = header + `export default defineConfig({
  product: "signal-relay",
  project: "secure-chat",
  relay: {
    deliveryRetention: "30d",
    attachmentRetention: "30d",
  },
  environments: {
    sandbox: {
      relay: { deliveryRetention: "1d", attachmentRetention: "1d" },
    },
    production: { relay: { relayReceipts: false } },
  },
});
`

// v3Sample is v2Sample in the config-v3.json form.
var v3Sample = strings.NewReplacer("relayReceipts", "signalRelayReceipts", "relay:", "signalRelay:").Replace(v2Sample)

func TestLoadReadsBothConfigForms(t *testing.T) {
	v2, err := Load(writeConfig(t, v2Sample))
	if err != nil {
		t.Fatal(err)
	}
	v3, err := Load(writeConfig(t, v3Sample))
	if err != nil {
		t.Fatal(err)
	}
	if v2.Format != FormatV2 || v3.Format != FormatV3 {
		t.Fatalf("the formats are %v and %v, want FormatV2 and FormatV3", v2.Format, v3.Format)
	}
	v2.Format = FormatV3
	if !reflect.DeepEqual(v2, v3) {
		t.Fatalf("the v2 file gave %#v, the v3 file gave %#v", v2, v3)
	}
	policy, err := v2.SignalProtocolRelayPolicyFor("production")
	if err != nil || policy.SignalProtocolRelayReceipts || policy.DeliveryRetention != "30d" {
		t.Fatalf("the v2 production policy is %#v, %v", policy, err)
	}
	policy, err = v2.SignalProtocolRelayPolicyFor("sandbox")
	if err != nil || !policy.SignalProtocolRelayReceipts || policy.DeliveryRetention != "1d" {
		t.Fatalf("the v2 sandbox policy is %#v, %v", policy, err)
	}
}

func TestLoadRefusesBothPolicyKeys(t *testing.T) {
	both := strings.Replace(v3Sample, "  signalRelay: {\n", "  relay: { deliveryRetention: \"7d\", attachmentRetention: \"7d\" },\n  signalRelay: {\n", 1)
	failure := requireCode(t, loadError(writeConfig(t, both)), "CONFIG_INVALID")
	requireFieldError(t, failure, "relay", "not allowed with signalRelay")
	path := writeConfig(t, both)
	requireCode(t, CheckEdit(path, Change{Path: []string{"project"}, Value: "renamed"}), "CONFIG_INVALID")
	requireFile(t, path, both)
}

func TestLoadRefusesMixedConfigForms(t *testing.T) {
	for name, test := range map[string]struct{ source, path string }{
		"v3 file with an old environment key": {
			strings.Replace(v3Sample, "      signalRelay: { deliveryRetention", "      relay: { deliveryRetention", 1),
			"environments.sandbox.relay",
		},
		"v2 file with a new environment key": {
			strings.Replace(v2Sample, "      relay: { deliveryRetention", "      signalRelay: { deliveryRetention", 1),
			"environments.sandbox.signalRelay",
		},
		"v3 file with the old receipts key": {
			strings.Replace(v3Sample, "signalRelayReceipts", "relayReceipts", 1),
			"environments.production.signalRelay.relayReceipts",
		},
		"v2 file with the new receipts key": {
			strings.Replace(v2Sample, "relayReceipts", "signalRelayReceipts", 1),
			"environments.production.relay.signalRelayReceipts",
		},
	} {
		t.Run(name, func(t *testing.T) {
			failure := requireCode(t, loadError(writeConfig(t, test.source)), "CONFIG_INVALID")
			requireFieldError(t, failure, test.path, "is not allowed")
		})
	}
}

func TestErrorPathsUseTheKeysOfTheFile(t *testing.T) {
	for name, test := range map[string]struct{ source, path, fragment string }{
		"v2 managed maximum": {
			strings.Replace(v2Sample, `relay: { deliveryRetention: "1d"`, `relay: { deliveryRetention: "14d"`, 1),
			"environments.sandbox.relay.deliveryRetention", "7d",
		},
		"v3 managed maximum": {
			strings.Replace(v3Sample, `signalRelay: { deliveryRetention: "1d"`, `signalRelay: { deliveryRetention: "14d"`, 1),
			"environments.sandbox.signalRelay.deliveryRetention", "7d",
		},
		"v2 receipts type": {
			strings.Replace(v2Sample, "relayReceipts: false", `relayReceipts: "off"`, 1),
			"environments.production.relay.relayReceipts", "",
		},
		"v3 receipts type": {
			strings.Replace(v3Sample, "signalRelayReceipts: false", `signalRelayReceipts: "off"`, 1),
			"environments.production.signalRelay.signalRelayReceipts", "",
		},
		"v2 missing policy": {
			strings.Replace(v2Sample, "  relay: {\n    deliveryRetention: \"30d\",\n    attachmentRetention: \"30d\",\n  },\n", "", 1),
			"signalRelay", "is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			failure := requireCode(t, loadError(writeConfig(t, test.source)), "CONFIG_INVALID")
			requireFieldError(t, failure, test.path, test.fragment)
		})
	}
}

func TestEditOfAV2FileKeepsTheV2Keys(t *testing.T) {
	path := writeConfig(t, v2Sample)
	changes := []Change{
		{Path: []string{"signalRelay", "signalRelayReceipts"}, Value: false},
		{Path: []string{"environments", "sandbox", "signalRelay", "deliveryRetention"}, Value: "3d"},
		{Path: []string{"environments", "production"}, Value: map[string]any{"signalRelay": map[string]any{"signalRelayReceipts": true, "attachmentRetention": "7d"}}},
	}
	before, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := Apply(before, changes...)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckEdit(path, changes...); err != nil {
		t.Fatal(err)
	}
	if err := Edit(path, changes...); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "signalRelay") {
		t.Fatalf("the edit of a v2 file wrote a v3 key:\n%s", contents)
	}
	for _, want := range []string{"    relayReceipts: false,\n", `deliveryRetention: "3d"`, `production: { relay: { relayReceipts: true, attachmentRetention: "7d" } }`} {
		if !strings.Contains(string(contents), want) {
			t.Fatalf("the edited file has no %q:\n%s", want, contents)
		}
	}
	edited, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if edited.Format != FormatV2 || !reflect.DeepEqual(applied, edited) {
		t.Fatalf("Apply gave %#v, Edit wrote %#v", applied, edited)
	}
	// A second edit with the same changes holds and writes nothing.
	if err := Edit(path, changes...); err != nil {
		t.Fatal(err)
	}
	requireFile(t, path, string(contents))
}

func TestEditOfAV2FileNamesTheV2PathOfAComputedValue(t *testing.T) {
	source := strings.Replace(v2Sample, `relay: { deliveryRetention: "1d", attachmentRetention: "1d" },`,
		`relay: { deliveryRetention: short, attachmentRetention: "1d" },`, 1)
	source = strings.Replace(source, "export default", "const short = \"1d\";\nexport default", 1)
	path := writeConfig(t, source)
	failure := requireCode(t, Edit(path, Change{Path: []string{"environments", "sandbox", "signalRelay", "deliveryRetention"}, Value: "3d"}), "CONFIG_EDIT_REQUIRED")
	edits, ok := failure.Data["edits"].([]ManualEdit)
	if !ok || len(edits) != 1 || edits[0].Path != "environments.sandbox.relay.deliveryRetention" {
		t.Fatalf("the edits are %#v", failure.Data["edits"])
	}
	requireFile(t, path, source)
}

func TestCreateWritesTheV3Keys(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	value := New("secure-chat")
	value.Format = FormatV2
	value.Environments.Production.SignalProtocolRelay = &SignalProtocolRelayOverride{SignalProtocolRelayReceipts: new(false)}
	if err := Create(path, value); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\n  signalRelay: {\n", "\n    signalRelayReceipts: true,\n", "      signalRelay: {\n        signalRelayReceipts: false,\n"} {
		if !strings.Contains(string(contents), want) {
			t.Fatalf("the new file has no %q:\n%s", want, contents)
		}
	}
	if strings.Contains(string(contents), " relay:") || strings.Contains(string(contents), " relayReceipts:") {
		t.Fatalf("the new file has a v2 key:\n%s", contents)
	}
	loaded, err := Load(path)
	if err != nil || loaded.Format != FormatV3 {
		t.Fatalf("the new file loads as %#v, %v", loaded, err)
	}
}

func TestFormatRenamesOnlyPolicyKeys(t *testing.T) {
	if got := FormatV2.Path("environments", "sandbox", "signalRelay", "signalRelayReceipts"); got != "environments.sandbox.relay.relayReceipts" {
		t.Fatalf("FormatV2.Path gave %s", got)
	}
	if got := FormatV3.Path("environments", "sandbox", "signalRelay", "signalRelayReceipts"); got != "environments.sandbox.signalRelay.signalRelayReceipts" {
		t.Fatalf("FormatV3.Path gave %s", got)
	}
	value := map[string]any{"environments": map[string]any{"sandbox": map[string]any{
		"identity":    map[string]any{"signalRelay": "kept"},
		"signalRelay": map[string]any{"signalRelayReceipts": true},
	}}}
	want := map[string]any{"environments": map[string]any{"sandbox": map[string]any{
		"identity": map[string]any{"signalRelay": "kept"},
		"relay":    map[string]any{"relayReceipts": true},
	}}}
	if got := renameKeys(value, nil, v3Names); !reflect.DeepEqual(got, want) {
		t.Fatalf("renameKeys gave %#v", got)
	}
	if got := renameKeys(want, nil, v2Names); !reflect.DeepEqual(got, value) {
		t.Fatalf("renameKeys back gave %#v", got)
	}
}
