package identityattempt

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/identity"
)

func base(t *testing.T, raw string) identity.ControlBaseURL {
	t.Helper()
	value, err := identity.ParseControlBaseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func slot(t *testing.T) Slot {
	t.Helper()
	value, err := NewSlot(base(t, "https://console.open-e2ee.dev/api/cli"), "org_1", "chat", "sandbox", Selection)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSlotEncodingAndFilenameGolden(t *testing.T) {
	value := slot(t)
	const wire = `["open-e2ee.identity-attempt-slot",1,"https://console.open-e2ee.dev/api/cli","org_1","chat","sandbox","selection"]`
	encoded, err := EncodeSlot(value)
	if err != nil || string(encoded) != wire || bytes.HasSuffix(encoded, []byte("\n")) {
		t.Fatalf("slot wire: %s %v", encoded, err)
	}
	decoded, err := DecodeSlot(encoded)
	if err != nil || !decoded.Equal(value) {
		t.Fatal("slot encoding did not round-trip")
	}
	stem, err := value.FilenameStem()
	if err != nil || stem != "c39db53cc39ebc193c3a2011b4b6b752f9a8c899401289076ad49ac0e7cc029e" {
		t.Fatalf("slot filename: %q %v", stem, err)
	}
	encoded[0] = 'x'
	if !decoded.Equal(value) || value.ControlBase().String() != "https://console.open-e2ee.dev/api/cli" || value.OrganizationID() != "org_1" || value.ProjectSlug() != "chat" || value.Environment() != "sandbox" || value.Kind() != Selection {
		t.Fatal("slot ownership or accessors changed")
	}
}

func TestSlotEquivalentBaseAndDistinctPublicCoordinates(t *testing.T) {
	original := slot(t)
	equivalent, err := NewSlot(base(t, "HTTPS://CONSOLE.OPEN-E2EE.DEV:443/api//cli/"), "org_1", "chat", "sandbox", Selection)
	if err != nil || !equivalent.Equal(original) {
		t.Fatal("equivalent base selected another slot")
	}
	a, _ := original.FilenameStem()
	b, _ := equivalent.FilenameStem()
	if a != b {
		t.Fatal("equivalent slot selected another filename")
	}
	for _, input := range []struct {
		address, organization, project, environment string
		kind                                        Kind
	}{
		{"https://console.open-e2ee.dev/api/other", "org_1", "chat", "sandbox", Selection},
		{"https://console.open-e2ee.dev/API/cli", "org_1", "chat", "sandbox", Selection},
		{"https://other.example/api/cli", "org_1", "chat", "sandbox", Selection},
		{"https://console.open-e2ee.dev/api/cli", "org_2", "chat", "sandbox", Selection},
		{"https://console.open-e2ee.dev/api/cli", "ORG_1", "chat", "sandbox", Selection},
		{"https://console.open-e2ee.dev/api/cli", "org_1", "other", "sandbox", Selection},
		{"https://console.open-e2ee.dev/api/cli", "org_1", "chat", "production", Selection},
		{"https://console.open-e2ee.dev/api/cli", "org_1", "chat", "sandbox", KeysOnly},
		{"https://console.open-e2ee.dev/api/cli", "org_1", "chat", "sandbox", Lifecycle},
	} {
		other, err := NewSlot(base(t, input.address), input.organization, input.project, input.environment, input.kind)
		if err != nil || other.Equal(original) {
			t.Fatal("distinct public coordinates merged")
		}
		otherStem, err := other.FilenameStem()
		if err != nil || a == otherStem {
			t.Fatal("finite distinct-coordinate fixture collided")
		}
	}
}

func TestSlotRefusesInvalidConstructionAndZeroEncoding(t *testing.T) {
	valid := slot(t)
	if _, err := NewSlot(valid.base, valid.organization, strings.Repeat("a", 63), valid.environment, valid.kind); err != nil {
		t.Fatal("rejected the maintained project-slug length boundary")
	}
	for _, change := range []func(*Slot){
		func(v *Slot) { v.base = identity.ControlBaseURL{} },
		func(v *Slot) { v.organization = "" },
		func(v *Slot) { v.organization = string([]byte{0xff}) },
		func(v *Slot) { v.project = "" },
		func(v *Slot) { v.project = "Chat" },
		func(v *Slot) { v.project = "chat--app" },
		func(v *Slot) { v.project = "-chat" },
		func(v *Slot) { v.project = "chat-" },
		func(v *Slot) { v.project = "chat/app" },
		func(v *Slot) { v.project = strings.Repeat("a", 64) },
		func(v *Slot) { v.environment = "" },
		func(v *Slot) { v.environment = "local" },
		func(v *Slot) { v.environment = "Sandbox" },
		func(v *Slot) { v.kind = "" },
		func(v *Slot) { v.kind = "keys" },
		func(v *Slot) { v.kind = "Lifecycle" },
	} {
		bad := valid
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted invalid slot")
		}
		if _, err := NewSlot(bad.base, bad.organization, bad.project, bad.environment, bad.kind); !errors.Is(err, ErrSlot) {
			t.Fatal("constructor did not own the complete slot validation")
		}
		if _, err := EncodeSlot(bad); !errors.Is(err, ErrSlot) {
			t.Fatal("encoded invalid slot")
		}
	}
	if (Slot{}).Equal(Slot{}) {
		t.Fatal("zero slots cannot establish an association")
	}
	if _, err := (Slot{}).FilenameStem(); !errors.Is(err, ErrSlot) {
		t.Fatal("zero slot produced a filename")
	}
}

func TestSlotDecoderClosesTupleAndPreservesFailedReceiver(t *testing.T) {
	value := slot(t)
	encoded, _ := EncodeSlot(value)
	for _, data := range [][]byte{
		[]byte(`null`), []byte(`{}`), []byte(`[]`), []byte(`1`),
		bytes.Replace(encoded, []byte(`,1,`), []byte(`,2,`), 1),
		bytes.Replace(encoded, []byte(`,1,`), []byte(`,1.0,`), 1),
		bytes.Replace(encoded, []byte(`,1,`), []byte(`,"1",`), 1),
		bytes.Replace(encoded, []byte(`identity-attempt-slot`), []byte(`identity-attempt-Slot`), 1),
		bytes.Replace(encoded, []byte(`https://console.open-e2ee.dev`), []byte(`HTTPS://CONSOLE.OPEN-E2EE.DEV`), 1),
		bytes.Replace(encoded, []byte(`"org_1"`), []byte(`null`), 1),
		bytes.Replace(encoded, []byte(`"org_1"`), []byte(`{"id":"org_1","id":"org_2"}`), 1),
		bytes.Replace(encoded, []byte(`"org_1"`), []byte(`"\ud800"`), 1),
		bytes.Replace(encoded, []byte(`"org_1"`), []byte(`"\udc00"`), 1),
		bytes.Replace(encoded, []byte(`org_1`), []byte{0xff}, 1),
		append(bytes.Clone(encoded), []byte(` null`)...),
		append(bytes.Clone(encoded[:len(encoded)-1]), []byte(`,"extra"]`)...),
	} {
		prior := value
		if value.UnmarshalJSON(data) == nil || !value.Equal(prior) {
			t.Fatal("invalid tuple changed the prior receiver")
		}
		if _, err := DecodeSlot(data); !errors.Is(err, ErrSlot) {
			t.Fatal("invalid tuple escaped the owning decoder")
		}
	}
	spaced := []byte(" \n" + strings.ReplaceAll(string(encoded), ",", ", ") + " \n")
	if decoded, err := DecodeSlot(spaced); err != nil || !decoded.Equal(value) {
		t.Fatal("formatting changed a valid slot value")
	}
}

func TestSlotOrganizationPreservesScalarTextWithoutInventedNormalization(t *testing.T) {
	for _, organization := range []string{"org_<>&", "org_é", "org_e\u0301", "org_😀", "org_\x00", strings.Repeat("x", 1024)} {
		value, err := NewSlot(base(t, "https://control.example/api/cli"), organization, "chat", "production", Lifecycle)
		if err != nil {
			t.Fatal("narrowed the maintained nonempty session Organization ID field")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeSlot(encoded)
		if err != nil || !decoded.Equal(value) || decoded.OrganizationID() != organization {
			t.Fatal("Organization ID text changed")
		}
	}
	composed, err := NewSlot(base(t, "https://control.example/api/cli"), "org_é", "chat", "production", Lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := NewSlot(base(t, "https://control.example/api/cli"), "org_e\u0301", "chat", "production", Lifecycle)
	if err != nil || composed.Equal(decomposed) {
		t.Fatal("normalized distinct Organization ID Unicode forms")
	}
}
