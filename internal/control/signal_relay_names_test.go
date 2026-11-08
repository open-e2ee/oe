package control

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/open-e2ee/oe/internal/wirename"
)

// signalRelayReader is one response type that reads a field under its old
// Console name or its Signal Protocol Relay name. value and other are two
// JSON values of the field, and want is the Go value of value. read decodes a
// response and returns the field.
type signalRelayReader struct {
	name         string
	pair         wirename.Pair
	value, other string
	want         any
	read         func([]byte) (any, error)
}

func decodeAs[T any](field func(T) any) func([]byte) (any, error) {
	return func(data []byte) (any, error) {
		var value T
		err := json.Unmarshal(data, &value)
		return field(value), err
	}
}

const (
	urlA = "https://signal-relay.example/a"
	urlB = `"https://signal-relay.example/b"`
)

var signalRelayReaders = []signalRelayReader{
	{
		"Bootstrap.SandboxSignalProtocolRelayURL",
		wirename.Pair{Name: "sandboxRelayUrl", Alias: "sandboxSignalProtocolRelayUrl"}, `"` + urlA + `"`, urlB, urlA,
		decodeAs(func(v Bootstrap) any { return v.SandboxSignalProtocolRelayURL }),
	},
	{
		"Deployment.SignalProtocolRelayURL",
		wirename.Pair{Name: "relayUrl", Alias: "signalRelayUrl"}, `"` + urlA + `"`, urlB, urlA,
		decodeAs(func(v Deployment) any { return v.SignalProtocolRelayURL }),
	},
	{
		"ProjectEnvironment.SignalProtocolRelayURL",
		wirename.Pair{Name: "relayUrl", Alias: "signalRelayUrl"}, `"` + urlA + `"`, urlB, urlA,
		decodeAs(func(v ProjectEnvironment) any { return v.SignalProtocolRelayURL }),
	},
	{
		"ProjectEnvironment.SignalProtocolRelayReceipts",
		wirename.Pair{Name: "relayReceipts", Alias: "signalRelayReceipts"}, "false", "true", false,
		decodeAs(func(v ProjectEnvironment) any {
			if v.SignalProtocolRelayReceipts == nil {
				return nil
			}
			return *v.SignalProtocolRelayReceipts
		}),
	},
	{
		"UsageReported.SignalProtocolRelayMAU",
		wirename.Pair{Name: "relayMau", Alias: "signalRelayMau"}, `"7"`, `"8"`, "7",
		decodeAs(func(v UsageReported) any {
			if v.SignalProtocolRelayMAU == nil {
				return nil
			}
			return *v.SignalProtocolRelayMAU
		}),
	},
	{
		"UsageLimits.SignalProtocolRelayMAU",
		wirename.Pair{Name: "relayMau", Alias: "signalRelayMau"}, "7", "8", 7,
		decodeAs(func(v UsageLimits) any { return v.SignalProtocolRelayMAU }),
	},
}

func TestSignalRelayReadersAcceptBothConsoleNames(t *testing.T) {
	for _, reader := range signalRelayReaders {
		t.Run(reader.name, func(t *testing.T) {
			old, renamed := `"`+reader.pair.Name+`":`, `"`+reader.pair.Alias+`":`
			for _, test := range []struct {
				name, data string
			}{
				{"the old name only", "{" + old + reader.value + "}"},
				{"the new name only", "{" + renamed + reader.value + "}"},
				{"both names", "{" + old + reader.value + "," + renamed + reader.value + "}"},
			} {
				got, err := reader.read([]byte(test.data))
				if err != nil || got != reader.want {
					t.Fatalf("%s: read %s = %#v, %v; want %#v", test.name, test.data, got, err, reader.want)
				}
			}
			_, err := reader.read([]byte("{" + old + reader.value + "," + renamed + reader.other + "}"))
			var conflict *wirename.ConflictError
			if !errors.As(err, &conflict) || conflict.Pair != reader.pair {
				t.Fatalf("two values returned %v, want a *wirename.ConflictError for %v", err, reader.pair)
			}
		})
	}
}

// TestUsageOutputWritesBothNames proves that oe project usage prints relayMau
// and signalRelayMau during the customer window.
func TestUsageOutputWritesBothNames(t *testing.T) {
	mau := "12"
	data, err := json.Marshal(Usage{Reported: &UsageReported{SignalProtocolRelayMAU: &mau}, Limits: &UsageLimits{SignalProtocolRelayMAU: 100}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"relayMau":"12"`, `"signalRelayMau":"12"`, `"relayMau":100`, `"signalRelayMau":100`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("the usage output %s has no %s", data, want)
		}
	}
	var decoded Usage
	if err := json.Unmarshal(data, &decoded); err != nil || *decoded.Reported.SignalProtocolRelayMAU != "12" || decoded.Limits.SignalProtocolRelayMAU != 100 {
		t.Fatalf("the usage output does not read back: %#v, %v", decoded, err)
	}
}

// TestPolicyRequestKeepsTheOldName proves that oe sends relayReceipts until
// the Console accepts signalRelayReceipts in a request.
func TestPolicyRequestKeepsTheOldName(t *testing.T) {
	data, err := json.Marshal(DeployRequest{Policy: SignalProtocolRelayPolicyRequest{SignalProtocolRelayReceipts: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"relayReceipts":true`) || strings.Contains(string(data), "signalRelay") {
		t.Fatalf("the deploy request changed its wire names: %s", data)
	}
}
