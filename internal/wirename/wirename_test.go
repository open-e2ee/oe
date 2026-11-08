package wirename

import (
	"encoding/json"
	"errors"
	"testing"
)

var url = Pair{Name: "relayUrl", Alias: "signalRelayUrl"}

func TestAcceptReadsEitherName(t *testing.T) {
	for _, test := range []struct {
		name, data string
	}{
		{"the old name only", `{"relayUrl":"https://a","id":"1"}`},
		{"the new name only", `{"signalRelayUrl":"https://a","id":"1"}`},
		{"both names with one value", `{"relayUrl":"https://a","signalRelayUrl": "https://a","id":"1"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			accepted, err := Accept([]byte(test.data), url)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]string
			if err := json.Unmarshal(accepted, &fields); err != nil {
				t.Fatal(err)
			}
			if len(fields) != 2 || fields["relayUrl"] != "https://a" || fields["id"] != "1" {
				t.Fatalf("Accept(%s) = %s", test.data, accepted)
			}
		})
	}
}

func TestAcceptLeavesDataWithoutAnAliasUnchanged(t *testing.T) {
	for _, data := range []string{`{"relayUrl":"https://a", "id":"1"}`, `null`, `"text"`, ``} {
		accepted, err := Accept([]byte(data), url)
		if err != nil || string(accepted) != data {
			t.Fatalf("Accept(%q) = %q, %v", data, accepted, err)
		}
	}
}

func TestAcceptRefusesTwoValues(t *testing.T) {
	_, err := Accept([]byte(`{"relayUrl":"https://a","signalRelayUrl":"https://b"}`), url)
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.Pair != url {
		t.Fatalf("Accept of two values returned %v", err)
	}
}

func TestEmitAddsEachAliasThatHasAName(t *testing.T) {
	mau := Pair{Name: "relayMau", Alias: "signalRelayMau"}
	emitted, err := Emit([]byte(`{"relayUrl":"https://a","relayMau":null}`), url, mau, Pair{Name: "absent", Alias: "newAbsent"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"relayUrl":"https://a","relayMau":null,"signalRelayUrl":"https://a","signalRelayMau":null}`; string(emitted) != want {
		t.Fatalf("Emit = %s, want %s", emitted, want)
	}
	if emitted, err := Emit([]byte(`{}`), url); err != nil || string(emitted) != `{}` {
		t.Fatalf("Emit of an empty object = %s, %v", emitted, err)
	}
}

func TestEmitRefusesAnObjectThatHasTheAlias(t *testing.T) {
	for _, data := range []string{`{"relayUrl":"a","signalRelayUrl":"a"}`, `[]`, `null`} {
		if emitted, err := Emit([]byte(data), url); err == nil {
			t.Fatalf("Emit(%s) = %s, want an error", data, emitted)
		}
	}
}
