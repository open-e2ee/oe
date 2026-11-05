package envvar

import (
	"strings"
	"testing"
)

func environment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestEveryNameHasTheOpenE2EEPrefix(t *testing.T) {
	for _, name := range []Name{AccessToken, AccessTokenScopes, ProtectionBypass, Environment, OperationID, SignalRelayURL, NextSignalRelayURL, ExpoSignalRelayURL, ViteSignalRelayURL} {
		current := name.Current
		for _, prefix := range []string{"NEXT_PUBLIC_", "EXPO_PUBLIC_", "VITE_"} {
			current = strings.TrimPrefix(current, prefix)
		}
		if !strings.HasPrefix(current, "OPEN_E2EE_") || name.Deprecated == "" || name.Deprecated == name.Current {
			t.Errorf("%#v breaks the naming rule", name)
		}
	}
}

func TestReaderReadsTheCurrentNameFirst(t *testing.T) {
	for _, test := range []struct {
		name   string
		values map[string]string
		want   string
		warned bool
	}{
		{"current name", map[string]string{"OPEN_E2EE_ENV": "production"}, "production", false},
		{"deprecated name", map[string]string{"OE_ENV": "production"}, "production", true},
		{"both names", map[string]string{"OPEN_E2EE_ENV": "sandbox", "OE_ENV": "production"}, "sandbox", false},
		{"empty current name", map[string]string{"OPEN_E2EE_ENV": "", "OE_ENV": "production"}, "production", true},
		{"neither name", map[string]string{}, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var warnings []Name
			getenv := Reader(environment(test.values), func(name Name) { warnings = append(warnings, name) })
			if got := getenv("OPEN_E2EE_ENV"); got != test.want {
				t.Fatalf("getenv = %q; want %q", got, test.want)
			}
			if test.warned != (len(warnings) == 1) || len(warnings) > 1 {
				t.Fatalf("warnings = %#v; want warned=%t", warnings, test.warned)
			}
		})
	}
}

func TestReaderWarnsOncePerVariable(t *testing.T) {
	var warnings []string
	getenv := Reader(environment(map[string]string{"OE_ACCESS_TOKEN": "token", "OE_OPERATION_ID": "op_12345678"}), func(name Name) {
		warnings = append(warnings, name.Warning())
	})
	for range 3 {
		getenv("OPEN_E2EE_ACCESS_TOKEN")
		getenv("OPEN_E2EE_OPERATION_ID")
	}
	want := []string{
		"warning: OE_ACCESS_TOKEN is deprecated. Set OPEN_E2EE_ACCESS_TOKEN instead. oe v6.0.0 stops reading OE_ACCESS_TOKEN.",
		"warning: OE_OPERATION_ID is deprecated. Set OPEN_E2EE_OPERATION_ID instead. oe v6.0.0 stops reading OE_OPERATION_ID.",
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Fatalf("warnings = %q; want %q", warnings, want)
	}
}

func TestReaderPassesOtherNamesThrough(t *testing.T) {
	getenv := Reader(environment(map[string]string{"HOME": "/home/a", "OE_ENV": "production"}), func(name Name) {
		t.Fatalf("unexpected warning for %#v", name)
	})
	if getenv("HOME") != "/home/a" || getenv("OE_ENV") != "production" {
		t.Fatal("Reader changed a name that it does not own")
	}
}
