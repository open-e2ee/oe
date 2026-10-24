package identity

import (
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"testing"
)

func controlBase(t *testing.T, raw string) ControlBaseURL {
	t.Helper()
	value, err := ParseControlBaseURL(raw)
	if err != nil {
		t.Fatalf("parse public fixture: %v", err)
	}
	return value
}

func TestControlBaseCanonicalAddresses(t *testing.T) {
	vectors := []struct{ input, want string }{
		{"https://console.open-e2ee.dev/api/cli", "https://console.open-e2ee.dev/api/cli"},
		{"HTTPS://CONTROL.EXAMPLE:443/api/cli/", "https://control.example/api/cli"},
		{"https://control.example:00443/api//./cli/", "https://control.example/api/cli"},
		{"https://control.example/first/../api/cli", "https://control.example/api/cli"},
		{"https://control.example/api/%63li", "https://control.example/api/cli"},
		{"https://control.example/%2Ewell-known/cli", "https://control.example/.well-known/cli"},
		{"https://control.example", "https://control.example"},
		{"https://control.example////", "https://control.example"},
		{"https://control.example/api/..", "https://control.example"},
		{"https://control.example/API/cli", "https://control.example/API/cli"},
		{"https://control.example/api%20prefix/cli", "https://control.example/api%20prefix/cli"},
		{"https://control.example/caf%C3%A9/cli", "https://control.example/caf%C3%A9/cli"},
		{"https://control.example/café/cli", "https://control.example/caf%C3%A9/cli"},
		{"https://control.example/a%3Fb/cli", "https://control.example/a%3Fb/cli"},
		{"https://control.example/a%23b/cli", "https://control.example/a%23b/cli"},
		{"https://BÜCHER.example/api/cli", "https://xn--bcher-kva.example/api/cli"},
		{"https://control.example./api/cli", "https://control.example./api/cli"},
		{"http://LOCALHOST:80/api/cli/", "http://localhost/api/cli"},
		{"http://127.0.0.1:3000/api/cli", "http://127.0.0.1:3000/api/cli"},
		{"http://[::1]:80/api/cli", "http://[::1]/api/cli"},
		{"https://[2001:0db8:0:0:0:0:0:1]:443/api/cli", "https://[2001:db8::1]/api/cli"},
		{"https://control.example:8443/api/cli", "https://control.example:8443/api/cli"},
	}
	for _, vector := range vectors {
		t.Run(vector.input, func(t *testing.T) {
			value := controlBase(t, vector.input)
			if value.String() != vector.want || value.Validate() != nil {
				t.Fatalf("canonical address: got %q, want %q", value.String(), vector.want)
			}
			if !value.Equal(controlBase(t, vector.want)) {
				t.Fatal("canonical address is not idempotent")
			}
		})
	}
}

func TestControlBaseRefusesAmbiguousOrCredentialAddresses(t *testing.T) {
	credentialAddress := func(user *url.Userinfo) string {
		return (&url.URL{Scheme: "https", Host: "control.example", User: user, Path: "/api/cli"}).String()
	}
	vectors := []string{
		"", "control.example/api/cli", "//control.example/api/cli", "/api/cli",
		"https:control.example/api/cli", "ftp://localhost/api/cli", "file:///api/cli",
		"http://control.example/api/cli", "http://localhost.example/api/cli", "http://localhost./api/cli",
		"http://127.1/api/cli", "http://127.0.0.2/api/cli", "http://[0:0:0:0:0:0:0:1]/api/cli",
		"https://127.1/api/cli", "https://2130706433/api/cli", "https://0x7f000001/api/cli",
		"https://127.000.000.001/api/cli", "https://[fe80::1%25en0]/api/cli",
		credentialAddress(url.User("secret")), credentialAddress(url.UserPassword("user", "secret")), credentialAddress(url.User("")),
		"https://control.example/api/cli?", "https://control.example/api/cli?x=1",
		"https://control.example/api/cli#", "https://control.example/api/cli#fragment",
		"https://control.example:/api/cli", "https://control.example:0/api/cli", "https://control.example:65536/api/cli",
		"https://control.example:bad/api/cli", "https://[::1/api/cli", "https://%63ontrol.example/api/cli",
		" https://control.example/api/cli", "https://control.example/api/cli ", "https://control.example/a\tb",
		"https://control.example/a\nb", "https://control.example/a\u200bb", "https://control.example/a\\b",
		"https://control.example/a%2fb", "https://control.example/a%2Fb", "https://control.example/a%5cb",
		"https://control.example/%2e/cli", "https://control.example/.%2E/cli", "https://control.example/%2e%2e/cli",
		"https://control.example/a%252fb", "https://control.example/%252e/cli", "https://control.example/a%25b",
		"https://control.example/a%00b", "https://control.example/a%7fb", "https://control.example/a%E2%80%8Bb",
		"https://control.example/%ff", "https://control.example/%", "https://control.example/%0g",
		"https://control.example/" + string([]byte{0xff}),
	}
	for i, input := range vectors {
		t.Run("invalid-"+strconv.Itoa(i+1), func(t *testing.T) {
			value, err := ParseControlBaseURL(input)
			if !errors.Is(err, ErrControlBaseURL) || value.String() != "" || err.Error() != ErrControlBaseURL.Error() {
				t.Fatal("unsafe address did not return the fixed refusal and zero value")
			}
		})
	}
}

func TestControlBaseEqualityKeepsDistinctPrefixesAndAddresses(t *testing.T) {
	base := controlBase(t, "https://control.example/api/cli")
	for _, input := range []string{
		"https://control.example/api/other", "https://control.example/API/cli",
		"https://control.example/api/cli/v1", "https://control.example",
		"https://control.example:8443/api/cli", "https://other.example/api/cli",
		"https://control.example./api/cli",
	} {
		if base.Equal(controlBase(t, input)) {
			t.Fatalf("merged distinct address %q", input)
		}
	}
	if controlBase(t, "http://localhost/api/cli").Equal(controlBase(t, "https://localhost/api/cli")) {
		t.Fatal("merged HTTP and HTTPS")
	}
	if controlBase(t, "https://control.example/café").Equal(controlBase(t, "https://control.example/cafe\u0301")) {
		t.Fatal("normalized distinct path Unicode forms")
	}
	if (ControlBaseURL{}).Equal(ControlBaseURL{}) {
		t.Fatal("zero values cannot identify an address")
	}
}

func TestControlBaseJSONRequiresCanonicalScalarValue(t *testing.T) {
	value := controlBase(t, "HTTPS://CONTROL.EXAMPLE:443/api/cli/")
	encoded, err := json.Marshal(value)
	if err != nil || string(encoded) != `"https://control.example/api/cli"` {
		t.Fatalf("canonical JSON: %s %v", encoded, err)
	}
	var decoded ControlBaseURL
	if json.Unmarshal(encoded, &decoded) != nil || !decoded.Equal(value) {
		t.Fatal("canonical JSON did not round-trip")
	}
	for _, data := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{}`), []byte(`1`),
		[]byte(`"HTTPS://CONTROL.EXAMPLE/api/cli"`), []byte(`"https://control.example/api/cli/"`),
		[]byte(`"https://control.example/\ud800"`), []byte(`"https://control.example/\udc00"`),
		[]byte("\"https://control.example/" + string([]byte{0xff}) + "\""),
		[]byte(`"https://control.example/api/cli" null`),
	} {
		prior := decoded
		if decoded.UnmarshalJSON(data) == nil || !decoded.Equal(prior) {
			t.Fatal("invalid JSON changed the previous address")
		}
	}
	if _, err := json.Marshal(ControlBaseURL{}); err == nil {
		t.Fatal("encoded a zero address")
	}
}

func TestControlBaseEndpointPreservesPrefixAndSeparatesQuery(t *testing.T) {
	base := controlBase(t, "https://control.example/root/api/cli/")
	query := url.Values{"environment": {"production"}, "action": {"current"}}
	got, err := base.Endpoint([]string{"v1", "projects", "chat", "identity"}, query)
	want := "https://control.example/root/api/cli/v1/projects/chat/identity?action=current&environment=production"
	if err != nil || got != want {
		t.Fatalf("prefixed request URL: %q %v", got, err)
	}
	query.Set("environment", "sandbox")
	if got != want || base.String() != "https://control.example/root/api/cli" {
		t.Fatal("caller mutation changed the endpoint or base")
	}
	got, err = base.Endpoint([]string{"v1", "name?part#suffix"}, url.Values{"value": {"a&b", "c d"}})
	if err != nil || got != "https://control.example/root/api/cli/v1/name%3Fpart%23suffix?value=a%26b&value=c+d" {
		t.Fatalf("path/query encoding: %q %v", got, err)
	}
	got, err = controlBase(t, "https://control.example/a%3Fb").Endpoint([]string{"v1", "health"}, nil)
	if err != nil || got != "https://control.example/a%3Fb/v1/health" {
		t.Fatalf("escaped prefix changed: %q %v", got, err)
	}
	for _, segments := range [][]string{nil, {""}, {"."}, {".."}, {"/v1"}, {"//evil.example"}, {"https://evil.example"}, {"a/b"}, {"a\\b"}, {"%2f"}, {"a\x00b"}, {string([]byte{0xff})}} {
		if _, err := base.Endpoint(segments, nil); !errors.Is(err, ErrControlBaseURL) {
			t.Fatal("accepted route data that can replace or escape the prefix")
		}
	}
	for _, query := range []url.Values{{string([]byte{0xff}): {"v"}}, {"k": {string([]byte{0xff})}}} {
		if _, err := base.Endpoint([]string{"v1"}, query); !errors.Is(err, ErrControlBaseURL) {
			t.Fatal("accepted invalid query scalar bytes")
		}
	}
}
