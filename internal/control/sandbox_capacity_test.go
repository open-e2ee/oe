package control

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func capacityFixture(t *testing.T) string {
	t.Helper()
	value, err := os.ReadFile("testdata/sandbox-capacity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, value); err != nil {
		t.Fatal(err)
	}
	return compact.String()
}

func TestProjectCapacityAuthenticatedSeparateContract(t *testing.T) {
	body := capacityFixture(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/api/cli/v1/projects/local-chat/sandbox-account-capacity" || r.URL.RawQuery != "environment=sandbox" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("wrong capacity request: %s %s", r.Method, r.URL)
		}
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL+"/api/cli", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	value, err := client.ProjectCapacity(t.Context(), CredentialRequest{AccessToken: "test-token"}, "local-chat", "sandbox")
	if err != nil || value.Capacity.AvailableSlots == nil || *value.Capacity.AvailableSlots != "2" {
		t.Fatalf("read: %#v %v", value, err)
	}
	if _, err = client.ProjectCapacity(t.Context(), CredentialRequest{}, "local-chat", "production"); err == nil || calls != 1 {
		t.Fatal("Production reached capacity transport")
	}
}

func TestProjectCapacityRefusesUnsupportedMalformedAndCrossedResponses(t *testing.T) {
	fixture := capacityFixture(t)
	for name, body := range map[string]string{
		"version":              strings.Replace(fixture, `"schemaVersion":1`, `"schemaVersion":2`, 1),
		"unknown field":        strings.Replace(fixture, `"schemaVersion":1`, `"monthlyActiveUsers":5,"schemaVersion":1`, 1),
		"duplicate":            strings.Replace(fixture, `"schemaVersion":1`, `"schemaVersion":1,"schemaVersion":1`, 1),
		"missing null":         strings.Replace(fixture, `,"pendingLimit":null`, "", 1),
		"arithmetic":           strings.Replace(fixture, `"availableSlots":"2"`, `"availableSlots":"3"`, 1),
		"leading zero":         strings.Replace(fixture, `"reservedAccounts":"1"`, `"reservedAccounts":"01"`, 1),
		"wrong project":        strings.Replace(fixture, `"project":"local-chat"`, `"project":"other"`, 1),
		"production":           strings.Replace(fixture, `"environment":"sandbox"`, `"environment":"production"`, 1),
		"unsafe integer":       strings.Replace(fixture, `"capacityRevision":2`, `"capacityRevision":9007199254740992`, 1),
		"pending null integer": strings.Replace(fixture, `"pendingLimit":null`, `"pendingLimit":{"registeredTestAccounts":null,"appliesAtMilliseconds":1,"controlOperationId":"pending"}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			t.Cleanup(server.Close)
			client, _ := New(server.URL, server.Client())
			if _, err := client.ProjectCapacity(t.Context(), CredentialRequest{}, "local-chat", "sandbox"); err == nil {
				t.Fatal("invalid capacity accepted")
			}
		})
	}
	for _, status := range []int{404, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				w.Write([]byte(`{"code":"UNSUPPORTED","message":"Capacity unavailable"}`))
			}))
			t.Cleanup(server.Close)
			client, _ := New(server.URL, server.Client())
			if _, err := client.ProjectCapacity(t.Context(), CredentialRequest{}, "local-chat", "sandbox"); err == nil {
				t.Fatal("unsupported route accepted")
			}
		})
	}
}

func TestCapacityUnknownExactCountsAndExpiration(t *testing.T) {
	fixture := capacityFixture(t)
	var value ProjectCapacity
	large := strings.NewReplacer(`"registeredAccounts":"5"`, `"registeredAccounts":"9007199254740993"`, `"availableSlots":"2"`, `"availableSlots":"0"`, `"overCapacity":false`, `"overCapacity":true`).Replace(fixture)
	if err := json.Unmarshal([]byte(large), &value); err != nil || *value.Capacity.RegisteredAccounts != "9007199254740993" {
		t.Fatalf("exact count lost: %v", err)
	}
	for _, offset := range []int64{-30_001, 60_001} {
		stale := value.Capacity.At(time.UnixMilli(1_800_000_000_000 + offset))
		if stale.State != "unknown" || stale.AvailableSlots != nil || stale.OverCapacity != nil || *stale.RegisteredAccounts != "9007199254740993" {
			t.Fatalf("expired result: %#v", stale)
		}
	}
	for _, state := range []string{"inactive", "partial", "unknown"} {
		body := strings.NewReplacer(`"state":"active"`, `"state":"`+state+`"`, `"availableSlots":"2"`, `"availableSlots":null`, `"overCapacity":false`, `"overCapacity":null`, `"reservedAccounts":"1"`, `"reservedAccounts":null`).Replace(fixture)
		if err := json.Unmarshal([]byte(body), &value); err != nil || value.Capacity.ReservedAccounts != nil || value.Capacity.AvailableSlots != nil {
			t.Fatalf("unknown observation: %s %v", body, err)
		}
	}
}
