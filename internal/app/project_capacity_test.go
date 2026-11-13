package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

func capacityDependencies(t *testing.T, body string, status int) (Dependencies, *int) {
	t.Helper()
	calls := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("capacity command lost authentication")
		}
		switch r.URL.Path {
		case "/api/cli/v1/projects/local-chat":
			w.Write([]byte(`{"slug":"local-chat","writer":"config"}`))
		case "/api/cli/v1/projects/local-chat/sandbox-account-capacity":
			if r.URL.RawQuery != "environment=sandbox" {
				t.Error("wrong capacity environment")
			}
			w.WriteHeader(status)
			w.Write([]byte(body))
		default:
			t.Errorf("capacity command reached unrelated route %s", r.URL)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(server.Close)
	client, err := control.New(server.URL+"/api/cli", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	store := credential.NewMemory()
	storeCredential(t, store, "project:read")
	return Dependencies{API: client, Store: store, WorkingDir: initializedProject(t, "local-chat"), Now: func() time.Time { return time.UnixMilli(1_800_000_000_000) }}, calls
}
func capacityBody(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../control/testdata/sandbox-capacity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		t.Fatal(err)
	}
	return compact.String()
}
func TestCapacityCommandUsesAuthenticatedSeparateReaderAndDirectoryProject(t *testing.T) {
	dependencies, calls := capacityDependencies(t, capacityBody(t), 200)
	exit, text, _ := run(t, dependencies, "project", "capacity")
	if exit != 0 || !strings.Contains(text, "Registered test accounts: 5") || !strings.Contains(text, "Reserved accounts: 1") || !strings.Contains(text, "Available slots: 2") || strings.Contains(text, "MAU") || *calls != 2 {
		t.Fatalf("capacity command: exit=%d calls=%d %s", exit, *calls, text)
	}
	exit, data, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat")
	result, ok := decodeEvent(t, []byte(data)).Data["capacity"].(map[string]any)
	if exit != 0 || !ok || result["project"] != "local-chat" || strings.Contains(data, "test-token") {
		t.Fatalf("capacity JSON: %d %s", exit, data)
	}
}
func TestCapacityCommandPreservesUnknownAndExpiresAvailability(t *testing.T) {
	for _, body := range []string{
		strings.Replace(capacityBody(t), `"observedAtMilliseconds":1800000000000`, `"observedAtMilliseconds":1799999900000`, 1),
		strings.NewReplacer(`"state":"active"`, `"state":"partial"`, `"availableSlots":"2"`, `"availableSlots":null`, `"overCapacity":false`, `"overCapacity":null`, `"reservedAccounts":"1"`, `"reservedAccounts":null`).Replace(capacityBody(t)),
	} {
		dependencies, _ := capacityDependencies(t, body, 200)
		exit, text, _ := run(t, dependencies, "project", "capacity")
		if exit != 0 || !strings.Contains(text, "Available slots: unknown") || !strings.Contains(text, "Registered test accounts: 5") {
			t.Fatalf("unknown became zero: %d %s", exit, text)
		}
		exit, text, _ = run(t, dependencies, "--json", "project", "capacity")
		if exit != 0 || !strings.Contains(text, `"availableSlots":null`) {
			t.Fatalf("JSON unknown lost: %d %s", exit, text)
		}
	}
}
func TestCapacityProductionIsRefusedBeforeAuthenticationOrHTTP(t *testing.T) {
	dependencies, calls := capacityDependencies(t, capacityBody(t), 200)
	exit, text, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat", "--env", "production")
	if exit != exitUsage || *calls != 0 || !strings.Contains(text, "only in Sandbox") {
		t.Fatalf("Production changed: %d %d %s", exit, *calls, text)
	}
}
func TestCapacityCommandRefusesUnsupportedAndUnauthenticatedResponses(t *testing.T) {
	for _, status := range []int{401, 404, 503} {
		dependencies, _ := capacityDependencies(t, `{"code":"CAPACITY_UNAVAILABLE","message":"Capacity unavailable"}`, status)
		exit, text, _ := run(t, dependencies, "--json", "project", "capacity")
		if exit == 0 || strings.Contains(text, `"availableSlots":"0"`) || strings.Contains(text, "test-token") {
			t.Fatalf("failure became success: %d %s", exit, text)
		}
	}
	dependencies, _ := capacityDependencies(t, `{"capacity":{}}`, 200)
	exit, text, _ := run(t, dependencies, "--json", "project", "capacity")
	if exit == 0 || strings.Contains(text, `"registeredAccounts":"0"`) {
		t.Fatalf("malformed became capacity: %d %s", exit, text)
	}
}
func TestUsageTextKeepsProductionMAUAndHidesSandboxMAU(t *testing.T) {
	zero := "0"
	usage := control.Usage{Project: "local-chat", Environment: "production", Period: "2026-11", Status: "reported", Reported: &control.UsageReported{DeliveryUnits: &zero, AttachmentOperations: &zero, SignalProtocolRelayMAU: &zero, LiveBytes: "0"}}
	want := "local-chat production usage, 2026-11 UTC\nDelivery units: 0\nAttachment operations: 0\nRelay MAU: 0\nLive bytes: 0"
	if value := usageText(usage); value != want {
		t.Fatalf("Production changed: %q", value)
	}
	usage.Environment = "sandbox"
	if value := usageText(usage); strings.Contains(value, "MAU") || !strings.Contains(value, "Live bytes: 0") {
		t.Fatalf("Sandbox meter remained: %q", value)
	}
}

func TestCapacityReadyDoesNotClaimAdmissionIsActive(t *testing.T) {
	body := strings.Replace(capacityBody(t), `"state":"active"`, `"state":"ready"`, 1)
	dependencies, _ := capacityDependencies(t, body, 200)
	exit, text, _ := run(t, dependencies, "project", "capacity")
	if exit != 0 || !strings.Contains(text, "Account admission has not been activated") {
		t.Fatalf("ready implied activation: %d %s", exit, text)
	}
}
