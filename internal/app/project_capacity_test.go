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

const capacityProjectBody = `{"slug":"local-chat","writer":"config","sandbox":{"relayUrl":"` + sandboxSignalProtocolRelayURL + `","revision":"1"}}`

func capacityDependencies(t *testing.T, body string, status int) (Dependencies, *int) {
	t.Helper()
	return capacityRoutes(t, http.StatusOK, capacityProjectBody, status, body)
}

// capacityRoutes serves the project read and the capacity read with the
// given statuses and bodies, and counts the requests.
func capacityRoutes(t *testing.T, projectStatus int, projectBody string, status int, body string) (Dependencies, *int) {
	t.Helper()
	calls := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("capacity command lost authentication")
		}
		switch r.URL.Path {
		case "/api/cli/v1/projects/local-chat":
			w.WriteHeader(projectStatus)
			w.Write([]byte(projectBody))
		case "/api/cli/v1/projects/local-chat/sandbox-account-capacity":
			if r.URL.RawQuery != "environment=sandbox" {
				t.Error("wrong capacity environment")
			}
			w.WriteHeader(status)
			w.Write([]byte(body))
		case "/api/cli/v1/auth/session":
			// A project refusal reads the session to name other organizations.
			w.WriteHeader(http.StatusNotFound)
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
func TestUsageTextKeepsMAUInBothEnvironments(t *testing.T) {
	zero := "0"
	usage := control.Usage{Project: "local-chat", Environment: "production", Period: "2026-11", Status: "reported", Reported: &control.UsageReported{DeliveryUnits: &zero, AttachmentOperations: &zero, SignalProtocolRelayMAU: &zero, LiveBytes: "0"}}
	if value, want := usageText(usage), "local-chat production usage, 2026-11 UTC\nDelivery units: 0\nAttachment operations: 0\nRelay MAU: 0\nLive bytes: 0"; value != want {
		t.Fatalf("Production changed: %q", value)
	}
	usage.Environment = "sandbox"
	if value, want := usageText(usage), "local-chat sandbox usage, 2026-11 UTC\nDelivery units: 0\nAttachment operations: 0\nRelay MAU: 0\nLive bytes: 0"; value != want {
		t.Fatalf("Sandbox lost its enforced MAU meter: %q", value)
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

const nextNotFoundPage = `<!DOCTYPE html><html><head><title>404: This page could not be found.</title></head><body><h1>404</h1><h2>This page could not be found.</h2></body></html>`

func TestCapacityCommandReportsAConsoleWithoutTheCapacityRoute(t *testing.T) {
	for name, body := range map[string]string{
		"HTML": nextNotFoundPage,
		"JSON": `{"code":"NOT_FOUND","message":"Not Found"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dependencies, calls := capacityDependencies(t, body, http.StatusNotFound)
			exit, stdout, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat")
			failure := decodeEvent(t, []byte(stdout))
			if exit != exitTemporary || failure.Code != "CAPACITY_UNAVAILABLE" || *calls != 2 ||
				!strings.Contains(failure.Error, "does not serve Sandbox account capacity yet") ||
				failure.Next != "oe project capacity local-chat --env sandbox" {
				t.Fatalf("missing route was not reported as unavailable capacity: exit=%d calls=%d %s", exit, *calls, stdout)
			}
		})
	}
}

func TestCapacityCommandKeepsAProjectReadRefusal(t *testing.T) {
	dependencies, calls := capacityRoutes(t, http.StatusNotFound, `{"code":"PROJECT_NOT_FOUND","message":"The project was not found, or this account has no access to it."}`, http.StatusOK, capacityBody(t))
	exit, stdout, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat")
	failure := decodeEvent(t, []byte(stdout))
	// The project read and its session read run; the capacity read does not.
	if exit != exitFailure || failure.Code != "PROJECT_NOT_FOUND" || failure.Next != "oe project list" || *calls != 2 {
		t.Fatalf("project refusal changed: exit=%d calls=%d %s", exit, *calls, stdout)
	}
}

func TestCapacityCommandReportsAnInvalidResponseAsUnavailable(t *testing.T) {
	fixture := capacityBody(t)
	for name, body := range map[string]string{
		"malformed":     `{"capacity":{}}`,
		"crossed":       strings.Replace(fixture, `"project":"local-chat"`, `"project":"other-chat"`, 1),
		"production":    strings.Replace(fixture, `"environment":"sandbox"`, `"environment":"production"`, 1),
		"not JSON":      nextNotFoundPage,
		"unknown field": strings.Replace(fixture, `"schemaVersion":1`, `"monthlyActiveUsers":5,"schemaVersion":1`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			dependencies, _ := capacityDependencies(t, body, http.StatusOK)
			exit, stdout, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat")
			failure := decodeEvent(t, []byte(stdout))
			if exit != exitTemporary || failure.Code != "CAPACITY_UNAVAILABLE" || failure.Next != "oe project capacity local-chat --env sandbox" ||
				strings.Contains(stdout, `"registeredAccounts"`) {
				t.Fatalf("invalid capacity was not unavailable: exit=%d %s", exit, stdout)
			}
		})
	}
}

func TestCapacityCommandRequiresAnActiveSandbox(t *testing.T) {
	dependencies, calls := capacityRoutes(t, http.StatusOK, `{"slug":"local-chat","writer":"config"}`, http.StatusOK, capacityBody(t))
	exit, stdout, _ := run(t, dependencies, "--json", "project", "capacity", "local-chat")
	failure := decodeEvent(t, []byte(stdout))
	if exit != exitFailure || failure.Code != "ENVIRONMENT_NOT_ACTIVE" || failure.Next != "oe new" || *calls != 1 {
		t.Fatalf("inactive Sandbox reached capacity: exit=%d calls=%d %s", exit, *calls, stdout)
	}
}

func TestCapacityTextContract(t *testing.T) {
	dependencies, _ := capacityDependencies(t, capacityBody(t), http.StatusOK)
	exit, text, _ := run(t, dependencies, "project", "capacity")
	want := "local-chat Sandbox account capacity\nReadiness: active\nRegistered test accounts: 5\nReserved accounts: 1\nAvailable slots: 2\nAccount limit: 8\n" +
		"Activation revision: 1\nCapacity revision: 2\nObserved at: 2027-01-15T08:00:00Z\n" +
		"A slot is free only after deletion confirms capacity release. Removing a device or clearing local storage does not free a slot.\n"
	if exit != 0 || text != want {
		t.Fatalf("capacity text changed:\n got %q\nwant %q", text, want)
	}
}

func TestCapacityTextNamesStaleObservations(t *testing.T) {
	// The Console and the CLI both expire an old active observation to unknown.
	for name, state := range map[string]string{"expired by the CLI": "active", "expired by the Console": "unknown"} {
		t.Run(name, func(t *testing.T) {
			body := strings.NewReplacer(`"observedAtMilliseconds":1800000000000`, `"observedAtMilliseconds":1799999900000`, `"state":"active"`, `"state":"`+state+`"`).Replace(capacityBody(t))
			if state == "unknown" {
				body = strings.NewReplacer(`"availableSlots":"2"`, `"availableSlots":null`, `"overCapacity":false`, `"overCapacity":null`).Replace(body)
			}
			dependencies, _ := capacityDependencies(t, body, http.StatusOK)
			exit, text, _ := run(t, dependencies, "project", "capacity")
			if exit != 0 || !strings.Contains(text, "Readiness: stale\n") || !strings.Contains(text, "Observed at: 2027-01-15T07:58:20Z (stale)\n") ||
				!strings.Contains(text, "Available slots: unknown\n") || !strings.Contains(text, "This observation is stale. Available slots stay unknown until Relay reports a current observation.\n") {
				t.Fatalf("stale capacity was not named stale: %d %s", exit, text)
			}
			exit, data, _ := run(t, dependencies, "--json", "project", "capacity")
			if exit != 0 || !strings.Contains(data, `"state":"unknown"`) || !strings.Contains(data, `"availableSlots":null`) {
				t.Fatalf("stale JSON changed: %d %s", exit, data)
			}
		})
	}
}

func TestCapacityTextNamesAnInactiveSandboxAsNotActivated(t *testing.T) {
	body := strings.NewReplacer(`"state":"active"`, `"state":"inactive"`, `"activationRevision":1`, `"activationRevision":null`, `"capacityRevision":2`, `"capacityRevision":null`,
		`"registeredAccounts":"5"`, `"registeredAccounts":null`, `"reservedAccounts":"1"`, `"reservedAccounts":null`, `"availableSlots":"2"`, `"availableSlots":null`,
		`"overCapacity":false`, `"overCapacity":null`, `"observedAtMilliseconds":1800000000000`, `"observedAtMilliseconds":null`).Replace(capacityBody(t))
	dependencies, _ := capacityDependencies(t, body, http.StatusOK)
	exit, text, _ := run(t, dependencies, "project", "capacity")
	if exit != 0 || !strings.Contains(text, "Readiness: inactive\n") || !strings.Contains(text, "Activation revision: not activated\n") ||
		!strings.Contains(text, "Account capacity is not activated for this Sandbox. Account admission does not use it yet.\n") || strings.Contains(text, "unknown\nCapacity") {
		t.Fatalf("inactive Sandbox was not named not activated: %d %s", exit, text)
	}
}
