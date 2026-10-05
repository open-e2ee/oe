package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func testAccessToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800}`))
	return fmt.Sprintf("%s.%s.signature", header, payload)
}

func TestWorkOSDeviceAuthorizationAndRefreshStayOffTheControlOrigin(t *testing.T) {
	var polls atomic.Int32
	var refreshes atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/auth/configuration":
			json.NewEncoder(response).Encode(authConfiguration{
				ClientID: "client_test", DeviceAuthorizationEndpoint: server.URL + "/user_management/authorize/device",
				SchemaVersion: 1, TokenEndpoint: server.URL + "/user_management/authenticate",
			})
		case "/user_management/authorize/device":
			if err := request.ParseForm(); err != nil || request.Form.Get("client_id") != "client_test" {
				t.Fatalf("invalid device authorization form: %v %#v", err, request.Form)
			}
			json.NewEncoder(response).Encode(deviceAuthorizationResponse{
				DeviceCode: "device-secret", ExpiresIn: 300, Interval: 1,
				UserCode: "ABCD-EFGH", VerificationURIComplete: "https://auth.example/device?user_code=ABCD-EFGH",
				VerificationURI: "https://auth.example/device",
			})
		case "/user_management/authenticate":
			if err := request.ParseForm(); err != nil {
				t.Fatal(err)
			}
			switch request.Form.Get("grant_type") {
			case "urn:ietf:params:oauth:grant-type:device_code":
				if request.Form.Get("device_code") != "device-secret" {
					t.Fatal("device code changed")
				}
				switch polls.Add(1) {
				case 1:
					response.WriteHeader(http.StatusBadRequest)
					response.Write([]byte(`{"error":"authorization_pending"}`))
					return
				case 2:
					response.WriteHeader(http.StatusBadRequest)
					response.Write([]byte(`{"error":"slow_down"}`))
					return
				}
				json.NewEncoder(response).Encode(oauthTokenResponse{AccessToken: testAccessToken(), RefreshToken: "refresh-one"})
			case "refresh_token":
				if request.Form.Get("refresh_token") != "refresh-one" {
					t.Fatal("refresh token changed")
				}
				if refreshes.Add(1) < 3 {
					response.WriteHeader(http.StatusServiceUnavailable)
					response.Write([]byte(`{"error":"temporarily_unavailable"}`))
					return
				}
				json.NewEncoder(response).Encode(oauthTokenResponse{AccessToken: testAccessToken(), RefreshToken: "refresh-two"})
			default:
				t.Fatalf("unexpected grant %q", request.Form.Get("grant_type"))
			}
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := client.StartAuthorization(context.Background(), AuthorizationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !authorization.CodeInURL || authorization.VerificationURL != "https://auth.example/device?user_code=ABCD-EFGH" ||
		authorization.BareVerificationURL != "https://auth.example/device" {
		t.Fatalf("complete verification URL: %#v", authorization)
	}
	pending, err := client.PollAuthorization(context.Background(), authorization)
	if err != nil || !pending.Pending {
		t.Fatalf("pending poll: %#v %v", pending, err)
	}
	slowed, err := client.PollAuthorization(context.Background(), authorization)
	if err != nil || !slowed.Pending || slowed.RetryAfterSeconds != 6 {
		t.Fatalf("slow-down poll: %#v %v", slowed, err)
	}
	issued, err := client.PollAuthorization(context.Background(), authorization)
	if err != nil || issued.AccessToken == "" || issued.RefreshToken != "refresh-one" || issued.ExpiresAt == "" {
		t.Fatalf("issued token: %#v %v", issued, err)
	}
	refreshed, err := client.RefreshAuthorization(context.Background(), issued.RefreshToken)
	if err != nil || refreshed.RefreshToken != "refresh-two" || refreshes.Load() != 3 {
		t.Fatalf("refreshed token: %#v %v", refreshed, err)
	}
}

func TestRefreshClassifiesInvalidGrantAsExpiredSession(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/auth/configuration" {
			json.NewEncoder(response).Encode(authConfiguration{
				ClientID: "client_test", DeviceAuthorizationEndpoint: server.URL + "/user_management/authorize/device",
				SchemaVersion: 1, TokenEndpoint: server.URL + "/user_management/authenticate",
			})
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RefreshAuthorization(context.Background(), "expired-refresh")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("invalid_grant was not classified as expired: %v", err)
	}
}

func TestPollClassifiesExpiredTokenAsExpiredAuthorization(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/auth/configuration" {
			json.NewEncoder(response).Encode(authConfiguration{
				ClientID: "client_test", DeviceAuthorizationEndpoint: server.URL + "/user_management/authorize/device",
				SchemaVersion: 1, TokenEndpoint: server.URL + "/user_management/authenticate",
			})
			return
		}
		response.WriteHeader(http.StatusBadRequest)
		response.Write([]byte(`{"error":"expired_token"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.PollAuthorization(context.Background(), Authorization{ClientID: "client_test", DeviceCode: "device", TokenEndpoint: server.URL + "/user_management/authenticate"})
	if !errors.Is(err, ErrAuthorizationExpired) {
		t.Fatalf("expired_token was not classified as an expired authorization: %v", err)
	}
}

func TestMutationsCarryBearerAndIdempotencyHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("unexpected authorization header %q", got)
		}
		if got := request.Header.Get("Idempotency-Key"); got != "operation-1" {
			t.Errorf("unexpected idempotency key %q", got)
		}
		if request.URL.Path != "/v1/projects/bootstrap" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(Bootstrap{ProjectSlug: "chat", Writer: "config"})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.BootstrapSandbox(context.Background(), CredentialRequest{AccessToken: "secret-token", OperationID: "operation-1"}, BootstrapRequest{ProjectSlug: "chat", Writer: "config"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNotificationConfigurationUsesExactEnvironmentAndVersion(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path != "/v1/projects/chat/notifications" {
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet {
			if request.URL.Query().Get("environment") != "sandbox" {
				t.Fatalf("environment query was lost: %s", request.URL.RawQuery)
			}
			json.NewEncoder(response).Encode(NotificationConfiguration{
				AllowedProfiles:      []NotificationProfile{NotificationBackgroundOnly},
				ConfigurationVersion: 4, Environment: "sandbox", Providers: []string{"apns"},
			})
			return
		}
		if request.Header.Get("Idempotency-Key") != "notification-operation" {
			t.Fatal("notification mutation lost its idempotency key")
		}
		var input NotificationConfigurationRequest
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.ExpectedConfigurationVersion != 4 || input.Environment != "sandbox" || len(input.AllowedProfiles) != 2 {
			t.Fatalf("unexpected notification request: %#v", input)
		}
		json.NewEncoder(response).Encode(NotificationConfiguration{
			AllowedProfiles: input.AllowedProfiles, ConfigurationVersion: 5,
			Environment: "sandbox", Providers: []string{"apns"},
		})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	current, err := client.Notifications(context.Background(), CredentialRequest{}, "chat", "sandbox")
	if err != nil || current.ConfigurationVersion != 4 {
		t.Fatalf("notification read failed: %#v %v", current, err)
	}
	updated, err := client.ConfigureNotifications(context.Background(), CredentialRequest{OperationID: "notification-operation"}, "chat", NotificationConfigurationRequest{
		AllowedProfiles: []NotificationProfile{NotificationBackgroundOnly, NotificationVisibleAlert},
		Environment:     "sandbox", ExpectedConfigurationVersion: current.ConfigurationVersion,
	})
	if err != nil || updated.ConfigurationVersion != 5 || calls != 2 {
		t.Fatalf("notification write failed: %#v calls=%d %v", updated, calls, err)
	}
}

func TestPostWithoutIdempotencyKeyIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/auth/configuration" {
			json.NewEncoder(response).Encode(authConfiguration{
				ClientID: "client_test", DeviceAuthorizationEndpoint: server.URL + "/user_management/authorize/device",
				SchemaVersion: 1, TokenEndpoint: server.URL + "/user_management/authenticate",
			})
			return
		}
		calls.Add(1)
		http.Error(response, `{"code":"temporary","message":"try later"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.StartAuthorization(context.Background(), AuthorizationRequest{})
	if err == nil {
		t.Fatal("expected authorization failure")
	}
	if calls.Load() != 1 {
		t.Fatalf("non-idempotent POST was retried %d times", calls.Load())
	}
}

func TestPostWithIdempotencyKeyRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(response, `{"code":"temporary","message":"try later"}`, http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(Bootstrap{ProjectSlug: "chat", Writer: "config"})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.BootstrapSandbox(context.Background(), CredentialRequest{OperationID: "stable-operation"}, BootstrapRequest{ProjectSlug: "chat", Writer: "config"})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("want 3 calls, got %d", calls.Load())
	}
}

func TestErrorDoesNotEchoBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		response.Write([]byte(`{"code":"unauthorized","message":"credential rejected"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.GetProject(context.Background(), CredentialRequest{AccessToken: "secret-token"}, "chat")
	if err == nil {
		t.Fatal("expected health failure")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("error exposed bearer token")
	}
}

func TestNewRejectsNonHTTPURLs(t *testing.T) {
	if _, err := New("file:///tmp/control", nil); err == nil {
		t.Fatal("accepted non-HTTP control URL")
	}
}

func TestTermsReadAndAcceptanceUseTheConsoleShapes(t *testing.T) {
	const documents = `[{"name":"Relay service terms","url":"https://open-e2ee.dev/legal/relay-terms/2026-08-26","version":"relay-2026-08-26"}]`
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/terms":
			response.Write([]byte(`{"acceptedAt":null,"canAccept":true,"documents":` + documents + `,"state":"required"}`))
		case "POST /v1/terms/acceptance":
			if request.Header.Get("Idempotency-Key") != "" {
				t.Error("an acceptance carried an idempotency key")
			}
			body, _ := io.ReadAll(request.Body)
			bodies = append(bodies, string(body))
			response.Write([]byte(`{"acceptedAt":"2026-09-30T12:00:00.000Z","canAccept":true,"changed":true,"documents":` + documents + `,"state":"accepted"}`))
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	terms, err := client.Terms(context.Background(), CredentialRequest{AccessToken: "token"})
	if err != nil || terms.State != TermsRequired || !terms.CanAccept || terms.AcceptedAt != nil || len(terms.Documents) != 1 ||
		terms.Documents[0].Version != "relay-2026-08-26" {
		t.Fatalf("terms read: %#v %v", terms, err)
	}
	for _, request := range []TermsAcceptanceRequest{{Actor: "agent", AgentName: "claude-code"}, {Actor: "person"}} {
		accepted, err := client.AcceptTerms(context.Background(), CredentialRequest{AccessToken: "token"}, request)
		if err != nil || accepted.State != TermsAccepted || !accepted.Changed || accepted.AcceptedAt == nil {
			t.Fatalf("acceptance: %#v %v", accepted, err)
		}
	}
	if len(bodies) != 2 || bodies[0] != `{"actor":"agent","agentName":"claude-code"}` || bodies[1] != `{"actor":"person"}` {
		t.Fatalf("acceptance bodies %q", bodies)
	}
}

func TestSessionReadUsesTheConsoleShape(t *testing.T) {
	answers := map[string]string{
		"person":               `{"schemaVersion":1,"user":{"id":"user_1","email":"jane@example.com","name":null},"organization":{"id":"org_1","name":"Acme Inc."},"role":null,"agent":null}`,
		"agent":                `{"schemaVersion":1,"user":{"id":"user_1","email":"jane@example.com","name":"Jane Doe"},"organization":{"id":"org_1","name":"Acme Inc."},"role":"admin","agent":{"registrationId":"agent_reg_1"}}`,
		"no organization name": `{"schemaVersion":1,"user":{"id":"user_1","email":"jane@example.com","name":null},"organization":{"id":"org_1","name":""},"role":null,"agent":null}`,
		"no registration":      `{"schemaVersion":1,"user":{"id":"user_1","email":"jane@example.com","name":null},"organization":{"id":"org_1","name":"Acme Inc."},"role":null,"agent":{}}`,
		"another version":      `{"schemaVersion":2,"user":{"id":"user_1","email":"jane@example.com","name":null},"organization":{"id":"org_1","name":"Acme Inc."},"role":null,"agent":null}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method+" "+request.URL.Path != "GET /api/cli/v1/auth/session" {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		bearer, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		if !ok {
			response.WriteHeader(http.StatusUnauthorized)
			response.Write([]byte(`{"code":"AUTHENTICATION_REQUIRED","message":"Run oe auth login first."}`))
			return
		}
		response.Write([]byte(answers[bearer]))
	}))
	defer server.Close()
	client, err := New(server.URL+"/api/cli", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	person, err := client.Session(context.Background(), CredentialRequest{AccessToken: "person"})
	if err != nil || person.User.Email != "jane@example.com" || person.User.Name != "" || person.Organization.Name != "Acme Inc." ||
		person.Role != "" || person.Agent != nil {
		t.Fatalf("person session: %#v %v", person, err)
	}
	agent, err := client.Session(context.Background(), CredentialRequest{AccessToken: "agent"})
	if err != nil || agent.User.Name != "Jane Doe" || agent.Role != "admin" || agent.Agent == nil || agent.Agent.RegistrationID != "agent_reg_1" {
		t.Fatalf("agent session: %#v %v", agent, err)
	}
	for _, token := range []string{"no organization name", "no registration", "another version"} {
		if _, err := client.Session(context.Background(), CredentialRequest{AccessToken: token}); err == nil {
			t.Fatalf("the %s answer passed", token)
		}
	}
	_, err = client.Session(context.Background(), CredentialRequest{})
	if failure, ok := errors.AsType[*APIError](err); !ok || failure.Status != http.StatusUnauthorized || failure.Code != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("a read without a token: %v", err)
	}
}

func TestTermsRefusalsKeepTheDocumentsAndRejectAnUnknownState(t *testing.T) {
	var answer string
	var status int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(status)
		response.Write([]byte(answer))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	status, answer = http.StatusOK, `{"acceptedAt":null,"canAccept":true,"documents":[],"state":"pending"}`
	if _, err := client.Terms(context.Background(), CredentialRequest{}); err == nil || !strings.Contains(err.Error(), `unknown terms state "pending"`) {
		t.Fatalf("an unknown terms state was accepted: %v", err)
	}
	status = http.StatusConflict
	answer = `{"code":"TERMS_REQUIRED","message":"Your Organization has not accepted the Relay service terms. Accept them, then retry.","canAccept":true,"documents":[{"name":"Relay service terms","url":"https://open-e2ee.dev/legal/relay-terms/2026-08-26","version":"relay-2026-08-26"}]}`
	_, err = client.GetProject(context.Background(), CredentialRequest{}, "chat")
	refusal, ok := errors.AsType[*APIError](err)
	if !ok || refusal.Code != "TERMS_REQUIRED" || !refusal.CanAccept || len(refusal.Documents) != 1 {
		t.Fatalf("a terms refusal lost its documents: %#v", err)
	}
}

func TestProductionStandingDeployBodiesAndCardRefusalMatchTheConsole(t *testing.T) {
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/projects/chat":
			response.Write([]byte(`{"production":{"blockedBy":"card","canActivate":false,"cardOnFile":false,"state":"inactive"},"sandbox":{"attachmentRetentionSeconds":86400,"deliveryTtlSeconds":86400,"relayUrl":"https://sandbox.example/relay","revision":"2"},"slug":"chat","writer":"config"}`))
		case "POST /v1/deploys":
			body, _ := io.ReadAll(request.Body)
			bodies = append(bodies, string(body))
			response.WriteHeader(http.StatusConflict)
			response.Write([]byte(`{"code":"CARD_REQUIRED","message":"Add a card.","billingSetupUrl":"https://console.example/signal-relay/project_chat"}`))
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	project, err := client.GetProject(context.Background(), CredentialRequest{}, "chat")
	if err != nil || project.Production == nil || project.Production.State != ProductionInactive || project.Production.BlockedBy != BlockedByCard ||
		project.Production.CardOnFile || project.Production.RelayURL != "" || project.Sandbox.Revision != "2" || project.Sandbox.State != "" {
		t.Fatalf("project read lost the Production standing: %#v %v", project, err)
	}
	policy := RelayPolicyRequest{AttachmentRetentionSeconds: 86_400, DeliveryRetentionSeconds: 86_400}
	for _, request := range []DeployRequest{
		{Environment: "production", ExpectedRevision: "0", PlanID: "plan_production", Policy: policy, ProjectSlug: "chat", Writer: "config"},
		{Environment: "sandbox", ExpectedRevision: "2", PlanID: "plan_sandbox", Policy: policy, ProjectSlug: "chat", Writer: "config"},
	} {
		_, err = client.Deploy(context.Background(), CredentialRequest{OperationID: "operation"}, request)
		if refusal, ok := errors.AsType[*APIError](err); !ok || refusal.Code != "CARD_REQUIRED" || refusal.BillingSetupURL != "https://console.example/signal-relay/project_chat" {
			t.Fatalf("a card refusal lost its setup URL: %#v", err)
		}
	}
	// The console deploy route takes exactly these fields, and environment is
	// required for both environments.
	if len(bodies) != 2 ||
		bodies[0] != `{"environment":"production","expectedRevision":"0","planId":"plan_production","policy":{"attachmentRetentionSeconds":86400,"deliveryTtlSeconds":86400},"project":"chat","writer":"config"}` ||
		bodies[1] != `{"environment":"sandbox","expectedRevision":"2","planId":"plan_sandbox","policy":{"attachmentRetentionSeconds":86400,"deliveryTtlSeconds":86400},"project":"chat","writer":"config"}` {
		t.Fatalf("deploy bodies %q", bodies)
	}
}
