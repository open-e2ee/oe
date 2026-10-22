package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProjectUsageReadsAuthenticatedEnvironment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.EscapedPath() != "/api/cli/v1/projects/my-chat/usage" ||
			request.URL.Query().Get("environment") != "production" || request.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("unexpected usage request: %s %s %s", request.Method, request.URL, request.Header.Get("Authorization"))
		}
		fmt.Fprint(response, `{"project":"my-chat","environment":"production","period":"2026-10","status":"no_usage","reported":{"deliveryUnits":"0","attachmentOperations":"0","relayMau":"0","liveBytes":"0"},"coverage":{"kind":"registered-sources-only","registeredSources":0,"reportedSources":0},"limits":null}`)
	}))
	defer server.Close()
	client, err := New(server.URL+"/api/cli", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	usage, err := client.ProjectUsage(context.Background(), CredentialRequest{AccessToken: "secret-token"}, "my-chat", "production")
	if err != nil || usage.Status != "no_usage" || usage.Reported == nil || usage.Reported.LiveBytes != "0" {
		t.Fatalf("usage read failed: %#v %v", usage, err)
	}
}
