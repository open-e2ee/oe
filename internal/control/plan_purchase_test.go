package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// planServer serves the plan routes of project chat. It records the method,
// path, credential source header, and body of each request.
type planServer struct {
	mu       sync.Mutex
	requests []string
	sources  []string
	bodies   []string
	// serve answers one request. attempt counts the requests to its path.
	serve func(response http.ResponseWriter, request *http.Request, attempt int)
}

func newPlanServer(t *testing.T, serve func(http.ResponseWriter, *http.Request, int)) (*Client, *planServer) {
	t.Helper()
	plans := &planServer{serve: serve}
	attempts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		plans.mu.Lock()
		route := request.Method + " " + request.URL.EscapedPath()
		plans.requests = append(plans.requests, route)
		plans.sources = append(plans.sources, request.Header.Get("OpenE2EE-CLI-Credential-Source"))
		body, _ := io.ReadAll(request.Body)
		plans.bodies = append(plans.bodies, string(body))
		attempts[route]++
		attempt := attempts[route]
		plans.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		plans.serve(response, request, attempt)
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client, plans
}

func TestPlanRoutesUseTheConsoleShapes(t *testing.T) {
	client, server := newPlanServer(t, func(response http.ResponseWriter, request *http.Request, _ int) {
		switch request.Method + " " + request.URL.EscapedPath() {
		case "GET /v1/projects/chat/plans":
			response.Write([]byte(`{"project":"chat","blockedBy":"","currentPlan":{"id":"relay_free_v1","name":"Free"},` +
				`"plans":[{"id":"relay_hobby_v1","name":"Hobby"}],"openPurchase":null}`))
		case "POST /v1/projects/chat/plan/quote":
			response.Write([]byte(`{"amountDue":4900,"tax":{"automatic":true,"subtotal":4900,"amount":490,"total":5390},"total":4900,` +
				`"currency":"usd","timing":"immediate","effectiveAtMilliseconds":1,"renewsAtMilliseconds":2,"paymentMethodRequired":false,` +
				`"pricePreviewId":"preview","confirmationToken":"token","quoteExpiresAtMilliseconds":3}`))
		case "POST /v1/projects/chat/plan/purchases":
			response.Write([]byte(`{"purchaseId":"purchase_1","state":"accepted","status":"in_progress","message":"accepted"}`))
		case "GET /v1/projects/chat/plan/purchases/purchase_1":
			response.Write([]byte(`{"purchaseId":"purchase_1","state":"failed","status":"failed","message":"failed",` +
				`"failure":{"code":"PAYMENT_FAILED","message":"declined","billingSetupUrl":"https://console.example/billing"}}`))
		default:
			http.Error(response, `{"code":"NOT_FOUND"}`, http.StatusNotFound)
		}
	})
	ctx, credential := context.Background(), CredentialRequest{AccessToken: "session"}
	plans, err := client.ProjectPlans(ctx, credential, "chat")
	if err != nil || plans.CurrentPlan == nil || plans.CurrentPlan.ID != "relay_free_v1" || len(plans.Plans) != 1 || plans.OpenPurchase != nil {
		t.Fatalf("plans became %+v, %v", plans, err)
	}
	quote, err := client.QuotePlan(ctx, credential, "chat", PlanQuoteRequest{TargetPlanID: "relay_hobby_v1"})
	if err != nil || quote.Charge() != (ChargeAmount{Amount: 5390, Currency: "usd"}) || quote.ConfirmationToken != "token" {
		t.Fatalf("quote became %+v, %v", quote, err)
	}
	purchase, err := client.PurchasePlan(ctx, credential, "chat", PlanPurchaseRequest{ConfirmationToken: "token", ConfirmedCharge: quote.Charge()})
	if err != nil || purchase.PurchaseID != "purchase_1" || purchase.Status != PurchaseInProgress {
		t.Fatalf("purchase became %+v, %v", purchase, err)
	}
	status, err := client.PurchaseStatus(ctx, credential, "chat", "purchase_1")
	if err != nil || status.Status != PurchaseFailed || status.Failure == nil || status.Failure.BillingSetupURL != "https://console.example/billing" {
		t.Fatalf("status became %+v, %v", status, err)
	}
	if server.bodies[1] != `{"targetPlanId":"relay_hobby_v1"}` ||
		server.bodies[2] != `{"confirmationToken":"token","confirmedCharge":{"amount":5390,"currency":"usd"}}` {
		t.Fatalf("the request bodies were %q", server.bodies)
	}
}

func TestQuoteChargeIsTheTaxTotalWhenTaxIsPresent(t *testing.T) {
	if got := (PlanQuote{AmountDue: 4900, Currency: "usd"}).Charge(); got != (ChargeAmount{Amount: 4900, Currency: "usd"}) {
		t.Fatalf("an untaxed quote charged %+v", got)
	}
	taxed := PlanQuote{AmountDue: 4900, Currency: "eur", Tax: &PlanQuoteTax{Subtotal: 4900, Amount: 931, Total: 5831}}
	if got := taxed.Charge(); got != (ChargeAmount{Amount: 5831, Currency: "eur"}) {
		t.Fatalf("a taxed quote charged %+v", got)
	}
}

func TestEachRequestSendsTheCredentialSourceOnlyForTheEnvironment(t *testing.T) {
	client, server := newPlanServer(t, func(response http.ResponseWriter, _ *http.Request, _ int) {
		response.Write([]byte(`{}`))
	})
	ctx, credential := context.Background(), CredentialRequest{AccessToken: "token"}
	for _, source := range []string{"", "keychain", "environment"} {
		client.SetCredentialSource(source)
		// A project read and a plan read stand for every control request.
		_, _ = client.GetProject(ctx, credential, "chat")
		if _, err := client.ProjectPlans(ctx, credential, "chat"); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"", "", "", "", "environment", "environment"}
	if strings.Join(server.sources, ",") != strings.Join(want, ",") {
		t.Fatalf("the credential sources were %q, want %q", server.sources, want)
	}
	if len(server.requests) != len(want) || server.requests[0] != "GET /v1/projects/chat" {
		t.Fatalf("the requests were %q", server.requests)
	}
}

func TestPurchaseIsSentAgainAfterATransientFailureAndAQuoteIsNot(t *testing.T) {
	client, server := newPlanServer(t, func(response http.ResponseWriter, request *http.Request, attempt int) {
		if attempt == 1 {
			http.Error(response, `{"code":"temporary","message":"try later"}`, http.StatusServiceUnavailable)
			return
		}
		response.Write([]byte(`{"purchaseId":"purchase_1","status":"in_progress"}`))
	})
	ctx, credential := context.Background(), CredentialRequest{AccessToken: "token"}
	if _, err := client.QuotePlan(ctx, credential, "chat", PlanQuoteRequest{TargetPlanID: "relay_hobby_v1"}); err == nil {
		t.Fatal("a refused quote succeeded")
	}
	purchase, err := client.PurchasePlan(ctx, credential, "chat", PlanPurchaseRequest{ConfirmationToken: "quote"})
	if err != nil || purchase.PurchaseID != "purchase_1" {
		t.Fatalf("the purchase became %+v, %v", purchase, err)
	}
	want := "POST /v1/projects/chat/plan/quote,POST /v1/projects/chat/plan/purchases,POST /v1/projects/chat/plan/purchases"
	if strings.Join(server.requests, ",") != want {
		t.Fatalf("the requests were %q", server.requests)
	}
	if server.bodies[1] != server.bodies[2] {
		t.Fatalf("the purchase was sent again with another body: %q", server.bodies)
	}
}

func TestPurchaseRefusalKeepsItsFieldsAndRedactsTheToken(t *testing.T) {
	const token = "quote-secret-token"
	client, _ := newPlanServer(t, func(response http.ResponseWriter, _ *http.Request, _ int) {
		response.WriteHeader(http.StatusConflict)
		json.NewEncoder(response).Encode(map[string]any{
			"code": "CHARGE_CONFIRMATION_MISMATCH", "message": "token " + token + " confirmed another charge",
			"detail": "token:" + token, "purchaseId": "purchase_1", "expected": map[string]any{"amount": 5390, "currency": "usd"},
		})
	})
	_, err := client.PurchasePlan(context.Background(), CredentialRequest{AccessToken: "session-access"}, "chat", PlanPurchaseRequest{ConfirmationToken: token})
	refusal, ok := errors.AsType[*APIError](err)
	if !ok || refusal.Code != "CHARGE_CONFIRMATION_MISMATCH" || refusal.PurchaseID != "purchase_1" ||
		refusal.Expected == nil || *refusal.Expected != (ChargeAmount{Amount: 5390, Currency: "usd"}) {
		t.Fatalf("the refusal became %#v", err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(refusal.Detail, token) || refusal.Detail != "token:[redacted]" {
		t.Fatalf("the refusal named the token: %q %q", err.Error(), refusal.Detail)
	}
}
