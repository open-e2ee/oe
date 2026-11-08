package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
)

const (
	upgradeSlug       = "acme-chat"
	upgradeQuoteToken = "quote-secret-7f3a9c"
	upgradePlanPage   = "https://console.open-e2ee.dev/signal-relay"
	upgradeTarget     = "relay_starter_v1"
)

var (
	freePlan    = control.PlanOffer{ID: "relay_free_v1", Name: "Free"}
	hobbyPlan   = control.PlanOffer{ID: "relay_hobby_v1", Name: "Hobby"}
	starterPlan = control.PlanOffer{ID: upgradeTarget, Name: "Starter"}
	// environmentCredential is OPEN_E2EE_ACCESS_TOKEN with the read scope.
	environmentCredential = map[string]string{"OPEN_E2EE_ACCESS_TOKEN": "ci-token", "OPEN_E2EE_ACCESS_TOKEN_SCOPES": "project:read"}
)

// purchaseIDFor is the purchase ID that the fake control API gives a
// confirmation token. The same token always names the same purchase.
func purchaseIDFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "purchase_" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// upgradeRefusal is a refusal of one plan route: its HTTP status and its body.
type upgradeRefusal struct {
	status int
	body   map[string]any
}

// upgradeConsole is a control API that serves the project and plan routes of
// one project over HTTP and counts the requests of each plan route.
type upgradeConsole struct {
	t  *testing.T
	mu sync.Mutex
	// plans are the answers of the plan reads in order. The last one repeats.
	plans []control.ProjectPlans
	quote control.PlanQuote
	// purchase is the answer of a purchase POST, without its purchase ID.
	purchase control.PlanPurchase
	// statuses are the answers of the purchase reads in order. The last one
	// repeats.
	statuses []control.PlanPurchase
	// refusals refuse a route by name: plans, quote, or purchase.
	refusals map[string]upgradeRefusal

	planReads, quotes, purchases, statusReads int
	quoteTargets                              []string
	bodies                                    []control.PlanPurchaseRequest
	// sources are the OpenE2EE-CLI-Credential-Source headers of the plan
	// route requests.
	sources []string

	api    control.API
	client *http.Client
}

func newUpgradeConsole(t *testing.T) *upgradeConsole {
	t.Helper()
	renews := int64(1_792_592_000_000)
	console := &upgradeConsole{
		t:     t,
		plans: []control.ProjectPlans{{Project: upgradeSlug, CurrentPlan: &freePlan, Plans: []control.PlanOffer{hobbyPlan, starterPlan}}},
		quote: control.PlanQuote{
			AmountDue: 4900, Tax: &control.PlanQuoteTax{Automatic: true, Subtotal: 4900, Amount: 490, Total: 5390},
			Total: 4900, Currency: "usd", Timing: control.TimingImmediate,
			EffectiveAtMilliseconds: 1_790_000_000_000, RenewsAtMilliseconds: &renews,
			PricePreviewID: "preview_1", ConfirmationToken: upgradeQuoteToken, QuoteExpiresAtMilliseconds: 1_790_000_600_000,
		},
		purchase: control.PlanPurchase{State: "accepted", Status: control.PurchaseInProgress, Message: "The purchase is in progress."},
		statuses: []control.PlanPurchase{{State: "fulfilled", Status: control.PurchaseFulfilled, PlanID: upgradeTarget, Message: "The plan changed."}},
		refusals: map[string]upgradeRefusal{},
	}
	base := "/v1/projects/" + upgradeSlug
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base, func(response http.ResponseWriter, request *http.Request) {
		_ = json.NewEncoder(response).Encode(control.Project{
			Slug: upgradeSlug, Writer: "config", Sandbox: projectEnvironment(sandboxSignalProtocolRelayURL, "3"),
		})
	})
	mux.HandleFunc("GET "+base+"/plans", console.handle("plans", func(response http.ResponseWriter, _ *http.Request) {
		answer := console.plans[min(console.planReads, len(console.plans)-1)]
		console.planReads++
		_ = json.NewEncoder(response).Encode(answer)
	}))
	mux.HandleFunc("POST "+base+"/plan/quote", console.handle("quote", func(response http.ResponseWriter, request *http.Request) {
		var body control.PlanQuoteRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode quote request: %v", err)
		}
		console.quotes++
		console.quoteTargets = append(console.quoteTargets, body.TargetPlanID)
		_ = json.NewEncoder(response).Encode(console.quote)
	}))
	mux.HandleFunc("POST "+base+"/plan/purchases", console.handle("purchase", func(response http.ResponseWriter, request *http.Request) {
		var body control.PlanPurchaseRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode purchase request: %v", err)
		}
		console.purchases++
		console.bodies = append(console.bodies, body)
		answer := console.purchase
		answer.PurchaseID = purchaseIDFor(body.ConfirmationToken)
		_ = json.NewEncoder(response).Encode(answer)
	}))
	mux.HandleFunc("GET "+base+"/plan/purchases/{id}", console.handle("status", func(response http.ResponseWriter, request *http.Request) {
		answer := console.statuses[min(console.statusReads, len(console.statuses)-1)]
		console.statusReads++
		answer.PurchaseID = request.PathValue("id")
		_ = json.NewEncoder(response).Encode(answer)
	}))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	api, err := control.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	console.api, console.client = api, server.Client()
	return console
}

// handle records the credential source of a plan route request, answers the
// refusal of the route when one is set, and serves the route otherwise.
func (c *upgradeConsole) handle(route string, serve http.HandlerFunc) http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if authorization := request.Header.Get("Authorization"); authorization != "Bearer test-token" && authorization != "Bearer ci-token" {
			http.Error(response, `{"code":"AUTHENTICATION_REQUIRED"}`, http.StatusUnauthorized)
			return
		}
		c.sources = append(c.sources, request.Header.Get("OpenE2EE-CLI-Credential-Source"))
		if refusal, ok := c.refusals[route]; ok {
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(refusal.status)
			_ = json.NewEncoder(response).Encode(refusal.body)
			return
		}
		serve(response, request)
	}
}

// dependencies runs oe against the console with a stored session. env is the
// process environment, so a test chooses whether an agent runs oe.
func (c *upgradeConsole) dependencies(env map[string]string) Dependencies {
	store := credential.NewMemory()
	storeCredential(c.t, store, "project:read")
	return Dependencies{
		API: c.api, HTTP: c.client, Store: store, Getenv: environment(env),
		In: unreadable{c.t}, Interactive: func() bool { return false },
		Sleep: func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		OpenURL: func(target string) error {
			c.t.Errorf("project upgrade opened %s", target)
			return nil
		},
	}
}

// upgrade runs oe project upgrade for the target plan with extra arguments.
func (c *upgradeConsole) upgrade(t *testing.T, env map[string]string, extra ...string) (int, string, string) {
	t.Helper()
	return run(t, c.dependencies(env), append([]string{"project", "upgrade", upgradeSlug, "--plan", upgradeTarget}, extra...)...)
}

func noTokenIn(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		if strings.Contains(output, upgradeQuoteToken) {
			t.Fatalf("the output names the quote token: %s", output)
		}
	}
}

func TestProjectUpgradeDryRunNamesTheTokenOnlyInJSONData(t *testing.T) {
	console := newUpgradeConsole(t)
	exit, stdout, stderr := console.upgrade(t, nil, "--json", "--dry-run")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Status != "ok" || result.Next != "oe project upgrade acme-chat --plan relay_starter_v1 --confirm-charge 53.90" {
		t.Fatalf("the dry run did not name the confirmed purchase as next: exit=%d %s %s", exit, stdout, stderr)
	}
	if result.Data["quote"] != upgradeQuoteToken || result.Data["total"] != 5390.0 || result.Data["totalMajor"] != "53.90" ||
		result.Data["currency"] != "usd" || result.Data["amountDue"] != 4900.0 {
		t.Fatalf("the dry run data is not the quote: %s", stdout)
	}
	if current, _ := result.Data["currentPlan"].(map[string]any); current["id"] != freePlan.ID {
		t.Fatalf("the dry run did not name the current plan: %s", stdout)
	}
	if strings.Contains(result.Message, upgradeQuoteToken) || strings.Contains(result.Next, upgradeQuoteToken) {
		t.Fatalf("the message or next names the quote token: %s", stdout)
	}
	if console.quotes != 1 || console.purchases != 0 || !slices.Equal(console.quoteTargets, []string{upgradeTarget}) {
		t.Fatalf("the dry run made %d quotes for %v and %d purchases", console.quotes, console.quoteTargets, console.purchases)
	}

	exit, stdout, stderr = console.upgrade(t, nil, "--dry-run")
	if exit != 0 || !strings.Contains(stdout, "total: 53.90 USD") || !strings.Contains(stdout, "tax: 4.90 USD") ||
		!strings.Contains(stdout, "next: oe project upgrade acme-chat --plan relay_starter_v1 --confirm-charge 53.90") {
		t.Fatalf("the text dry run did not show the quote and next: exit=%d %s %s", exit, stdout, stderr)
	}
	noTokenIn(t, stdout, stderr)
	if console.purchases != 0 {
		t.Fatalf("a dry run made %d purchases", console.purchases)
	}
}

func TestProjectUpgradeDryRunOfALaterChangeNamesNoPurchase(t *testing.T) {
	console := newUpgradeConsole(t)
	console.quote.Timing = "period_end"
	exit, stdout, _ := console.upgrade(t, nil, "--json", "--dry-run")
	result := decodeEvent(t, []byte(stdout))
	if exit != 0 || result.Next != "" || !strings.Contains(result.Message, upgradePlanPage) {
		t.Fatalf("a later change named a purchase: exit=%d %s", exit, stdout)
	}
}

func TestProjectUpgradeUnderAnAgentNeverPostsAPurchase(t *testing.T) {
	agent := map[string]string{"CLAUDECODE": "1"}
	for name, extra := range map[string][]string{
		"quote":              {"--confirm-charge", "53.90", "--yes"},
		"confirmation token": {"--quote", upgradeQuoteToken, "--confirm-charge", "53.90usd", "--yes"},
	} {
		t.Run(name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			exit, stdout, stderr := console.upgrade(t, agent, extra...)
			result := decodeEvent(t, []byte(stdout))
			if exit != exitPersonAction || result.Status != "pending" || result.Next != "oe project upgrade acme-chat --plan relay_starter_v1 --wait" {
				t.Fatalf("an agent run did not hand the purchase to a person: exit=%d %s %s", exit, stdout, stderr)
			}
			if result.Action.Kind != "browser" || result.Action.URL != upgradePlanPage || result.Action.Reason != "purchase" {
				t.Fatalf("an agent run did not name the plan page: %s", stdout)
			}
			if _, ok := result.Data["quote"]; ok {
				t.Fatalf("an agent run named the quote token in data: %s", stdout)
			}
			noTokenIn(t, stdout, stderr)
			if console.purchases != 0 {
				t.Fatalf("an agent run made %d purchases", console.purchases)
			}
		})
	}
}

func TestProjectUpgradeUnderAnAgentQuotesForThePerson(t *testing.T) {
	console := newUpgradeConsole(t)
	exit, stdout, _ := console.upgrade(t, map[string]string{"CLAUDECODE": "1"})
	result := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || result.Data["total"] != 5390.0 || !strings.Contains(result.Message, "53.90 USD") || console.quotes != 1 {
		t.Fatalf("an agent run did not show the quote total: exit=%d quotes=%d %s", exit, console.quotes, stdout)
	}
}

func TestProjectUpgradeUnderAnAgentWaitsForThePersonPurchase(t *testing.T) {
	console := newUpgradeConsole(t)
	open := console.plans[0]
	open.OpenPurchase = &control.OpenPurchase{ID: purchaseIDFor("person"), State: "accepted"}
	changed := control.ProjectPlans{Project: upgradeSlug, CurrentPlan: &starterPlan, Plans: []control.PlanOffer{}}
	console.plans = append(console.plans, open, changed)
	// The person authenticates the payment in the Console, so the wait goes on.
	console.statuses = []control.PlanPurchase{{Status: control.PurchaseRequiresAction, RequiresActionURL: upgradePlanPage + "/acme-chat/plan"}}
	exit, stdout, stderr := console.upgrade(t, map[string]string{"CLAUDECODE": "1"}, "--wait")
	events := decodeEvents(t, stdout)
	if exit != 0 || len(events) != 2 || events[0].Status != "pending" || events[0].Next != "" || events[0].Action.URL != upgradePlanPage {
		t.Fatalf("an agent wait did not write the handoff first: exit=%d %s %s", exit, stdout, stderr)
	}
	if events[1].Status != "ok" || events[1].Data["changed"] != true || console.purchases != 0 || console.statusReads != 1 {
		t.Fatalf("an agent wait did not end on the plan change: purchases=%d reads=%d %s", console.purchases, console.statusReads, stdout)
	}
}

func TestProjectUpgradeUnderAnAgentStopsWhenThePersonPurchaseFails(t *testing.T) {
	console := newUpgradeConsole(t)
	open := console.plans[0]
	open.OpenPurchase = &control.OpenPurchase{ID: purchaseIDFor("person"), State: "accepted"}
	console.plans = append(console.plans, open)
	console.statuses = []control.PlanPurchase{{
		Status: control.PurchaseFailed,
		Failure: &control.PlanPurchaseFailure{
			Code: "PAYMENT_FAILED", Message: "The card was declined.", BillingSetupURL: "https://console.open-e2ee.dev/billing",
		},
	}}
	exit, stdout, _ := console.upgrade(t, map[string]string{"CLAUDECODE": "1"}, "--wait")
	events := decodeEvents(t, stdout)
	last := events[len(events)-1]
	if exit != exitPersonAction || last.Code != "PAYMENT_FAILED" || last.Action.URL != "https://console.open-e2ee.dev/billing" || last.Action.Reason != "billing" {
		t.Fatalf("a failed person purchase did not end the agent wait: exit=%d %s", exit, stdout)
	}
}

func TestProjectUpgradeWithAnEnvironmentCredentialBuysNothing(t *testing.T) {
	console := newUpgradeConsole(t)
	exit, stdout, stderr := console.upgrade(t, environmentCredential, "--json", "--confirm-charge", "53.90", "--yes")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitPersonAction || result.Code != "AGENT_PURCHASE_NOT_ALLOWED" || result.Action.URL != upgradePlanPage || result.Action.Reason != "purchase" {
		t.Fatalf("an environment credential was not refused: exit=%d %s %s", exit, stdout, stderr)
	}
	if console.quotes != 0 || console.purchases != 0 {
		t.Fatalf("an environment credential made %d quotes and %d purchases", console.quotes, console.purchases)
	}
	if !slices.Equal(console.sources, []string{"environment"}) {
		t.Fatalf("the plans read sent the credential sources %q", console.sources)
	}

	exit, stdout, _ = console.upgrade(t, environmentCredential, "--json", "--dry-run")
	if exit != 0 || decodeEvent(t, []byte(stdout)).Data["quote"] != upgradeQuoteToken {
		t.Fatalf("an environment credential could not quote: exit=%d %s", exit, stdout)
	}
	if !slices.Equal(console.sources, []string{"environment", "environment", "environment"}) {
		t.Fatalf("the dry run sent the credential sources %q", console.sources)
	}
}

func TestProjectUpgradeRefusesAChargeThatIsNotTheQuoteTotal(t *testing.T) {
	for _, test := range []struct {
		charge, code string
	}{
		{"49.00", "CHARGE_CONFIRMATION_MISMATCH"},
		{"53.90eur", "CHARGE_CONFIRMATION_MISMATCH"},
		{"53.91 usd", "CHARGE_CONFIRMATION_MISMATCH"},
		{"53.905", "USAGE_ERROR"},
	} {
		t.Run(test.charge, func(t *testing.T) {
			console := newUpgradeConsole(t)
			exit, stdout, _ := console.upgrade(t, nil, "--json", "--confirm-charge", test.charge)
			result := decodeEvent(t, []byte(stdout))
			if exit != exitUsage || result.Code != test.code {
				t.Fatalf("--confirm-charge %s became exit=%d %s", test.charge, exit, stdout)
			}
			if console.purchases != 0 {
				t.Fatalf("--confirm-charge %s made %d purchases", test.charge, console.purchases)
			}
			if test.code == "CHARGE_CONFIRMATION_MISMATCH" {
				expected, _ := result.Data["expected"].(map[string]any)
				if result.Next != "" || expected["amount"] != 5390.0 || expected["currency"] != "usd" || expected["major"] != "53.90" {
					t.Fatalf("the mismatch did not name the quote total: %s", stdout)
				}
			}
		})
	}
}

func TestProjectUpgradeWithoutAConfirmedChargeBuysNothing(t *testing.T) {
	for name, extra := range map[string][]string{"no flags": nil, "yes": {"--yes"}} {
		t.Run(name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			exit, stdout, _ := console.upgrade(t, nil, append([]string{"--json"}, extra...)...)
			result := decodeEvent(t, []byte(stdout))
			if exit != exitUsage || result.Code != "CONFIRMATION_REQUIRED" || result.Next != "" ||
				!strings.Contains(result.Error, "oe project upgrade acme-chat --plan relay_starter_v1 --dry-run") {
				t.Fatalf("a run without --confirm-charge became exit=%d %s", exit, stdout)
			}
			if console.quotes != 0 || console.purchases != 0 {
				t.Fatalf("a run without --confirm-charge made %d quotes and %d purchases", console.quotes, console.purchases)
			}
		})
	}
}

func TestProjectUpgradeBuysAtTheConfirmedQuoteTotal(t *testing.T) {
	console := newUpgradeConsole(t)
	console.statuses = []control.PlanPurchase{{Status: control.PurchaseInProgress}, {Status: control.PurchaseFulfilled}}
	exit, stdout, stderr := console.upgrade(t, nil, "--json", "--confirm-charge", "53.9")
	result := decodeEvent(t, []byte(stdout))
	charge, _ := result.Data["charge"].(map[string]any)
	if exit != 0 || result.Data["changed"] != true || result.Data["purchaseId"] != purchaseIDFor(upgradeQuoteToken) ||
		charge["amount"] != 5390.0 || charge["currency"] != "usd" {
		t.Fatalf("the confirmed purchase did not end on the plan: exit=%d %s %s", exit, stdout, stderr)
	}
	want := []control.PlanPurchaseRequest{{ConfirmationToken: upgradeQuoteToken, ConfirmedCharge: control.ChargeAmount{Amount: 5390, Currency: "usd"}}}
	if !reflect.DeepEqual(console.bodies, want) || console.statusReads != 2 {
		t.Fatalf("the purchase sent %+v and read %d statuses", console.bodies, console.statusReads)
	}
	if slices.ContainsFunc(console.sources, func(source string) bool { return source != "" }) {
		t.Fatalf("a stored session sent the credential sources %q", console.sources)
	}
	noTokenIn(t, stderr)
}

func TestProjectUpgradeRequiresActionExitsFiveWithThePaymentPage(t *testing.T) {
	page := upgradePlanPage + "/acme-chat/plan?purchase=" + purchaseIDFor(upgradeQuoteToken)
	requiresAction := control.PlanPurchase{Status: control.PurchaseRequiresAction, RequiresActionURL: page, Message: "The bank asks the person to authenticate the payment."}
	for name, setup := range map[string]func(*upgradeConsole){
		"purchase answer": func(c *upgradeConsole) { c.purchase = requiresAction },
		"status read":     func(c *upgradeConsole) { c.statuses = []control.PlanPurchase{requiresAction} },
	} {
		t.Run(name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			setup(console)
			exit, stdout, _ := console.upgrade(t, nil, "--json", "--confirm-charge", "53.90")
			result := decodeEvent(t, []byte(stdout))
			if exit != exitPersonAction || result.Code != "PAYMENT_ACTION_REQUIRED" || result.Action.URL != page ||
				result.Action.Reason != "payment" || result.Next != "" || result.Data["purchaseId"] != purchaseIDFor(upgradeQuoteToken) {
				t.Fatalf("requires_action became exit=%d %s", exit, stdout)
			}
		})
	}
}

func TestProjectUpgradeResendsTheSamePurchaseForTheSameQuote(t *testing.T) {
	console := newUpgradeConsole(t)
	console.purchase = control.PlanPurchase{Status: control.PurchaseFulfilled}
	var ids []any
	for range 2 {
		exit, stdout, stderr := console.upgrade(t, nil, "--json", "--quote", upgradeQuoteToken, "--confirm-charge", "53.90usd")
		if exit != 0 {
			t.Fatalf("the resend failed: exit=%d %s %s", exit, stdout, stderr)
		}
		noTokenIn(t, stdout, stderr)
		ids = append(ids, decodeEvent(t, []byte(stdout)).Data["purchaseId"])
	}
	if ids[0] != purchaseIDFor(upgradeQuoteToken) || ids[1] != ids[0] || console.quotes != 0 || console.purchases != 2 {
		t.Fatalf("the resend named purchases %v after %d quotes and %d purchases", ids, console.quotes, console.purchases)
	}
	if console.bodies[0] != console.bodies[1] || console.bodies[0].ConfirmedCharge != (control.ChargeAmount{Amount: 5390, Currency: "usd"}) {
		t.Fatalf("the resend sent %+v", console.bodies)
	}

	exit, stdout, _ := console.upgrade(t, nil, "--json", "--quote", upgradeQuoteToken, "--confirm-charge", "53.90")
	if exit != exitUsage || decodeEvent(t, []byte(stdout)).Code != "USAGE_ERROR" || console.purchases != 2 {
		t.Fatalf("--quote without a currency became exit=%d %s", exit, stdout)
	}
	noTokenIn(t, stdout)
}

func TestProjectUpgradeAsksAPersonAtATerminal(t *testing.T) {
	for _, test := range []struct {
		answer    string
		exit      int
		purchases int
	}{
		{"y\n", 0, 1},
		{"n\n", exitFailure, 0},
	} {
		t.Run(strings.TrimSpace(test.answer), func(t *testing.T) {
			console := newUpgradeConsole(t)
			console.purchase = control.PlanPurchase{Status: control.PurchaseFulfilled}
			dependencies := console.dependencies(nil)
			dependencies.Interactive, dependencies.In = terminal, strings.NewReader(test.answer)
			exit, stdout, stderr := run(t, dependencies, "project", "upgrade", upgradeSlug, "--plan", upgradeTarget)
			if exit != test.exit || console.purchases != test.purchases {
				t.Fatalf("answer %q became exit=%d purchases=%d %s %s", test.answer, exit, console.purchases, stdout, stderr)
			}
			if !strings.Contains(stderr, "total: 53.90 USD") || !strings.Contains(stderr, "charge 53.90 USD now? [y/N]") {
				t.Fatalf("the prompt did not show the quote total: %s", stderr)
			}
			if test.purchases == 1 && console.bodies[0].ConfirmedCharge != (control.ChargeAmount{Amount: 5390, Currency: "usd"}) {
				t.Fatalf("the prompt purchase confirmed %+v", console.bodies[0].ConfirmedCharge)
			}
			if test.purchases == 0 && !strings.Contains(stderr, "was cancelled; nothing was charged") {
				t.Fatalf("a declined prompt did not say that nothing was charged: %s %s", stdout, stderr)
			}
			noTokenIn(t, stdout, stderr)
		})
	}
}

func TestProjectUpgradeTimesOutWhileThePurchaseIsPending(t *testing.T) {
	console := newUpgradeConsole(t)
	console.statuses = []control.PlanPurchase{{Status: control.PurchaseInProgress}}
	dependencies := console.dependencies(nil)
	dependencies.Sleep = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	exit, stdout, _ := run(t, dependencies, "--json", "project", "upgrade", upgradeSlug, "--plan", upgradeTarget, "--confirm-charge", "53.90", "--timeout", "10ms")
	result := decodeEvent(t, []byte(stdout))
	if exit != exitTemporary || result.Code != "PURCHASE_PENDING" || result.Next != "oe project show acme-chat" ||
		result.Data["purchaseId"] != purchaseIDFor(upgradeQuoteToken) {
		t.Fatalf("a pending purchase became exit=%d %s", exit, stdout)
	}
}

func TestProjectUpgradeChecksThePlanBeforeAQuote(t *testing.T) {
	t.Run("not available", func(t *testing.T) {
		console := newUpgradeConsole(t)
		exit, stdout, _ := run(t, console.dependencies(nil), "--json", "project", "upgrade", upgradeSlug, "--plan", "relay_business_v1", "--confirm-charge", "1")
		result := decodeEvent(t, []byte(stdout))
		if exit != exitFailure || result.Code != "PLAN_NOT_AVAILABLE" || !reflect.DeepEqual(result.Data["plans"], []any{hobbyPlan.ID, starterPlan.ID}) || console.quotes != 0 {
			t.Fatalf("an unavailable plan became exit=%d quotes=%d %s", exit, console.quotes, stdout)
		}
	})
	t.Run("already on plan", func(t *testing.T) {
		console := newUpgradeConsole(t)
		console.plans[0].CurrentPlan = &starterPlan
		exit, stdout, _ := console.upgrade(t, nil, "--json", "--confirm-charge", "53.90")
		result := decodeEvent(t, []byte(stdout))
		if exit != 0 || result.Data["changed"] != false || console.quotes != 0 || console.purchases != 0 {
			t.Fatalf("the current plan became exit=%d %s", exit, stdout)
		}
	})
	t.Run("billing permission", func(t *testing.T) {
		console := newUpgradeConsole(t)
		console.plans = []control.ProjectPlans{{Project: upgradeSlug, BlockedBy: control.BlockedByBillingPermission}}
		exit, stdout, _ := console.upgrade(t, nil, "--json", "--dry-run")
		result := decodeEvent(t, []byte(stdout))
		if exit != exitPersonAction || result.Code != "BILLING_PERMISSION_REQUIRED" || result.Action.Reason != "purchase" || console.quotes != 0 {
			t.Fatalf("a session without the billing permission became exit=%d %s", exit, stdout)
		}
	})
	t.Run("later change", func(t *testing.T) {
		console := newUpgradeConsole(t)
		console.quote.Timing = "period_end"
		exit, stdout, _ := console.upgrade(t, nil, "--json", "--confirm-charge", "53.90")
		result := decodeEvent(t, []byte(stdout))
		if exit != exitPersonAction || result.Code != "PURCHASE_NOT_IMMEDIATE" || result.Action.URL != upgradePlanPage || console.purchases != 0 {
			t.Fatalf("a later change became exit=%d %s", exit, stdout)
		}
	})
}

func TestProjectUpgradeUsageErrors(t *testing.T) {
	for name, extra := range map[string][]string{
		"dry run with quote":  {"--dry-run", "--quote", upgradeQuoteToken},
		"dry run with charge": {"--dry-run", "--confirm-charge", "53.90"},
		"dry run with wait":   {"--dry-run", "--wait"},
		"not an amount":       {"--confirm-charge", "fifty"},
		"four decimal places": {"--confirm-charge", "53.9000"},
		"negative amount":     {"--confirm-charge", "-53.90"},
		"zero timeout":        {"--confirm-charge", "53.90", "--timeout", "0s"},
		"second project":      {"other-chat"},
	} {
		t.Run(name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			exit, stdout, _ := console.upgrade(t, nil, append([]string{"--json"}, extra...)...)
			if exit != exitUsage || decodeEvent(t, []byte(stdout)).Code != "USAGE_ERROR" || console.quotes != 0 || console.purchases != 0 {
				t.Fatalf("%v became exit=%d %s", extra, exit, stdout)
			}
			noTokenIn(t, stdout)
		})
	}
	t.Run("missing plan", func(t *testing.T) {
		exit, stdout, _ := run(t, Dependencies{Getenv: environment(nil)}, "--json", "project", "upgrade", upgradeSlug)
		if exit != exitUsage || decodeEvent(t, []byte(stdout)).Code != "USAGE_ERROR" {
			t.Fatalf("a run without --plan became exit=%d %s", exit, stdout)
		}
	})
}

func TestProjectUpgradeTakesTheProjectFromTheConfig(t *testing.T) {
	console := newUpgradeConsole(t)
	dependencies := console.dependencies(nil)
	dependencies.WorkingDir = initializedProject(t, upgradeSlug)
	exit, stdout, _ := run(t, dependencies, "--json", "project", "upgrade", "--plan", upgradeTarget, "--dry-run")
	if exit != 0 || decodeEvent(t, []byte(stdout)).Data["project"] != upgradeSlug {
		t.Fatalf("a run without PROJECT did not use the config project: exit=%d %s", exit, stdout)
	}
}

// upgradeRefusalCase drives one refusal of oe project upgrade.
type upgradeRefusalCase struct {
	name string
	// env is the process environment. It is a stored session when nil.
	env    map[string]string
	setup  func(*upgradeConsole)
	extra  []string
	code   string
	exit   int
	next   string
	reason string
	url    string
	// local is true when oe refuses before a purchase POST.
	local bool
}

func refused(route string, status int, body map[string]any) func(*upgradeConsole) {
	return func(c *upgradeConsole) { c.refusals[route] = upgradeRefusal{status: status, body: body} }
}

func TestProjectUpgradeMapsEachRefusalToItsExit(t *testing.T) {
	const (
		retry   = "oe project upgrade acme-chat --plan relay_starter_v1 --confirm-charge 53.90"
		requote = "oe project upgrade acme-chat --plan relay_starter_v1 --dry-run"
		billing = "https://console.open-e2ee.dev/billing"
	)
	page := upgradePlanPage + "/acme-chat/plan?purchase=" + purchaseIDFor(upgradeQuoteToken)
	charge := []string{"--confirm-charge", "53.90"}
	cases := []upgradeRefusalCase{
		{name: "QUOTE_EXPIRED", setup: refused("purchase", 409, map[string]any{"code": "QUOTE_EXPIRED", "message": "The quote expired."}), code: "QUOTE_EXPIRED", exit: 1, next: requote},
		{name: "PRICE_CHANGED", setup: refused("purchase", 409, map[string]any{"code": "PRICE_CHANGED", "message": "The price changed."}), code: "PRICE_CHANGED", exit: 1, next: requote},
		{name: "AUTHORITY_CHANGED", setup: refused("purchase", 409, map[string]any{"code": "AUTHORITY_CHANGED", "message": "The billing authority changed."}), code: "AUTHORITY_CHANGED", exit: 1, next: requote},
		{name: "METHOD_CHANGED", setup: refused("purchase", 409, map[string]any{"code": "METHOD_CHANGED", "message": "The payment method changed."}), code: "METHOD_CHANGED", exit: 1, next: requote},
		{name: "CARD_REQUIRED", setup: refused("quote", 409, map[string]any{"code": "CARD_REQUIRED", "message": "Add a card.", "billingSetupUrl": billing + "/card"}), code: "CARD_REQUIRED", exit: 5, reason: "card", url: billing + "/card", local: true},
		{name: "TAX_LOCATION_REQUIRED", setup: refused("quote", 409, map[string]any{"code": "TAX_LOCATION_REQUIRED", "message": "Add a billing address.", "billingSetupUrl": billing}), code: "TAX_LOCATION_REQUIRED", exit: 5, reason: "tax", url: billing, local: true},
		{name: "EU_UK_VAT_ID_REQUIRED missing", setup: refused("quote", 409, map[string]any{"code": "EU_UK_VAT_ID_REQUIRED", "message": "Add a VAT ID.", "detail": "vat_id:missing", "billingSetupUrl": billing}), code: "EU_UK_VAT_ID_REQUIRED", exit: 5, reason: "tax_id", url: billing, local: true},
		{name: "EU_UK_VAT_ID_REQUIRED unverified", setup: refused("quote", 409, map[string]any{"code": "EU_UK_VAT_ID_REQUIRED", "message": "The VAT ID is not verified.", "detail": "vat_id:unverified"}), code: "EU_UK_VAT_ID_REQUIRED", exit: 5, reason: "tax_id", url: upgradePlanPage, local: true},
		{name: "EU_UK_VAT_ID_REQUIRED pending", setup: refused("quote", 409, map[string]any{"code": "EU_UK_VAT_ID_REQUIRED", "message": "The VAT ID check is pending.", "detail": "vat_id:pending"}), code: "EU_UK_VAT_ID_REQUIRED", exit: 6, next: retry, local: true},
		{name: "PAYMENT_ACTION_REQUIRED", setup: func(c *upgradeConsole) {
			c.purchase = control.PlanPurchase{Status: control.PurchaseRequiresAction, RequiresActionURL: page, Message: "Authenticate the payment."}
		}, code: "PAYMENT_ACTION_REQUIRED", exit: 5, reason: "payment", url: page},
		{name: "SUPPORT_REQUIRED", setup: func(c *upgradeConsole) {
			c.purchase = control.PlanPurchase{Status: control.PurchaseNeedsReview, Message: "Support reviews the purchase."}
		}, code: "SUPPORT_REQUIRED", exit: 5, reason: "support", url: upgradePlanPage},
		{name: "ACTIVATE_FREE_FIRST", setup: refused("quote", 409, map[string]any{"code": "ACTIVATE_FREE_FIRST", "message": "Activate Production on Free first."}), code: "ACTIVATE_FREE_FIRST", exit: 5, reason: "activate", url: upgradePlanPage, local: true},
		{name: "PAYMENT_FAILED", setup: func(c *upgradeConsole) {
			c.purchase = control.PlanPurchase{Status: control.PurchaseFailed, Failure: &control.PlanPurchaseFailure{Code: "PAYMENT_FAILED", Message: "The card was declined.", BillingSetupURL: billing}}
		}, code: "PAYMENT_FAILED", exit: 5, reason: "billing", url: billing},
		{name: "AGENT_PURCHASE_NOT_ALLOWED environment", env: environmentCredential, code: "AGENT_PURCHASE_NOT_ALLOWED", exit: 5, reason: "purchase", url: upgradePlanPage, local: true},
		{name: "AGENT_PURCHASE_NOT_ALLOWED server", setup: refused("purchase", 403, map[string]any{"code": "AGENT_PURCHASE_NOT_ALLOWED", "message": "Only a person buys a paid plan.", "detail": "credential:agent"}), code: "AGENT_PURCHASE_NOT_ALLOWED", exit: 5, reason: "purchase", url: upgradePlanPage},
		{name: "PURCHASE_OPEN", setup: refused("purchase", 409, map[string]any{"code": "PURCHASE_OPEN", "message": "Another purchase is open.", "purchaseId": purchaseIDFor("other")}), code: "PURCHASE_OPEN", exit: 6, next: retry},
		{name: "PAID_PURCHASE_UNAVAILABLE", setup: refused("quote", 503, map[string]any{"code": "PAID_PURCHASE_UNAVAILABLE", "message": "Paid plans are not on sale."}), code: "PAID_PURCHASE_UNAVAILABLE", exit: 6, next: retry, local: true},
		{name: "CHARGE_CONFIRMATION_MISMATCH local", extra: []string{"--confirm-charge", "49.00"}, code: "CHARGE_CONFIRMATION_MISMATCH", exit: 2, local: true},
		{name: "CHARGE_CONFIRMATION_MISMATCH server", setup: refused("purchase", 409, map[string]any{
			"code": "CHARGE_CONFIRMATION_MISMATCH", "message": "The confirmed charge is not the quote total.", "expected": map[string]any{"amount": 5390, "currency": "usd"},
		}), extra: []string{"--quote", upgradeQuoteToken, "--confirm-charge", "49.00usd"}, code: "CHARGE_CONFIRMATION_MISMATCH", exit: 2},
		{name: "CONFIRMATION_REQUIRED", extra: []string{}, code: "CONFIRMATION_REQUIRED", exit: 2, local: true},
		{name: "PLAN_NOT_AVAILABLE", setup: func(c *upgradeConsole) { c.plans[0].Plans = []control.PlanOffer{hobbyPlan} }, code: "PLAN_NOT_AVAILABLE", exit: 1, local: true},
		{name: "PURCHASE_NOT_IMMEDIATE", setup: func(c *upgradeConsole) { c.quote.Timing = "period_end" }, code: "PURCHASE_NOT_IMMEDIATE", exit: 5, reason: "purchase", url: upgradePlanPage, local: true},
		{name: "BILLING_PERMISSION_REQUIRED", setup: func(c *upgradeConsole) {
			c.plans = []control.ProjectPlans{{Project: upgradeSlug, BlockedBy: control.BlockedByBillingPermission}}
		}, code: "BILLING_PERMISSION_REQUIRED", exit: 5, reason: "purchase", url: upgradePlanPage, local: true},
	}
	actual := map[string]any{}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			if test.setup != nil {
				test.setup(console)
			}
			extra := test.extra
			if extra == nil {
				extra = charge
			}
			exit, stdout, stderr := console.upgrade(t, test.env, append([]string{"--json"}, extra...)...)
			result := decodeEvent(t, []byte(stdout))
			if exit != test.exit || result.Status != "error" || result.Code != test.code || result.Next != test.next {
				t.Fatalf("%s became exit=%d code=%s next=%q, want exit=%d next=%q: %s %s", test.name, exit, result.Code, result.Next, test.exit, test.next, stdout, stderr)
			}
			if result.Action.Reason != test.reason || result.Action.URL != test.url || (test.url != "" && result.Action.Kind != "browser") {
				t.Fatalf("%s gave the action %+v, want %s at %s", test.name, result.Action, test.reason, test.url)
			}
			if test.local && console.purchases != 0 {
				t.Fatalf("%s made %d purchases", test.name, console.purchases)
			}
			noTokenIn(t, stdout, stderr)
			var document map[string]any
			if err := json.Unmarshal([]byte(stdout), &document); err != nil {
				t.Fatal(err)
			}
			actual[test.name] = map[string]any{"exit": exit, "output": document}
		})
	}
	compareUpgradeGolden(t, actual)
}

// compareUpgradeGolden compares the refusals with the checked-in JSON. With
// OE_CAPTURE_PROJECT_UPGRADE_REFUSALS set to a path, it writes them there.
func compareUpgradeGolden(t *testing.T, actual map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if target := os.Getenv("OE_CAPTURE_PROJECT_UPGRADE_REFUSALS"); target != "" {
		if err := os.WriteFile(target, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "project_upgrade_refusals.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected, got map[string]any
	if err := json.Unmarshal(golden, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	for name := range expected {
		if _, ok := got[name]; !ok {
			t.Errorf("no refusal ran for golden %s", name)
		}
	}
	for name, value := range got {
		if !reflect.DeepEqual(value, expected[name]) {
			text, _ := json.MarshalIndent(value, "", "  ")
			t.Errorf("refusal %s changed:\n%s", name, text)
		}
	}
}

func TestMajorAmountConvertsToMinorUnits(t *testing.T) {
	for _, test := range []struct {
		value, currency string
		want            int64
		fails           bool
	}{
		{"49.00", "usd", 4900, false},
		{"49", "usd", 4900, false},
		{"49.5", "usd", 4950, false},
		{"0.01", "usd", 1, false},
		{"00.10", "usd", 10, false},
		{"0", "usd", 0, false},
		{"49.005", "usd", 0, true},
		{"1000", "jpy", 1000, false},
		{"1000.5", "jpy", 0, true},
		{"1.234", "kwd", 1234, false},
		{"1.2", "kwd", 1200, false},
		{"9007199254740991", "jpy", 9007199254740991, false},
		{"9007199254740992", "jpy", 0, true},
		{"99999999999999999999", "usd", 0, true},
	} {
		amount, err := parseMajorAmount(test.value)
		if err != nil {
			t.Fatalf("parse %q: %v", test.value, err)
		}
		got, err := amount.minor(test.currency)
		if test.fails {
			if err == nil {
				t.Errorf("%s %s became %d, want a refusal", test.value, test.currency, got)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Errorf("%s %s became %d, %v; want %d", test.value, test.currency, got, err, test.want)
		}
	}
}

func TestParseMajorAmountReadsTheCurrency(t *testing.T) {
	for value, want := range map[string]majorAmount{
		"49.00usd":  {whole: "49", fraction: "00", currency: "usd"},
		"49.00 USD": {whole: "49", fraction: "00", currency: "usd"},
		" 49 ":      {whole: "49"},
	} {
		if got, err := parseMajorAmount(value); err != nil || got != want {
			t.Errorf("parse %q became %+v, %v; want %+v", value, got, err, want)
		}
	}
	for _, value := range []string{"", "49.", ".50", "-1", "1.2345", "49,00", "49.00 dollars", "1e3"} {
		if got, err := parseMajorAmount(value); err == nil {
			t.Errorf("parse %q became %+v, want a refusal", value, got)
		}
	}
}

func TestFormatMajorWritesMajorUnits(t *testing.T) {
	for _, test := range []struct {
		amount   int64
		currency string
		want     string
	}{
		{4900, "usd", "49.00"},
		{5, "usd", "0.05"},
		{0, "usd", "0.00"},
		{-150, "usd", "-1.50"},
		{1000, "jpy", "1000"},
		{1234, "kwd", "1.234"},
	} {
		if got := formatMajor(test.amount, test.currency); got != test.want {
			t.Errorf("formatMajor(%d, %s) = %q, want %q", test.amount, test.currency, got, test.want)
		}
	}
	if got := formatCharge(5390, "usd"); got != "53.90 USD" {
		t.Errorf("formatCharge = %q", got)
	}
}

func TestProjectShowNamesThePlan(t *testing.T) {
	t.Run("plan", func(t *testing.T) {
		console := newUpgradeConsole(t)
		console.plans[0].CurrentPlan = &starterPlan
		exit, stdout, _ := run(t, console.dependencies(nil), "--json", "project", "show", upgradeSlug)
		project, _ := decodeEvent(t, []byte(stdout)).Data["project"].(map[string]any)
		if exit != 0 || !reflect.DeepEqual(project["plan"], map[string]any{"id": upgradeTarget, "name": "Starter"}) {
			t.Fatalf("project show did not name the plan: exit=%d %s", exit, stdout)
		}
		exit, stdout, _ = run(t, console.dependencies(nil), "project", "show", upgradeSlug)
		if exit != 0 || !strings.Contains(stdout, "\n  plan: Starter (relay_starter_v1)\n") {
			t.Fatalf("project show text did not name the plan: exit=%d %s", exit, stdout)
		}
	})
	t.Run("no plan", func(t *testing.T) {
		console := newUpgradeConsole(t)
		console.plans[0].CurrentPlan = nil
		exit, stdout, _ := run(t, console.dependencies(nil), "--json", "project", "show", upgradeSlug)
		project, _ := decodeEvent(t, []byte(stdout)).Data["project"].(map[string]any)
		if plan, ok := project["plan"]; exit != 0 || !ok || plan != nil {
			t.Fatalf("project show did not name the plan as null: exit=%d %s", exit, stdout)
		}
	})
	for name, setup := range map[string]func(*upgradeConsole){
		"plans refused": refused("plans", 403, map[string]any{"code": "PERMISSION_REQUIRED", "message": "No billing permission."}),
		"blocked": func(c *upgradeConsole) {
			c.plans = []control.ProjectPlans{{Project: upgradeSlug, BlockedBy: control.BlockedByBillingPermission}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			console := newUpgradeConsole(t)
			setup(console)
			exit, stdout, _ := run(t, console.dependencies(nil), "--json", "project", "show", upgradeSlug)
			project, _ := decodeEvent(t, []byte(stdout)).Data["project"].(map[string]any)
			if _, ok := project["plan"]; exit != 0 || ok {
				t.Fatalf("project show named a plan that it could not read: exit=%d %s", exit, stdout)
			}
		})
	}
}

func TestPushNamesProjectUpgradeAtAFreeLimit(t *testing.T) {
	const upgrade = "oe project upgrade gated-chat --plan relay_hobby_v1"
	plans := func(context.Context, control.CredentialRequest, string) (control.ProjectPlans, error) {
		return control.ProjectPlans{Project: "gated-chat", CurrentPlan: &freePlan, Plans: []control.PlanOffer{hobbyPlan, starterPlan}}, nil
	}
	for _, test := range []struct {
		name, code, actionURL string
		setup                 func(*pushConsole)
	}{
		{"gate free project limit", "FREE_PROJECT_LIMIT", "", func(c *pushConsole) { c.blockProduction(control.BlockedByFreeProjectLimit) }},
		{"gate free payment method limit", "FREE_PAYMENT_METHOD_LIMIT", organizationBillingURL, func(c *pushConsole) {
			c.blockProduction(control.BlockedByFreePaymentMethodLimit)
		}},
		{"apply free project limit", "FREE_PROJECT_LIMIT", "", func(c *pushConsole) {
			c.fail["deploy production"] = &control.APIError{Status: 409, Code: "FREE_PROJECT_LIMIT", Message: "The organization has two Free Production projects."}
		}},
		{"apply free payment method limit", "FREE_PAYMENT_METHOD_LIMIT", organizationBillingURL, func(c *pushConsole) {
			c.fail["deploy production"] = &control.APIError{Status: 409, Code: "FREE_PAYMENT_METHOD_LIMIT", Message: paymentMethodLimitRefusal, BillingSetupURL: organizationBillingURL}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := initializedProject(t, "gated-chat")
			console := newPushConsole(t, "gated-chat")
			console.projectPlans = plans
			test.setup(console)
			dependencies := pushDependencies(t, console, directory)
			dependencies.Getenv = environment(nil)
			exit, stdout, _ := run(t, dependencies, "--json", "config", "push", "--yes")
			result := decodeEvent(t, []byte(stdout))
			if exit != exitPersonAction || result.Code != test.code || result.Next != upgrade || result.Action.URL != test.actionURL {
				t.Fatalf("%s did not name oe project upgrade: exit=%d %s", test.name, exit, stdout)
			}
			if strings.HasPrefix(test.name, "gate") && !strings.Contains(result.Error, "a paid plan with "+upgrade) {
				t.Fatalf("%s did not say to buy a plan with oe project upgrade: %s", test.name, result.Error)
			}
		})
	}
	t.Run("plans blocked", func(t *testing.T) {
		directory := initializedProject(t, "gated-chat")
		console := newPushConsole(t, "gated-chat")
		console.projectPlans = func(context.Context, control.CredentialRequest, string) (control.ProjectPlans, error) {
			return control.ProjectPlans{BlockedBy: control.BlockedByBillingPermission}, nil
		}
		console.blockProduction(control.BlockedByFreePaymentMethodLimit)
		dependencies := pushDependencies(t, console, directory)
		dependencies.Getenv = environment(nil)
		exit, stdout, _ := run(t, dependencies, "--json", "config", "push", "--yes")
		if result := decodeEvent(t, []byte(stdout)); exit != exitPersonAction || result.Next != "oe config push --yes" {
			t.Fatalf("a session without the billing permission named oe project upgrade: exit=%d %s", exit, stdout)
		}
	})
	t.Run("plans read fails", func(t *testing.T) {
		directory := initializedProject(t, "gated-chat")
		console := newPushConsole(t, "gated-chat")
		console.projectPlans = func(context.Context, control.CredentialRequest, string) (control.ProjectPlans, error) {
			return control.ProjectPlans{}, errors.New("unavailable")
		}
		console.blockProduction(control.BlockedByFreeProjectLimit)
		dependencies := pushDependencies(t, console, directory)
		dependencies.Getenv = environment(nil)
		exit, stdout, _ := run(t, dependencies, "--json", "config", "push", "--yes")
		if result := decodeEvent(t, []byte(stdout)); exit != exitPersonAction || result.Code != "FREE_PROJECT_LIMIT" || result.Next != "" {
			t.Fatalf("a failed plans read changed the refusal: exit=%d %s", exit, stdout)
		}
	})
}
