package control

import (
	"context"
	"net/http"
	"net/url"
)

// ProjectPlans is the plan state of one project as a person with the billing
// permission reads it before a quote. BlockedBy is BlockedByBillingPermission
// when the session holds no billing permission; then Plans is empty.
// CurrentPlan is nil for a project whose Production holds no plan. Plans are
// the plans that the project can quote now, in plan order. OpenPurchase is
// the open purchase of this project. PlanURL is the Console plan page of the
// project, when the control API names it.
type ProjectPlans struct {
	Project      string        `json:"project"`
	BlockedBy    string        `json:"blockedBy"`
	CurrentPlan  *PlanOffer    `json:"currentPlan"`
	Plans        []PlanOffer   `json:"plans"`
	OpenPurchase *OpenPurchase `json:"openPurchase"`
	PlanURL      string        `json:"planUrl,omitempty"`
}

// PlanOffer is one plan by its ID and its display name.
type PlanOffer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OpenPurchase is a purchase of the project that has not ended.
type OpenPurchase struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// PlanQuoteRequest asks for the price of a change to one plan.
type PlanQuoteRequest struct {
	TargetPlanID string `json:"targetPlanId"`
}

// PlanQuote is the price of a plan change. Amounts are in the minor units of
// Currency. Tax is the exclusive tax amount of a taxed quote, and nil for an
// untaxed quote. Total is the tax-inclusive charge of a taxed quote, else the
// amount due. ConfirmationToken binds a purchase to this quote until
// QuoteExpiresAtMilliseconds. It is a secret of the person who quoted.
type PlanQuote struct {
	AmountDue                  int64  `json:"amountDue"`
	Tax                        *int64 `json:"tax"`
	Total                      int64  `json:"total"`
	Currency                   string `json:"currency"`
	Timing                     string `json:"timing"`
	EffectiveAtMilliseconds    int64  `json:"effectiveAtMilliseconds"`
	RenewsAtMilliseconds       *int64 `json:"renewsAtMilliseconds"`
	PaymentMethodRequired      bool   `json:"paymentMethodRequired"`
	PricePreviewID             string `json:"pricePreviewId"`
	ConfirmationToken          string `json:"confirmationToken"`
	QuoteExpiresAtMilliseconds int64  `json:"quoteExpiresAtMilliseconds"`
}

// TimingImmediate is the timing of a quote that a purchase can buy now.
const TimingImmediate = "immediate"

// Charge is the charge that a purchase confirms: the total of the quote. The
// server refuses a purchase whose confirmed charge is not this charge.
func (q PlanQuote) Charge() ChargeAmount {
	return ChargeAmount{Amount: q.Total, Currency: q.Currency}
}

// ChargeAmount is an exact amount in the minor units of a lowercase ISO 4217
// currency.
type ChargeAmount struct {
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
}

// PlanPurchaseRequest buys the plan of a quote at the charge that a person
// confirmed.
type PlanPurchaseRequest struct {
	ConfirmationToken string       `json:"confirmationToken"`
	ConfirmedCharge   ChargeAmount `json:"confirmedCharge"`
}

// Purchase statuses. A purchase in progress has not ended. Every other status
// is final for oe.
const (
	PurchaseInProgress     = "in_progress"
	PurchaseFulfilled      = "fulfilled"
	PurchaseRequiresAction = "requires_action"
	PurchaseNeedsReview    = "needs_review"
	PurchaseFailed         = "failed"
)

// PlanPurchase is the status of one purchase. A requires_action purchase
// names RequiresActionURL, where the person authenticates the payment. A
// failed purchase names its Failure.
type PlanPurchase struct {
	PurchaseID        string               `json:"purchaseId"`
	State             string               `json:"state"`
	Status            string               `json:"status"`
	PlanID            string               `json:"planId,omitempty"`
	Code              string               `json:"code,omitempty"`
	Message           string               `json:"message"`
	RequiresActionURL string               `json:"requiresActionUrl,omitempty"`
	Failure           *PlanPurchaseFailure `json:"failure,omitempty"`
}

// PlanPurchaseFailure is the code and the text of a purchase that ended with
// no plan change. BillingSetupURL is the page where the person fixes it.
type PlanPurchaseFailure struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	BillingSetupURL string `json:"billingSetupUrl,omitempty"`
}

// ProjectPlans reads the plan state of a project.
func (c *Client) ProjectPlans(ctx context.Context, credential CredentialRequest, project string) (ProjectPlans, error) {
	var response ProjectPlans
	err := c.do(ctx, http.MethodGet, projectPath(project, "plans"), credential, nil, &response)
	return response, err
}

// QuotePlan prices a change of the project to one plan. It changes nothing,
// so a failed attempt is not sent again.
func (c *Client) QuotePlan(ctx context.Context, credential CredentialRequest, project string, request PlanQuoteRequest) (PlanQuote, error) {
	var response PlanQuote
	err := c.do(ctx, http.MethodPost, projectPath(project, "plan/quote"), credential, request, &response)
	return response, err
}

// PurchasePlan buys the plan of a quote. The server answers the same purchase
// for the same confirmation token, so a failed attempt is sent again.
func (c *Client) PurchasePlan(ctx context.Context, credential CredentialRequest, project string, request PlanPurchaseRequest) (PlanPurchase, error) {
	var response PlanPurchase
	credential.Replayable = true
	err := c.do(ctx, http.MethodPost, projectPath(project, "plan/purchases"), credential, request, &response)
	return response, sanitizeCredentialError(err, request.ConfirmationToken)
}

// PurchaseStatus reads one purchase of the project.
func (c *Client) PurchaseStatus(ctx context.Context, credential CredentialRequest, project, purchaseID string) (PlanPurchase, error) {
	var response PlanPurchase
	err := c.do(ctx, http.MethodGet, projectPath(project, "plan/purchases/"+url.PathEscape(purchaseID)), credential, nil, &response)
	return response, err
}
