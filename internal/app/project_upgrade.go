package app

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/open-e2ee/oe/internal/control"
	"github.com/open-e2ee/oe/internal/credential"
	"github.com/open-e2ee/oe/internal/output"
)

const (
	// upgradeTimeout is the default bound of the wait for a plan change.
	upgradeTimeout = 5 * time.Minute
	// upgradePollInterval is the time between two reads of a purchase.
	upgradePollInterval = 2 * time.Second
)

// purchaseIDPattern is the form of a purchase ID that the control API names.
// oe reads only a purchase whose ID has this form.
var purchaseIDPattern = regexp.MustCompile(`^purchase_[A-Za-z0-9_-]{43}$`)

// upgradeOptions are the parsed arguments of oe project upgrade.
type upgradeOptions struct {
	project string
	plan    string
	dryRun  bool
	// quote is a confirmation token from an earlier dry run. It is a secret,
	// so no next and no message names it.
	quote   string
	yes     bool
	wait    bool
	timeout time.Duration
	// timeoutSet is true when the command line names --timeout.
	timeoutSet bool
	// charge is the --confirm-charge value, or nil when the run names none.
	charge *majorAmount
	// chargeText is the --confirm-charge value as the caller wrote it.
	chargeText string
}

// command writes the command line of these options without the quote token,
// so a next can name it. extra flags follow the plan.
func (o upgradeOptions) command(extra ...string) string {
	args := []string{"project", "upgrade", o.project, "--plan", o.plan}
	return commandLine(append(args, extra...))
}

// dryRunCommand quotes the plan again.
func (o upgradeOptions) dryRunCommand() string { return o.command("--dry-run") }

// retryCommand repeats the run without the quote token. A run with a token
// quotes again, so its charge confirmation stays.
func (o upgradeOptions) retryCommand() string {
	var extra []string
	if o.dryRun {
		extra = append(extra, "--dry-run")
	}
	if o.yes {
		extra = append(extra, "--yes")
	}
	if o.charge != nil {
		extra = append(extra, "--confirm-charge", o.chargeText)
	}
	if o.wait {
		extra = append(extra, "--wait")
	}
	if o.timeoutSet {
		extra = append(extra, "--timeout", o.timeout.String())
	}
	return o.command(extra...)
}

// parseUpgrade parses the arguments of oe project upgrade. PROJECT may come
// before or after the flags. Without PROJECT, the project is the one in
// open-e2ee.config.ts.
func (r *runner) parseUpgrade(args []string) (upgradeOptions, error) {
	flags := newFlags("project upgrade")
	plan := flags.String("plan", "", "the plan to buy")
	dryRun := flags.Bool("dry-run", false, "quote the plan and buy nothing")
	quote := flags.String("quote", "", "the confirmation token of a dry run")
	yes := flags.Bool("yes", false, "do not prompt")
	wait := flags.Bool("wait", false, "wait for the plan change")
	timeout := flags.Duration("timeout", upgradeTimeout, "the bound of the wait")
	charge := flags.String("confirm-charge", "", "the charge that the person confirms, in major units")
	var positional []string
	for rest := args; ; {
		if err := parseArguments(flags, "project", rest); err != nil {
			return upgradeOptions{}, err
		}
		if flags.NArg() == 0 {
			break
		}
		positional = append(positional, flags.Arg(0))
		rest = flags.Args()[1:]
	}
	options := upgradeOptions{
		plan: strings.TrimSpace(*plan), dryRun: *dryRun, quote: strings.TrimSpace(*quote),
		yes: *yes, wait: *wait, timeout: *timeout, chargeText: strings.TrimSpace(*charge),
	}
	chargeSet := false
	flags.Visit(func(set *flag.Flag) {
		options.timeoutSet = options.timeoutSet || set.Name == "timeout"
		chargeSet = chargeSet || set.Name == "confirm-charge"
	})
	switch {
	case len(positional) > 1:
		return upgradeOptions{}, usageError("project", "oe project upgrade takes at most one PROJECT")
	case options.plan == "":
		return upgradeOptions{}, usageError("project", "oe project upgrade needs --plan PLAN")
	case options.timeout <= 0:
		return upgradeOptions{}, usageError("project", "--timeout must be positive")
	case options.dryRun && (options.quote != "" || options.wait || options.timeoutSet || chargeSet):
		return upgradeOptions{}, usageError("project", "--dry-run buys nothing, so it takes no --quote, --confirm-charge, --wait, or --timeout")
	}
	if chargeSet {
		amount, err := parseMajorAmount(options.chargeText)
		if err != nil {
			return upgradeOptions{}, usageError("project", err.Error())
		}
		options.charge = &amount
	}
	if options.quote != "" && (options.charge == nil || options.charge.currency == "") {
		// The token is opaque to oe, so oe cannot read the currency of its
		// charge, nor how many decimal places the currency has.
		return upgradeOptions{}, usageError("project", "--quote needs --confirm-charge with the currency of the quote, such as --confirm-charge 49.00usd")
	}
	if len(positional) == 1 {
		options.project = positional[0]
	} else {
		_, value, err := r.loadConfig()
		if err != nil {
			return upgradeOptions{}, err
		}
		options.project = value.Project
	}
	return options, nil
}

// projectUpgrade quotes a paid plan for a project and buys it for a person.
// An agent or a credential from OPEN_E2EE_ACCESS_TOKEN never buys: the run
// hands the purchase to a person on the Console plan page.
func (r *runner) projectUpgrade(ctx context.Context, args []string) error {
	options, err := r.parseUpgrade(args)
	if err != nil {
		return err
	}
	access, err := r.access(ctx, "project:read", false)
	if err != nil {
		return err
	}
	if _, err := r.getProject(ctx, access, options.project); err != nil {
		return err
	}
	request := control.CredentialRequest{AccessToken: access.AccessToken, CredentialSource: r.credentialSource}
	plans, err := r.api.ProjectPlans(ctx, request, options.project)
	if err != nil {
		return r.upgradeFailure(err, options, r.planPage(control.ProjectPlans{}, options.plan))
	}
	page := r.planPage(plans, options.plan)
	if plans.BlockedBy != "" {
		return &problem{
			code: "BILLING_PERMISSION_REQUIRED", exit: exitPersonAction, actionURL: page, actionReason: "purchase",
			data:    map[string]any{"project": options.project, "blockedBy": plans.BlockedBy},
			message: fmt.Sprintf("this account cannot manage billing for project %s; a person with the billing permission buys the plan at %s", options.project, page),
		}
	}
	if plans.CurrentPlan != nil && plans.CurrentPlan.ID == options.plan {
		return r.out.Success("project upgrade",
			fmt.Sprintf("Project %s is already on plan %s.", options.project, planLabel(*plans.CurrentPlan)),
			map[string]any{"project": options.project, "plan": planData(plans.CurrentPlan), "changed": false})
	}
	index := slices.IndexFunc(plans.Plans, func(offer control.PlanOffer) bool { return offer.ID == options.plan })
	if index < 0 {
		available := make([]string, 0, len(plans.Plans))
		for _, offer := range plans.Plans {
			available = append(available, offer.ID)
		}
		message := fmt.Sprintf("project %s cannot change to plan %s", options.project, options.plan)
		if len(available) > 0 {
			message += "; the plans it can change to are " + strings.Join(available, ", ")
		}
		return &problem{
			code: "PLAN_NOT_AVAILABLE", exit: exitFailure, message: message,
			data: map[string]any{"project": options.project, "plan": options.plan, "plans": available},
		}
	}
	target := plans.Plans[index]
	if options.dryRun {
		return r.upgradeDryRun(ctx, request, options, plans, target, page)
	}
	if r.credentialSource == "environment" {
		return &problem{
			code: "AGENT_PURCHASE_NOT_ALLOWED", exit: exitPersonAction, actionURL: page, actionReason: "purchase",
			data: map[string]any{"project": options.project, "plan": options.plan},
			message: fmt.Sprintf("the credential comes from OPEN_E2EE_ACCESS_TOKEN, and only a signed-in person buys a paid plan; "+
				"a person buys plan %s at %s. %s shows the charge", target.ID, page, options.dryRunCommand()),
		}
	}
	if r.underAgent {
		return r.upgradeHandoff(ctx, request, access, options, target, page)
	}
	return r.upgradePurchase(ctx, request, access, options, target, page)
}

// upgradeDryRun quotes the plan and buys nothing. Only the JSON data names the
// confirmation token.
func (r *runner) upgradeDryRun(ctx context.Context, request control.CredentialRequest, options upgradeOptions, plans control.ProjectPlans, target control.PlanOffer, page string) error {
	quote, err := r.quote(ctx, request, options, target)
	if err != nil {
		return r.upgradeFailure(err, options, page)
	}
	data := quoteData(options.project, target, quote)
	data["currentPlan"] = planData(plans.CurrentPlan)
	data["quote"] = quote.ConfirmationToken
	charge := quote.Charge()
	text := quoteText(options.project, target, quote)
	if quote.Timing != control.TimingImmediate {
		text += "\nThis change does not take effect now, so oe cannot buy it. Change the plan at " + page + "."
		return r.out.Success("project upgrade", text, data)
	}
	next := options.command("--confirm-charge", formatMajor(charge.Amount, charge.Currency))
	return r.out.SuccessNext("project upgrade", text, next, data)
}

// upgradeHandoff hands the purchase to a person on the Console plan page. It
// quotes first, so the person and the agent see the charge. With --wait, it
// then waits until the project is on the plan.
func (r *runner) upgradeHandoff(ctx context.Context, request control.CredentialRequest, access credential.Credential, options upgradeOptions, target control.PlanOffer, page string) error {
	data := map[string]any{"project": options.project, "plan": planData(&target)}
	message := fmt.Sprintf("An agent cannot buy a paid plan. A person buys plan %s for project %s at %s.", planLabel(target), options.project, page)
	if options.quote == "" {
		quote, err := r.quote(ctx, request, options, target)
		if err != nil {
			return r.upgradeFailure(err, options, page)
		}
		data = quoteData(options.project, target, quote)
		charge := quote.Charge()
		message = fmt.Sprintf("An agent cannot buy a paid plan. A person buys plan %s for project %s at %s; the quote total is %s.",
			planLabel(target), options.project, page, formatCharge(charge.Amount, charge.Currency))
	}
	action := output.Action{Kind: "browser", URL: page, Reason: "purchase"}
	if !options.wait {
		_ = r.out.PendingNext("project upgrade", message, options.command("--wait"), action, data)
		return &problem{code: "PURCHASE_HANDOFF", exit: exitPersonAction, message: message, reported: true}
	}
	_ = r.out.PendingNext("project upgrade", message+" Waiting for the plan change... (press Ctrl-C to stop)", "", action, data)
	return r.waitForPlan(ctx, access, options, target, page)
}

// upgradePurchase buys the plan for a person. A person at a terminal confirms
// the quote total in one prompt. Any other run names the charge with
// --confirm-charge, and a charge that is not the quote total buys nothing.
func (r *runner) upgradePurchase(ctx context.Context, request control.CredentialRequest, access credential.Credential, options upgradeOptions, target control.PlanOffer, page string) error {
	prompt := options.charge == nil && options.quote == "" && !options.yes && r.canPrompt() && r.mode == output.Text
	if options.charge == nil && !prompt {
		return &problem{
			code: "CONFIRMATION_REQUIRED", exit: exitUsage,
			data: map[string]any{"project": options.project, "plan": options.plan},
			message: fmt.Sprintf("buying plan %s charges the payment method of the organization, so a person must confirm the charge; "+
				"ask the person, run %s to show the charge, then run oe project upgrade with --confirm-charge AMOUNT", target.ID, options.dryRunCommand()),
		}
	}
	token := options.quote
	var charge control.ChargeAmount
	if token == "" {
		quote, err := r.quote(ctx, request, options, target)
		if err != nil {
			return r.upgradeFailure(err, options, page)
		}
		if quote.Timing != control.TimingImmediate {
			return &problem{
				code: "PURCHASE_NOT_IMMEDIATE", exit: exitPersonAction, actionURL: page, actionReason: "purchase",
				data:    quoteData(options.project, target, quote),
				message: fmt.Sprintf("the change to plan %s does not take effect now, so oe cannot buy it; change the plan at %s", target.ID, page),
			}
		}
		token, charge = quote.ConfirmationToken, quote.Charge()
		if prompt {
			fmt.Fprintln(r.errOut, quoteText(options.project, target, quote))
			confirmed, err := askConfirmation(r.in, r.errOut, fmt.Sprintf("Buy plan %s for project %s and charge %s now?",
				planLabel(target), options.project, formatCharge(charge.Amount, charge.Currency)))
			if err != nil {
				return err
			}
			if !confirmed {
				return &problem{
					code: "PURCHASE_CANCELLED", exit: exitFailure,
					message: fmt.Sprintf("the purchase of plan %s was cancelled; nothing was charged", target.ID),
				}
			}
		} else if err := confirmCharge(*options.charge, charge, options); err != nil {
			return err
		}
	} else {
		amount, err := options.charge.minor(options.charge.currency)
		if err != nil {
			return usageError("project", err.Error())
		}
		charge = control.ChargeAmount{Amount: amount, Currency: options.charge.currency}
	}
	purchase, err := r.api.PurchasePlan(ctx, request, options.project, control.PlanPurchaseRequest{ConfirmationToken: token, ConfirmedCharge: charge})
	if err != nil {
		return r.upgradeFailure(err, options, page)
	}
	return r.waitForPurchase(ctx, access, options, target, page, purchase, charge)
}

// confirmCharge compares the charge that the person confirmed with the quote
// total. A charge in another currency, or with more decimal places than the
// currency has, is not the quote total.
func confirmCharge(confirmed majorAmount, expected control.ChargeAmount, options upgradeOptions) error {
	if confirmed.currency != "" && confirmed.currency != expected.Currency {
		return chargeMismatch(expected, options.chargeText, options)
	}
	amount, err := confirmed.minor(expected.Currency)
	if err != nil {
		return usageError("project", err.Error())
	}
	if amount != expected.Amount {
		return chargeMismatch(expected, options.chargeText, options)
	}
	return nil
}

func chargeMismatch(expected control.ChargeAmount, confirmed string, options upgradeOptions) *problem {
	return &problem{
		code: "CHARGE_CONFIRMATION_MISMATCH", exit: exitUsage,
		data: map[string]any{
			"project": options.project, "plan": options.plan, "confirmed": confirmed,
			"expected": map[string]any{"amount": expected.Amount, "currency": expected.Currency, "major": formatMajor(expected.Amount, expected.Currency)},
		},
		message: fmt.Sprintf("the quote total is %s, not %s; nothing was charged. Ask the person to confirm the new total",
			formatCharge(expected.Amount, expected.Currency), confirmed),
	}
}

func (r *runner) quote(ctx context.Context, request control.CredentialRequest, options upgradeOptions, target control.PlanOffer) (control.PlanQuote, error) {
	quote, err := r.api.QuotePlan(ctx, request, options.project, control.PlanQuoteRequest{TargetPlanID: target.ID})
	if err != nil {
		return control.PlanQuote{}, err
	}
	if quote.ConfirmationToken == "" || !validCurrency(quote.Currency) {
		return control.PlanQuote{}, errors.New("control API returned a quote without a confirmation token or a currency")
	}
	return quote, nil
}

// waitForPurchase reads the purchase until it ends or the wait ends.
func (r *runner) waitForPurchase(ctx context.Context, access credential.Credential, options upgradeOptions, target control.PlanOffer, page string, purchase control.PlanPurchase, charge control.ChargeAmount) error {
	if !purchaseIDPattern.MatchString(purchase.PurchaseID) {
		return errors.New("control API returned a purchase without a valid purchase ID")
	}
	waitCtx, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	for announced := false; ; announced = true {
		switch purchase.Status {
		case control.PurchaseFulfilled:
			return r.out.Success("project upgrade",
				fmt.Sprintf("Project %s is on plan %s. The charge was %s.", options.project, planLabel(target), formatCharge(charge.Amount, charge.Currency)),
				map[string]any{
					"project": options.project, "plan": planData(&target), "changed": true, "purchaseId": purchase.PurchaseID,
					"charge": map[string]any{"amount": charge.Amount, "currency": charge.Currency},
				})
		case control.PurchaseRequiresAction, control.PurchaseNeedsReview, control.PurchaseFailed:
			return r.upgradeFailure(purchaseRefusal(purchase), options, page)
		}
		if !announced {
			_ = r.out.Progress("project upgrade", "Purchase accepted. Waiting for the plan change...", map[string]any{"purchaseId": purchase.PurchaseID})
		}
		if err := r.sleep(waitCtx, upgradePollInterval); err != nil {
			return purchasePending(ctx, err, options, purchase.PurchaseID)
		}
		var err error
		access, err = r.refreshedAccess(waitCtx, access)
		if err == nil {
			request := control.CredentialRequest{AccessToken: access.AccessToken, CredentialSource: r.credentialSource}
			purchase, err = r.api.PurchaseStatus(waitCtx, request, options.project, purchase.PurchaseID)
		}
		if err != nil {
			if waitCtx.Err() != nil && ctx.Err() == nil {
				return purchasePending(ctx, err, options, purchase.PurchaseID)
			}
			return r.upgradeFailure(err, options, page)
		}
	}
}

// waitForPlan reads the plans of the project until it is on target. A
// purchase that a person opened in the Console and that ends with no plan
// change ends the wait.
func (r *runner) waitForPlan(ctx context.Context, access credential.Credential, options upgradeOptions, target control.PlanOffer, page string) error {
	waitCtx, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	for {
		if err := r.sleep(waitCtx, upgradePollInterval); err != nil {
			return purchasePending(ctx, err, options, "")
		}
		plans, purchase, err := r.readPlanChange(waitCtx, &access, options)
		if err != nil {
			if waitCtx.Err() != nil && ctx.Err() == nil {
				return purchasePending(ctx, err, options, "")
			}
			return r.upgradeFailure(err, options, page)
		}
		if plans.CurrentPlan != nil && plans.CurrentPlan.ID == target.ID {
			return r.out.Success("project upgrade",
				fmt.Sprintf("Project %s is on plan %s.", options.project, planLabel(target)),
				map[string]any{"project": options.project, "plan": planData(&target), "changed": true})
		}
		if purchase != nil && (purchase.Status == control.PurchaseNeedsReview || purchase.Status == control.PurchaseFailed) {
			return r.upgradeFailure(purchaseRefusal(*purchase), options, page)
		}
	}
}

// readPlanChange reads the plans of the project and the status of its open
// purchase, when it has one.
func (r *runner) readPlanChange(ctx context.Context, access *credential.Credential, options upgradeOptions) (control.ProjectPlans, *control.PlanPurchase, error) {
	refreshed, err := r.refreshedAccess(ctx, *access)
	if err != nil {
		return control.ProjectPlans{}, nil, err
	}
	*access = refreshed
	request := control.CredentialRequest{AccessToken: access.AccessToken, CredentialSource: r.credentialSource}
	plans, err := r.api.ProjectPlans(ctx, request, options.project)
	if err != nil || plans.OpenPurchase == nil || !purchaseIDPattern.MatchString(plans.OpenPurchase.ID) {
		return plans, nil, err
	}
	purchase, err := r.api.PurchaseStatus(ctx, request, options.project, plans.OpenPurchase.ID)
	if err != nil {
		return plans, nil, err
	}
	return plans, &purchase, nil
}

// refreshedAccess renews a stored session that nears its expiry during a
// wait. A credential from the environment stays as it is.
func (r *runner) refreshedAccess(ctx context.Context, access credential.Credential) (credential.Credential, error) {
	if access.Source == "environment" || access.RefreshToken == "" || !credentialNeedsRefresh(access, r.now()) {
		return access, nil
	}
	return r.access(ctx, "", false)
}

// purchasePending is the end of a wait while the plan change has not
// happened. The purchase goes on, so the failure is temporary. Any other
// failure stays as it is.
func purchasePending(ctx context.Context, err error, options upgradeOptions, purchaseID string) error {
	if ctx.Err() != nil {
		return err
	}
	data := map[string]any{"project": options.project, "plan": options.plan}
	if purchaseID != "" {
		data["purchaseId"] = purchaseID
	}
	next := "oe project show " + options.project
	message := fmt.Sprintf("project %s is not on plan %s after %s; ", options.project, options.plan, options.timeout)
	if purchaseID != "" {
		message += "the purchase goes on, and " + next + " shows the plan"
	} else {
		next = options.command("--wait")
		message += "a person buys the plan in the Console, and " + next + " waits again"
	}
	return &problem{code: "PURCHASE_PENDING", exit: exitTemporary, next: next, data: data, message: message, cause: err}
}

// purchaseRefusal is the refusal of a purchase that ended with no plan
// change, with the code of its status.
func purchaseRefusal(purchase control.PlanPurchase) error {
	switch purchase.Status {
	case control.PurchaseRequiresAction:
		return &control.APIError{Code: cmp.Or(purchase.Code, "PAYMENT_ACTION_REQUIRED"), Message: purchase.Message, BillingSetupURL: purchase.RequiresActionURL, PurchaseID: purchase.PurchaseID}
	case control.PurchaseNeedsReview:
		return &control.APIError{Code: "SUPPORT_REQUIRED", Message: purchase.Message, PurchaseID: purchase.PurchaseID}
	}
	if purchase.Failure == nil {
		return &control.APIError{Code: "PAYMENT_FAILED", Message: cmp.Or(purchase.Message, "the purchase did not change the plan"), PurchaseID: purchase.PurchaseID}
	}
	return &control.APIError{
		Code: cmp.Or(purchase.Failure.Code, "PAYMENT_FAILED"), Message: purchase.Failure.Message,
		BillingSetupURL: purchase.Failure.BillingSetupURL, PurchaseID: purchase.PurchaseID,
	}
}

// Upgrade refusal guidance. A requote code needs a new quote. A person code
// needs a person on a Console page. A temporary code clears by itself.
var (
	upgradeRequoteCodes = []string{"QUOTE_EXPIRED", "PRICE_CHANGED", "AUTHORITY_CHANGED", "METHOD_CHANGED"}
	upgradePersonCodes  = map[string]string{
		"CARD_REQUIRED":              "card",
		"TAX_LOCATION_REQUIRED":      "tax",
		"EU_UK_VAT_ID_REQUIRED":      "tax_id",
		"PAYMENT_ACTION_REQUIRED":    "payment",
		"SUPPORT_REQUIRED":           "support",
		"ACTIVATE_FREE_FIRST":        "activate",
		"PAYMENT_FAILED":             "billing",
		"AGENT_PURCHASE_NOT_ALLOWED": "purchase",
	}
	upgradeTemporaryCodes = []string{"PURCHASE_OPEN", "PAID_PURCHASE_UNAVAILABLE"}
)

// upgradeFailure gives a refusal of a plan route the exit and the guidance of
// its code. No next or message names the quote token.
func (r *runner) upgradeFailure(err error, options upgradeOptions, page string) error {
	if _, ok := errors.AsType[*problem](err); ok {
		return err
	}
	failure := classify(err, options.retryCommand(), r.environment)
	refusal, _ := errors.AsType[*control.APIError](err)
	if refusal != nil {
		if failure.data == nil {
			failure.data = map[string]any{}
		}
		failure.data["project"], failure.data["plan"] = options.project, options.plan
		if refusal.Detail != "" {
			failure.data["detail"] = refusal.Detail
		}
		if refusal.PurchaseID != "" {
			failure.data["purchaseId"] = refusal.PurchaseID
		}
	}
	code := failure.code
	switch {
	case slices.Contains(upgradeRequoteCodes, code):
		failure.exit, failure.next = exitFailure, options.dryRunCommand()
		failure.actionURL, failure.actionReason = "", ""
	case code == "EU_UK_VAT_ID_REQUIRED" && refusal != nil && refusal.Detail == "vat_id:pending":
		failure.exit, failure.next = exitTemporary, options.retryCommand()
		failure.actionURL, failure.actionReason = "", ""
	case upgradePersonCodes[code] != "":
		failure.exit, failure.next = exitPersonAction, ""
		failure.actionURL, failure.actionReason = page, upgradePersonCodes[code]
		if refusal != nil && refusal.BillingSetupURL != "" {
			failure.actionURL = refusal.BillingSetupURL
		}
		if code == "ACTIVATE_FREE_FIRST" {
			var step string
			failure.next, step = r.productionActivation(options.project, "")
			failure.message = strings.TrimSuffix(failure.message, ".") + "; " + step
		}
	case slices.Contains(upgradeTemporaryCodes, code):
		failure.exit, failure.next = exitTemporary, options.retryCommand()
	case code == "CHARGE_CONFIRMATION_MISMATCH":
		failure.exit, failure.next = exitUsage, ""
		if refusal != nil && refusal.Expected != nil {
			failure.data["expected"] = map[string]any{
				"amount": refusal.Expected.Amount, "currency": refusal.Expected.Currency,
				"major": formatMajor(refusal.Expected.Amount, refusal.Expected.Currency),
			}
		}
	}
	if options.quote != "" {
		failure.message = strings.ReplaceAll(failure.message, options.quote, "[redacted]")
	}
	return failure
}

// planPage is the Console plan page of the project with the plan chosen. The
// page that the control API names is used only on the host of the control
// API. Without it, the page is the Console list of the signal-relay projects.
func (r *runner) planPage(plans control.ProjectPlans, plan string) string {
	controlURL, err := url.Parse(r.controlURL)
	if err != nil {
		return "the console"
	}
	if plans.PlanURL != "" {
		page, err := url.Parse(plans.PlanURL)
		if err == nil && (page.Scheme == "https" || page.Scheme == "http") && page.Host == controlURL.Host {
			query := page.Query()
			query.Set("plan", plan)
			page.RawQuery = query.Encode()
			return page.String()
		}
	}
	return controlURL.Scheme + "://" + controlURL.Host + "/signal-relay"
}

func planLabel(plan control.PlanOffer) string {
	if plan.Name == "" || plan.Name == plan.ID {
		return plan.ID
	}
	return plan.Name + " (" + plan.ID + ")"
}

func planData(plan *control.PlanOffer) any {
	if plan == nil {
		return nil
	}
	return map[string]any{"id": plan.ID, "name": plan.Name}
}

// quoteData is the quote without its confirmation token.
func quoteData(project string, target control.PlanOffer, quote control.PlanQuote) map[string]any {
	charge := quote.Charge()
	var tax any
	if quote.Tax != nil {
		tax = map[string]any{"automatic": quote.Tax.Automatic, "subtotal": quote.Tax.Subtotal, "amount": quote.Tax.Amount, "total": quote.Tax.Total}
	}
	var renewsAt any
	if quote.RenewsAtMilliseconds != nil {
		renewsAt = milliseconds(*quote.RenewsAtMilliseconds)
	}
	return map[string]any{
		"project": project, "plan": planData(&target),
		"amountDue": quote.AmountDue, "tax": tax, "total": charge.Amount, "currency": charge.Currency,
		"totalMajor": formatMajor(charge.Amount, charge.Currency),
		"timing":     quote.Timing, "effectiveAt": milliseconds(quote.EffectiveAtMilliseconds), "renewsAt": renewsAt,
		"paymentMethodRequired": quote.PaymentMethodRequired,
		"quoteExpiresAt":        milliseconds(quote.QuoteExpiresAtMilliseconds),
	}
}

// quoteText is the quote for a person. It never names the confirmation token.
func quoteText(project string, target control.PlanOffer, quote control.PlanQuote) string {
	var text strings.Builder
	charge := quote.Charge()
	fmt.Fprintf(&text, "Quote for plan %s on project %s:", planLabel(target), project)
	fmt.Fprintf(&text, "\n  amount due: %s", formatCharge(quote.AmountDue, quote.Currency))
	if quote.Tax != nil {
		fmt.Fprintf(&text, "\n  tax: %s", formatCharge(quote.Tax.Amount, quote.Currency))
	}
	fmt.Fprintf(&text, "\n  total: %s", formatCharge(charge.Amount, charge.Currency))
	fmt.Fprintf(&text, "\n  timing: %s, effective %s", quote.Timing, milliseconds(quote.EffectiveAtMilliseconds))
	if quote.RenewsAtMilliseconds != nil {
		fmt.Fprintf(&text, "\n  renews: %s", milliseconds(*quote.RenewsAtMilliseconds))
	}
	fmt.Fprintf(&text, "\n  quote expires: %s", milliseconds(quote.QuoteExpiresAtMilliseconds))
	return text.String()
}

func milliseconds(value int64) string {
	return time.UnixMilli(value).UTC().Format(time.RFC3339)
}

// majorAmount is a charge in the major units of a currency, as a person
// writes it: whole units, an optional fraction, and an optional currency.
type majorAmount struct {
	whole    string
	fraction string
	// currency is the lowercase ISO 4217 code, or empty when the caller
	// names none.
	currency string
}

var majorAmountPattern = regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?\s*([A-Za-z]{3})?$`)

// maxFractionDigits is the most decimal places of any currency.
const maxFractionDigits = 3

// maxChargeAmount is the largest charge, in minor units, that the control API
// accepts: the largest integer that a JSON number holds exactly.
const maxChargeAmount = 1<<53 - 1

func parseMajorAmount(value string) (majorAmount, error) {
	match := majorAmountPattern.FindStringSubmatch(strings.TrimSpace(value))
	if match == nil {
		return majorAmount{}, fmt.Errorf("--confirm-charge %q is not an amount; write the total in major units, such as 49.00 or 49.00usd", value)
	}
	if len(match[2]) > maxFractionDigits {
		return majorAmount{}, fmt.Errorf("--confirm-charge %q has more than %d decimal places", value, maxFractionDigits)
	}
	return majorAmount{whole: match[1], fraction: match[2], currency: strings.ToLower(match[3])}, nil
}

// minor converts the amount to the minor units of currency. An amount with
// more decimal places than the currency has, such as 49.005 in usd, has no
// exact charge, so it is refused.
func (a majorAmount) minor(currency string) (int64, error) {
	exponent := currencyExponent(currency)
	if len(a.fraction) > exponent {
		return 0, fmt.Errorf("--confirm-charge %s has %d decimal places, and %s has %d", a.text(), len(a.fraction), strings.ToUpper(currency), exponent)
	}
	digits := strings.TrimLeft(a.whole+a.fraction+strings.Repeat("0", exponent-len(a.fraction)), "0")
	if digits == "" {
		return 0, nil
	}
	amount, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || amount > maxChargeAmount {
		return 0, fmt.Errorf("--confirm-charge %s is larger than any charge", a.text())
	}
	return amount, nil
}

func (a majorAmount) text() string {
	text := a.whole
	if a.fraction != "" {
		text += "." + a.fraction
	}
	return text
}

// currencyExponent is the number of decimal places of a lowercase ISO 4217
// currency in the minor units of the payment provider.
func currencyExponent(currency string) int {
	switch currency {
	case "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "ugx", "vnd", "vuv", "xaf", "xof", "xpf":
		return 0
	case "bhd", "jod", "kwd", "omr", "tnd":
		return 3
	default:
		return 2
	}
}

var currencyPattern = regexp.MustCompile(`^[a-z]{3}$`)

func validCurrency(currency string) bool { return currencyPattern.MatchString(currency) }

// formatMajor writes an amount in minor units in the major units of currency,
// such as 4900 usd as 49.00.
func formatMajor(amount int64, currency string) string {
	exponent := currencyExponent(currency)
	sign := ""
	if amount < 0 {
		sign, amount = "-", -amount
	}
	if exponent == 0 {
		return sign + strconv.FormatInt(amount, 10)
	}
	scale := int64(math.Pow10(exponent))
	return fmt.Sprintf("%s%d.%0*d", sign, amount/scale, exponent, amount%scale)
}

// formatCharge writes an amount with its currency, such as 49.00 USD.
func formatCharge(amount int64, currency string) string {
	return formatMajor(amount, currency) + " " + strings.ToUpper(currency)
}
