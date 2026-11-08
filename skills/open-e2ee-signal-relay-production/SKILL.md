---
name: open-e2ee-signal-relay-production
description: Use this skill to activate or change the Production environment of an OpenE2EE Signal Protocol Relay project with the oe CLI. It covers the Production section of open-e2ee.config.ts, oe config push --dry-run, and oe config push --yes, and oe project upgrade for a paid plan. Use it when a person asks to go to Production or to buy a paid plan, or when the oe CLI returns CARD_REQUIRED, BILLING_PERMISSION_REQUIRED, FREE_PROJECT_LIMIT, FREE_PAYMENT_METHOD_LIMIT, or TERMS_REQUIRED for a push.
---

# OpenE2EE Signal Protocol Relay Production

A project has a Sandbox environment from `oe new`. Production joins the
project only when `open-e2ee.config.ts` has a Production section. The first
push with that section activates Production on the Free plan. The activation
uses one of the two Free Production projects of the organization.

## Rules

- Switch on `code`. Do not parse the text of `error`.
- Run `oe config push --dry-run` before each push that changes Production.
- Pass `--yes` only after the person agrees to use one of the two Free
  Production slots of the organization.
- When `action.url` is present, give the URL to the person. The person must
  open it.
- A push never deactivates Production. Do not remove the Production section
  to stop Production.

## Activate Production

1. Add the Production section under `environments` in
   `open-e2ee.config.ts`:

   ```ts
   environments: {
     sandbox: { /* keep this section */ },
     production: {},
   },
   ```

2. Run `oe config push --dry-run`. In
   `data.environments.production`, `activation` is `free` for an
   activation. `blockedBy` names a gate that stops the activation.
3. Show the changes to the person. Tell the person that the activation uses
   one of the two Free Production slots of the organization.
4. Run `oe config push --yes` only after the person agrees.
5. Read `data.environments.production.status`. `applied` means that
   Production is active.

`oe config push` writes the Production Relay connection URL to
`.env.production.local`. If the host of the app does not read that file,
tell the person to set the same variable in the production build
environment. Do not print the value.

## Change Production

1. Edit the Production values in `open-e2ee.config.ts`.
2. Run `oe config push --dry-run`, and show the changes to the person.
3. Run `oe config push --yes` only after the person agrees.

## Codes

The activation checks the gates in this order: the billing permission, the
terms, the Free plan slot, the card, and the Free limit of the payment method.

| `code`                        | What to do                                                                                                                                                                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CONFIRMATION_REQUIRED`       | A Production change needs `--yes`. Show the changes to the person. Run `next` only after the person agrees.                                                                                                                              |
| `BILLING_PERMISSION_REQUIRED` | This account does not have the billing permission. Tell the person that a billing administrator must run the push or grant the permission. `next` is empty.                                                                              |
| `TERMS_REQUIRED`              | The organization did not accept the terms. Use the terms steps of the `open-e2ee-signal-relay-setup` skill. Then run the command in `data.retry`.                                                                                        |
| `FREE_PROJECT_LIMIT`          | The organization already has two Free Production projects. When `next` is `oe project upgrade`, use [Buy a paid plan](#buy-a-paid-plan). When `next` is empty, tell the person to change a plan in the console, then run the push again. |
| `CARD_REQUIRED`               | The organization has no card. Give `action.url` to the person. After the person adds a card, run `next`.                                                                                                                                 |
| `FREE_PAYMENT_METHOD_LIMIT`   | The default payment method of the organization already backs two Free Production projects. When `next` is `oe project upgrade`, use [Buy a paid plan](#buy-a-paid-plan). Otherwise give `action.url` to the person, then run `next`.     |

## Buy a paid plan

`oe project upgrade [PROJECT] --plan PLAN` buys a paid plan for a project. An
agent can quote a plan, but only a person can buy it. `oe project show` names
the current plan in `data.project.plan`.

1. Run `oe project upgrade --plan PLAN --dry-run`. It buys nothing.
   `data.totalMajor` and `data.currency` are the charge.
2. Show the plan and the charge to the person. Do not print `data.quote`. It
   confirms the purchase.
3. Run `oe project upgrade --plan PLAN` without `--dry-run`. The run sends no
   purchase. It exits 5 with a pending event. Give `action.url` to the person.
   The person buys the plan on that page.
4. To wait for the purchase, run `next`, which adds `--wait`. `PURCHASE_PENDING`,
   exit 6, means that the wait ended before the plan changed.

`AGENT_PURCHASE_NOT_ALLOWED` means that the credential comes from
`OPEN_E2EE_ACCESS_TOKEN`. Give `action.url` to the person.

| `code`                                                                                                                                                    | What to do                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `QUOTE_EXPIRED`, `PRICE_CHANGED`, `AUTHORITY_CHANGED`, `METHOD_CHANGED`                                                                                   | Exit 1. Run `next` to quote again. Show the new charge to the person. |
| `CARD_REQUIRED`, `TAX_LOCATION_REQUIRED`, `EU_UK_VAT_ID_REQUIRED`, `PAYMENT_ACTION_REQUIRED`, `SUPPORT_REQUIRED`, `ACTIVATE_FREE_FIRST`, `PAYMENT_FAILED` | Exit 5. Give `action.url` to the person.                              |
| `PURCHASE_OPEN`, `PAID_PURCHASE_UNAVAILABLE`, and `EU_UK_VAT_ID_REQUIRED` with exit 6                                                                     | Exit 6. Run `next` again later.                                       |
| `BILLING_PERMISSION_REQUIRED`                                                                                                                             | Exit 5. A person with the billing permission buys at `action.url`.    |
| `PLAN_NOT_AVAILABLE`                                                                                                                                      | Exit 1. `data.plans` lists the plans that the project can change to.  |
