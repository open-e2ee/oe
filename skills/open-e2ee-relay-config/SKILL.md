---
name: open-e2ee-relay-config
description: Use this skill to change the OpenE2EE Relay policy of a project with open-e2ee.config.ts and the oe CLI. It covers oe config push, oe config pull, and --dry-run. Use it when a person asks to change a retention value, to apply the config, or to bring a console change into the file. Use it when the oe CLI returns CONFIRMATION_REQUIRED, CONFIG_EDIT_REQUIRED, CONFIG_NOT_FOUND, CONFIG_INVALID, or CONSOLE_WRITER.
---

# OpenE2EE Relay config

`open-e2ee.config.ts` is the public service policy of one project. It is in
the root of the app, next to `package.json`. Do not put secrets in it.

```ts
// Public service policy. Do not put secrets in this file.
import { defineConfig } from "@open-e2ee/oe/config";

export default defineConfig({
  product: "signal-relay",
  project: "my-chat",
  relay: {
    deliveryRetention: "30d",
    attachmentRetention: "30d",
    relayReceipts: true,
  },
  environments: {
    sandbox: {
      relay: {
        deliveryRetention: "1d",
        attachmentRetention: "1d",
      },
    },
  },
});
```

- The `relay` section is the shared policy. An environment section can
  override each value.
- A retention value is one of `1h`, `6h`, `12h`, `1d`, `3d`, `7d`, `14d`,
  and `30d`.
- `relayReceipts` turns Relay delivery receipts on or off. It is `true` when
  the file leaves it out. A Relay delivery receipt means that the recipient
  device stored and acknowledged the message. It never proves decryption.
  Each stored Relay delivery receipt uses one delivery unit for each sender
  device.
- `oe` reads the file with Node.js 22.18 or later. The schema refuses an
  unknown field.

## Rules

- Switch on `code`. Do not parse the text of `error`.
- Run `oe config push --dry-run` before a push that changes Production.
  Show the changes to the person.
- Pass `--yes` only after the person agrees to the changes.
- Exit 6 means that the failure is temporary. Run `next` again later.

## Push the file

`oe config push` applies the Sandbox section, then the Production section
when the file has one. When Sandbox does not apply, the push skips
Production.

1. Edit `open-e2ee.config.ts`.
2. Run `oe config push --dry-run`. It shows the changes and changes nothing.
3. Run `oe config push`.
4. Read `data.environments`. The `status` of each environment is `applied`,
   `unchanged`, `blocked`, `failed`, or `skipped`. A dry run gives `planned`.

A Sandbox change needs no consent. A Production change needs `--yes`. To
change Production, use the `open-e2ee-relay-production` skill.
`oe config push --env sandbox` applies only the Sandbox section.

## Pull the console policy

`oe config pull` writes the Relay policy of each active environment into
`open-e2ee.config.ts`. It changes only the values and keeps the comments.

1. Run `oe config pull --dry-run`. It shows the changes and writes nothing.
2. Run `oe config pull`. An added value needs no consent.
3. If the pull replaces a value, it stops with `CONFIRMATION_REQUIRED`.
   Show the changes in `data` to the person. A replaced value is often a
   local edit that is not pushed.
4. Run `oe config pull --yes` only after the person agrees.

## Make the edit that CONFIG_EDIT_REQUIRED asks for

`oe` changes only a literal value. When the file computes a value with an
expression, `oe` cannot change it and writes nothing. `data.edits` holds one
entry for each such value:

- `file` is the path of `open-e2ee.config.ts`.
- `path` is the property path of the value, for example
  `environments.sandbox.relay.deliveryRetention`.
- `currentExpression` is the expression in the file now.
- `newValue` is the value that the file must give.

Do these steps for each entry:

1. Open `file` and find `currentExpression` at `path`.
2. Change the source so that the value at `path` is `newValue`. Keep the
   code that gives the other values.
3. Run the same command again.

Do not delete the expression without a reason. If the expression reads a
value that you do not understand, ask the person.

## Codes

| `code`                  | What to do                                                                                                                          |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `CONFIG_NOT_FOUND`      | The directory has no `open-e2ee.config.ts`. Use the `open-e2ee-relay-setup` skill.                                                  |
| `CONFIG_INVALID`        | The file does not load, or the schema refuses it. There is no `next`. Fix the field that `error` names, then run the command again. |
| `CONFIRMATION_REQUIRED` | The change needs consent. Show the changes to the person. Run `next` only after the person agrees.                                  |
| `CONFIG_EDIT_REQUIRED`  | The file computes a value that `oe` must change. Follow [the manual edit](#make-the-edit-that-config_edit_required-asks-for).       |
| `CONSOLE_WRITER`        | The console owns the policy of this project. Tell the person to change the policy in the console. `oe config push` changes nothing. |
| `NODE_REQUIRED`         | Node.js 22.18 or later is not on `PATH`. Give `action.url` to the person.                                                           |
