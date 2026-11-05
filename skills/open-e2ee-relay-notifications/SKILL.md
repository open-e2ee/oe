---
name: open-e2ee-relay-notifications
description: Use this skill to set up and verify iOS notification profiles for an OpenE2EE Signal Protocol Relay project with the oe notifications commands. It covers background wakes, visible alerts, the Notification Service Extension, and the Apple filtering request. Use it when a person asks to add push notifications to an iOS, Expo, or React Native app that uses the Relay.
---

# OpenE2EE Signal Protocol Relay notifications

A push is a best-effort wake. The Relay mailbox is the delivery authority.
The app gets each message with an authenticated pull and acknowledges it.
Do not put message content, ciphertext, identifiers, or receipt state in a
push payload.

## Commands

Run each command in the app directory. Each command uses the Sandbox
environment unless `--env production` or `OPEN_E2EE_ENV` selects Production.

| Command                                                | What it does                                                               |
| ------------------------------------------------------ | -------------------------------------------------------------------------- |
| `oe notifications status`                              | Shows the notification profiles that the environment allows.               |
| `oe notifications setup ios --profile background-only` | Stages background wakes in the app and allows the profile.                 |
| `oe notifications setup ios --profile visible-alert`   | Stages generic visible alerts in the app and allows the profile.           |
| `oe notifications add-nse`                             | Adds a generic Notification Service Extension.                             |
| `oe notifications verify ios`                          | Checks the iOS configuration of the app.                                   |
| `oe notifications verify ios --app-bundle ./App.app`   | Also checks a signed app bundle.                                           |
| `oe notifications apple-filtering-request`             | Gives the Apple page that requests the notification filtering entitlement. |

## Steps

1. Run `oe notifications setup ios --profile background-only`. Use
   `--profile visible-alert` when the person wants a generic visible alert.
2. Read `data.remainingAction`. When it is not empty, tell the person what
   to do. For example, a bare React Native app needs an Xcode step.
3. Run `oe notifications verify ios`.
4. If the person asks for an extension, run `oe notifications add-nse`, then
   run `oe notifications verify ios` again.

## Rules

- An Expo app needs a development build or a native build. Expo Go cannot
  verify a remote push or hold a Notification Service Extension.
- The extension gets no App Group and no Keychain access. It does not
  decrypt a preview.
- The Apple filtering entitlement lets an approved, signed extension
  suppress an alert. It does not make delivery more reliable. Do not tell
  the person that it does.
- Filtering stays blocked until Apple approves it, a signed build passes
  inspection, and a physical device shows the suppression. A Simulator
  result is not physical-device evidence.
