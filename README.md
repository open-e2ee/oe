# OpenE2EE CLI

`oe` creates OpenE2EE projects, keeps public service policy in a deterministic
file, and provides the command boundary for hosted Sandbox and Production.

The OpenE2EE Signal Protocol Relay provides hosted encrypted delivery, built to
work with the OpenE2EE Signal Protocol SDK. This public repository lets
developers inspect the command, config, credential, and release contracts.

## Install

Install the command from npm:

```bash
npm install --global @open-e2ee/oe
oe version
```

To run the command without a global install, give the full package name.
`npx oe` does not name this package.

```bash
npx @open-e2ee/oe@latest version
```

To build the command from source instead, run
`go build -o ./bin/oe ./cmd/oe`.

## Start

Run the command in the application directory:

```bash
oe new --project my-chat
npm install
oe doctor --wait
```

`oe new` creates the project and its Sandbox environment. It needs a session
but no card. At a terminal, it starts the login when no session is stored. It
writes:

- `open-e2ee.config.ts`, which contains public desired service policy for
  Sandbox.
- `.env.local`, which holds the Sandbox Relay connection.
- `.open-e2ee.lock` and `.env.local` in `.gitignore`.
- The `@open-e2ee/oe` devDependency in `package.json`, at the version of the
  running command, when the directory has a `package.json`.

`oe new` does not run the package manager. Its result names the install
command. Without a `package.json`, `oe new` writes no `package.json`. `oe`
reads the `@open-e2ee/oe/config` import of `open-e2ee.config.ts` with its own
copy, so the file loads without an install. Without `--project`, the project
slug comes from the directory name. `--dry-run` needs a session. It shows the
files that it would change, without a change. A directory that already has
`open-e2ee.config.ts` fails with `ALREADY_SET_UP`, and a `--project` value
that is not a slug fails with `PROJECT_INVALID`, exit 2. A slug that the
organization already uses fails with `PROJECT_EXISTS`, exit 2, in the run and
in the dry run. Its `next` creates a project with another slug, and its
message also names `oe link` for the project that exists. `oe new` never
connects a directory to an existing project.

`oe link PROJECT` connects the directory to a project that exists. When the
directory has no config, it writes `open-e2ee.config.ts` from the server
policy. It then adds the `@open-e2ee/oe` devDependency to a `package.json` and
names the install command, as `oe new` does.

`oe doctor --wait` waits for a managed message that is acknowledged after the
wait starts. When no message is acknowledged before `--timeout`, it fails with
`FIRST_MESSAGE_TIMED_OUT`, exit 6, and `next` is the same command. The control
API reports only whether the first message of a project was ever
acknowledged, so a project whose first message was acknowledged before the
wait fails at once with `FIRST_MESSAGE_ALREADY_ACKNOWLEDGED`, exit 1, and
`next` is `oe doctor`.

## Command contract

```text
oe new                  create a project and its Sandbox environment, and write the config and its Relay connection
oe auth login           log in with a browser, store the session in the OS keychain, and accept the terms; --organization selects the organization
oe auth status          show the person, the organizations, the terms state, and where the session is
oe auth logout          remove the stored session
oe org show             show the organization selected in the current session
oe org list             list the organizations of the account, and mark the current one
oe org switch [ORG]     move the stored session to another organization
oe doctor               check project, environment, connection, credentials, and control-plane health; --wait waits for the first acknowledged Sandbox message
oe identity check       check a public draft identity profile with an optional transient assertion
oe link [PROJECT]       link the directory to a project and write the env file of each active environment
oe project list         list the projects of the organization of the session, with the state of Production
oe project show         read a project and the state of each environment
oe project usage        show the current billing-period Relay usage of one environment
oe project connection   print the Relay connection URL of one environment
oe project upgrade      quote a paid plan for a project, or buy it for a person; --dry-run buys nothing
oe config push          apply the Sandbox section, then the Production section when the config has one; --dry-run changes nothing
oe config pull          write the Relay policy of each active environment into open-e2ee.config.ts
oe notifications        stage and verify best-effort notification profiles
oe agent setup          install the OpenE2EE skills for coding agents; --check writes nothing
oe version              print the CLI version
oe help [COMMAND]       show every command, or the usage of one command
```

Aliases keep the canonical command's data, exit status, and JSON `command` value.

| Canonical command                 | Aliases                                                                                               |
| --------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `oe project show [PROJECT]`       | `oe project`, `oe app`, `oe project view [PROJECT]`, `oe app show [PROJECT]`, `oe app view [PROJECT]` |
| `oe project list`                 | `oe projects`, `oe apps`, `oe app list`, `oe projects list`, `oe apps list`                           |
| `oe project usage [PROJECT]`      | `oe app usage [PROJECT]`                                                                              |
| `oe project connection [PROJECT]` | `oe app connection [PROJECT]`                                                                         |
| `oe auth status`                  | `oe auth`                                                                                             |
| `oe org show`                     | `oe org`, `oe org view`                                                                               |
| `oe org list`                     | `oe orgs`, `oe organizations`                                                                         |
| `oe notifications status`         | `oe notifications`                                                                                    |
| `oe agent setup --check`          | `oe agent`, `oe agent status`                                                                         |

A project read without `PROJECT` uses the local config. It never picks another
project from the account. `oe project my-chat` is invalid. Use
`oe project show my-chat`. `oe agent` and `oe agent status` write no files. `oe help --json`
lists aliases in `data.aliases`.

`oe help` lists short command descriptions and global flags. It also shows exit
codes and environment variables. `oe help COMMAND` and `oe COMMAND --help` show
scoped usage, flags, and aliases. `oe help --json` returns the unchanged command
surface as data. `oe login`, `oe logout`, and
`oe whoami` fail with exit 2, and `next` names the `oe auth` command.

Global flags can come before or after the command. Global `--json` emits one
final JSON document, and `oe auth login` emits one pending event before it. `--json-stream` emits newline-delimited progress and final
events. `--agent yes|no|auto` says whether a coding agent runs `oe`.
`--env sandbox|production` (`-e`) selects the environment. Without it,
`oe doctor`, `oe identity`, `oe project`, and `oe notifications` read `OPEN_E2EE_ENV`, then use
sandbox. `oe new` always uses sandbox. The config pull reads each active
environment, and `oe config push` applies every environment section of the
config. Only `--env` narrows either to one environment; `OPEN_E2EE_ENV` never changes
what a pull reads or what a push applies.

## Identity setup check

Run the check from a linked application directory with a current CLI session.
The session needs read access to the project and the selected environment.
The check writes no identity configuration or member account.

Save a public draft profile in `public-profile.json`:

```json
{
  "mode": "custom-token",
  "algorithms": ["ES256"],
  "issuer": "https://members.example",
  "audience": "signal-relay-production",
  "subjectClaim": "sub",
  "keys": [
    {
      "kid": "signing-1",
      "kty": "EC",
      "crv": "P-256",
      "x": "PUBLIC_X",
      "y": "PUBLIC_Y"
    }
  ]
}
```

Replace the example values with your public verifier values.
Use canonical base64url P-256 coordinates for `x` and `y`.
Keep private keys on your backend.
Native Clerk and Firebase profiles are unavailable in this check.
An external `provider-bound` profile uses the same explicit ES256 fields.

For an external profile, supply a fresh registration assertion through stdin:

```bash
oe identity check --profile public-profile.json --assertion-stdin --env production
```

This command sends the transient assertion once to the authenticated Console verifier.
Supply it through a protected stdin pipe from your backend or test harness.
Do not put assertions in command arguments, repository files, or support messages.
The assertion must follow the [Relay identity contract](https://docs.open-e2ee.dev/signal-relay/identity).

For device-owned identity, use `{"mode":"device-owned"}` as the profile.
Omit `--assertion-stdin`. The command forbids that flag and reads no assertion.

The result is `accepted_at_check` or `not_applicable` for device-owned identity.
An accepted result records the signed expiry as a historical fact.
It does not prove that the assertion remains valid.
Installed configuration, device admission, member binding, encrypted exchange, and lifecycle remain `unverified`.
The output omits assertions, member subjects, public keys, and arbitrary server errors.

After configuration, test the application with two test members and two devices.
Confirm separate accounts, repeat-member stability, message decryption, key rotation, removal, and suspension.
The Console check accepts drafts before the first account admission.
This CLI check can validate a draft for an existing project without changing it.

## Identity lifecycle limits

For normal key rotation, add the new public key while keeping the old key.
Start signing with the new key on your backend.
Remove the old key after its assertions expire, including clock tolerance.
`oe identity keys rotate --keys PATH` replaces the complete public key set.
For a config-writer project, `open-e2ee.config.ts` can declare the keys in `environments.<env>.identity.keys`.
In that case, edit that field and run `oe config push`.
`oe identity keys rotate` then refuses with `IDENTITY_CONFIG_WRITER`, because the next push would restore the file keys.
Key removal does not revoke existing device credentials.
Registered devices can still renew with a device proof.

`oe identity lifecycle suspend --target-stdin` refuses registration, linking,
renewal, recovery and identified requests for the target. It keeps account data
and devices. Stop issuing assertions for suspended members in your application.
`oe identity lifecycle activate --target-stdin` prepares a new change, subject to
current authority guards. `oe identity operation resume --kind lifecycle --operation-id ID`
continues the same lifecycle change. Permanently revoked devices stay revoked.

Previously issued anonymous capabilities, attachment URLs, sender certificates
and group tokens keep their independent expiry and policy.
Relay cannot recall downloaded or decrypted content.
Provider sign-in cannot recover a lost device-owned account key.
Read the [key rotation limits](https://docs.open-e2ee.dev/signal-relay/custom-token#key-rotation-and-revocation-limits)
and [account lifecycle procedure](https://docs.open-e2ee.dev/signal-relay/device-lifecycle-and-recovery#suspend-and-continue-an-account-change)
before a change.

## Identity operations

The server holds each identity operation. The CLI keeps no local operation state.
Each selection, keys rotation and lifecycle failure after dispatch reports the
operation ID and a status command:

```bash
oe identity operation status --kind K --operation-id ID --env E
```

Without `--operation-id`, status reads the current selection or keys operation.
For lifecycle, status without an ID needs `--target-stdin` and reports the
bound account's current operation.

To repeat one selection or keys-only mutation, run the same command again with
`OPEN_E2EE_OPERATION_ID=ID`. The server replays the same input and refuses changed input
with `IDENTITY_CONFLICT`. Lifecycle refuses `OPEN_E2EE_OPERATION_ID`. Continue a lifecycle
change with `oe identity operation resume --kind lifecycle --operation-id ID`.

Cancel a selection or keys operation with
`oe identity operation cancel --kind K --operation-id ID`.
A cancel sends its own operation ID. For a cancel, `OPEN_E2EE_OPERATION_ID` sets that
ID, and it cannot equal `--operation-id`.
A failed cancel reports its own ID in `data.cancellationOperationId`. To repeat
that cancel, set `OPEN_E2EE_OPERATION_ID` to that ID.
Production writes still require `--yes` or the existing interactive confirmation.

A dry-run and a `CONFIRMATION_REQUIRED` refusal show the exact identity change.
`oe identity select` and `oe identity keys rotate` return it in `data.changes`.
`oe config push` returns it in `data.environments.<env>.identity.changes`.
Each change has a `path`, an `action`, the installed public identity in `from`,
and the declared value in `to`. A keys-only change has the path
`environments.<env>.identity.keys`. A person at a terminal sees the change
before the Production prompt. The `next` of `CONFIRMATION_REQUIRED` is the
command that ran, with `--yes` added.

## Upgrade to 6.0

Version 6.0 renames each OpenE2EE Signal Protocol Relay name that `oe` keeps in
a file or prints in JSON output. Version 6.0 reads the old names and the new
names. Version 7.0 stops reading the old names.

| Place                            | Old name                                             | New name                                                           |
| -------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------ |
| `open-e2ee.config.ts` key        | `relay`                                              | `signalRelay`                                                      |
| `open-e2ee.config.ts` key        | `relayReceipts`                                      | `signalRelayReceipts`                                              |
| Config schema                    | `schema/config-v2.json`                              | `schema/config-v3.json`                                            |
| Skill directory                  | `open-e2ee-relay-config`                             | `open-e2ee-signal-relay-config`                                    |
| Skill directory                  | `open-e2ee-relay-notifications`                      | `open-e2ee-signal-relay-notifications`                             |
| Skill directory                  | `open-e2ee-relay-production`                         | `open-e2ee-signal-relay-production`                                |
| Skill directory                  | `open-e2ee-relay-setup`                              | `open-e2ee-signal-relay-setup`                                     |
| `oe doctor` error code           | `RELAY_CONNECTION_STALE`, `RELAY_CONNECTION_MISSING` | `SIGNAL_RELAY_CONNECTION_STALE`, `SIGNAL_RELAY_CONNECTION_MISSING` |
| `oe doctor` JSON key             | `relay`, `relayOrigin`                               | `signalRelay`, `signalRelayOrigin`                                 |
| `oe project connection` JSON key | `relayUrl`                                           | `signalRelayUrl`                                                   |
| `oe project show` JSON key       | `relayReceipts`                                      | `signalRelayReceipts`                                              |
| `oe project usage` JSON key      | `relayMau`                                           | `signalRelayMau`                                                   |

Until version 7.0, `oe` does these things:

- It reads a config file that uses the old keys or the new keys. A file that
  sets `relay` and `signalRelay` fails with `CONFIG_INVALID`.
- `oe new` writes the new keys. `oe config pull` writes the keys that the file
  already uses, and names each change with those keys.
- `oe doctor` prints one warning on stderr for a file that uses the old keys.
- The `defineConfig` types of `@open-e2ee/oe/config` accept both forms. The
  types of the old form are deprecated.
- The JSON output gives each old key and its new key, with the same value.
- `oe agent setup` installs each skill under its new name. It removes an old
  skill directory that holds only an unchanged copy that `oe` wrote. It keeps
  an old directory that you changed, and names it in the result.
- It accepts the old names and the new names in OpenE2EE Console responses.
- `oe doctor` returns each new error code in `code` and the old code in
  `data.legacyCode`.
- It reads the old environment variable names of
  [Upgrade to 5.0](#upgrade-to-50).

The old `oe doctor` error codes are deprecated. Version 7.0 removes
`data.legacyCode`.

Do these steps in each project.

1. In `open-e2ee.config.ts`, rename `relay` to `signalRelay` in the shared
   section and in each environment section.
2. Rename each `relayReceipts` key to `signalRelayReceipts`.
3. Run `oe doctor`. Make sure that it prints no warning about the config keys.
4. Run `oe agent setup`. If you installed the skills in the home directory,
   also run `oe agent setup --scope user`.
5. Move your changes from each old skill directory that `oe agent setup` keeps
   to the new skill. Then delete the old directory.
6. Change scripts that switch on `RELAY_CONNECTION_STALE` or
   `RELAY_CONNECTION_MISSING` to read `code` and use the new codes.
7. Change scripts that read an old JSON key to the new key.
8. Complete the steps of [Upgrade to 5.0](#upgrade-to-50) before version 7.0.

## Upgrade to 5.0

Version 5.0 renames each environment variable that you set for `oe`, and each
variable that `oe` writes for the application. Each new name starts with
`OPEN_E2EE_`, after any framework prefix.

| Old name                          | New name                                 |
| --------------------------------- | ---------------------------------------- |
| `OE_ACCESS_TOKEN`                 | `OPEN_E2EE_ACCESS_TOKEN`                 |
| `OE_ACCESS_TOKEN_SCOPES`          | `OPEN_E2EE_ACCESS_TOKEN_SCOPES`          |
| `OE_PROTECTION_BYPASS`            | `OPEN_E2EE_PROTECTION_BYPASS`            |
| `OE_ENV`                          | `OPEN_E2EE_ENV`                          |
| `OE_OPERATION_ID`                 | `OPEN_E2EE_OPERATION_ID`                 |
| `OPEN_E2EE_RELAY_URL`             | `OPEN_E2EE_SIGNAL_RELAY_URL`             |
| `NEXT_PUBLIC_OPEN_E2EE_RELAY_URL` | `NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL` |
| `EXPO_PUBLIC_OPEN_E2EE_RELAY_URL` | `EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL` |
| `VITE_OPEN_E2EE_RELAY_URL`        | `VITE_OPEN_E2EE_SIGNAL_RELAY_URL`        |

Versions 5.0 and 6.0 accept both names. Version 7.0 stops reading and writing
the old names. Until then, `oe` does these things:

- It reads the new name first. When the new name is empty, it reads the old
  name. It then prints one warning on stderr for that name. When you set both
  names, it uses the new name.
- It writes the new name to `.env.local` and `.env.production.local`. When the
  file already assigns the old name, it sets that line to the same value. It
  then prints a warning. It never adds an old name to a file.
- `oe doctor` reads the old name when the env file does not assign the new
  name. It then prints a warning.

The JSON output reports the new name in `data.variable` and
`data.connection.variable`. `oe auth status` reports the source
`OPEN_E2EE_ACCESS_TOKEN`. Help, errors, and messages use the new names.
`--env-var NAME` still selects a custom name. `oe` reads no old name for it.

Do these steps in each project.

1. In CI and scripts, rename each variable that you set for `oe`.
2. Run `oe link`. It writes the new name to `.env.local` and
   `.env.production.local`.
3. Change the application to read the new name.
4. Set the new name in the production build environment of the hosting
   provider, if it holds the Relay URL. Use the same value. Remove the old name after the
   deployed application reads the new name.
5. Change scripts that parse the JSON `variable` field or the `oe auth status`
   source.
6. Remove the old name from each env file. `oe` stops updating it in version
   7.0.

## Upgrade to 4.0

Version 4.0 removes the local identity operation store and the
`oe identity operation retry` command. It also removes the
`--confirm-state-never-used` and `--confirm-slot-never-used` flags. The server
holds each identity operation. Do these steps to continue a pending operation.

1. Before you upgrade, read each pending operation with the old version. The old
   status command takes a store lease and can write lock files. Run it in each
   project directory, for each kind and environment that you used:

   ```bash
   oe identity operation status --kind K --env E
   ```

   Record each pending operation ID. With `--json`, the ID is in
   `data.operation.operationId`.

2. After you upgrade, continue each pending operation by its ID.
   - For selection or keys-only, run the original command again with
     `OPEN_E2EE_OPERATION_ID=ID`. You can also use `oe identity operation status` or
     `oe identity operation cancel` with `--operation-id ID`. `oe config push`
     takes no `OPEN_E2EE_OPERATION_ID`. For a selection from a config push, use status
     or cancel.
   - For lifecycle, run
     `oe identity operation resume --kind lifecycle --operation-id ID`. A
     lifecycle ID starts with `lc1_`. Lifecycle commands refuse `OPEN_E2EE_OPERATION_ID`.

3. Remove `--confirm-state-never-used` and `--confirm-slot-never-used` from
   scripts. Version 4.0 refuses each flag with `IDENTITY_INPUT_INVALID` and exit 2.

4. Replace `oe identity operation retry` with the original command and
   `OPEN_E2EE_OPERATION_ID=ID`. Version 4.0 refuses `retry` with `IDENTITY_INPUT_INVALID`
   and exit 2.

5. Version 4.0 does not read the old store directory. The directory is `CONFIG/open-e2ee/oe/identity-attempts` on macOS and Linux, and `%LOCALAPPDATA%\OpenE2EE\oe\identity-attempts` on Windows.
   `CONFIG` is `~/Library/Application Support` on macOS, and `$XDG_CONFIG_HOME`
   or `~/.config` on Linux. You can delete the directory after step 1. `oe` does
   not delete it.

## Use from a coding agent

A coding agent can do each task in this section with `oe` and no console page.

Install the command without a prompt:

```bash
npm install --global @open-e2ee/oe
oe --json version
```

`oe` detects a coding agent from the environment variables that the agent sets,
for example `CLAUDECODE` or `CODEX_THREAD_ID`. Under an agent, the default
output is JSON, and `oe` never prompts and never opens a browser. Pass
`--agent yes` for an agent that `oe` does not detect. `--agent no` restores
text output. In JSON mode, each run writes one JSON document to stdout for the
result, for success and for failure. `oe auth login` also writes one pending
event before the result (see below). Under an agent, `oe project upgrade`
writes a pending event, and with `--wait` the result follows it. See
[Buy a paid plan](#buy-a-paid-plan).

```json
{"status":"ok","command":"project show","message":"...","data":{}}
{"status":"error","command":"config push","error":"...","code":"CONFIG_NOT_FOUND","next":"oe new"}
```

`command` is the command path, for example `project show` or `config push`.
Switch on `code`, not on the text of `error`. When `next` is present, it is the
command that moves the task forward. When `action` is present, `action.url` is a
page that a person must open, so give it to the person. In text mode, a failure
goes to stderr as `error:`, `action:`, and `next:` lines, and stdout stays clean.

| Exit code | Meaning                                                                                                                                              |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0         | The command succeeded.                                                                                                                               |
| 1         | The command failed. `code` tells why.                                                                                                                |
| 2         | The command line is invalid, or a required input is missing, for example `--yes`.                                                                    |
| 4         | Authentication is required. Run `next`, which is `oe auth login`, with `--organization ORG` after a failed switch. See `ACCESS_TOKEN_INVALID` below. |
| 5         | A person must act. `error` tells what to do. When `action.url` is present, it is the page to open.                                                   |
| 6         | The failure is temporary. `next` is the same command. Run it again later.                                                                            |

Log in once. A person must approve the login in a browser. At a terminal, `oe`
opens the browser and prints the page and the code:

```bash
oe auth login
```

```text
Open https://.../device?user_code=ABCD-EFGH and confirm that it shows the code ABCD-EFGH.
On another device, go to https://.../device and enter ABCD-EFGH.
```

For a control URL behind Vercel Authentication, set `OPEN_E2EE_PROTECTION_BYPASS`
before login. The CLI trims whitespace and sends the value in
`x-vercel-protection-bypass` only to the control URL. It never sends this header
to WorkOS or another host. Login stores the value with the session for that
control URL. Later commands use `OPEN_E2EE_PROTECTION_BYPASS` when it is not empty,
then the stored value, then no bypass. The value never appears in output.
An expired session removes only its session credentials and keeps this bypass
for the next login. Explicit `oe auth logout` removes both. If Vercel blocks a
request, `DEPLOYMENT_PROTECTION_REQUIRED` exits 5 and asks for a valid
`OPEN_E2EE_PROTECTION_BYPASS`. Another login cannot bypass deployment protection.

Under an agent, `oe` does not open the browser. It writes a pending event, then
the result after the person approves, so start the command in the background and
give the person `action.url` and `data.userCode`. The person opens the URL and
confirms that the page shows the code. On another device, the person goes to
`data.bareVerificationUrl` and enters the code:

```json
{"status":"pending","command":"auth login","message":"A person must approve this device.","action":{"kind":"browser","url":"https://.../device?user_code=ABCD-EFGH","reason":"login"},"data":{"bareVerificationUrl":"https://.../device","expiresInSeconds":300,"userCode":"ABCD-EFGH"}}
{"status":"ok","command":"auth login","message":"Signed in as Jane Doe (jane@example.com) in Acme Inc. Acme Inc. has not accepted the OpenE2EE terms.","data":{"email":"jane@example.com","userName":"Jane Doe","organizationName":"Acme Inc.","terms":"required","canAccept":true,"documents":[]},"next":"oe auth login --accept-terms"}
```

When no person approves the device in time, the login fails with
`LOGIN_TIMED_OUT`, exit 6, and `next` is the same command. Run it again, and
give the person the new URL and code. `--timeout` sets the wait. The wait ends
earlier when the code expires.

The organization accepts the terms once. When `data.terms` is `required`, show
the person the URL of each document in `data.documents`, and run
`oe auth login --accept-terms` only after the person agrees. With a stored
session, it starts no second login. When `canAccept` is false, an administrator
of the organization must accept, and `--accept-terms` fails with
`TERMS_PERMISSION_REQUIRED`, exit 5. A command that needs the terms fails with
`TERMS_REQUIRED`, exit 5, and `data.retry` is the command to run again after the
acceptance.

After the terms, `next` names the setup step of the directory: `oe new` in a
directory with a `package.json` and no `open-e2ee.config.ts`, `oe link` in a
directory that a config sets up and whose `.env.local` has no Relay
connection, `oe doctor` in a directory that a config sets up and whose
`.env.local` has the connection, and nothing in other directories. A person at a
terminal who logs in, in an app directory with no config, chooses to create a
project with `oe new`, link one with `oe link`, or skip. An agent or a run
without a terminal gets no prompt, only `next`.

`oe auth status` shows the person, the organization, the terms state, and where
the session is, and exits 4 without a session. An agent session names the
person that the agent works for. The organization line names each organization
of the account, its role, and the current one. The text shows no ID:

```text
Signed in as Jane Doe (jane@example.com) in Acme Inc. (macOS Keychain)
Acme Inc. has accepted the OpenE2EE terms.
Organizations: Acme Inc. (admin, current), Beta LLC (member)
```

The store is `macOS Keychain`, `Secret Service` on Linux,
`Windows Credential Manager`, or `OPEN_E2EE_ACCESS_TOKEN`. In JSON, `data` also has the
IDs (`user`, `organization.id`, and `agent.registrationId` for an agent), `role`,
`source`, and `store` (`keychain`, `secret-service`, `wincred`, or
`environment`), and `data.organizations` when the control API lists them. It
never has a token. Protected CI uses a scoped `OPEN_E2EE_ACCESS_TOKEN` instead of a
login.

`data.protectionBypass` is `{"source":"environment"}`,
`{"source":"keychain"}`, or `{"source":"none"}`. Text output adds
`Protection bypass: environment.` or `Protection bypass: keychain.` only when
a bypass is in use. Neither output format shows the value.

A person can belong to more than one organization. The session is in one
organization at a time, and each project command reads only the projects of
that organization. `oe project list` starts with the line
`Projects in Acme Inc.:`, and `data.organization` has its `id` and `name`.
When the list is empty and the person belongs to another organization, `next`
is `oe org switch`.

```bash
oe org list
oe org switch "Beta LLC"
oe auth login --organization "Beta LLC"
```

`oe org list` prints the name and the role of each organization, and marks the
current one with `*`. In JSON, `data.current` is the ID of the current
organization, and each entry of `data.organizations` has `id`, `name`, `role`,
`current`, and `switchable`. `oe org switch ORG` moves the stored session to
ORG. ORG is an ID, or a name that only one organization has, in any case.
Without ORG, a person at a terminal chooses one, and Enter keeps the current
organization. Under `--json` or an agent, `oe org switch` without ORG fails with
`USAGE_ERROR`, exit 2, and `data.organizations` lists the choices. An unknown
or ambiguous ORG fails with `USAGE_ERROR`, and `data.candidates` lists the
organizations that can match. A control command that needs an organization
fails with `ORGANIZATION_REQUIRED`, and `next` is `oe org switch`.

Some organizations need their own sign-in, for example SSO or MFA enrollment.
A switch to one of them fails with `ORGANIZATION_SIGN_IN_REQUIRED`, exit 5,
and the stored session does not change. `next` is
`oe auth login --organization ORG`. The person signs in again and chooses that
organization on the sign-in page. When the control API confirms another
organization after a switch, the switch fails with
`ORGANIZATION_SWITCH_FAILED`, exit 1, and `next` is `oe org list`. When the
control API does not list organizations yet, `oe org` fails with
`CONTROL_UPDATE_REQUIRED`, exit 1. `oe auth status` and `oe project list` then
show no organization line.

`oe auth login --organization ORG` logs in, then switches to ORG when the
session is in another organization. Without the flag, a person at a terminal
who belongs to more than one organization chooses one after a new login.
`oe org switch` and `--organization` refuse a session from `OPEN_E2EE_ACCESS_TOKEN`.
`oe org switch` also refuses an agent session, because it belongs to one
organization.

`OPEN_E2EE_ACCESS_TOKEN` takes precedence over the stored session, and
`oe auth login` never replaces it. When the control API refuses the token,
each command that sends it, `oe auth login` too, fails with
`ACCESS_TOKEN_INVALID`, exit 4, and no `next`. Set `OPEN_E2EE_ACCESS_TOKEN` to a new token, or unset it and run
`oe auth login`.

Read the Relay connection URL of a project. Text mode prints only the URL, so a
shell can capture it:

```bash
oe project connection
oe project connection my-chat --env production --json
```

Read the current UTC billing-period usage. Without `PROJECT`, the command uses
the project in the current directory's `open-e2ee.config.ts`. It uses the
current authenticated session or a scoped `OPEN_E2EE_ACCESS_TOKEN`, and defaults to
Sandbox (or `OPEN_E2EE_ENV`):

```bash
oe project usage
oe project usage my-chat --env production --json
```

`no_usage` means Relay verified zero activity. Missing or untrusted reporting
fails with `USAGE_UNAVAILABLE`, exit 6, instead of presenting zero usage.
`partial` and `stale` results include their status with the reported figures.

In JSON, `data.variable` names the variable that the application reads (see
[Configuration ownership](#configuration-ownership)). A project with no active
environment fails with `ENVIRONMENT_NOT_ACTIVE`. For Sandbox, `next` is
`oe new`. For Production, `next` is `oe config push` only when the config of
the project has a Production section and the repository writes the policy.
Otherwise `next` is empty, and the message names the steps that apply: add
`production: {}` under `environments`, then run `oe config push`, or activate
Production on the plan page of the project in the console.

A project read (`oe project show`, `oe project connection`, `oe link`,
`oe doctor`, `oe config push`, and `oe config pull`) names `oe project list` as
`next` when it cannot find the project. A value that is not a slug fails with
`PROJECT_INVALID`, exit 2, before a request. A project that the account cannot
read fails with `PROJECT_NOT_FOUND`, exit 1. For a person in more than one
organization, the error adds that the project can belong to another
organization, and names `oe org list`. When the control API refuses to
read a project that the project list shows, the read fails with
`CONTROL_CONFLICT`, exit 1, and `data.listed` is `true`. The control API
also gives that code to a project that it is deleting or that cannot take a
request yet, so run the command again once. When the refusal stays, the
service holds an inconsistent record that no `oe` command repairs. `next` is
empty, and `action.url` is the page where a person reports the slug and the
error.

`oe config push` applies the Sandbox section, then the Production section. The
`production` entry under `environments` is the opt-in: without it, a push never
changes Production. When Sandbox does not apply, the push skips Production.
`data.environments.<env>.status` is `applied`, `unchanged`, `blocked`, `failed`,
or `skipped`, and a push that does not apply every section takes the `code` of
the first section that did not apply. `oe config push --dry-run` shows the
changes and changes nothing.

A Production change never waits for an answer that no person can give. Without
a terminal, under an agent, and in JSON and CI modes, the push stops with
`CONFIRMATION_REQUIRED`. Review the changes, then run `oe config push --yes`.
An activation needs the billing permission, the terms, an open Free plan slot,
a card on the organization, and a default payment method that backs fewer than
2 Free projects. Each missing one exits 5: `BILLING_PERMISSION_REQUIRED`,
`TERMS_REQUIRED`, `FREE_PROJECT_LIMIT`, `CARD_REQUIRED`, or
`FREE_PAYMENT_METHOD_LIMIT`. For `CARD_REQUIRED`, `action.url` is the card page.
A person at a terminal waits on the card page instead, and `oe` opens it in a
browser. For `FREE_PAYMENT_METHOD_LIMIT`, `action.url` is the billing page of
the organization. After the card, the person can still get
`FREE_PAYMENT_METHOD_LIMIT`.
When the project can buy a paid plan, `next` for `FREE_PROJECT_LIMIT` and
`FREE_PAYMENT_METHOD_LIMIT` is `oe project upgrade PROJECT --plan PLAN`. `PLAN`
is the first plan that the control API offers to the project. When the project
cannot buy a plan, `FREE_PROJECT_LIMIT` has no `next`, and
`FREE_PAYMENT_METHOD_LIMIT` names the push again.

### Buy a paid plan

`oe project upgrade [PROJECT] --plan PLAN` buys a paid plan for a project, for
example `--plan relay_starter_v1`. Without `PROJECT`, the project is the one in
`open-e2ee.config.ts`. `oe project show` names the current plan in
`data.project.plan`, which is `null` for a project with no plan. It leaves out
`plan` when the session cannot read the plans of the project.

A purchase charges the payment method of the organization. So a person must
confirm the charge:

1. `oe project upgrade --plan PLAN --dry-run` quotes the plan and buys nothing.
   `data.total` and `data.currency` are the charge in minor units, and
   `data.totalMajor` is the same charge in major units. `next` is the purchase
   command with `--confirm-charge` set to that total.
2. Show the quote to the person.
3. When the person agrees, the person runs `next`.

A person at a terminal can also run the command without `--confirm-charge`.
`oe` shows the quote and asks once. Any other run without `--confirm-charge`
fails with `CONFIRMATION_REQUIRED`, exit 2, and buys nothing. `--yes` alone
never buys. When `--confirm-charge` is not the total of a new quote, the run
fails with `CHARGE_CONFIRMATION_MISMATCH`, exit 2, and buys nothing.
`data.expected` is the total of the quote. `--quote TOKEN` buys at the quote
of a dry run, and needs `--confirm-charge` with the currency, such as
`--confirm-charge 53.90usd`. `data.quote` of the dry run is that token. Keep it
private, because it confirms the purchase. The control API compares the charge
with the quote, and the same token always names the same purchase. After a
purchase, `oe` waits for the plan change for at most `--timeout`, 5 minutes by
default. At the end of the wait, the run fails with `PURCHASE_PENDING`, exit 6,
and the purchase goes on.

An agent cannot buy a plan. Under an agent, `oe project upgrade` without
`--dry-run` never sends a purchase. It writes one pending event and exits 5.
Without `--quote`, the event holds the quote. `action.url` is the plan page
where the person buys, and `next` adds `--wait`. With `--wait`, the run waits
for the purchase of the person, for at most `--timeout`. With a credential from
`OPEN_E2EE_ACCESS_TOKEN`, a run without `--dry-run` fails with
`AGENT_PURCHASE_NOT_ALLOWED`, exit 5, before a quote.

| `code`                                                                                                                                                    | Exit | What to do                                                                        |
| --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | --------------------------------------------------------------------------------- |
| `QUOTE_EXPIRED`, `PRICE_CHANGED`, `AUTHORITY_CHANGED`, `METHOD_CHANGED`                                                                                   | 1    | Quote again with `next`, and show the new total to the person.                    |
| `CARD_REQUIRED`, `TAX_LOCATION_REQUIRED`, `EU_UK_VAT_ID_REQUIRED`, `PAYMENT_ACTION_REQUIRED`, `SUPPORT_REQUIRED`, `ACTIVATE_FREE_FIRST`, `PAYMENT_FAILED` | 5    | Give `action.url` to the person.                                                  |
| `PURCHASE_OPEN`, `PAID_PURCHASE_UNAVAILABLE`, and `EU_UK_VAT_ID_REQUIRED` with `data.detail` `vat_id:pending`                                             | 6    | Run `next` again later.                                                           |
| `CHARGE_CONFIRMATION_MISMATCH`, `CONFIRMATION_REQUIRED`                                                                                                   | 2    | Ask the person to confirm the total of a new quote.                               |
| `BILLING_PERMISSION_REQUIRED`                                                                                                                             | 5    | A person with the billing permission buys the plan at `action.url`.               |
| `PLAN_NOT_AVAILABLE`                                                                                                                                      | 1    | Choose a plan from `data.plans`.                                                  |
| `PURCHASE_NOT_IMMEDIATE`                                                                                                                                  | 5    | The change does not take effect now. The person changes the plan at `action.url`. |

For `ACTIVATE_FREE_FIRST`, `next` is `oe config push` when the config has a
Production section.

## Configuration ownership

`open-e2ee.config.ts` is public policy. `oe` evaluates it with Node.js 22.18 or
later and validates its default export against `schema/config-v3.json`. A file
that uses the deprecated `relay` key validates against `schema/config-v2.json`
until version 7.0. See [Upgrade to 6.0](#upgrade-to-60). The
schema rejects unknown fields so a secret cannot silently remain in the file. Secrets belong in the service secret store. Login
credentials belong in the operating-system keychain. Protected CI can supply a
scoped `OPEN_E2EE_ACCESS_TOKEN`. The CLI keeps it in memory and never stores it.

If the control URL needs `OPEN_E2EE_PROTECTION_BYPASS`, login stores that secret with the
session in the keychain. The environment value takes precedence. The header
goes only to the control URL, and the value never appears in output.

Each project has one writer mode:

- `config` makes the repository the desired-state writer.
- `console` makes the console the desired-state writer.

Local mutation commands take an advisory project lock on `.open-e2ee.lock`, an
empty file next to `open-e2ee.config.ts`. The file stays after the command, and
`oe new`, `oe link`, `oe config push`, and `oe config pull` add it to
`.gitignore`. Remote mutations include
a stable idempotency key. Plans and deploys include the server's expected
revision. A console-first project or a revision conflict fails closed.

`oe config pull` writes the Relay policy of each active environment from the
console into `open-e2ee.config.ts` with the fewest changes. A value that the
shared `signalRelay` section already gives stays shared. A different value becomes an
override in the environment section, and the shared section never changes. The
pull adds a missing section for an active environment, and it keeps the section
of an inactive environment. It changes only the values and keeps every comment.

An addition needs no consent. A replaced value needs `--yes` or the answer of a
person at a terminal. Without them, the pull stops with `CONFIRMATION_REQUIRED`,
exit 2, and returns the changes in `data`. The pull writes nothing when the file
computes a value that the pull changes. It then stops with
`CONFIG_EDIT_REQUIRED`, exit 5, and `data.edits` holds one entry for each such
value. With `--dry-run`, the pull returns the changes and the edits, and writes
nothing.

The config holds no Relay connection. `oe new` writes the sandbox
connection to `.env.local`. `oe config push` writes the production value to
`.env.production.local` when Production applies. The commands add both files to `.gitignore`. The application
does not select a Relay hostname or pair an endpoint with a second key.

The variable follows the framework in `package.json`:

| Dependency                      | Variable                                 |
| ------------------------------- | ---------------------------------------- |
| `next`                          | `NEXT_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL` |
| `expo`                          | `EXPO_PUBLIC_OPEN_E2EE_SIGNAL_RELAY_URL` |
| `vite`                          | `VITE_OPEN_E2EE_SIGNAL_RELAY_URL`        |
| Any other, or no `package.json` | `OPEN_E2EE_SIGNAL_RELAY_URL`             |

The first match in the table wins. The CLI replaces only its own comment and
the lines that assign its variable. It keeps every other line, the line
breaks, an `export` prefix, and the file permissions. Until version 7.0, the
CLI also sets a line that assigns the old name of its variable. See
[Upgrade to 5.0](#upgrade-to-50).

`oe config push` writes `.env.production.local`. If the hosting provider does
not read that file, install the value of the variable that `oe config push`
names in the production build environment. The application source stays unchanged.

## iOS notification workflow

Push is a best-effort wake. The durable Relay mailbox, authenticated pull, and
acknowledgement are delivery authority.

```bash
oe notifications setup ios --profile background-only
oe notifications setup ios --profile visible-alert
oe notifications add-nse
oe notifications verify ios
oe notifications verify ios --app-bundle ./path/to/App.app
oe notifications apple-filtering-request
```

`setup ios` supports discretionary background wakes or generic visible alerts.
It does not put message content, ciphertext, identifiers, or receipt state in a
provider payload. Expo projects must use a development or native build. Expo Go
cannot verify remote push or contain a Notification Service Extension.

`add-nse` creates a generic, timeout-safe Notification Service Extension. Expo
CNG uses `@bacons/apple-targets`. Bare React Native receives the same source and
an exact Xcode target handoff. The extension does not get App Group or Keychain
access by default and does not decrypt a preview.

Apple's notification-filtering entitlement is separate from an NSE. It permits
an approved, signed extension to suppress an alert. It does not improve APNs
transport or guarantee execution. The CLI keeps filtering unavailable until
Apple approval, signed-build inspection, and physical-device suppression
evidence all pass. Simulator results are not physical-device evidence.

## Distribution contract

`@open-e2ee/oe` contains a small Node launcher and six optional native packages:
macOS, Linux, and Windows on arm64 and x64. Installation does not run a
postinstall download. The release workflow cross-compiles the Go command, creates
checksums and a CycloneDX SBOM, and creates GitHub build-provenance attestations
for every release artifact. Verify a published artifact with:

```bash
gh attestation verify PATH_TO_ARTIFACT -R open-e2ee/oe
```

The repository also contains a Homebrew formula for the native command.

## Development

Development needs Go 1.26.10 or later, Node 22.18 or later, and npm 11 or later.
CI and release builds use Go 1.27.3; CI also tests Go 1.26.10.

```bash
go test -race ./...
go vet ./...
npm ci
npm test
npm run format:check
npm run homebrew:test
```

The CLI does not contain telemetry. The service measures managed activation from
the first authenticated control request and first acknowledged message. This
command does not use an analytics SDK.

## Security

See [SECURITY.md](./SECURITY.md). Do not open a public issue for a suspected
credential, authentication, authorization, or cryptographic defect.

`OPEN_E2EE_ACCESS_TOKEN` stays in memory. `OPEN_E2EE_PROTECTION_BYPASS` is a secret that login
stores with the session for the control URL. The environment value takes
precedence over the stored bypass. The CLI sends the header only to the control
URL. The bypass value never appears in output. `oe auth logout` removes the
stored session and its bypass.

## License

Apache-2.0. See [LICENSE](./LICENSE).
