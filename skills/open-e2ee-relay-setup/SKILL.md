---
name: open-e2ee-relay-setup
description: Use this skill to set up the OpenE2EE Signal Protocol Relay in an app with the oe CLI. It covers the login, the OpenE2EE terms, a new project, a link to a project that exists, and the first message check. Use it when a person asks to add the Relay to an app, or to create or link an OpenE2EE project. Use it when the oe CLI returns AUTHENTICATION_REQUIRED, ACCESS_TOKEN_INVALID, LOGIN_TIMED_OUT, ALREADY_SET_UP, PROJECT_EXISTS, PROJECT_INVALID, PROJECT_NOT_FOUND, PROJECT_REQUIRED, CONTROL_CONFLICT, TERMS_REQUIRED, TERMS_PERMISSION_REQUIRED, FIRST_MESSAGE_TIMED_OUT, or FIRST_MESSAGE_ALREADY_ACKNOWLEDGED.
---

# OpenE2EE Relay setup

`oe` is the OpenE2EE CLI. When a coding agent runs `oe`, `oe` writes one JSON
document to stdout. It never prompts and never opens a browser.

## Rules

- Switch on `code`. Do not parse the text of `error`.
- When `next` is present, it is the command that moves the task forward. Run
  it, unless a rule in this skill tells you not to.
- When `action.url` is present, give the URL to the person. The person must
  open it.
- Exit 4 means that a login is necessary. With `ACCESS_TOKEN_INVALID`, a
  login does not help. Exit 5 means that a person must act. Exit 6 means that
  the failure is temporary. Run `next` again later.
- Run `oe help` for the usage of each command.

## Log in

1. Start `oe auth login` in the background. It writes a pending event, then
   the result after the person approves the login.
2. Give the person `action.url` and `data.userCode` from the pending event. The
   person opens the URL and confirms that the page shows the code. On another
   device, the person goes to `data.bareVerificationUrl` and enters the code.
3. Read the result. The message names the person and the organization, for
   example "Signed in as Jane Doe (jane@example.com) in Acme Inc." Show it to
   the person. `oe auth status` shows the session at any time.
4. If `data.terms` is `required`, follow [The terms](#the-terms).

## The terms

The organization accepts the OpenE2EE terms one time.

1. Show the person the `name` and the `url` of each entry in
   `data.documents`.
2. Ask the person to agree to the terms.
3. Run `oe auth login --accept-terms` only after the person agrees. With a
   stored session, it starts no second login.
4. If `data.retry` is present, run that command again.

Do not accept the terms for a person who did not agree. When
`data.canAccept` is `false`, an administrator of the organization must
accept the terms.

## Create a project

Run `oe new` in the app directory. The app directory holds the
`package.json` of the app.

- `oe new --dry-run` shows the files that `oe new` writes, and changes
  nothing. It needs a session, and it fails with `PROJECT_EXISTS` when the
  organization already uses the slug.
- `oe new --project my-chat` sets the project slug. Without `--project`, the
  slug comes from the name of the directory.

`oe new` creates the project and its Sandbox environment. It writes these
files:

- `open-e2ee.config.ts`, the public service policy. The file imports
  `defineConfig` from `@open-e2ee/oe/config`. Do not put secrets in it.
- `.env.local`, which holds the Sandbox Relay connection URL. `oe` adds the
  file to `.gitignore`.
- The `@open-e2ee/oe` devDependency in `package.json`.

`oe new` does not run the package manager. Run the command in
`data.install`. `data.connection.variable` is the variable that the app
reads. Do not print the value of the variable.

## Link a project that exists

Run `oe link my-chat` only when the person names the project `my-chat`.
`oe project list` lists the projects that the session can read. When no
person names a project, ask the person which project to link.

`oe link my-chat` writes `open-e2ee.config.ts` from the server policy when
the directory has no config. It writes the env file of each active
environment. When it writes the config, it adds the `@open-e2ee/oe`
devDependency to `package.json`, as `oe new` does. Run the command in
`data.install`. In a directory that `open-e2ee.config.ts` already sets up,
`oe link` rewrites only the env files.

## Check the setup

Start `oe doctor --wait` in the background. It checks the config, the
session, the project, and the Relay connection. Then it waits for the first
acknowledged Sandbox message. Tell the person to start the app and send a
message. Only an acknowledgment that comes after the wait starts counts.

## Codes

| `code`                               | What to do                                                                                                                                                                                                  |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AUTHENTICATION_REQUIRED`            | No session is stored. Follow [Log in](#log-in), then run the command again.                                                                                                                                 |
| `ACCESS_TOKEN_INVALID`               | The control API refused the token in `OE_ACCESS_TOKEN`, and `oe auth login` never replaces it. Tell the person to set `OE_ACCESS_TOKEN` to a new token, or to unset it and log in.                          |
| `LOGIN_TIMED_OUT`                    | No person approved the device in time. Run `next` again, and give the person the new URL and code.                                                                                                          |
| `ALREADY_SET_UP`                     | `open-e2ee.config.ts` already sets up this directory. Do not run `oe new` again. Run `oe link` to write the env files.                                                                                      |
| `PROJECT_EXISTS`                     | The organization already has a project with this slug. `next` creates a project with another slug. Never replace `next` with `oe link` unless the person asked for that project. Another person can own it. |
| `PROJECT_INVALID`                    | The `--project` value or the `PROJECT` argument is not a slug. Run `next`. Ask the person before you use a slug that the person did not give.                                                               |
| `PROJECT_NOT_FOUND`                  | No project that this account can read has this slug. `next` is `oe project list`. Ask the person which project to link.                                                                                     |
| `PROJECT_REQUIRED`                   | No slug comes from the directory name, or `oe link` has no project. Run `next`. If `next` is `oe project list`, ask the person which project to link.                                                       |
| `CONTROL_CONFLICT`                   | When `data.listed` is `true`, the project is in the list, but the service refused to read it. No `oe` command repairs it. Give `action.url` to the person to report the slug and the error.                 |
| `TERMS_REQUIRED`                     | The organization did not accept the terms. Follow [The terms](#the-terms). Then run the command in `data.retry`.                                                                                            |
| `TERMS_PERMISSION_REQUIRED`          | This account cannot accept the terms. Tell the person that an administrator of the organization must accept them.                                                                                           |
| `FIRST_MESSAGE_TIMED_OUT`            | No message was acknowledged before `--timeout`. Tell the person to send a message from the app, then run `next`.                                                                                            |
| `FIRST_MESSAGE_ALREADY_ACKNOWLEDGED` | The first message of the project was acknowledged before the wait started, so the wait cannot see a new one. Run `next`, which checks the Relay connection.                                                 |

## Agent skills

`oe agent setup` installs this skill and the other OpenE2EE skills in the
project. `oe agent setup --check` reports each skill as current, missing, or
changed.
