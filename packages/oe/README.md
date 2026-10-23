# `@open-e2ee/oe`

This package installs the `oe` command through an optional native package for
the current operating system and CPU. It does not download a binary during
installation.

Run `oe auth login` to log in with a browser and accept the terms for the
organization. Run `oe org switch` to move the session to another organization.
Use `oe new` to create a project and its Sandbox environment,
and `oe config push` to apply the environment sections of the config.

`open-e2ee.config.ts` imports `defineConfig` and the config types from
`@open-e2ee/oe/config`. `oe` reads the file with Node.js 22.18 or later, and
the file loads without `node_modules`. Run `oe config pull` to write the Relay
policy of each active environment from the console into the file.

Run `oe help` for short command descriptions, exit codes, and environment
variables. Run `oe help COMMAND` for scoped usage and flags. Under a coding
agent, or with `--agent yes`, `oe` writes JSON by default. Each run writes one
JSON document to stdout with a stable `code` and, when there is one, the `next`
command. Run
`oe project connection --env sandbox` to print the Relay connection URL of an
environment.
