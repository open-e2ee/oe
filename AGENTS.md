# OpenE2EE CLI

This repository is the `oe` command-line tool. The OpenE2EE workspace
instructions also apply here.

## Checks

Development needs Go 1.26.10 or later, Node 22.18 or later, and npm 11 or
later. Run these commands before you open a pull request:

```bash
go test -race ./...
go vet ./...
npm ci
npm test
npm run format:check
npm run homebrew:test
```

Pull requests target `main`, and CI runs on each pull request.

`README.md` holds the command contract and the distribution contract.
