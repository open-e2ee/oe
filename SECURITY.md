# Security policy

Do not report a suspected vulnerability in a public issue.

Use GitHub's private vulnerability reporting for `open-e2ee/oe`. Include the
affected command and version, the operating system, the expected security
boundary, and a minimal reproduction when it is safe to provide one. Do not send
real access tokens, private keys, recovery material, or customer data.

## Credential boundaries

- The CLI stores interactive credentials only in the operating-system keychain.
- `OPEN_E2EE_ACCESS_TOKEN` is a scoped CI input. The CLI does not persist it.
- The CLI sends secret values only to the protected control API. The CLI does not
  write or print them.
- Public project configuration can contain one OpenE2EE Signal Protocol Relay
  connection URL for each environment. The URL can resolve public bootstrap
  data. It must not contain a service credential, protocol private key, or
  secret query value.
- The npm launcher selects an installed optional native package. It does not
  download or execute a binary during package installation.

The release workflow gives each artifact a GitHub build-provenance attestation.
Verify an artifact before execution if it came from another source.
