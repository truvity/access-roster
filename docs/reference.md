# Reference

Every value, flag, input and output: its default, its type, what it does
and when it is required. The test for whether something belongs here:
*what does this knob do.* This page is an index; the pages below hold the
tables.

- [reference/configuration.md](reference/configuration.md) — every value
  of the `access-issuer` chart, the overlay format, and the objects the
  service writes
- [reference/access-issuer.md](reference/access-issuer.md) — the values
  that carry a reason, and every endpoint the issuer serves
- [reference/access-proxy.md](reference/access-proxy.md) — every value of
  the `access-proxy` chart
- [reference/policy.md](reference/policy.md) — the policy file: groups,
  matchers, clients, lifetimes and GitHub bindings
- [reference/accessctl.md](reference/accessctl.md) — every command and
  flag of `accessctl`, and its exit codes;
  [`credential`](reference/accessctl.md#credential-certificates-openbao-mints)
  for SSH, database and client certificates from OpenBAO
- [connect/github-actions.md](connect/github-actions.md#workflow-side-the-action)
  — every input and output of the GitHub Action, and the
  [`token-source: access-roster`](connect/github-actions.md#in-a-reusable-workflow-token-source-access-roster)
  pattern for a reusable workflow
- [reference/contracts.md](reference/contracts.md) — the ConnectRPC
  services, installation tokens at `/token`, and the whoami endpoint
- [connect/openbao.md#console-side](connect/openbao.md#console-side) —
  the secret stores the console shows on its Secret stores page
  (`/secret-stores`): the `secretManagers` values, the grant the reader
  needs, and the four states a group is drawn in
- [reference/go-module.md](reference/go-module.md) — the Go module
  `github.com/truvity/access-roster`
- [reference/typescript.md](reference/typescript.md) — the TypeScript
  package, and installing it from GitHub Packages
- [conformance.md](conformance.md) — the last OpenID conformance run,
  column by column
- `charts/*/values.schema.json` — the schema each chart's values are
  checked against; an unknown key fails the render
