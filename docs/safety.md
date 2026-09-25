# Safety

What can break and how access-roster prevents it: every refusal at
render or at load, every default chosen because the other one failed,
and the traps that were met in use, each with the failure that earned
it. The test for whether something belongs here: *what goes wrong if I
do the obvious thing.* This page is an index; the pages below hold the
substance.

- [reference/policy.md](reference/policy.md#validation-at-load) — what the
  policy loader refuses, so that a typo fails a rollout rather than a
  sign-in
- [reference/policy.md](reference/policy.md#clients-that-describe-themselves)
  — what a client that registers itself by serving a document may and may
  not do, why an allow-list of origins is the guard rather than a refusal
  of unknown clients, and why there is no stale fallback
- [reference/policy.md](reference/policy.md#resources--what-a-token-is-for)
  — what a client asking for a resource gets and what it is refused, why
  the parameter is refused rather than ignored, and why the session has to
  remember which resource it was opened for
- [reference/configuration.md](reference/configuration.md) and
  [reference/access-issuer.md](reference/access-issuer.md) — the strict
  values schema, the values that refuse to render unset, and the two
  things the chart will not do for you (mint its signing key, sit behind
  a proxy)
- [reference/access-proxy.md](reference/access-proxy.md) and
  [design/access-proxy.md](design/access-proxy.md#failure-semantics) —
  the cookie secret the chart will not mint, the refresh that is the
  revocation window, and what the proxy does when the issuer or Valkey
  is down
- [connect/github-organisation.md](connect/github-organisation.md#what-the-render-refuses-and-why-each-is-silent-otherwise)
  — what the render refuses about GitHub bindings, and why each would
  otherwise be silent
- [connect/github-apps-catalogue.md](connect/github-apps-catalogue.md#errors)
  — how a token request is refused, and what the audit trail records
- [architecture.md](architecture.md#failure-semantics) and
  [design/access-roster.md](design/access-roster.md#failure-semantics) —
  what happens when the directory, the store or the issuer is down
- [design/trust.md](design/trust.md#recovery-is-the-root-not-a-back-door)
  and [operations/runbook.md](operations/runbook.md#lost-operator-access)
  — the way back in when nobody can sign in
- [operations/runbook.md](operations/runbook.md#what-unhealthy-means-and-what-to-do)
  — what each unhealthy state means and what to do, and
  [when the audit trail cannot be written](operations/runbook.md#when-the-audit-trail-cannot-be-written)
- [connect/console-app.md](connect/console-app.md#traps-that-were-real) —
  the traps of putting a console behind the gateway
- [reference/accessctl.md](reference/accessctl.md#what-each-failure-exits-with)
  — every failure of `accessctl credential` and its exit code, and a key
  it will never overwrite
- [conformance.md](conformance.md) — what the OpenID conformance suite
  found, and what was fixed
- [CONTRIBUTING.md](../CONTRIBUTING.md) — the fixes that must not be
  reached for, each because it was the first idea and the wrong one
- [SECURITY.md](../SECURITY.md) — reporting a vulnerability, and the
  design notes a reviewer should read first
