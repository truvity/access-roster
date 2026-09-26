# 0008 — Credentials only where we govern membership

**Status:** Accepted
**Date:** 2026-09-26

## Context

ADR 0002 draws a boundary: the issuer mints tokens that carry `groups`, and
reconciles membership lists from the same table. Minting credentials for
another system is out of scope. Yet the issuer already mints GitHub App
installation tokens — it holds a GitHub App private key and hands out
short-lived installation tokens decided by policy. This is a credential for
another system. The boundary as written is not honest about what ships.

A new pressure on the same boundary is incoming: a CI system needs
short-lived, prefix-scoped object-storage credentials for a cache on a
provider with no OIDC federation. The request asks whether the issuer should
mint them. The same tension will recur for each new system that cannot read
an identity token but can do something useful with a short-lived credential
keyed to a policy group.

## Decision

The issuer mints a credential for another system **only where that system is
one access-roster already governs by membership** — that is, a system it
reconciles, for which it holds that system's app identity and a catalogue of
policy-driven grants.

Today that system is GitHub alone. The issuer holds a GitHub App's private
key; when a caller asks for an installation token, the issuer decides the
grant from `groups` — using the same catalogue and policy evaluation every
other feature uses — and mints a credential scoped to that grant and no
wider.

Everywhere else, the pattern is an **external broker that is an ordinary
relying party**: access-roster mints a token for the broker's own audience,
gated by `requires` with groups decided by policy. The broker verifies the
token against the issuer's JWKS and alone holds the upstream secret it mints
from. Example: a broker service that turns an identity token into
short-lived, prefix-scoped object-storage credentials for an S3-compatible
store without OIDC federation. The issuer knows the broker exists and what
audience it has; it does not know or hold the store's secret.

Keeping the upstream secret in the broker is also a containment line: a
compromised issuer must not yield every downstream secret, and a compromised
broker must not yield identity. Each holds only its own.

## Consequences

This supersedes ADR 0002 in part: its "Out of scope" paragraph now reads
through this record. A minter for any other system inside the issuer needs a
membership reconciler for that same system first. Everything else in ADR 0002 stands.

An installation that wants to mint object-storage credentials for a
cache on a provider without OIDC federation gets a broker and a policy
example: CI job identity (with `ci:cache:reader` and `ci:cache:writer`
groups decided by workflow event, branch, or pull-request permission),
a client or resource row for the broker's audience, gated by `requires`.

**For CI in particular**: write access is only granted for `event_name ==
push` on the default branch, never for `pull_request_target` or
`workflow_run`, which run in the base branch's context. A CI system that
runs third-party code must not be able to overwrite another system's cache
entries.

## Alternatives considered

**A generic, pluggable minter interface inside the issuer**, callable by any
broker. Rejected: it grows the issuer into a secret store for every upstream
system, with every store's policies, every store's key rotation, every
store's breach. That is exactly the thing ADR 0002 exists to prevent. A
minter specific to GitHub is defensible because the issuer already reconciles
GitHub membership; a generic minter for every provider is not.

**Forbid the GitHub minter too**, for consistency and purity. Rejected: it
removes a working, policy-scoped capability that already ships. GitHub is
already governed here; the issuer's GitHub App private key is already kept.
Removing the feature serves purity over practicality, when GitHub is a
different case than an external provider.
