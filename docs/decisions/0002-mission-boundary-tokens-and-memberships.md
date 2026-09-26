# 0002 — Mission boundary: tokens and memberships

**Status:** Accepted; partly superseded by [0008](0008-credentials-only-where-we-govern-membership.md)
**Date:** 2026-09-25

## Context

The policy is the product: one vocabulary of internal groups, declared
once, in git
([reference/policy.md](../reference/policy.md)). Every feature this
repository adds either delivers that vocabulary somewhere new or it does
not belong here. Two shapes of "somewhere new" exist, and they are not
the same feature wearing different clothes:

- a system that can **read a claim** gets a **token** — a cluster, AWS, a
  console, a secret store's login;
- a system that cannot — because it has its own membership model with no
  token in front of it — gets a **membership**, kept in step by a
  reconciler. GitHub teams are the one built today
  ([design/access-roster.md#the-github-controller](../design/access-roster.md#the-github-controller));
  a chat workspace's channel membership is the next candidate for the
  same shape.

Without a stated boundary, "reach one more system from the policy" keeps
looking like the natural next feature, and each one pulls this repository
one system's worth closer to holding that system's own credentials or
understanding its own authorization model — which is a second, unbounded
product growing inside the first one.

## Decision

**In scope:** minting a token that carries `groups`, and reconciling a
membership list from the same table. Nothing else.

**Out of scope:** minting a *credential* for another system (a cloud
access key, a database password held on that system's behalf) and reading
*another system's own authorization model* to decide anything. A
per-system mapping from an internal group to that system's own roles — an
RBAC binding, a policy attached to a login — is real and useful, and it is
published as a **recipe** (a connect page under
[connect/](../connect/), such as
[connect/openbao.md](../connect/openbao.md)), never carried as a
first-class feature of the service itself. A recipe can go stale without
taking the issuer down with it; a feature cannot.

**Consequences applied inside the 1.x line** (per
[0007](0007-breaking-changes-inside-1x.md)), because they follow directly
from this boundary:

- **Removed:** the console's secret-store page, the chart's
  `secretManagers` values, and the issuer's own reader grant into a
  secret store. Showing a secret store's grants was reading another
  system's authorization model from inside this one — exactly what is now
  out of scope — and the chart carried a reader credential for no reason
  but that page.
- **Removed:** `accessctl secrets`. Reading a team's shared values back
  out of a secret store's KV engine is that store's own job, once it can
  authenticate a person by this issuer's token; a courier command for it
  here duplicated a client the store itself should ship.
- **Kept:** `accessctl token` — the core of the CLI, printing a token for
  any audience, is squarely the token half of the mission. `accessctl
  credential db` and `accessctl credential client` stay too, as thin
  client-side couriers: one exchange for the store's own audience, then
  the store's own signing call, key generated on the caller's machine and
  never sent
  ([design/accessctl.md#credential-the-broker-for-what-openbao-mints](../design/accessctl.md#credential-the-broker-for-what-openbao-mints)).
  Nothing server-side reads the store's policy; the command is a courier
  for a proof, not a reader of another system's grants.
- **Secret-store login moves to the store's own OIDC flow.** Rather than
  this issuer's client minting a token an operator pastes somewhere, an
  operator runs the store's own OIDC login (for example `bao login
  -method=oidc`) against a confidential client row declared for that
  store, listing its loopback callback among its `redirects`. This works
  because the OIDC library behind this issuer accepts an `http://`
  redirect for a **confidential** client using the code flow, when the
  URI matches exactly — which a loopback login needs, and which is
  granted here because the client is confidential, not because a
  loopback address is special. A store's OIDC-type role also needs its
  own `jwt_supported_algs` set explicitly to admit this issuer's default
  ES384 token, the way any ES384-refusing verifier does
  ([0005](0005-es384-signing-algorithm.md)).

## Consequences

An installation that wants a *dashboard* of who can reach what in a
secret store builds or buys one against that store's own audit and policy
API — this repository will not grow one back. A team that relied on
`accessctl secrets` for local development points its tooling at the
store's own client instead; the exchange and the groups it reads are
unchanged, only which binary performs the last step.

The boundary also answers the standing question of "should access-roster
learn to reach system X" without re-litigating it per system: if X can
read a claim, it is a client or a resource, declared like any other; if
it cannot, it is a reconciler, built the way the GitHub one is; if the
ask is "read X's own policy and show it here", the answer is a recipe,
not a feature.

## Alternatives considered

**Grow a reader for each secret store's authorization model**, so the
console could show more than a store's grants — its actual policies, its
bindings. Rejected: that is exactly the second, per-system authorization
model this boundary exists to keep out; each store would need its own
reader, its own credential, its own staleness story, permanently, for a
view a store's own UI already gives its own operators.

**Keep `accessctl secrets` and add more `secrets`-shaped subcommands as
other stores appear.** Rejected: every such subcommand is this
repository re-implementing a client for somebody else's data plane, which
is the shape [design/access-proxy.md](../design/access-proxy.md) already
argues against for sessions; a store's own client does not go stale when
this repository's release cadence does not match its own.
