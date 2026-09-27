# 0014 — Minting third-party credentials: only where membership is governed, brokers elsewhere

**Status:** Accepted
**Date:** 2026-09-27

## Context

[0008](0008-credentials-only-where-we-govern-membership.md) drew the
line: the issuer mints a credential for another system only where that
system is one it already governs by membership, and named GitHub as
today's one case, with an external broker sketched as the pattern for
everything else. What 0008 left open is what that broker actually does
and how it decides — it names "a policy example: CI job identity...a
client or resource row for the broker's audience, gated by `requires`"
in one paragraph, without saying how the broker maps a verified claim to
a permission, or whether the client that talks to it stays one command.

That gap is no longer hypothetical. An installation needs short-lived,
prefix-scoped credentials for an object store without OIDC federation
(Cloudflare R2 temporary credentials are the public example; the shape
is the same for any store with no `AssumeRoleWithWebIdentity`
equivalent). A concrete broker for this is being designed, and it needs
an explicit answer to a question 0008 did not have to face yet: where
does the *authorization* decision live — "a pull request may read a
cache prefix, a push to the default branch may write to it" — the
broker, or this repository's policy? Splitting it across both is the
mistake 0008 already warns against for a different reason (a compromised
issuer must not yield every downstream secret); here the risk is a
second, competing decision engine even when no secret moves through it.

## Decision

**1. The issuer mints a credential for a third-party system only where
that system passes the 0008 test — its membership is already governed
here.** GitHub passes: the issuer reconciles GitHub organisation and
team membership, so the GitHub App installation-token minter
(`accessctl github-token`) stays exactly as it is, a principled and
documented exception to "deliver tokens, not credentials", not an
oversight to eventually close.

**2. Everything else is a relying party, not a minter inside the
issuer.** Storage credentials for an object store without OIDC
federation are minted by a separate broker service — its own project,
its own parent key, never a feature added here. The broker:

- verifies a standard OIDC token against this issuer's discovery
  document — issuer, audience, a `groups` claim — nothing specific to
  access-roster; any OIDC provider that shapes a token the same way
  could stand in its place;
- maps **group only** to bucket, prefixes and permission. There is
  deliberately no claim-matching language in the broker beyond that: a
  rule like "a pull request may read, a push to the default branch may
  write" is decided in this repository's policy, as an ordinary group
  grant using the `repository`, `ref` and `event_name` matchers this
  policy engine already has — the same shape [0008](0008-credentials-only-where-we-govern-membership.md)'s
  CI example already used for `ci:cache:reader` and `ci:cache:writer`.
  Putting any of that decision in the broker instead would split one
  authorization question across two engines that can drift out of
  agreement with each other;
- holds the parent credential (an R2 API token or equivalent) itself,
  isolated from the issuer process — the same containment line 0008
  draws: a compromised issuer yields no downstream secret, a
  compromised broker yields no identity;
- records every minted and refused credential in the installation's own
  audit trail, the way every other credential-shaped action here already
  is.

**3. The client stays one command.** `accessctl` will offer a thin
wrapper around the broker's own CLI — sign in, hand the resulting token
to the broker CLI in its environment, then exec it unchanged — the same
shape [0013](0013-openbao-access-through-the-bao-cli.md) already ships
for `accessctl bao`: this tool authenticates, the other project's own
binary does everything after that, and a release of this repository
never has to catch up with a release of that one. The broker CLI itself
accepts any OIDC token from any issuer, so it works standalone, without
access-roster in front of it, for an installation that has no use for
the rest of this repository. This wrapper is **planned, not shipped** —
recorded here so the shape is decided before the code is, not worked out
differently by whoever writes it first.

**4. A store with OIDC federation needs no broker.** AWS S3 (and
anything else reachable through `AssumeRoleWithWebIdentity`) is already
covered by `accessctl aws` today; nothing here changes that path or adds
a second one for it.

## Consequences

**access-roster gains no storage code, in the broker or in the issuer.**
The parent key for an object store never enters this repository's
process, its config, or its chart values — only a client row for the
broker's audience and the group grants that decide what it may mint.

**Storage credentials cost one extra hop**: exchange at this issuer,
then a call to the broker, versus a direct mint. That is the same hop
[0008](0008-credentials-only-where-we-govern-membership.md) already
priced in for this exact case, not a new cost this record introduces.

**The broker CLI is one more binary an installation that wants storage
credentials must install**, the same dependency `accessctl bao` already
has on the real `bao` binary being on `PATH`.

**The GitHub App keys stay in the issuer process**, unchanged. This is
the one place a credential's parent secret and identity governance sit
together, and it stays that way because GitHub is the one system this
repository governs membership for — not because the containment line
this record draws for everything else does not apply to GitHub too.

**A future system whose membership this repository comes to govern**
(a chat workspace's channel membership is 0002's example) would pass the
same test GitHub does, and a minter for it inside the issuer would be
the same kind of principled exception, decided then on its own record,
not implied by this one.

## Alternatives considered

**Minting inside the issuer behind a generic minter interface**, so any
broker-shaped need becomes a plugin rather than a separate project.
Rejected for the reason [0008](0008-credentials-only-where-we-govern-membership.md)
already gives for its own generic-minter alternative: it grows the
issuer into a secret store for every upstream system, and puts every
such system's parent key in the one process that also holds every
identity this installation trusts. Widening the mission this way once is
the same mistake regardless of which store is first through the door.

**The broker trusting a CI provider's OIDC token directly**, with no
access-roster in between, for an installation that already runs this
repository. Rejected for that installation specifically: it puts the
authorization decision — which group may read or write which prefix — in
the broker's own claim-matching rules, a second engine deciding the same
question this repository's policy already decides for every other
audience, with its own drift risk and its own place to get out of sync.
This stays a real option for an installation that does **not** run
access-roster at all — the broker's OIDC-only contract does not require
this repository to be the token's source, which is exactly why it is a
separate project and not a feature of this one.

**Moving the GitHub minter out of the issuer too**, so no third-party
credential is ever minted here, without exception. Not chosen now:
GitHub passes the 0008 test today, and removing a working, governed
capability for uniformity's sake repeats the purity-over-practicality
mistake 0008 already rejected for the same command. Revisit if key
isolation for the GitHub App's private key becomes a concern on its own
terms — that would be a reason grounded in this system, not a reason
borrowed from every other system's broker shape.
