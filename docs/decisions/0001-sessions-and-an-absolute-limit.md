# 0001 — Sessions and an absolute limit

**Status:** Accepted
**Date:** 2026-09-25

## Context

Three things get called a session here, and each has exactly one owner.
The issuer holds the **SSO session** with the browser and one
**per-client session** — a refresh chain, indexed and revocable — per
identity and client
([design/access-roster.md#sessions-and-sign-out](../design/access-roster.md#sessions-and-sign-out)).
An application signed in through either door then keeps **its own local
session**, on its own clock. A limit enforced at the issuer can only ever
reach the first two; the third is somebody else's state.

The issuer also has no activity signal to key a timeout on. A
gateway-fronted console refreshes on every request it forwards, signed in
or idle behind it; a background tab polls whether anyone is looking or
not. An idle timeout would have to be measured at the relying party, on a
clock nobody here can audit — measuring it at the issuer would time out
the wrong thing.

## Decision

An **absolute limit of 24 hours from `auth_time`**, enforced in three
places: at refresh, at a silent `/authorize` (so an SSO session cannot be
extended past it by opening a second console), and on the console's own
session. `auth_time` is fixed at sign-in and carried unchanged across
every refresh
([reference/policy.md#groups--token-by-deep-merge](../reference/policy.md#groups--token-by-deep-merge)),
so the limit is measured from when the person actually authenticated —
never reset by use. No token outlives it. There is **no idle timeout** at
the issuer, for the reason above: it has nothing to measure idleness with.

Every relying party falls into one of two classes:

| Class | Shape | How the limit reaches it |
|---|---|---|
| **A** | refreshes against the issuer: a gateway-fronted console, an application with refresh enabled, `accessctl`, kubelogin | directly, with lag no worse than the token's own lifetime or `ttl_cap` |
| **B** | mints its own session after one sign-in and never comes back | not automatically — it must cap its own session at or under 24h itself, or accept Back-Channel Logout to learn of a sign-out sooner |

**Which door a new application should use** follows from the same split.
Native OIDC — the application signs in as its own client — when it needs
identity *inside* itself: per-user authorization from `groups`, per-user
audit, tokens of its own to call something else. Gateway OIDC —
`access-proxy` or an equivalent — when the application has no
authorization model of its own, or only needs "may this person reach it
at all". Never both on one application: a second door doubles the sign-out
surface that has to be reasoned about, which is exactly where this
repository has found real bugs before — a revoke path that ended one
session and left its parent SSO session standing looked, from the
console, like a complete sign-out
([design/access-roster.md#telling-the-relying-party-back-channel-logout](../design/access-roster.md#telling-the-relying-party-back-channel-logout)).

**Gateway OIDC's caveats, worth stating rather than discovering:**

- a per-request refresh races a rotating, one-use refresh token across
  replicas of the same proxy; the issuer tolerates a short grace window
  for it, so a client fronted this way should never be given a very
  short `ttl_cap`;
- there is no server-side session to receive Back-Channel Logout — the
  refresh interval is the whole dial
  ([design/access-proxy.md#sign-out](../design/access-proxy.md#sign-out));
- the `groups` claim rides in the cookie, so it grows with group count;
- a misconfigured gateway policy can fail open rather than closed.

## Consequences

A relying party that never refreshes — a cached access token used past
its own expiry, or a class-B session with no cap of its own — can outlive
24 hours without the issuer ever knowing. That is the honest boundary:
the limit binds what comes back to the issuer, not what does not.

An application already running a multi-day session of its own needs a
deliberate choice, not the default: cap its session at or under 24h, or
wire up
[Back-Channel Logout](../design/access-roster.md#telling-the-relying-party-back-channel-logout)
and accept the window that leaves. Silence on this from the application's
own design is not a safe default.

## Alternatives considered

**A data-plane session inside access-roster** — an authorization check on
every request, or a cookie shared across a parent domain spanning every
console — would buy near-zero-lag revocation. Rejected: it puts the
issuer in every request path of every application it touches, forces a
shared parent domain across consoles that otherwise share nothing, and
rebuilds `access-proxy` a second time inside the issuer, which
[design/access-proxy.md#why-not-something-else](../design/access-proxy.md#why-not-something-else)
already argues against for the proxy that exists today. Revisit only if
sub-minute revocation becomes a hard requirement, and then as a separate,
opt-in component — not folded into the issuer's own request path.
