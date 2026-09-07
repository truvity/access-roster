# access-issuer — the token service

**Status:** designed 2026-09-07; **built after the hub**, as the second
service of access-roster. Nothing in the hub depends on it.

## Purpose

One issuer that every cluster, cloud account, CD system and console of an
installation trusts, fed by the corporate identity providers the
installation already has and by the identity tokens its CI platform
already mints, with the mapping from directory groups to entitlements
written in one file. It exists so that an installation does not run a
full identity provider — a user store, a login UI, a database — only to
get the part of one it uses: federation with claim shaping and
workload-token exchange.

It is a **security token service**, not an identity provider. The line:

- it never proves who anyone is; it verifies proofs produced elsewhere;
- it holds no passwords, no user records, no MFA, no consent screens, no
  self-registration, no second way in;
- break-glass lives outside it, in the cloud account and the cluster's
  own access mechanisms;
- its console surface grants nothing: the only write is revoking a
  session or a registration; policy changes are commits.

The day a requirement needs one of the things on that list is the day to
stop and reconsider, not to extend.

## What it verifies

| Proof | From | How |
|---|---|---|
| a corporate sign-in | Google Workspace, Microsoft Entra | an OIDC authorization-code flow the issuer starts and finishes, routed by email domain; the address is then resolved through the hub |
| a CI identity token | GitHub Actions, per organisation | RFC 8693 token exchange; verified against the platform's keys, the organisation checked against an allow-list, claims such as repository and ref matched by a machine group's matchers |
| a workload token | a Kubernetes ServiceAccount | token exchange verified with TokenReview, for the rare in-cluster service that needs a token another system trusts |

Every human login and refresh asks the hub `ResolveUser`: is the account
live, which groups, and is that answer authoritative. A suspended account
gets no token even though its identity provider would still sign it in.
That is the second half of global logout: the proxy ends the session; the
issuer stops refreshing.

## What it issues, and to whom

A standard OpenID Provider surface, from a library rather than written.
The library is `github.com/zitadel/oidc/v3` (`op` package), which is
OpenID-certified for the Basic and Config profiles and already ships
every grant below except dynamic registration; the issuer implements the
library's storage interfaces over Valkey and the policy, and nothing
else of the protocol. "Fully implement" means one thing here: the
profiles named as *in* pass the OpenID Foundation conformance suite in
the acceptance run, and nothing named as *out* is served.

The list below is one thing, not ten: an OpenID Connect provider from a
library. It is grouped by what someone is doing, because that is what
decides whether a row costs us anything.

| Someone is… | Which means | Who does the work |
|---|---|---|
| a person signing in to a console or a cluster | ordinary OpenID Connect login — authorization code with PKCE, refresh, `userinfo` — plus discovery with a rotating JWKS, and RP-initiated logout (`end_session`) | **the library.** This is the only part that is certified, and it is what "an OpenID Provider" means. It is the conformance target |
| a person in a terminal — kubelogin, accessctl, the Kargo CLI — with no browser to redirect | the device authorization flow (RFC 8628) | the library |
| a CI job or a workload swapping its own token for ours, or an exchange for an AWS role | token exchange (RFC 8693) | the library, plus **our verifier** for the incoming proof: GitHub's keys and the organisation allow-list, or TokenReview |
| an operator revoking someone, or a person signing out everywhere | token revocation (RFC 7009) | the library, plus **our session index**, so there is something to list and to revoke |
| a proxy registering itself when it starts | dynamic client registration (RFC 7591) | **us**, one endpoint. The library does not have it, and the rule — ServiceAccount token, per-namespace host pattern — is ours anyway |
| a confidential client proving itself with a key rather than a secret; an in-cluster service that is its own client | JWT client authentication (RFC 7523); client credentials | the library, switched on |
| a relying party checking a token it received | the access token is a JWT (RFC 9068), verified offline against the JWKS | the library, switched on; it is why there is no introspection endpoint |

What the issuer itself is, then, is not protocol: the storage behind the
library in Valkey; the mapping from the policy to the claims in a token;
the three verifiers; the registration endpoint; the session index; and
three small HTML pages. The conformance suite proves the library is
wired correctly, not that we wrote a protocol.

**Deliberately not served**, so nobody adds them later without a reason:
introspection (RFC 7662; JWT access tokens make it unnecessary and an
endpoint nobody calls is attack surface); the implicit and hybrid flows
(superseded by code with PKCE; the library supports implicit and it is
switched off); back-channel logout for 1.0 (the proxy does not consume
it, so a revoked session dies at the proxy's next refresh, five minutes
by default; the library supports it if a relying party ever needs the
push); the session-management iframe, front-channel logout, PAR, DPoP,
mTLS and CIBA (no relying party asks; each is surface without a
consumer).

## The policy

One file, shared with the hub: [reference/policy.md](../reference/policy.md).
Every proof resolves to internal groups — people through directory
membership the hub confirms, jobs and workloads through matchers — and
from there a person and a job are the same thing. The token is the fixed
identity claims plus the deep merge of the groups' claim fragments;
lifetime is the shortest across the groups, capped by the client. The
`clients` table is the audience: its id is `aud`, its `requires` is the
gate, its kind says whether there is a secret. AWS roles are clients of
kind `exchange`, which is where the earlier audience table went.

## Sessions and sign-out

Three things get called a session and each has one owner. The proxy
holds the **browser session** for one console, a ticket cookie with the
state in Valkey, and refreshes the token behind it. The issuer holds the
**SSO session** with the browser, so a second console needs no second
login, and one **refresh token per identity and client**, which is what
kubelogin, accessctl, and every proxy actually hold. The hub's own cookie
exists only in standalone day-one mode and lists nothing.

Sessions are first-class issuer state, not opaque tokens in a store: the
issuer keeps a per-identity index — client, how it was obtained (code,
device, exchange), issued, expires, last refreshed — so that they can be
**listed** per identity and per client and **revoked** per identity, per
client, or one at a time. Revocation is RFC 7009 underneath and the only
write the console has against the issuer; it removes access and can never
grant it, which is why it may live in a console at all.

Sign-out has two halves and both are already designed: the proxy ends its
session and chains to `end_session`, which ends the SSO session; a
revoked or suspended person is stopped by the issuer refusing the next
refresh, with the hub's liveness signal behind it. What was missing was
the operator's lever between those two — cutting a person off *before*
their next refresh — and the person's own: "sign out everywhere". Both
are revocation of the identity's sessions, one by an operator, one by
the identity itself.

Where this shows: on a person's page in the console, an **Active
sessions** section with Revoke; on a client's page, the sessions open on
it; on your own page, **Sign out everywhere**. The operator contract for
it is a small session service, list and revoke, gated like the rest.

The issuer serves three pages of its own, minimal HTML from the same
theme, because each runs before any session exists: the sign-in chooser
by email domain, the device-code entry page, and the signed-out page.
They are not the console.

## State

No database. Signing keys in Secrets, rotated. Authorization codes,
refresh tokens with their per-identity session index, device codes and
the last-known groups per identity in Valkey, external to the chart.
Static clients and the policy from the deployment; dynamic registrations
in the issuer's own namespace.

## Failure semantics

| Situation | Effect |
|---|---|
| the hub answers non-authoritative | existing identities keep their last-known groups for the hold window; new identities get nothing |
| the hub is down | same, then no new human logins after the window; workload exchange unaffected |
| the issuer is down | no new logins anywhere; existing sessions and tokens live to expiry; break-glass is outside it |
| a proof fails verification | `invalid_grant`, never a partial token |
| an audience is not granted | `invalid_target`, the exchange is refused |
| a registration names a host outside its namespace's pattern | refused, logged |

## Before building: the spike

1. Rule-gated audiences accepted by trust policies across two cloud
   accounts.
2. Whether the cloud passes a custom issuer's `amr` values through.
3. The device flow through kubelogin against a cluster, and one console
   login through `access-proxy`.
4. One CI exchange from a real workflow, on a fork branch too.
5. Dynamic registration from a proxy's ServiceAccount, and its refusal
   for a foreign host.
6. The hold window when the hub answers non-authoritative.
7. The OpenID Foundation conformance suite against the spike, Basic OP,
   Config and RP-Initiated Logout profiles, so that "fully implemented"
   is a green run and not an opinion.

Each with a number attached. The migration that follows is consumer by
consumer, the previous issuer running as fallback until it has no relying
party left ([operations/migration-from-an-idp.md](../operations/migration-from-an-idp.md)).
