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

| Standard | Status | Why |
|---|---|---|
| OpenID Connect Core 1.0, authorization code with PKCE (RFC 7636); ID token, `userinfo`; refresh (RFC 6749 §6) | **in**, conformance target | every human login: consoles through the proxy, kubelogin, accessctl |
| OpenID Connect Discovery 1.0, JWKS (RFC 7517) with rotation; RFC 8414 metadata | **in**, conformance target | what relying parties read |
| OpenID Connect RP-Initiated Logout 1.0 (`end_session`) | **in**, conformance target | the proxy's sign-out chains here; ends the issuer's browser session |
| RFC 8628 device authorization | **in** | kubelogin, accessctl, the Kargo CLI |
| RFC 8693 token exchange | **in** | CI and workload proofs, and the AWS `exchange` clients |
| RFC 7523 JWT profile for client authentication | **in** | confidential clients that hold a key rather than a secret |
| RFC 6749 §4.4 client credentials | **in** | the rare in-cluster service that is its own client |
| RFC 7009 token revocation | **in** | the mechanism behind Revoke and "sign out everywhere" |
| RFC 7591 dynamic client registration | **in, written here** | proxies self-register; the library does not cover it and the rule (ServiceAccount token, per-namespace host pattern) is ours |
| RFC 9068 JWT access tokens (`typ: at+jwt`) | **in** | relying parties verify offline against JWKS; no introspection round-trip |
| RFC 7662 introspection | **out** | JWT access tokens make it unnecessary; an endpoint nobody calls is attack surface |
| implicit and hybrid flows | **out** | superseded by code + PKCE; the library supports implicit and it is disabled |
| OpenID Connect Back-Channel Logout 1.0 | **out for 1.0** | the proxy does not consume it; a revoked session dies at the proxy's next refresh, five minutes by default. Revisit if a relying party needs the push |
| session-management iframe, front-channel logout, PAR, DPoP, mTLS, CIBA | **out** | no relying party asks; each is surface without a consumer |

Claims: `sub` stable per identity, `email`, `name`, `groups` — the role
names relying parties already read — and `aud`, the set of audiences the
policy allows for this client and identity.

**Clients** come to exist in exactly two ways, never in a console:

| Way | Which |
|---|---|
| **declared** in the policy's `clients` table | one public client per cluster, the AWS roles as `exchange` clients, ArgoCD and Kargo as `confidential`, accessctl and kubelogin as `public`, and one `local-dev` public client for laptops |
| **self-registered** by an in-cluster workload through RFC 7591, authenticated with its ServiceAccount token and constrained by the host pattern allowed for its namespace | every `access-proxy` instance, and any other in-cluster relying party |

Dynamic registration is the convention that removes per-console
bookkeeping: a proxy comes up, registers `https://<its host>/oauth2/callback`,
receives a client id and secret, and is done. The issuer records the
registration in a ConfigMap and a Secret in its own namespace, keyed by
the registering ServiceAccount, and refuses a host outside that
namespace's allowed pattern.

**Audiences** carry the cloud and cluster decisions. A rule-gated audience
is minted only for identities the client's `requires` admits, and a role's trust policy
names only that audience: one trust policy per role, no per-user policies,
several organisations behind one issuer. For a custom issuer a cloud
trust policy can see only `sub`, `aud`, `amr` and `email`, which is why the
decision rides in `aud`. Whether the cloud passes a custom issuer's `amr`
through — a cleaner carrier for groups — is a spike item, not an
assumption.

**Discovery of what you are granted.** `GET /.access/grants` answers, for
the caller's identity, the clients its groups admit it to. `accessctl
kubeconfig` and `accessctl aws-config` read it and write the files for
every cluster and role a person may use, so nobody maintains kubeconfigs
by hand.

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
