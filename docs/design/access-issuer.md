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
  own access mechanisms. **The issuer has no recovery sign-in of its
  own, by rule** (decided 2026-09-08): the hub's recovery gets a person
  into one console, where they can fix a membership, and it is already
  gated by cluster RBAC; a standing way into the issuer would be a
  skeleton key to every cluster, account and console it mints for. When
  the issuer itself is what is broken, recovery is the cloud account and
  kubectl, which is where that privilege is meant to live;
- its console surface grants nothing: the only write is revoking a
  session or a registration; policy changes are commits.

The day a requirement needs one of the things on that list is the day to
stop and reconsider, not to extend.

## What it verifies

| Proof | From | How |
|---|---|---|
| a corporate sign-in | Google Workspace, Microsoft Entra | an OIDC authorization-code flow the issuer starts and finishes; the address it returns is then resolved through the hub |
| a CI identity token | GitHub Actions, per organisation | RFC 8693 token exchange; verified against the platform's keys, the organisation checked against an allow-list, claims such as repository and ref matched by a machine group's matchers |
| a workload token | a Kubernetes ServiceAccount | token exchange verified with TokenReview, for the rare in-cluster service that needs a token another system trusts |

The OAuth client it signs people in with is configuration, not a
decision this service makes: it is given a client id, a secret and its own
base URL. Pointing it at the same Secret the hub reads keeps the
installation's rule — one project, one client — and costs one more
redirect URI on that client, for the issuer's host. Giving it a client of
its own works identically and is what an installation would do if it
wanted revoking sign-in and revoking directory access to be separate
acts.

The hub is reached over its API listener with a projected ServiceAccount
token, read fresh on every call because a projected token is rotated
under the pod. A failure to reach it is an error and never an empty
answer: the issuer holds a last-known standing for the hold window, and
it can only do that if "I could not ask" is distinguishable from "the
directory says nothing".

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
| a person signing in when no directory can vouch for anybody | recovery: a ServiceAccount token, checked by TokenReview | **us**, and it is the same primitive as the row below. The deadlock it breaks is total: a console asks this issuer for a token, this issuer asks the hub, the hub cannot answer because no directory is connected, and the directory is connected FROM that console. It grants nothing by itself -- the sign-in completes as the ServiceAccount subject and the policy's `service_account` matchers decide |
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

**The browser makes those calls, not the hub.** Sessions live here and
the console is served by the hub, which must not depend on this service:
the hub answers *is this account live* for consumers, and that has to
keep working when the issuer is down. So the console — which already
speaks to the hub's own operator services — speaks to the session service
at the issuer's host directly, and the hub's code learns nothing about
the issuer at all. The console reads the issuer's URL from settings and
shows the sessions sections only when there is one, so a hub deployed
alone simply has no such sections. The cost is that the issuer allows the
console's origin, which is one value in its chart.

There is no second console. The whole surface is the one graph the hub
serves, with two sections in it that happen to be answered from here.

The issuer serves three pages of its own, minimal HTML and no
JavaScript, because each runs before any session exists: the sign-in
chooser, the device-code entry page, and the signed-out page.

The chooser follows the same rule as the hub's — one button per provider
*kind*, never one per company, because an anonymous page that lists the
companies an installation serves has published them to anyone who loads
it. With one provider configured there is no question to ask, so it does
not ask: it redirects, and a click is saved on every login in the estate.

The address the provider returns is the whole of what is taken from it.
The hub decides whether that address is anybody here, and a refusal is
delivered *there*, on that page, naming the address — everywhere
downstream the person would simply find themselves admitted nowhere with
nothing that explained why. The half-finished authorization request
travels in the signed state, so a callback carrying somebody else's
request id cannot finish their login as this person.

The state is signed with a key derived from the signing key rather than a
second Secret of its own: it protects something that lives ten minutes,
and a rotated signing key invalidating half-finished logins is nothing to
recover from. The signed-out page says what did and did not happen —
"signed out" on a page that ended one session and left three running is
the kind of half-truth people plan around.
They are not the console, and they cannot be: each runs before there is
anyone to authorize.

`access-proxy` serves no page of ours. Upstream oauth2-proxy shows a
sign-in interstitial, and it is skipped, so a person meets one login
experience at this issuer rather than a different doorway per console.

## State

No database. A login in progress — the authorization request a browser is
part-way through, the code it comes back with, the tokens that follow, the
device flow a CLI is polling — lives in Valkey, shared by every replica.
It has to: a browser starts at `/authorize` on one replica, comes back
from the provider at another, and the client redeems the code at a third,
while a terminal polls whichever answers. Held in one process, each of
those is a coin toss that looks like an intermittent failure and only
appears above one replica.

Everything there carries its own expiry and nothing sweeps: a store that
has to be swept is a store that grows when the sweeper stops, and
low-entropy device codes accumulating is exactly how they start
colliding. A user code is claimed with a single atomic write, because two
replicas minting the same short code at the same moment must not both
believe they own it.

The signing key comes from a Secret **this service does not create** — cert-manager issuing one, or external-secrets delivering one —
mounted as a file. It holds no permission to read Secrets at all.

Two reasons, and the second is the one that decides it. A key minted per
process invalidates every token it signed on every rollout, and two
replicas with two keys hand out tokens half the fleet cannot verify,
which reads as an intermittent outage and is really a coin toss on which
pod answered. And a service that creates its own credential is an
exception to how every other credential in this estate is provisioned;
exceptions are what make an estate hard to reason about, and this one
would put the rotation of the most sensitive key we hold outside the
machinery that rotates everything else.

The key id is the key's own RFC 7638 thumbprint rather than a name given
to it. That is what lets the key arrive from anywhere: nothing has to
carry an id beside it, every replica computes the same one, and a key and
its id cannot separate because the id is a function of the key. Rotation
follows from the same property — a new key is a new id, so the previous
public key can stay in the JWKS for one token lifetime without either
being mistaken for the other. PKCS#1 and PKCS#8 are both read, because
both are what cert-manager writes depending on its issuer. Authorization codes,
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

## What running it already settled

The decision core and the OpenID surface are built against the library
with in-memory state, which is what the spike calls for, and six things
came out of running it rather than reading about it. They are recorded
here because each one changes what somebody else has to build.

**A token exchange authenticates with HTTP Basic and nothing else.** The
library reads the exchange's client credentials from the Basic header
only; unlike the code grant it never looks at a posted `client_id`. A
public client therefore presents `Basic base64(<client id>:)`, with an
empty password. The GitHub Action has to send exactly that, and a job
that posts its client id in the form gets `invalid_client` with no hint
as to why.

**A public client is authenticated by presenting no secret.** The library
asks the storage to authorize every exchange, public clients included.
That is the right question with the wrong premise: in an exchange the
subject token is the credential — a CI identity token checked against the
platform's keys — and the client id only names who is asking. So a public
client presenting nothing is admitted, and one presenting a secret is
refused, because it should not have one.

**An exchange yields an access token and never a refresh token.** A job's
proof is short-lived by design, minted per run; trading it for a
credential that outlives the run would undo that and leave a standing key
on a machine whose whole appeal is holding none. So an exchange leaves no
session behind, and there is nothing to revoke afterwards: the access
ends when the token expires, whether or not anyone remembers it.

**Revocation arrives as a session id, not the token.** The library
resolves a refresh token through `GetRefreshTokenInfo` and then hands
back what that returned. A storage that handles only the raw token
answers 200 and revokes nothing — success reported for a security control
that did not act, which is the worst answer available. Both forms are
handled.

**Discovery over-promises, so it is corrected on the way out.** The
library composes `response_types_supported` from a hardcoded list that
includes the implicit and hybrid flows. Every client here declares `code`
alone, so such a request is refused — but a relying party that believes
the metadata is told a flow exists that does not, and an auditor reading
discovery sees something we deliberately do not serve. Metadata that lies
is a defect in a service whose whole job is to be trusted, so the
document is rewritten before it is served.

**The issuer URL must be HTTPS**, and the library refuses otherwise
unless told explicitly. It is right to: every token this service signs is
a bearer credential, and an issuer reached over plaintext can be
impersonated by anyone on the path. The override exists for a local run
and a test; a deployment that sets it has misconfigured itself.

None of this changes the model. The gate holds: a CI job on the declared
branch reaches the AWS role through its rule, the same repository on a
branch anyone with a fork can push reaches nothing, and the audience in
the token is exactly the role asked for. That is the claim the whole
design rests on, and it is now a test that fails when the check is
removed.

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

Items 1 to 5 need real infrastructure — two cloud accounts, a cluster, a
workflow — and item 6 and the model beneath all of them are already
settled above.

Each with a number attached. The migration that follows is consumer by
consumer, the previous issuer running as fallback until it has no relying
party left ([operations/migration-from-an-idp.md](../operations/migration-from-an-idp.md)).
