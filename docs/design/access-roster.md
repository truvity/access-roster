# access-roster — the design

**Status:** shipped. One process reads the corporate directories, applies
the policy, issues tokens, serves the login page and serves the console.

This is the design of that process. The rule it stands on — two trust
anchors, one vocabulary — is [trust.md](trust.md); every container and
how they connect is [architecture.md](../architecture.md); the contracts
are under [reference/](../reference/). It replaces two earlier documents,
one per service, and the appendix at the end says what was removed on the
way and why.

## Purpose

One installation-wide issuer that every cluster, cloud account, CD system
and console trusts, fed by the corporate directories the company already
runs.

It answers two questions about a person — **is this account live** and
**who is in this group** — and turns the answer into a token, under a
policy that is a file in git. It holds every directory credential so that
nothing downstream holds any. It authenticates nobody: sign-in, passwords,
MFA and device policy stay with Google Workspace or Entra.

## One process, and why

The directory reader and the token service were two deployments until
0.12. The split was built so that several things could ask the directory
of record — a controller, a hook, another cluster. The issuer became its
only consumer, and from then on the split was paid for on **every single
login**: a ConnectRPC call, a TokenReview, a NetworkPolicy hop, a second
store, and a class of failure where the two halves disagreed about the
same person.

So the answer about a person is a function call. What that leaves is one
Deployment, one Valkey, one policy file, one health endpoint, and a
console served on the issuer's own origin.

The directory endpoint returns when something needs it again — the GitHub
controller is the candidate — under the grant model already shipped, and
authenticated by token exchange like every other machine. Not before.

## The directory model

```
Workspace {
  id           string      # the backend's tenant id (Google: customer id)
  backend      google | entra
  domains      []string    # DISCOVERED from the backend, re-read on every probe
  serve        []string    # OPTIONAL: which of those to answer for; empty = all
  admin        string      # the account the credential acts as
  credential   oauth-refresh-token | service-account-key
  connectedBy  string      # console identity that connected it
  connectedAt  time
  health       { probedAt, ok, error }
}
```

The console calls a workspace a **provider**, and the groups it holds
**provider groups**. The word changed in 0.12 so that both sides of the
rail could read simply *Groups*, with the section heading telling them
apart; the model, the URLs and the API keep the older word.

- **Domains are discovered, not typed.** After connecting, the tenant's
  domain list is read and re-read on every probe. A domain that moves
  between tenants follows automatically: the backend never lets one domain
  belong to two tenants at once, so the move is sequential. Should two
  connected workspaces ever claim one domain, neither is authoritative for
  it until the conflict clears, and the console says so.
- **Routing is by email domain.** Every request naming an address is
  answered by the workspace serving that domain. An address in no served
  domain gets `in_domain=false` — no opinion, never "gone".
- **Serving is narrower than owning.** A workspace answers for every domain
  its tenant owns unless it is narrowed to a subset. What is left out is
  still discovered and still shown, so an operator can tell "not our
  business" from "missing"; it routes nothing and its accounts are not
  kept.

  Three things fall out of it. A tenant that happens to own a domain
  another tenant serves is no longer a conflict, so two overlapping
  directories can coexist. The choice cannot grant anything, because the
  only domains that may be named are the ones discovery returned — the
  ceiling is the directory's own verified list, and every setting is a
  subtraction from it. And because the served list is intersected with
  discovery rather than trusted over it, a domain moving between tenants
  hands over on its own.
- **Authoritative is per domain.** A domain is authoritative when its
  workspace's last probe succeeded within the freshness window and no
  other workspace serves it too. Consumers that remove access act only on
  authoritative answers; this flag is the safety-critical part of the
  contract.

## Freshness

The directory is not read on the request path. One **snapshot per
workspace** is kept — domains, every group with its flat members, every
account with its live flag, and `snapshot_at` — and a background refresher
replaces it every `refresh_interval` (default 15 minutes) under a shared
lease, so one replica fetches for all.

Every read takes an optional `max_age`: omitted serves the current
snapshot, a value makes it fresher first when it is older, zero fetches
now, and a failed fetch serves the stale snapshot with
`authoritative=false`. Freshness is honoured by the cheapest path that
satisfies it. Bulk reads trigger a full workspace read, single-flight.
Point reads fetch one account and its groups live and patch the snapshot,
so a login is never held behind a full read. A miss on an in-domain
address always goes live once before answering `found = false`, because
not-found is a removal signal: an account created after the last snapshot
is never reported absent.

A served domain that is not authoritative is **provisional**, and the
console says why: *first snapshot pending*, *snapshot stale*, or *probe
failed*; a domain two workspaces both serve is *contested*. The wire
contract is the `authoritative` boolean and nothing else; the word is the
console's.

### Nothing slow on the request path

Decided 2026-09-09, after the first live connect, when three things had
crept onto the request path and all three met a gateway's fifteen-second
timeout. Each was cancelled mid-read, each restarted from zero on the
next request, and a consent callback reported failure on a connect that
had succeeded.

The rule: **a request never waits on the directory.** Adopting a
workspace stores it and returns; the first snapshot runs detached, under
the process's own context, single-flight. A read with no snapshot answers
*first snapshot pending* — provisional and empty — and lets the refresher
fill it. Narrowing stores the new list, drops what is now excluded at
once, and refreshes detached. The only request-scoped read left is the
point lookup, which is one account and bounded. Raising the gateway's
timeout is not the fix: a longer timeout would only hide the next thing
that approached it.

### Every replica knows every workspace

Also 2026-09-09. Readers were opened from stored credentials once, at
start, so a workspace adopted on one replica did not exist on the other
until it restarted. The store is the truth and the reader map is a cache
of it: a replica with no reader for a workspace the store knows opens one
from the stored credential on first use.

### The cache

Snapshots, sessions and the logins in progress live in **Valkey**,
external to the process: the chart takes an address and credentials. With
a shared store, replicas answer from the same snapshot, a restart is warm,
and the directory is read once per interval regardless of replica count.
Valkey holds no credential — losing it costs one fetch per workspace and
one sign-in per person.

Two things about it were learned the hard way on 2026-09-10, when a
Valkey pod moved and every client went on dialling the old address for
half an hour while reporting healthy.

- **Cluster mode is off unless there are several shards.** With one shard
  it makes the client learn node addresses from `CLUSTER SLOTS` and talk
  to those, bypassing the Kubernetes Service — the one mechanism whose
  whole job is to survive a pod moving.
- **Readiness follows the store; liveness deliberately does not.** A
  replica that cannot reach it leaves the gateway's rotation and answers
  fast instead of hanging, and nothing is restarted, so one blip cannot
  restart the fleet. The refusal names the dependency and the reason.

The refresh lease is **held for the interval, not for the work**.
Replicas do not tick together: a lease let go when a refresh finished
would be taken by the replica whose turn came four minutes later, which
would read the same directory again — and a directory's API quota is per
tenant, not per reader. A successful pass leaves its lease to expire; only
a failed pass hands one straight back, because then somebody else should
try. None of it applies to a refresh somebody asked for.

## The policy

One file: [reference/policy.md](../reference/policy.md). Every proof
resolves to internal groups — people through their provider groups,
machines through matchers — and the groups are the whole of what a token
carries and the whole of what a client's `requires` gates on.

**One layer.** Who is in which internal group is this file, rendered from
the installation's own access model and reviewed in git, and nothing
else. A console that could add a membership was a second source of truth
beside git and a merge to reconcile them, so `git log` is the complete
history of access.

**Validated at load.** A policy the process will not accept is a start-up
failure, which in a rolling update means the new pod crash-loops while the
previous pods go on serving the previous policy — the ConfigMap is
correct, every Application reads Synced, and the only symptom is that the
new clients are absent. That failure is invisible by construction, so the
render validates its own output with this same loader at CI time.

## What it verifies

| Proof | From | How |
|---|---|---|
| a corporate sign-in | Google Workspace, Entra next | an OIDC authorization-code flow this process starts and finishes; the address it returns is resolved against the directory in the same process |
| a CI identity token | GitHub Actions, per organisation | token exchange, verified against GitHub's key set. The **owner** allow-list is the whole trust boundary — anybody gets a valid token for their own repository, so an empty list verifies nothing — and the audience must be this issuer's own URL, so a token minted for a cloud provider cannot be replayed here |
| a workload token | a ServiceAccount in **any** cluster | token exchange, verified against the key set that cluster publishes for its own ServiceAccount tokens. One row per cluster: a name and a URL, no credential |

The third row is what makes one issuer serve many clusters cheaply. The
other way to check such a token is a TokenReview, which means holding a
kubeconfig for every cluster whose workloads may exchange, inside the
service designed to hold almost no credential. A key set is public: EKS
publishes one per cluster — it is what IRSA rests on — and Talos serves
the same keys at the API server's `/openid/v1/jwks`. This process's own
cluster is a row like any other, because a special case for it would be a
second code path only one installation exercises.

What is given up, plainly: a TokenReview notices a deleted ServiceAccount
and a key set does not, so a token stays usable until it expires. Bound
tokens are short-lived, so the window is minutes.

A failure to reach the directory is an error and never an empty answer.
The hold window rests on that distinction: an identity keeps its
last-known groups for a bounded time only while "I could not ask" can be
told from "the directory says nothing".

## What it issues

Six grants, and nothing else. Each exists for one of three needs: a
browser reaching a web UI, a CLI on a laptop with a browser to confirm in,
and a machine that already holds a token.

| Grant | For |
|---|---|
| authorization code + PKCE | every browser flow, and every CLI: kubelogin and `accessctl` open a browser and listen on a loopback port |
| refresh | sessions that outlive a token |
| userinfo | relying parties that ask |
| `end_session` | sign-out ends the sign-in, not one application's cookie |
| revocation | "sign out everywhere", and the operator's revoke |
| **token exchange** | the one machine grant, and the CLI's re-audiencing for AWS |

Three of the six are grants and three are endpoints, so
`grant_types_supported` prints three and the rest are advertised in their
own fields. Listing an endpoint as a grant type would be the metadata
lying in a new way.

Token exchange takes three kinds of subject, all verified the same way,
against a key set this process trusts and holds no credential for:

| Subject | Verified against | Rule kind |
|---|---|---|
| a GitHub Actions token | GitHub's key set, an owner allow-list | CI job: repository and ref |
| a ServiceAccount token from any cluster | that cluster's key set | workload: cluster, namespace, name |
| a person's own token | our own key set | none: re-audiencing for AWS or a cluster |

The third row is why it is *one* grant. AWS accepts only a token whose
`aud` matches a client on its OIDC provider, so `accessctl` trades the
token it holds for one audienced at AWS.

The protocol is a library — `github.com/zitadel/oidc/v3` — certified for
the Basic and Config profiles. What this process contributes is not
protocol: the storage behind the library in Valkey, the mapping from the
policy to the claims in a token, the verifiers, the session index, and two
small HTML pages. The conformance suite proves the library is wired
correctly, not that we wrote a protocol.

## Sessions and sign-out

Three things get called a session and each has one owner. A proxy holds
the **browser session** for one console, a ticket cookie with the state in
Valkey. This process holds the **SSO session** with the browser, so a
second console needs no second login, and one **refresh token per identity
and client**, which is what kubelogin, `accessctl` and every proxy
actually hold.

**The SSO session is the keystone.** A cookie at the issuer's host,
HttpOnly, backed by a record in the shared store: identity, `auth_time`,
how they authenticated. `/authorize` completes **silently** when it is
live, so signing in at one console and opening a second is a redirect with
no prompt; it honours `prompt=login` and `max_age`. `end_session` clears
it. Each per-client session points at the SSO session that parents it, so
*sign out everywhere* is one operation on the parent.

Per-client sessions are first-class too, not opaque tokens in a store: a
per-identity index of client, how it was obtained, issued, expires, last
refreshed, so they can be **listed** per identity and per client and
**revoked** per identity, per client, or one at a time. The index lives in
the **shared** store, because an index per process listed what one replica
happened to record and revoked only there — for a control whose whole job
is to end access, the worst failure available. A refresh token is hashed
into its key, so an index that can be read is not an index that can be
replayed.

Sign-out ends the sign-in AND every session opened under it, and it does
both through whichever door was used: `/logout`, which a person follows,
and `end_session`, which a proxy chains to. Ending the sign-in alone
stops the next silent `/authorize` and nothing else.

The design used to say only that much, and leaned on the other sessions
dying *"at their next refresh"*. They do not, because nothing was
revoking the refresh tokens — so a console the person had already opened
kept refreshing successfully and serving pages for as long as its own
cookie lasted, after a sign-out that reported success. Reported from
hubble; fixed in v0.14.2 for `/logout` and v0.14.4 for `end_session`,
which is the door that actually mattered because it is the one a proxy
uses.

What a sign-out reaches is scoped by what the request can PROVE, which is
the cookie it carries. An `id_token_hint` is a hint in the specification
rather than a credential — the library accepts an expired one by design —
so it chooses the signed-out page and nothing else. A request that proves
nothing ends nothing: before v0.14.4 it ended every session in the
installation, which is [the security note](../../CHANGELOG.md).

A revoked or suspended person is stopped separately, by the next refresh
being refused, with the directory's liveness signal behind it. To end
somebody *else's* session is **revocation**, through `RevokeSessions`,
which authorizes the caller first.

**And the console got exactly that wrong** (found in production, 0.12.8).
Every Revoke button on the Sessions page sent a *session id*, and the
by-id path ends one session and nothing else. Revoking every row of a
browser therefore left its SSO session standing: the list emptied, the
person believed they had signed out everywhere, and the next `/authorize`
completed silently with no password. The half sign-out that looks exactly
like a whole one — the failure this design names twice and the console
still shipped.

The page now offers **signing the browser out** beside the rows, which
ends the SSO session and every session under it. The rows keep their
narrow meaning, because ending one session that is not the one you are
using is a real thing to want, and the two acts should not be one button.

What none of this reaches is a relying party's **own** session. A console
that ran its own flow holds its own cookie, and revoking here does not
call it: `end_session` is front-channel, and back-channel logout is not
built. Kargo signed in an hour ago still answers after every session here
is gone, until its own session expires. That is the honest boundary of
revocation at an issuer, and the reason a relying party's session
lifetime is a decision rather than a detail.

### One origin

The issuer sits at the **root** of the domain and the console takes a path
beside it. That is protocol, not taste: the issuer URL is the `iss` claim
in every token, and discovery lives at
`/.well-known/openid-configuration` at an origin root. An issuer with a
path component relocates its discovery URL to a place Kubernetes and AWS
handle badly.

What the shape buys is that the console is **same-origin**: its session
pages call the issuer with the browser's own cookie, and the question of
how a console reaches sessions in another origin stops existing.

Since the merge the prefix is stripped in-process rather than by the
gateway, which surfaced the one thing that is easy to miss: the console's
handlers never see the prefix, but every link they hand a **browser** has
to carry it, because `/login` resolves against the origin — where the
issuer's page is, not the console's. The mount is read from the address
the console is published at rather than configured a second time.

The **admin-consent callback stays at the origin root**. It is the one
flow that runs before anybody can be signed in, and its redirect URI is
registered with every corporate tenant, so moving it under the console's
path would mean re-registering it in each of them.

Renaming an issuer invalidates every token in circulation, which is why
the decision was made while exactly one client trusted it.

## The console

**It signs people in as a client of this issuer.** Somebody with no
session is sent to `/authorize` with the console's own declared client,
signs in once at the issuer's login page, and comes back with the
issuer's session cookie set — which the console then reads, the way it
reads anybody's. One door, and the console holds nothing special.

Two things fall out of that, and both are the point. There is no proxy
in front of the console running an OpenID flow against a service in the
same process, and there is no login of the console's own — the second
door an installation with a gateway turns off.

The code the flow hands back is **never redeemed**. What the console
needed was the session the flow established, not a token: it reads the
directory and the policy in this same process. Redeeming would mean
holding something it has no use for and either a client secret to keep
or a verifier to carry across the redirect. The code expires unused and
is stripped from the URL, so it reaches no bookmark and no referrer.

The console **reads**. It shows every person, every provider group, every
internal group, every rule that grants one, and every open session — the
whole chain from a directory to a client, and why each link exists.

It changes exactly two things, and both are removals or bootstrap rather
than policy:

- **Connect a provider** by admin consent. Google's consent genuinely
  needs a browser and there is no infrastructure-as-code way to obtain
  that credential; what it produces — a refresh token — is the one thing
  this process writes for itself.
- **Revoke a session.** A removal, and the lever between sign-out and
  expiry.

It cannot change who is in a group. Operator therefore means *may connect
a provider* and *may revoke*; everything else is a viewer.

Every page reads in the same direction, from the identity side toward the
access side, and the two group pages carry the same sections mirrored. The
visual vocabulary has one meaning per form, which is what keeps a
data-dense page readable: a name is a link, monospace when it is an
identifier; a chip is a state and nothing else is; facts are a label over
a value; two-column data is a list and tabular data is a table.

## The issuer's own HTML

Two pages: `/login`, the sign-in chooser, and `/signed-out`, where a
person lands when a client declares no page of its own. Both stay for one
reason — each runs before there is anyone to authorize, so neither can be
a console page. Everything else a person sees is the console.

## The store

Plain Kubernetes objects in the process's own namespace, read and written
by it. Nothing else is in the loop: no external-secrets operator, no cloud
parameter store, no cache. How a *declared* Secret gets into the namespace
is the deployment's business.

A workspace is two objects because the record and the credential have
different readers: the record is what the console shows, the credential is
written once and read once, at the next start. Splitting them keeps a
secret out of the type the console handles, and makes the failure modes
independent — a record whose credential has gone is a workspace with no
reader, which is reported as unhealthy, rather than a process that refuses
to start.

Start-up has three cases. A workspace the values declare is opened from
what the deployment mounts. A workspace whose stored record says it was
declared, and which the values no longer mention, has been taken out of
the deployment: its record is deleted, because leaving it would be a
directory nobody could disconnect. Everything else was connected in the
console and is opened from the credential stored beside it — and if that
credential is missing or refused, the process says so and carries on,
because refusing to start would take every other directory down with it.

There is no backup mechanism: a consent credential is cheap to mint again,
so the recovery for a lost workspace Secret is **Reconnect**, and a
declared Secret is re-delivered by whatever declared it. The console never
returns secret material, the logs never print it, and **Disconnect**
revokes the token at the backend before the Secret is deleted.

The signing key is a file, never read through the API, so a compromise of
this process cannot become a read of every credential in its namespace.
Confidential clients' secrets are files for the same reason, one per
client id.

## Recovery

The way in on the day no directory can vouch for anybody. It exists
because of a deadlock that is otherwise complete: a console asks for a
token, the answer needs the directory, the directory is not connected yet,
and it is connected *from* that console.

The proof is a ServiceAccount token minted for a mandatory audience and
checked by the API server with a **TokenReview** — the one thing left that
asks the cluster anything, and deliberately so: on the day everything else
is broken it should depend on nothing but the API server. Nothing is
stored. The authority is the cluster's RBAC: who may mint a token for that
account, revocable by removing a binding and landed in the audit log.

It grants nothing by itself. A recovered sign-in completes as the
ServiceAccount *subject*, and only a `service_account` matcher in the
policy puts that subject in a group.

## Failure semantics

| Situation | What consumers and operators see |
|---|---|
| Probe failed, snapshot still young | answers from the snapshot, `authoritative=false` |
| Snapshot older than the freshness window | same |
| Full refresh failed a page | old snapshot kept; nothing partial is ever served |
| Domain claimed by two workspaces | `authoritative=false` for that domain on both |
| Address in no served domain | `in_domain=false`: no opinion |
| Account missing from the snapshot | one live read first; `found=false` only after the backend said so |
| Valkey unreachable | the replica leaves readiness and says which dependency; sessions and snapshots are unavailable until it returns |
| Credential revoked or admin suspended | probe fails → provisional; reconnect is the recovery |
| A request would wait on the directory | it does not: the work runs detached and the answer is *first snapshot pending* |
| A policy the process refuses to load | the new pod does not start and the previous pods keep serving the previous policy |
| The whole installation is down | no new sign-ins; existing sessions and tokens live to expiry; recovery is by cluster proof |

The rule under all of them: **access is removed only on an authoritative
answer.** Everything that can go wrong degrades to *provisional*, never to
"gone".

## Appendix: what was removed, and why

Each of these shipped and was taken out. They are listed so that nobody
adds one back without a reason.

| Removed | Why |
|---|---|
| the directory's API listener, and the TokenReview between the two services | there was one consumer and it is now the same process. The endpoint returns when a second consumer exists |
| the console layer of the policy, and the `memberships` table | a second source of truth beside git, and a merge to reconcile them. The key is refused now, not ignored: one silently dropped is a grant somebody wrote, reviewed and merged that never took effect |
| `SetOAuthClient` | the client is a Secret, delivered the way every other credential in the estate is |
| the `/account` page | it was here because it had to be same-origin with the session service; the console is same-origin and now the same process, and already shows both halves |
| the device flow | for a machine with no browser. Both headless cases here — a CI job and a workload — are token exchange |
| client credentials | a machine with a stored secret, which is the thing this design exists not to have |
| JWT bearer (RFC 7523) | token exchange with a different spelling, and two ways to say one thing is two things to keep truthful |
| introspection (RFC 7662) | never applied: these are JWTs, verified offline against the key set |
| dynamic client registration (RFC 7591) | every client is declared, so the set of them is answerable by reading the repository; an endpoint that mints trust is not carried |
| the implicit and hybrid flows | superseded by code with PKCE, which is what PKCE exists for |
| TokenReview for workload exchange | it works on one cluster and would need a kubeconfig per cluster for the rest. A published key set needs none. It stays for recovery alone |

Not served, and never was: back-channel logout, the session-management
iframe, front-channel logout, PAR, DPoP, mTLS and CIBA. Each is surface
without a consumer.

Back-channel logout is the one with a real cost, and it is worth naming
rather than waving past. Signing out revokes the sessions immediately, but
a proxy only learns that at its next refresh — so it keeps serving for up
to its `cookie_refresh`, five minutes on the consoles here. Back-channel
logout would close that window by telling each client at the moment of
sign-out. It stays unserved because oauth2-proxy does not consume it, so
building it would buy nothing today; the window is the price, and it is
bounded by a setting we choose.

## Build

`devbox shell`, then `just check`. The chart is `charts/access-issuer`;
`charts/access-proxy` is for a console with no OpenID flow of its own and
has [its own document](access-proxy.md).
