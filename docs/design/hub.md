# directory-roster — the directory hub

Part of [access-roster](../../README.md): the hub is the first service,
[access-issuer](access-issuer.md) the second, later one. This document is
the hub alone.

**Status:** accepted 2026-09-06; API, secret-handling, freshness and access
decisions closed 2026-09-07. Successor to
[google-group-sync](https://github.com/truvity/google-group-sync), which is
archived once its consumers have moved.

## Purpose

One deployment that answers, for every corporate directory an installation
owns, two questions: **is this account live**, and **who is in this group**.
It holds every directory credential so that its consumers hold none. Today
the backend is Google Workspace; Microsoft Entra is the next backend behind
the same record and the same contracts.

Consumers reach it over the cluster network, each presenting its
Kubernetes ServiceAccount token: whatever computes roles at login — an
identity provider's login hook today, this repository's token service
later — and [github-roster](https://github.com/truvity/github-roster)
(groups → GitHub teams). The console is reached by operators through the
hub's own login, or through an authenticating gateway where one fronts
every console. The hub never issues a token and never authenticates anyone; it answers
questions.

## The model

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

- **Domains are discovered, not typed.** After connecting, the hub reads the
  tenant's domain list and re-reads it on every probe. A domain that moves
  from one tenant to another (a company migrating its mail domain) follows
  automatically: the backend never lets one domain belong to two tenants at
  once, so the move is sequential and the hub tracks it. Should two
  connected workspaces ever claim the same domain, neither is authoritative
  for it until the conflict clears, and the console says so.
- **Routing is by email domain.** Every request that names an address is
  answered by the workspace serving that domain. An address in no served
  domain gets `in_domain=false` — no opinion, never "gone".
- **Serving is narrower than owning.** A workspace answers for every domain
  its tenant owns unless it is narrowed to a subset — in the values for a
  declared workspace, on its console page for a connected one. What is left
  out is still discovered and still shown, so an operator can tell "not our
  business" from "missing"; it simply routes nothing, and its accounts are
  not kept in the snapshot. Only what a served answer needs is cached: the
  served domains' accounts, the served domains' groups, and any group at
  another domain that a served person belongs to.

  Three things fall out of it. A tenant that happens to own a domain
  another tenant serves is no longer a conflict, so two overlapping
  directories can coexist. The choice cannot grant anything, because the
  only domains that may be named are the ones discovery returned — the
  ceiling is the directory's own verified list, and every setting is a
  subtraction from it. And because the served list is intersected with
  discovery rather than trusted over it, a domain moving between tenants
  hands over on its own: the old workspace stops serving it the moment the
  directory stops listing it, the new one picks it up when its own
  discovery returns it, and the now-meaningless entry in the old list is
  flagged as no longer owned rather than left to contest anything.
- **Authoritative is per domain.** A domain is authoritative when its
  workspace's last probe succeeded within the freshness window and no other
  workspace serves the domain too. Consumers that remove access act only on
  authoritative answers; this flag is the safety-critical part of the
  contract.

## Contracts

The hub speaks **ConnectRPC only**. There is no REST façade: a consumer
that still speaks google-group-sync's REST routes moves to the generated
client. Connect serves idempotent RPCs over plain GET with JSON, so a
shell and `curl` are enough to debug from a pod.

Two listeners, so a consumer can never reach an operator call:

| Port | Services | Reached by |
|---|---|---|
| API | `DirectoryService` | consumers over the cluster network (ClusterIP, NetworkPolicy) |
| console | `WorkspaceService`, `SettingsService`, `AccessService`, the SPA, the login routes | operators, through the hub's own login or a gateway in front |

- **`DirectoryService`** — google-group-sync's proto plus **additive**
  fields, so its existing clients stay valid: `Describe` gains a structured
  domain list (name, authoritative, workspace, backend) beside the plain
  list; `Account` and `ResolveUserResponse` gain `authoritative`;
  `ListGroupsRequest` gains an optional `domain` filter — empty means the
  union of every served domain, each group tagged with its domain. A
  consumer that removes access reads `authoritative` first: a
  non-authoritative answer is no opinion, never a removal.
  Every read call takes an optional `max_age` and returns `snapshot_at`
  (see *Freshness*).
- **`WorkspaceService`** (ConnectRPC, operator-gated) — `ListWorkspaces`,
  `BeginConnect` (returns the consent URL and sets the state cookie; the
  callback itself is a plain HTTP route), `Reconnect` (the same, bound to
  an existing workspace; the callback checks the tenant id matches),
  `UploadKey`, `Probe`, `Refresh` (a new snapshot now — the operator's
  `max_age = 0`), `Disconnect` (revoke at the backend, then delete;
  declared workspaces refuse).
- **`SettingsService`** — `GetSettings` (the OAuth client id and where it
  came from, never the secret; the intervals and the cache backend,
  read-only) and `SetOAuthClient` (refused when the chart declared one).
  Intervals are chart values: operational knobs belong to the deployment.
- **`AccessService`** — the reads a console composes its pages from:
  `WhoAmI`; `Explain` (what a proof effectively gets, what put it there,
  and which directory served it); `GetPolicy` (groups with members by
  layer and matchers structured, clients, the console layer for export);
  `ListDirectoryGroups` and `GetDirectoryGroup` (a directory group with
  its members and the internal groups it feeds); `SearchPeople` (by name,
  by directory, by account state, with the total before the limit);
  `ListHolders` (who holds an internal group or reaches a client right
  now). And the one write: `AddMembership`/`RemoveMembership`. Everything
  else the policy declares is read-only here.

## Freshness

The hub does not read the backend on the request path. It keeps one
**snapshot per workspace** — domains, every group with its flat members,
every account with its live flag, and `snapshot_at` — and a background
refresher replaces it every `refresh_interval` (default 15 minutes) under a
shared lock, so one replica fetches for all. Every read answers from the
snapshot and says which one: `snapshot_at` and `authoritative` come back on
every response.

Every read call takes an optional `max_age`: omitted serves the current
snapshot, a value makes it fresher first when it is older, zero fetches
now, and a failed fetch serves the stale snapshot with
`authoritative=false`. The normative semantics are in
[reference/contracts.md](../reference/contracts.md#freshness-max_age-and-snapshot_at).

Freshness is honoured by the cheapest path that satisfies it. Bulk calls
(`ListGroups`, `GetGroup`) trigger a full workspace read, single-flight.
Point calls (`ResolveUser`, `GetAccount`, `ResolveAccounts`) read that one
account and its groups live and patch the snapshot, so a login-time caller
with a short timeout is never held behind a full read. And a miss on an
in-domain address always goes live once before the hub answers
`found = false`, because not-found is a removal signal: an account created
after the last snapshot is never reported absent.

A domain is authoritative when its workspace's last probe succeeded, its
snapshot is younger than the freshness window (default twice the refresh
interval) and no domain conflict exists.

A served domain that is not authoritative is **provisional**, and the
console says why: *first snapshot pending*, *snapshot stale*, or *probe
failed*; a domain two workspaces both serve is *contested*. The wire
contract is unchanged — consumers read the `authoritative` boolean and
nothing else — the word is the console's. It replaced *hold* on
2026-09-09: *hold* named what a consumer does, not what the domain is,
and on a tenant connected ten seconds earlier it read as an alarm beside
a green health chip. An unserved domain is neither: it is simply not
read.

### Nothing slow on the request path

Decided 2026-09-09, after the first live connect. Three things had crept
onto the request path, and all three met a gateway's fifteen-second route
timeout: `Adopt` took the first snapshot before answering the consent
callback; a console list call with no snapshot yet read the directory
under the request's own context; and narrowing a workspace refreshed it
before returning. Each was cancelled mid-read, each restarted from zero
on the next request, and the callback reported a failure on a connect
that had succeeded.

The rule: **a request never waits on the directory.** Adopting a
workspace stores it and returns; the first snapshot runs detached, under
the hub's own context, single-flight. A read with no snapshot answers
*first snapshot pending* — provisional and empty — and lets the
refresher fill it. Narrowing stores the new list, drops what is now
excluded from the snapshot at once, and refreshes detached. The only
request-scoped read that remains is the point lookup, which is one
account and bounded. Raising the gateway's timeout is not the fix: after
this nothing on the console path approaches it, and a longer timeout
would only hide the next thing that does.

A full read is also bounded in wall-clock: group members are listed with
bounded concurrency — a handful in flight per workspace, because the
directory's quota is per tenant, not per reader — and every pass logs
its duration. *(0.8; today the members of every group are read one
group after another.)*

### Every replica knows every workspace

Also 2026-09-09. Readers were opened from stored credentials once, at
start. A workspace adopted on one replica did not exist on the other
until it restarted, so half of all requests answered *workspace not
found* for a directory that had just been connected — and a narrowing
that landed on the wrong replica dropped the snapshot. The store is the
truth and the reader map is a cache of it: a replica that has no reader
for a workspace the store knows opens one from the stored credential on
first use.

### The cache

Snapshots live in **Valkey**, which is external to the hub: the chart takes
an address and credentials, and the configuration reference recommends how
to run one. With a shared cache, replicas answer from the same snapshot,
a restart is warm, and the backend is read once per interval regardless of
replica count. An in-memory backend exists for development and a single
replica; a production installation with more than one replica needs
Valkey. Valkey holds only snapshots and leases — losing it costs one fetch
per workspace, never a credential.

The lease is what makes "once per interval" true, and it is **held for the
interval, not for the work**. Replicas do not tick together: a lease let go
when a refresh finished would simply be taken by the replica whose turn
came four minutes later, which would read the same directory again — and a
directory's API quota is per tenant, not per reader. So a successful pass
leaves its lease to expire, and only a failed pass hands one straight back,
because then somebody else should try. None of it applies to a refresh
somebody asked for: an operator pressing Refresh, or a caller passing
`max_age=0`, is asking for a read now.

A snapshot is stored gzipped, and the reverse index from a person to their
groups is rebuilt on read rather than written — it is derived from the
memberships, so storing it would double the payload and make a copy that
could disagree with them.

## Connecting a workspace

### One-time prerequisite, per installation

The admin-consent flow works the way a SaaS vendor's does: the vendor
registers one OAuth client once; every tenant then connects by clicking
through consent. Here the installation is its own vendor, so the step is
done once per installation, never per company.

1. A Google Cloud project owned by the installation. Enable the Admin SDK
   API.
2. Consent screen: audience **External**, publishing status **In
   production**. Not Internal — an Internal app accepts only the tenant that
   owns the project, and an installation serves several. Not Testing —
   refresh tokens minted in Testing expire after seven days and the workspace
   would go stale silently.
3. Scopes, all read-only: Admin SDK user, group, group member, and domain.
   The domain scope is what makes discovery possible.
4. One OAuth client, type Web application, with **two** redirect URIs:
   `https://<hub host>/connect/google/callback` for an administrator
   granting access to a company, and `https://<hub host>/login/google/callback`
   for a person signing in. They are separate because the endpoints have
   opposite authorisation, and a client missing the second works until
   somebody tries to sign in. While the hub is being tried on a
   workstation the `http://localhost:8081/...` pair may sit on the same
   client; remove them afterwards.
5. Paste the client id and secret into the hub's Settings once, or hand the
   chart the name of a Secret that already holds them. Nothing else reads
   them.

Verification by Google is optional. Unverified, the consent screen shows
"Google hasn't verified this app" and the admin clicks through; a tenant
admin can also mark the client id as trusted in the Workspace admin console,
which removes the interstitial for that tenant and is required where the
tenant policy blocks unconfigured apps. Verification needs a public
homepage and privacy policy and a scope justification, takes days, and only
removes the interstitial.

### Per workspace, repeatable, no manual steps

1. Operator presses **Connect Google Workspace**. Nothing to fill in.
2. The hub sets a state cookie and redirects to the consent URL with the
   four scopes, offline access and forced consent (so a refresh token is
   always returned).
3. The operator signs in as the tenant's **admin role account** — not a
   person: the refresh token acts as whoever consents and dies with their
   account. A Super Admin: the reads need Users, Groups AND domain read,
   and the last is the one a narrower role tends not to satisfy. It is
   who consents, not what the token can do -- the token stays bounded by
   the four read-only scopes.
4. Consent, redirect back. The callback lands on the **bootstrap
   surface** — the route a gateway policy does not cover, so that a
   redirect from the directory is never swallowed by a login prompt —
   and therefore carries **no gateway identity**. Its authority is the
   signed state: issued when an operator asked for the consent on a
   request the gateway did authenticate, pinned to this browser by a
   cookie, and naming who asked. Decided 2026-09-09: a callback that
   insisted on an identity in the request refused the one flow it exists
   to finish.
5. The hub exchanges the code, records the consenting account, reads the
   tenant id **from the consenting administrator's own user record** —
   `Customers.Get` returns the same id but needs a fifth scope nobody
   granted — and the domain list, and stores the workspace. If any of
   this fails, the page says so in the directory's own words; never a
   5xx, which a CDN in front replaces with a page of its own.
6. **Which domains?** Before anything is read, the console asks.
   The consenting administrator's own domain is pre-selected; every
   other domain the tenant owns is listed and off; *all of them,
   including ones added later* is an explicit choice. The first
   installation connected a tenant with seven domains, most of them not
   employee domains, and the default of serving all of them read every
   one immediately and showed seven provisional domains before the
   operator had done anything. The first snapshot starts after the
   choice, detached; the page shows *first snapshot pending* until it
   lands.

### The second way in

Upload a service-account key with domain-wide delegation, plus the admin to
impersonate. Same record, different credential type. For installations that
prefer a robot identity or cannot publish an external consent screen.

### Afterwards

Access tokens are minted from the refresh token; the workspace is probed on
an interval. A revoked token, a suspended admin account or a tenant policy
change fails the probe: the workspace shows unhealthy, its domains turn
provisional (*probe failed*), consumers hold their removals, and the
console offers **Reconnect**, which is the same button again.

## The store

Plain Kubernetes objects in the hub's own namespace, read and written by
the hub itself. Nothing else is in the loop: no external-secrets operator,
no cloud parameter store, no cache. How a *declared* Secret gets into the
namespace — an external-secrets `ExternalSecret`, a sealed secret, `kubectl`
— is the deployment's business; the configuration reference carries an
example, the hub has no dependency on it.

The objects — a ConfigMap and a Secret per workspace, the OAuth client,
the session key, the admin password, console-added memberships, the
declared overlay — are listed once, in
[reference/configuration.md](../reference/configuration.md#kubernetes-objects-the-hub-owns).
Valkey holds snapshots, refresh leases and the short negative cache,
never a credential.

A workspace is two objects because the record and the credential have
different readers: the record is what the console shows, the credential is
written once and read once, at the next start. Splitting them keeps a
secret out of the type the console handles, and makes the failure modes
independent — a record whose credential has gone is a workspace with no
reader, which the hub already reports as unhealthy, rather than a hub that
refuses to start.

Start-up is the other half of the store, and has three cases. A workspace
the values declare is opened from what the deployment mounts. A workspace
whose stored record says it was declared, and which the values no longer
mention, has been taken out of the deployment: its record is deleted,
because leaving it would be a directory nobody could disconnect. Everything
else was connected in the console and is opened from the credential stored
beside it — and if that credential is missing or refused, the hub says so
and carries on, because refusing to start would take every other directory
down with it.

What the chart includes and what it expects: it renders everything that is
a standard Kubernetes API — Deployment, Services, ServiceAccount and Role,
NetworkPolicy, the Gateway API `Gateway`/`HTTPRoute` for the console — and
it expects the two things that are infrastructure to exist already: a
Valkey to point at, and the gateway authentication in front of the console
host.

The overlay is how an existing installation moves without a Connect step:
its service-account keys are declared, the hub serves them on day one, and
the operator connects through consent later, at which point the declared
workspace is removed from the overlay.

The ServiceAccount holds a namespaced Role on ConfigMaps and Secrets, which
is why the hub has a namespace of its own. Encryption at rest is the
cluster's. There is no backup mechanism in the hub: a consent credential is
cheap to mint again, so the recovery for a lost workspace Secret is
**Reconnect**, and a declared Secret is re-delivered by whatever declared
it. The export, for anyone who wants a copy in a vault, is
`kubectl get -o yaml`. The console never returns secret material; the logs
never print it; **Disconnect** revokes the token at the backend before the
Secret is deleted.

## The console

Built on the shared fleet console stack (Vite, MUI, Connect-Web), and
organised around what the content actually is: a graph of named things,
where the chain runs from a directory group to an internal group to a
claim and a lifetime to a client and its audience.

Three rules hold it together. **Every name is a link**, so the chain is
walkable in both directions. **Every page opens with one plain-language
summary line**, then its edges, then raw detail behind a disclosure, which
is what lets the same page serve an employee and an operator. **Actions
live on the object they change.**

The graph has two sides, and the navigation rail shows them as two
groups with one adjective each, so that "group" never means two things:

| | Identity — where people come from | Access — what they get |
|---|---|---|
| container | a **directory**: one connected tenant | the policy and its layers, in Settings |
| group | a **directory group**, feeding by membership; a **matcher**, feeding by shape | an **internal group** |
| leaf | a **person**; a machine's proof exists only while it runs, so it is simulated rather than listed | a **client** |

The membership joins the two group levels, and it is the one edge the
console edits — from either end.

| Surface | Answers |
|---|---|
| Search, on every page | almost every task starts with a name: a person, a group on either side, a client, a directory. One field resolves any of them |
| Overview | is anything broken: failing directories, provisional or contested domains with the reason for each, directory groups attached to nothing, internal groups nobody feeds, a recovery password if one is kept. On an installation that is not finished it leads with what is left to do instead, because the counts cannot say anything useful yet |
| Directories, and one page per directory | which tenants we read, their domains and standing, the actions on the tenant itself, and the groups and accounts it holds — every one a link. **Add a directory** offers both ways in, admin consent and an uploaded key, and only the ways this deployment can take |
| Directory groups, and one page per group | what the directories say exists, and which of it the policy uses. A group's page reads along the chain: its members as the directory reports them, the internal groups it feeds, the clients that therefore open |
| People, and one page per person | every account, as the last snapshot has it, filtered by directory and by whether it is live. A person's page is where the two sides meet: their directory groups, then the chain one row per internal group held — what put them in it and what it opens — then what did not open and why. Once the issuer exists it gains **Active sessions** with Revoke, and your own page **Sign out everywhere** |
| Matchers | every rule that admits a proof by its shape — a CI job, a workload, a verified sign-in — with the internal group it feeds and the clients that opens. The identity side's second way in: a directory group feeds by membership, a matcher by pattern. Below the list, a simulator for a concrete proof, because a CI run exists only while it runs and cannot be listed |
| Internal groups, and one page per group | the vocabulary of access. A group's page mirrors a directory group's: the directory groups that feed it, the people that puts in it now, what it adds to a token, the clients it opens |
| Clients, and one page per client | kind, redirects, cap, the internal groups that open it, the people who therefore reach it, and the rules that admit machines into it; once the issuer exists, the sessions open on it |
| Settings | the OAuth client, the policy layers with their export, the intervals |

Every page reads in the same direction, from the identity side toward
the access side, and the two group pages carry the same sections
mirrored. The visual vocabulary has one meaning per form, which is what
keeps a data-dense page readable: a name is a link, monospace when it is
an identifier; a chip is a state and nothing else is; facts are a label
over a value; two-column data is a list and tabular data is a table. The
navigation is a rail with the two sides as groups, which is what Material
recommends for this many destinations. The account sits at the foot of
the rail as two controls: your name and role are one button, to your own
page, which then also says how you signed in; sign out is the other. The
header is left to search alone. On a wide window a detail page splits:
the main column carries the edges, the aside carries the facts and the
reference material — directory groups, claims, redirects, what a group
adds — that would otherwise push the edges below the fold.

The console is composed from a handful of reads and one write, and the
contract is shaped so that no page needs a second call to finish a
sentence: an explanation names the directory that served the address, a
people search reports how many matched before the limit, and the policy
carries its matchers structured rather than as prose. The reverse edges
are what make it navigable: from a directory group, the internal groups
it feeds; from an internal group, the people in it; from a client, the
groups and the people. Two of those questions
the policy file cannot answer alone. Who is in an internal group right
now: the file says which directory groups count, and only the directory
knows who is in them. And what a directory group grants: the direction an
admin who just changed one in the directory thinks in, which is the
memberships table read backwards.

## Access to the hub itself

The hub authorizes its own operators the way it serves everyone else:
from directory groups. That makes a standalone installation
self-sufficient — no identity provider is deployed for the hub's sake —
and it resolves the apparent redundancy between "the hub integrates with
the corporate directory" and "operators sign in with the corporate
directory": those are two protocols against the same tenant, sign-in and
directory reads, and the hub happens to hold a client capable of both.

### One session, established three ways

In an installation with an authenticating proxy in front of its consoles
— the normal case — the hub's console sits behind that proxy like every
other console, and the **forwarded bearer** is the identity: the hub
verifies it against the configured issuer and resolves the address
through the directory like any other, so the same memberships grant the
same role. The hub's **own login page** exists for two situations only: a
standalone installation with no proxy, where operators sign in with a
connected directory itself (this installation's OAuth client, asking for
openid, email and profile and nothing else; the address must be in a
served domain), and recovery.

There is deliberately no third: an external OIDC issuer does not drive the
hub's own login page. An installation that has an issuer has access-proxy
in front of it — that is what the issuer is for — and the proxy's
forwarded identity is the path. Building a second OIDC client here would
be a login flow with no user, on the service that must keep working when
the issuer does not.

| Source | Normal for |
|---|---|
| forwarded bearer | an installation with a proxy in front of every console |
| the connected directory, own login | a standalone installation; also what makes day one work before any issuer exists |
| recovery | day one and the day the rest is broken, by port-forward |

Whichever source, the result is one HttpOnly cookie signed with the
hub's session key, short-lived, revoked only by rotating the key. The
console never sees a token. The routes are HTTP, not RPC: `/login`,
`/login/<backend>/start` and `/callback`,
`/callback`, `/logout`, and `/admin/login`.

### Recovery

The way in for the day the ordinary one is broken: nobody in the operators
group, the group renamed, the directory refusing to answer. It is reached
at `/login` under a disclosure rather than as a field on the page —
recovery that looks like the normal way in gets used as one — and it posts
to `POST /login/recovery`.

**In a cluster it stores nothing.** The proof is a ServiceAccount token
minted for one audience and a few minutes, checked with a TokenReview:

```sh
kubectl -n directory-roster create token <release>-recovery \
  --audience <release>-recovery --duration 10m
```

The sign-in page prints that command with this installation's own
namespace and account in it, for the same reason the setup steps print the
real redirect URI: the alternative is somebody guessing a release name
during an outage. None of it is a secret — they are object names, visible
to anyone who may read the namespace, from a chart that is public — and
none of it works without the RBAC to mint the token, which is itself
enough to reach the hub by other means. What the page needs beside it is
not concealment but a warning, because it is an instruction to produce
operator access and a person who *does* hold that RBAC could be talked
into running it for someone else: *never run it because someone asked you
to.*

The reasoning starts from a fact that makes a stored secret look much less
useful than it seems: **whoever could read a break-glass Secret already
has cluster access to that namespace, and could equally exec into the
hub.** So the secret was never protecting the console from an attacker —
it was converting cluster access into a console session. Doing that
directly is better on every axis. There is no standing credential to
rotate, to leak, or to find in an etcd backup. The authority becomes the
cluster's own RBAC — who may create a token for that account — which is
where cluster privilege is supposed to be visible, is revocable by
removing a binding, and is recorded in the cluster's audit log. Expiry and
audience come for free, and the audience is what stops every mounted
ServiceAccount token in the cluster from being a recovery token. And the
session names *who* recovered; a shared password made every recovery look
like the same person.

It fails when the API server is unreachable — but so does reading a
Secret, and so does port-forwarding to the console, so nothing is lost. A
review that could not run is reported as exactly that, never as a wrong
proof: telling an operator "wrong password" on the day the API server is
down would send them hunting for the wrong thing.

**Outside a cluster** there is no authority to prove access to, so a
password is generated at start and printed once. It is held only as an
Argon2id digest with a random salt and compared in constant time — the
stretching is for the installation that sets a memorable one, where
reaching the process memory should not hand the password back. Because
verifying costs memory deliberately and anyone who can reach the console
can ask for it, verifications are serialised and the password stops
answering for a minute after ten failures, the correct one included, since
a limit that lets it through is a hint about which guess was close. This
shape *is* a standing credential, so it is the only one the console warns
about and the only one with a "turn it off" step.

Two alternatives, recorded so they are not re-litigated. A **recovery
key** — generated only, shown once, formatted in groups — is a real
improvement over a chooseable password and still a standing credential
stored somewhere, failing in exactly the situations the token does; it
would only be the answer if a TokenReview verifier were not needed anyway.
A **password-authenticated key exchange** (SRP and friends) buys not
sending the password to the server, but this server is the party being
authenticated to and holds the password already; what it costs is
JavaScript doing modular arithmetic, a multi-step exchange with ephemeral
state shared between replicas, and a lightly-maintained crypto dependency,
placed on the one path that must work when everything else is broken.
Recovery earns its keep by having the fewest moving parts.

### Roles come from the policy, membership from the console

The hub is a relying party of the family's own [policy](../reference/policy.md):
`all:access-roster:operator` and `all:access-roster:viewer` are two declared internal groups, and
an identity holds a role by being in one of them. Who is in them is the
one thing the console edits: a group's page attaches a directory group,
picked from the hub's own snapshots, to a declared internal group, and
detaches what it attached. Group names, claim fragments, lifetimes and
clients are declared in the deployment and shown locked.

When the directory answer for a signed-in identity is not authoritative,
the last granted role is kept for the hold window and no new identity is
granted anything: the same hold-never-remove rule, applied to the hub's
own door. The window is a chart value, because staying usable while its
own directory is uncertain is a property of the hub rather than of the
policy.

### What the console may change

| Area | Console | Declared only |
|---|---|---|
| memberships | attach a snapshotted directory group to a declared internal group; detach what the console attached | the baseline |
| group names, claim fragments, lifetimes, clients, matchers | nothing | all |
| workspaces | connect, reconnect, upload a key, probe, refresh, disconnect what it connected | a workspace the deployment declared |
| the OAuth client | set it once, when the chart did not declare one | a declared client |
| sessions, once the issuer exists | revoke another identity's (operator); sign out everywhere (anyone, their own). Removal only: a console can end access here, never grant it. The browser calls the issuer directly, so the hub's own code stays independent of it | — |
| recovery, the intervals, the sign-in sources | nothing | all |

A console that could re-enable its own recovery path would be a back
door, which is why that flag is the chart's alone — and why recovery is
not expressed as an ordinary policy matcher, tempting as that is: it has
to work on the day the policy is what is broken.

### Explaining a proof

"What does this proof get, and what put it there" is one answer, and a
person, a CI job and a workload are one question: every proof resolves to
internal groups and stops being anything else. So one component renders
it, in two places. A person is a thing with a name, so their answer is
their page, reached by searching for them. A CI job and a workload have
no name to search for — they do not exist until one runs — so the
Matchers page keeps the proof picker for exactly those two, under the
list of rules a proof is checked against.

The answer opens with a sentence: their role here, how many internal
groups they hold, how many clients they reach. Then what they reach, one
row per client, with the group that opened it and how long the token
lives once the client's cap applies. Then the internal groups with the
directory group or matcher behind each, then the directory groups the hub
reports, then the claims a token would carry, behind a disclosure because
they are the least actionable thing on the page and the tallest.

That client table is where the model stops being a diagram: groups are
the vocabulary, and clients are what the vocabulary buys.

Anyone may ask about themselves; explaining anyone else needs viewer. A
viewer already sees every group's members and every client's
requirements, so withholding a conclusion they could reach by hand
protected nothing and blocked the auditor, who is read-only by
definition.

### Day one

A deployment that declares a workspace and a non-empty operators group
has no day one: it is signed into through the directory from its first
boot. That is the gitops path, and it is the common one.

A standalone installation is the other path, and the console leads it:
recovery → OAuth client → connect the first workspace → one membership from
the group picker → sign in as yourself → admin off. Overview carries
those five steps until none is left, each disappearing as it completes.

It is there rather than only in a runbook because the values are this
installation's own. The redirect URI to register is the hub's hostname
plus a fixed path, and the scopes are a fixed list; a document can only
describe them, so an operator reads one, translates it, and retypes a
hostname into a cloud console. That is where a day-one setup goes wrong,
and it fails much later, at the first probe, complaining about a redirect
mismatch. The hub knows the value exactly, so it shows it.

The sequence is drawn in
[the architecture](../architecture.md#58-day-one-of-a-standalone-installation)
and the commands are in [the runbook](../operations/runbook.md#day-one).

### Declared workspaces

A deployment that already holds directory credentials declares them
rather than clicking through consent: a backend, an admin to impersonate
and a Secret holding the key. The hub adopts each at start, and a
declared workspace is read-only in the console and wins a contested
domain.

The tenant id is optional, and discovering it is the better path. The
credential opens exactly one tenant and that tenant knows its own id, so
a value copied out of a cloud console by hand is a value that can be
mistyped. Supplying it turns adoption into a check instead: a credential
that opens a different tenant than the deployment named is refused, which
matters because the failure it prevents is silent. Everything downstream
— who is live, who is in which group — would otherwise be answered
correctly about the wrong company.

A declared workspace that cannot be adopted stops the process. The
deployment asked for a directory; starting without it means answering
"no opinion" about every address in it, which reads to a consumer exactly
like a tenant that was removed. A hub that refuses to start is visible in
one place. A hub that quietly serves less than it was configured to is
visible nowhere.

### Consumers

The API listener authenticates callers by Kubernetes ServiceAccount
token: the consumer mounts a projected token with audience
`directory-roster` and a short expiry, the hub verifies it with a
TokenReview, and an allow-list of `namespace/serviceAccount` pairs in the
chart decides who may read. Bound tokens die with their pod. It is the
one cluster-scoped permission the chart creates, and it reads nothing.
NetworkPolicy stays as the second layer, never the only one.

That is the **cluster anchor**, and it is the right one for the
consumers the hub has — the issuer and github-roster, both next door.
There is no exchange in front of a same-cluster call: the issuer would
verify the same token and re-sign it, on the hottest path in the system,
and the issuer *calls this listener*, so a hub that required issuer
tokens would deadlock the estate on cold start. A consumer **outside the
cluster** — another cluster's workload, a laptop, a person — presents an
issuer token on the same port, verified by the verifier the console
already has; and the grant is then keyed by the **principal**, not the
anchor, so one consumer table stands behind both doors. The rule and its
reasons are [trust.md](trust.md); the how-to for a consumer is
[../connect/service-to-service.md](../connect/service-to-service.md).

## Two boundaries worth naming

**The library.** The Connect flow (consent, tenant and domain discovery,
the first probe, reconnect), the per-backend clients and the policy engine
are importable Go packages behind storage interfaces, not code welded to
the Kubernetes store. A product that lets a customer's administrator
connect their own directory in one click imports the same packages with
its own store; sign-in for that customer's users is the product's identity
provider's job, and the two compose behind one screen. The boundary is
kept from day one because it is cheap then and expensive later.

**The issuer.** The second service of this repository, access-issuer, is a
security token service: it verifies proofs — corporate sign-ins, CI
tokens, workload tokens — applies the policy, and issues tokens that
clusters, cloud accounts and consoles trust. It is the hub's first
consumer and shares its policy engine. It is designed in
[access-issuer.md](access-issuer.md) and runs beside the hub. Nothing in
the hub depends on it; an installation that only wants the sync model
never deploys it. The hub's two listeners are the two trust anchors made
physical, which is why the hub is the pattern every service with a
console and an API should follow ([trust.md](trust.md)).

## Failure semantics

- A failed probe makes a workspace's domains non-authoritative; the last
  known good snapshot is still served, marked stale.
- A domain served by no workspace is "no opinion", never absent.
- A domain claimed by two workspaces is authoritative for neither.
- Group reads are atomic per group — a page failure fails the group, never
  a silent partial.

## What is not carried from google-group-sync

The Lambda and Lambda-extension flavours (single-workspace by construction),
the one-workspace-per-process configuration, the environment-variable
credential path (replaced by the overlay), and the REST routes
(`/users/{email}/groups`, `/groups`, `/groups/{email}`): their one consumer
moves to the ConnectRPC client and learns `authoritative` at the same time.

## Build

1. Workspace model, Kubernetes store, overlay.
2. Routing by domain, per-domain authoritative flag, domain discovery,
   probes; snapshots in Valkey, the refresher, `max_age` and the
   cheapest-path rule; the additive contract fields.
3. `WorkspaceService`, the consent flow, key upload, `SettingsService`.
4. The console.
5. Documentation (below).

## Documentation at 1.0

| File | Holds |
|---|---|
| `README.md` | what it is, the contracts, quick start |
| `docs/architecture.md` | the family in one page: context, containers, the hub's components, who owns what, use cases, failure semantics |
| `docs/design/access-issuer.md` | the issuer's design and its guardrail |
| `docs/reference/contracts.md` | `DirectoryService`, `WorkspaceService`, `SettingsService`, `AccessService`; `max_age`/`snapshot_at`; the additive fields vs google-group-sync |
| `docs/reference/configuration.md` | chart values, the overlay format, the policy and consumers, Kubernetes objects, what the chart includes vs expects; a Valkey recommendation; an example of delivering a declared Secret with external-secrets |
| `docs/operations/connect-runbook.md` | the one-time GCP prerequisites, the per-workspace flow, trusting the client, verification |
| `docs/operations/runbook.md` | day one, health, reconnect as the recovery, lost operator access, domain moves and conflicts, export |
| `docs/operations/migration-from-google-group-sync.md` | overlay first, consumers moved to the ConnectRPC client, Connect later, archive |
| `docs/development/testing.md` | fakes for the backend and the store |
| `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, chart README, `values.schema.json` | estate-standard |

Entra is the first change after 1.0: a second backend behind the same
workspace record, with its own consent flow.
