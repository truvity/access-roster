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
- **Authoritative is per domain.** A domain is authoritative when its
  workspace's last probe succeeded within the freshness window and no domain
  conflict exists. Consumers that remove access act only on authoritative
  answers; this flag is the safety-critical part of the contract.

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
- **`AccessService`** — `WhoAmI`, `GetAccessPolicy`, `AddRule`,
  `RemoveRule`: the rules that grant viewer and operator (see *Access to
  the hub itself*). Declared rules are read-only here.

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

### The cache

Snapshots live in **Valkey**, which is external to the hub: the chart takes
an address and credentials, and the configuration reference recommends how
to run one. With a shared cache, replicas answer from the same snapshot,
a restart is warm, and the backend is read once per interval regardless of
replica count. An in-memory backend exists for development and a single
replica; a production installation with more than one replica needs
Valkey. Valkey holds only snapshots and locks — losing it costs one fetch
per workspace, never a credential.

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
4. One OAuth client, type Web application, redirect URI
   `https://<hub host>/connect/google/callback`. While the hub is being
   tried on a workstation a second URI, `http://localhost:8080/connect/
   google/callback`, may sit on the same client; remove it afterwards.
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
   account. The account needs the Users and Groups read privileges.
4. Consent, redirect back. The browser carries the gateway session, so the
   callback is authenticated like any other page.
5. The hub exchanges the code, records the consenting account, reads the
   customer id and domain list, runs a first probe, and stores the
   workspace. Its domains are served from that moment.

### The second way in

Upload a service-account key with domain-wide delegation, plus the admin to
impersonate. Same record, different credential type. For installations that
prefer a robot identity or cannot publish an external consent screen.

### Afterwards

Access tokens are minted from the refresh token; the workspace is probed on
an interval. A revoked token, a suspended admin account or a tenant policy
change fails the probe: the workspace shows unhealthy, its domains stop
being authoritative, consumers hold their removals, and the console offers
**Reconnect**, which is the same button again.

## The store

Plain Kubernetes objects in the hub's own namespace, read and written by
the hub itself. Nothing else is in the loop: no external-secrets operator,
no cloud parameter store, no cache. How a *declared* Secret gets into the
namespace — an external-secrets `ExternalSecret`, a sealed secret, `kubectl`
— is the deployment's business; the configuration reference carries an
example, the hub has no dependency on it.

The objects — workspace Secrets and ConfigMaps, the OAuth client, the
session key, the admin password, console-added rules, the declared
overlay — are listed once, in
[reference/configuration.md](../reference/configuration.md#kubernetes-objects-the-hub-owns).
Valkey holds snapshots, refresh locks and the short negative cache, never
a credential.

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

Built on the shared fleet console stack (gateway-auth library, Vite, MUI,
Connect-Web): Workspaces (each with domains, health, authoritative state,
Connect / Reconnect / Disconnect), Settings (the OAuth client, the
read-only knobs) and Access (who is signed in, the rules, the admin
banner).

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
verifies it against the configured issuer and a `claim` rule grants the
role. The hub's **own login page** exists for two situations only: a
standalone installation with no proxy and no issuer, where operators sign
in with the connected directory itself (the workspace's OAuth client with
the openid, email and profile scopes; the address must be live in a served
domain), and break-glass. An external OIDC issuer can also drive the own
login page, for the rare installation with an issuer but no proxy.

| Source | Normal for |
|---|---|
| forwarded bearer | an installation with a proxy in front of every console |
| the connected directory, own login | a standalone installation; also what makes day one work before any issuer exists |
| an external OIDC issuer, own login | an issuer but no proxy |
| the admin account | day one and break-glass, by port-forward |

Whichever source, the result is one HttpOnly cookie signed with the
hub's session key, short-lived, revoked only by rotating the key. The
console never sees a token. The routes are HTTP, not RPC: `/login`,
`/login/directory/start` and `/callback`, `/login/oidc/start` and
`/callback`, `/logout`, and `/admin/login`.

### The break-glass account

A local `admin` with a password generated on first start into the Secret
`hub-admin`, shown nowhere else. It signs in only through `/admin/login`,
so behind a gateway it is reached by port-forward. The console shows a
banner while it is enabled; a chart value turns it off. It exists for day
one and for the day the corporate sign-in is what is broken.

### Rules

Authorization is a list of rules, evaluated in order, default deny.
Operator implies viewer. Four subject kinds:

| Subject | Matches | Needs |
|---|---|---|
| `directoryGroup` | members of a group the hub snapshots, in a served domain, live | a connected workspace |
| `claim` | a value in a named claim of a verified token from a named issuer — a groups claim, a roles claim | the OIDC or forwarded source |
| `email` | one address | nothing |
| `emailDomain` | every address in a domain | nothing |

Declared rules come from the chart and are read-only in the console;
console-added rules are stored by the hub and evaluated after them. The
Access view offers a picker over snapshotted groups, so the first rule is
a click, not a typed address. When the directory answer for a signed-in
identity is not authoritative, the last granted role is kept for a
bounded window and no new identity is granted anything: the same
hold-never-remove rule, applied to the hub's own door.

### Day one

Admin → OAuth client → connect the first workspace → one rule from the
group picker → sign in as yourself → admin off. The sequence is drawn in
[the architecture](../architecture.md#58-day-one-of-a-standalone-installation)
and the commands are in [the runbook](../operations/runbook.md#day-one).

### Consumers

The API listener authenticates callers by Kubernetes ServiceAccount
token: the consumer mounts a projected token with audience
`directory-roster` and a short expiry, the hub verifies it with a
TokenReview, and an allow-list of `namespace/serviceAccount` pairs in the
chart decides who may read. Bound tokens die with their pod. It is the
one cluster-scoped permission the chart creates, and it reads nothing.
NetworkPolicy stays as the second layer, never the only one. A consumer
outside the cluster, if one ever exists, presents an OIDC token through
the same verifier the console uses.

## Two boundaries worth naming

**The library.** The Connect flow (consent, tenant and domain discovery,
the first probe, reconnect), the per-backend clients and the rules engine
are importable Go packages behind storage interfaces, not code welded to
the Kubernetes store. A product that lets a customer's administrator
connect their own directory in one click imports the same packages with
its own store; sign-in for that customer's users is the product's identity
provider's job, and the two compose behind one screen. The boundary is
kept from day one because it is cheap then and expensive later.

**The issuer.** The second service of this repository, access-issuer, is a
security token service: it verifies proofs — corporate sign-ins, workload
tokens — applies rules, and issues tokens that clusters, cloud accounts
and consoles trust. It is the hub's first consumer and shares its
verifiers, backends and rules engine. It is designed in
[access-issuer.md](access-issuer.md) and built after the hub. Nothing in
the hub depends on it; an installation that only wants the sync model
never deploys it.

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
| `docs/reference/contracts.md` | `DirectoryService`, `WorkspaceService`, `SettingsService`; `max_age`/`snapshot_at`; the additive fields vs google-group-sync |
| `docs/reference/configuration.md` | chart values, the overlay format, access rules and consumers, Kubernetes objects, what the chart includes vs expects; a Valkey recommendation; an example of delivering a declared Secret with external-secrets |
| `docs/operations/connect-runbook.md` | the one-time GCP prerequisites, the per-workspace flow, trusting the client, verification |
| `docs/operations/runbook.md` | day one, health, reconnect as the recovery, lost operator access, domain moves and conflicts, export |
| `docs/operations/migration-from-google-group-sync.md` | overlay first, consumers moved to the ConnectRPC client, Connect later, archive |
| `docs/development/testing.md` | fakes for the backend and the store |
| `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, chart README, `values.schema.json` | estate-standard |

Entra is the first change after 1.0: a second backend behind the same
workspace record, with its own consent flow.
