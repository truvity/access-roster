# directory-roster — contracts

The issuer's endpoints are in [access-issuer.md](access-issuer.md); this page is the hub.

Three ConnectRPC services on two listeners. The proto files under
[`proto/`](../../proto) are the source of truth; this page is the reading
guide. Connect speaks JSON over plain HTTP as well as gRPC, and serves
idempotent calls over `GET`, so `curl` works without a generated client.

| Listener | Services | Reached by | Path prefix |
|---|---|---|---|
| API (`:8080`) | `directory.v1.DirectoryService` | consumers over the cluster network | `/directory.v1.DirectoryService/` |
| console (`:8081`) | `directoryroster.v1.WorkspaceService`, `SettingsService`, `AccessService`, the SPA, the login routes, `/connect/<backend>/callback` | operators: own login, or through a gateway | `/directoryroster.v1.*/` |

## Authentication

**API listener.** Callers present a Kubernetes ServiceAccount token as a
bearer, projected with the audience `listeners.api.audience` names — the
release name by default, so two hubs in one cluster cannot accept each
other's callers. The hub verifies it with a TokenReview and checks the
subject against the chart's `consumers` allow-list; anything else is 401
with `WWW-Authenticate`, and which of "not a real token" or "not a
consumer" it was is in the hub's log rather than in the answer.
NetworkPolicy is the second layer, never the only one.

A deployment that declares no consumers admits **nobody**: this listener
answers everything the hub knows about every company it serves, and one
that answered everyone by default would be a forgotten value away from
serving a directory to the whole cluster. Outside a cluster there is
nothing to verify a token against, so the listener is open and the
process says so at start — a development posture, never a deployed one.

**Console listener.** One session cookie, HttpOnly, signed with the hub's
session key, obtained through one of the login routes below or — behind
an authenticating gateway — minted from the forwarded bearer on the first
request. Roles come from membership of two declared policy groups:
`hub-viewers` reads, `hub-operators` writes. Unauthenticated RPCs get `unauthenticated`; a missing role gets
`permission_denied`.

| Route | Does |
|---|---|
| `GET /login` | the login page: the enabled sources as buttons |
| `GET /login/<backend>/start` → `GET /login/<backend>/callback` | sign in with a directory: this installation's OAuth client, `openid email profile` and nothing else. The address it returns is all that is taken from the provider; whether it is live, which company it belongs to and what it may do are answered by the directory and the policy. An address in no served domain, or one the directory authoritatively does not have, is refused at the door rather than given a session with no role |
| `POST /login/recovery` | the recovery sign-in, while a deployment has one. In a cluster the proof is a ServiceAccount token minted for the recovery audience, verified by TokenReview; elsewhere it is the generated password. The proof may come in the form, as JSON, or as a bearer, so a runbook can be one curl |
| `POST /logout` | clears the session |
| `GET /connect/<backend>/callback` | the admin-consent callback, authenticated like any page |

## Compatibility with google-group-sync

`directory.v1.DirectoryService` is google-group-sync's contract with
additive fields only. A client generated from the older proto keeps
working and is served as if `max_age` were omitted; it does not see
`authoritative`, so it must be upgraded before it may act on removals from
a multi-workspace hub. The REST routes google-group-sync also served
(`/users/{email}/groups`, `/groups`, `/groups/{email}`) are **not**
carried; their one consumer moves to the Connect client.

## Freshness: `max_age` and `snapshot_at`

Every read is answered from a per-workspace **snapshot** and returns
`snapshot_at`. Every read request takes an optional `max_age`
(`google.protobuf.Duration`):

| `max_age` | Behaviour |
|---|---|
| omitted | serve the current snapshot; nothing is fetched on the request path |
| a duration | if the snapshot is older, make it fresher first, then answer |
| `0s` | fetch now |

How "make it fresher" happens depends on the call, by the cheapest path
that satisfies the request:

- **Bulk calls** (`ListGroups`, `GetGroup`) trigger a full workspace read,
  single-flight: concurrent requests wait for the one in progress.
- **Point calls** (`ResolveUser`, `GetAccount`, `ResolveAccounts`) read that
  one account and its groups live and patch the snapshot. A login-time
  caller with a short timeout is never held behind a full read.
- **A miss on an in-domain address** always goes live once before the hub
  answers `found=false`, whatever `max_age` says: not-found is a removal
  signal, and an account created after the last snapshot must never be
  reported absent.

When the fetch fails, the stale snapshot is served with
`authoritative=false`. It is never an error to the caller.

## Served domains

A workspace serves every domain its tenant owns, unless it is narrowed to
a subset. The domains are always **discovered**; `serve` says which of the
discovered ones this installation answers for. An unserved domain routes
nothing — an address in it comes back `in_domain=false`, exactly as if no
directory here had ever heard of it — and its accounts are not kept in the
snapshot at all.

Two consequences worth stating:

- **A domain contests only when two workspaces both serve it.** Owning a
  domain another tenant serves is not a conflict, which is what lets one
  installation hold two directories that overlap on paper.
- **The served list is intersected with discovery, never trusted over
  it.** A domain moving between tenants therefore hands over by itself:
  the old workspace stops serving it the moment the directory stops
  listing it, and the new one picks it up when its own discovery returns
  it. The stale entry in the old list is reported as `owned=false` for an
  operator to tidy; it grants nothing in the meantime.

A workspace may be narrowed in the deployment's values (`workspaces[].serve`,
for a declared workspace) or in the console (`SetServedDomains`, for a
connected one). Either way the only domains that may be named are the ones
discovery returned: the ceiling is the tenant's own verified domains, so
every setting is a subtraction from what the directory itself allows.

## Authority

A domain is **authoritative** when all three hold: its workspace's last
probe succeeded, its snapshot is younger than the freshness window, and no
other workspace **serves** the domain too. Every answer that names an
account or a group carries the flag for the domain it came from.

The contract with consumers: **act on removals only when
`authoritative=true`.** A non-authoritative "suspended", "not found" or
"not a member" is a hold, not a change.

## `directory.v1.DirectoryService`

| RPC | Request | Response | Notes |
|---|---|---|---|
| `Describe` | — | `domains[]`, `backend`, `served[]{name, authoritative, workspace_id, backend, snapshot_at}` | `domains` and `backend` are the legacy fields; `served` is the structured list |
| `Probe` | `workspace_id?` | `healthy`, `detail`, `workspaces[]{workspace_id, healthy, detail, probed_at}` | empty id probes every workspace; exercises the credential now |
| `GetGroup` | `email`, `max_age?` | `group{email, members[], domain}`, `found`, `authoritative`, `snapshot_at` | flat members, nested groups not expanded; `found=false` = the backend said not-found |
| `ListGroups` | `domain?`, `max_age?` | `groups[]`, `served[]` | empty domain = union of every served domain, each group tagged with its domain |
| `GetAccount` | `email`, `max_age?` | `account{email, in_domain, found, live, given_name, family_name, authoritative}`, `snapshot_at` | see the `Account` table below |
| `ResolveAccounts` | `emails[]`, `max_age?` | `accounts[]` (same order), `snapshot_at` (oldest) | addresses may span workspaces; each is routed on its own |
| `ResolveUser` | `email`, `max_age?` | `groups[]`, `suspended`, `in_domain`, `found`, `authoritative`, `snapshot_at` | the login-time call |

`Account` semantics:

| `in_domain` | `found` | `live` | Meaning |
|---|---|---|---|
| true | true | true | a live account |
| true | true | false | suspended — gone, if authoritative |
| true | false | — | deleted or absent — gone, if authoritative |
| false | — | — | no opinion: the address's domain is not served here |

Error model: the API returns Connect errors only for malformed requests
(`invalid_argument`: empty or unparseable address) and for internal
faults that are not a backend read (`internal`). A backend read failing is
not an error; it is a non-authoritative answer.

## `directoryroster.v1.WorkspaceService`

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `ListWorkspaces` | viewer | — | `workspaces[]` | id, backend, domains with authoritative/conflict/served/owned flags, admin, credential type, connected_by/at, health, snapshot_at, declared |
| `BeginConnect` | operator | `backend` | `consent_url` | sets the state cookie; the browser navigates to the URL |
| `Reconnect` | operator | `workspace_id` | `consent_url` | the callback checks the consenting tenant is the same, then replaces the credential |
| `UploadKey` | operator | `backend`, `key` (bytes), `admin` | `workspace` | service-account key with domain-wide delegation; creates or re-credentials |
| `SetServedDomains` | operator | `workspace_id`, `domains[]` | `workspace` | which of the tenant's domains this hub answers for; empty = all of them, including ones added later. Only discovered domains may be named (`InvalidArgument` otherwise); a declared workspace refuses (`FailedPrecondition`) — its list is in the values. A new snapshot is taken so that what was excluded stops being cached |
| `Probe` | operator | `workspace_id` | `health`, `domains[]` | credential check now, domain list re-read |
| `Refresh` | operator | `workspace_id` | `snapshot_at` | a full snapshot now |
| `Disconnect` | operator | `workspace_id` | — | revokes at the backend, deletes the Secret and the record. `failed_precondition` for a declared workspace |

The consent callback, `GET /connect/google/callback?code&state`, is an
ordinary HTTP route on the console listener: it verifies the state cookie,
exchanges the code, discovers the tenant id and the domain list, runs a
first probe, stores the workspace and redirects to that tenant's page.

Errors: `permission_denied` when the role is missing; `not_found` for an
unknown workspace id; `failed_precondition` for an operation the
workspace's kind refuses (Disconnect on a declared one); `invalid_argument`
for a key that does not parse or an admin address without a domain.

## `directoryroster.v1.SettingsService`

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `GetSettings` | viewer | — | `oauth_client{client_id, configured, source}`, `refresh_interval`, `freshness_window`, `probe_interval`, `cache_backend`, `connectors[]`, `key_connectors[]`, `version`, `setup[]{backend, redirect_uris[], scopes[]}` | never the client secret. `setup` is the one-time cloud-console step as values to copy: the redirect URIs are this installation's own hostname, which a document can only describe; there are two because consent and sign-in return to endpoints with opposite authorisation, and a client missing one works until somebody tries that flow. `connectors` are the backends this deployment can add a directory from; `key_connectors` the subset that also take an uploaded key |
| `SetOAuthClient` | operator | `client_id`, `client_secret` | — | `failed_precondition` when the deployment declared the client |

The intervals are chart values. The console shows them so an operator
can see what the hub runs with; changing them is a deployment change.

## `directoryroster.v1.AccessService`

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `WhoAmI` | any signed-in identity | — | `identity{email, subject, source, role, groups[], given_name, family_name}`, `version` | groups are the internal groups the policy puts the caller in |
| `Explain` | self: any; anything else: viewer | one proof: `email?`, `github{repository, owner, ref, workflow, environment}?` or `service_account{namespace, name}?` | the identity, the directory's answer (`in_domain`, `found`, `suspended`, `authoritative`), `workspace_id`, `directory_groups[]`, `held[]{group, via[]}`, `claims`, `lifetime`, `clients[]{id, kind, requires[], admitted, lifetime}` | what a proof effectively gets and why. A person, a CI job and a workload are the same question, so they are the same call; nothing set explains the caller |
| `GetPolicy` | viewer | — | `groups[]{name, members[]{address, layer}, rules[]{kind, rule}, claims, lifetime}`, `clients[]{id, kind, requires[], redirects[], ttl_cap, secret}`, `admin_enabled`, `login_sources[]`, `console_layer` | `console_layer` is the console's own edits as YAML, for export; a confidential client names the Secret holding its secret, never the secret |
| `AddMembership` | operator | `group`, `directory_group` | — | the group must be declared |
| `RemoveMembership` | operator | `group`, `directory_group` | — | `failed_precondition` for a membership the deployment declared |
| `ListHolders` | viewer | `group?` or `client?`, `limit?` | `holders[]{email, given_name, family_name, live, authoritative, via[], lifetime}`, `examined`, `truncated` | who holds a group, or reaches a client, right now. The policy says which directory groups count; only the directory knows who is in them |
| `SearchPeople` | viewer | `query?`, `workspace_id?`, `account?` (live, suspended), `limit?` | `people[]{email, given_name, family_name, workspace_id, live}`, `total`, `truncated` | accounts by address or name across every snapshot, or one tenant's accounts, so a console can start from a name and a tenant's page can list who it holds |
| `ListDirectoryGroups` | viewer | `domain?` | `groups[]{email, domain, workspace_id, members}` | the picker's source: the hub's own snapshots |
| `GetDirectoryGroup` | viewer | `email` | `email, domain, workspace_id, found, authoritative, snapshot_at`, `members[]{email, given_name, family_name, known, live}`, `feeds[]{group, layer}` | one directory group: its members as the directory reports them, and the memberships table read backwards. The direction an admin who just changed a group in the directory thinks in, and not derivable from the policy alone |

Errors: `unauthenticated` with no session; `permission_denied` without the
role; `not_found` for an undeclared group; `failed_precondition` for
anything the deployment owns.

## The whoami endpoint

`GET /.access/whoami` on the console listener, the same shape every
adapter of the Go module serves:

```json
{
  "status": "signed-in",
  "email": "alice@example.com",
  "name": "Alice Ant",
  "givenName": "Alice",
  "familyName": "Ant",
  "roles": ["operator", "viewer"],
  "source": "forwarded",
  "groups": ["engineering", "hub-operators"],
  "version": "v1.0.0",
  "signOutUrl": "/logout"
}
```

## Calling from a shell

```sh
# From a consumer pod: the projected token is the bearer.
TOKEN=$(cat /var/run/secrets/directory-roster/token)

# Describe, over GET (Connect's idempotent-GET encoding)
curl -s -H "authorization: Bearer $TOKEN" \
  'http://directory-roster.directory-roster.svc:8080/directory.v1.DirectoryService/Describe?encoding=json&message=%7B%7D'

# ResolveUser, over POST
curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","maxAge":"600s"}' \
  http://directory-roster.directory-roster.svc:8080/directory.v1.DirectoryService/ResolveUser
```
