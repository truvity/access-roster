# The console's contracts

The issuer's endpoints are in [configuration.md](configuration.md#endpoints). This
page is what the **console** calls: the services behind its pages.

The proto files under [`proto/`](../../proto) are the source of truth;
this page is the reading guide. Connect speaks JSON over plain HTTP as
well as gRPC, and serves idempotent calls over `GET`, so `curl` works
without a generated client.

| Services | Reached by | Path prefix |
|---|---|---|
| `directoryroster.v1.WorkspaceService`, `SettingsService`, `AccessService`, `GitHubService`, `SlackService`, `SlackChannelService`, `SlackSharedChannelService`, `SlackAppService`, and the SPA; the audit installation's `QueryService`, forwarded under `/audit/` | the console, same-origin under `console.mount`; a workload with its own ServiceAccount token | `/directoryroster.v1.*/` |
| `/login/*`, `/connect/*`, `/.access/*` | the origin root: the bootstrap surface, and the endpoints a CLI reads | — |

> **`directory.v1.DirectoryService` has no listener.** Its one consumer
> was the issuer, and the issuer is the same process, so the question is
> a function call. No chart value turns it on and nothing outside the
> process reaches it. The proto stays as the schema of the directory
> answers — what the console's own services and the login path return,
> and what a listener would serve if something outside ever needed one,
> authenticated by token exchange like every other machine. Its RPC
> table below is a reading guide to those answers, not to an endpoint.

## Authentication

**A workload.** A caller presents a Kubernetes ServiceAccount token as a
bearer, projected for the audience `exchange.audience` names, and the
service verifies it against the key set its cluster publishes — one of
the `exchange.clusters` rows, the same rows token exchange uses — never
by a TokenReview, so that it holds access to no cluster. The policy's
`service_account` matchers put the subject in groups, and the two the
console's own roles read are `all:access-roster:viewer` and
`all:access-roster:operator`. This is how the GitHub controller reads
`ListHolders` and `Explain`, and the Slack controller reads `ListHolders`,
`ResolveDirectoryGroups`, `ListServedDomains` and `Explain`, and how each
records what it did. Anything else is
401 with `WWW-Authenticate`. NetworkPolicy is the second layer, never
the only one.

A deployment that declares no consumers admits **nobody**: this listener
answers everything the service knows about every company it serves, and one
that answered everyone by default would be a forgotten value away from
serving a directory to the whole cluster. Outside a cluster there is
nothing to verify a token against, so the listener is open and the
process says so at start — a development posture, never a deployed one.

**Console listener.** One session cookie, HttpOnly, signed with the service's
session key, obtained through one of the login routes below or — behind
an authenticating gateway — minted from the forwarded bearer on the first
request. Roles come from membership of two declared policy groups:
the viewers group reads, the operators group writes. A directory's own
operators and viewers (`<directory-workspace-id>:access-roster:operator` and
`:viewer`) hold the same roles over the Slack workspaces and GitHub
organisations that directory owns; see [configuration.md#roles](configuration.md#roles).
Unauthenticated RPCs get `unauthenticated`; a missing role gets
`permission_denied`.

**A workload calling the console's API** — a controller beside the
issuer: the GitHub controller and the Slack controller — presents its own projected
ServiceAccount token as `Authorization: Bearer`, with the audience token
exchange uses (`exchange.audience`, the release name by default). It is
verified against the same cluster key sets as an exchange, so only a
cluster the chart federates can produce one, and there is no exchange in
front of it: the issuer would verify that very token and re-sign it. The
identity it becomes has source `workload`, and its role is whatever the
policy's `service_account` matchers put it in — **never** recovery's
operator, which is the one other identity that arrives as a
ServiceAccount. A policy that names no workload admits none. Read the
token file on every call; the kubelet rotates it.

| Route | Does |
|---|---|
| `GET /login` | the login page: the enabled sources as buttons |
| `GET /login/<backend>/start` → `GET /login/<backend>/callback` | sign in with a directory: this installation's OAuth client, `openid email profile` and nothing else. The address it returns is all that is taken from the provider; whether it is live, which company it belongs to and what it may do are answered by the directory and the policy. An address in no served domain, or one the directory authoritatively does not have, is refused at the door rather than given a session with no role |
| `POST /login/recovery` | the recovery sign-in, while a deployment has one. In a cluster the proof is a ServiceAccount token minted for the recovery audience, verified by TokenReview; elsewhere it is the generated password. The proof may come in the form, as JSON, or as a bearer, so a runbook can be one curl |
| `GET /connect/<backend>/callback` | the consent callback, on the bootstrap surface. Its authority is the signed state (cookie-pinned, ten minutes, naming the operator who started the flow), not an identity on the request — there is none there by design. Every failure renders a page in the console's style with the directory's message verbatim and the usual causes, with a **4xx — never a 5xx**, which a CDN in front replaces with a page of its own; a consent that worked redirects to the directory's page |
| `POST /logout` | clears the session |

## Compatibility with google-group-sync

`directory.v1.DirectoryService` extends google-group-sync's contract
with additive fields only, so a client generated from the older proto
still compiles against it — though there is no listener here to point
one at. Such a client does not see `authoritative`, which is the field a
consumer must have before it may act on removals from an installation
serving more than one workspace. The REST routes google-group-sync also
served (`/users/{email}/groups`, `/groups`, `/groups/{email}`) are
**not** carried.

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
- **A miss on an in-domain address** always goes live once before the service
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

That boolean is the whole wire contract. The console's word for a served
domain whose flag is `false` is **provisional**, and it carries a reason —
`first_snapshot_pending`, `snapshot_stale`, `probe_failed` — on the
operator-facing `ListWorkspaces` only; a domain two workspaces
both serve is `conflict` there. Nothing about the consumer-facing
`DirectoryService` changes with the rename.

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
| `ListWorkspaces` | viewer | — | `workspaces[]` | id, backend, `sync_groups` and `discovered_groups` (what a sync chooser offers), domains with authoritative/conflict/served/owned flags and — when served and not authoritative — a `reason` (`first_snapshot_pending`, `snapshot_stale`, `probe_failed`), admin, credential type, connected_by/at, health, snapshot_at, declared |
| `BeginConnect` | operator | `backend` | `consent_url` | sets the state cookie; the browser navigates to the URL. The state is signed by the service and **names the operator who asked**: the callback lands on the bootstrap surface with no gateway identity, and the state is its authority |
| `Reconnect` | operator | `workspace_id` | `consent_url` | the callback checks the consenting tenant is the same, then replaces the credential |
| `UploadKey` | operator | `backend`, `key` (bytes), `admin` | `workspace` | service-account key with domain-wide delegation; creates or re-credentials |
| `SetServedDomains` | operator | `workspace_id`, `domains[]` | `workspace` | which of the tenant's domains this service answers for; empty = all of them, including ones added later. Only discovered domains may be named (`InvalidArgument` otherwise); a declared workspace refuses (`FailedPrecondition`) — its list is in the values. What was excluded is dropped from the snapshot at once and a new one is taken **detached**: the call returns without waiting on the directory. Called at connect time with the operator's choice, before the first snapshot |
| `SetSyncedGroups` | operator | `workspace_id`, `groups[]` | `workspace` | which of the tenant's groups this service keeps; empty keeps every group in the served domains. Only a group the last read held may be named (`InvalidArgument` otherwise); a declared workspace refuses (`FailedPrecondition`). Excluded groups leave the snapshot at once and the re-read is detached |
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

The intervals are chart values. The console shows them so an operator
can see what the service runs with; changing them is a deployment change.
There is no `SetOAuthClient`: a credential a console can change is one
somebody can change from a browser, so the client is declared.

## `directoryroster.v1.AccessService`

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `WhoAmI` | any signed-in identity | — | `identity{email, subject, source, role, groups[], given_name, family_name}`, `version` | groups are the internal groups the policy puts the caller in |
| `Explain` | self: any; anything else: viewer | one proof: `email?`, `github{repository, owner, ref, workflow, environment, visibility}?` or `service_account{cluster, namespace, name}?` | the identity, the directory's answer (`in_domain`, `found`, `suspended`, `authoritative`), `workspace_id`, `directory_groups[]`, `held[]{group, via[]}`, `claims`, `lifetime`, `clients[]{id, kind, requires[], admitted, lifetime}`, `policy_digest` | what a proof effectively gets and why. `policy_digest` names the policy the answer was computed under; a consumer acting on `held` refuses an answer under a policy other than its own. A person, a CI job and a workload are the same question, so they are the same call; nothing set explains the caller |
| `GetPolicy` | viewer | — | `groups[]{name, members[]{address}, rules[]{kind, rule}, claims, lifetime, github_grants[]{app_id, app_name, org, repositories[], permissions{}, last_minted}}`, `clients[]{id, kind, requires[], redirects[], ttl_cap, secret}`, `teams[]{org, team, members[], maintainers[]}`, `orgs[]{org, members[]}`, `recovery_enabled`, `recovery_kind`, `login_sources[]` | a confidential client names the Secret holding its secret, never the secret. A team's and an organisation's `members` are internal groups, as `requires` is; an organisation that binds only teams has no `orgs` row. `github_grants` is the reverse of a catalogue App's grants — which Apps this group may mint installation tokens of, and for how much — read from the catalogue alone, so it says nothing about an App's state on GitHub and costs no call to GitHub. `last_minted` is when a token was last minted under that grant, from the same memory `ListGitHubAppTokens` reads: absent means nothing is remembered — a restart forgets it — and never that the grant is unused |
| `ListHolders` | viewer | `group?` or `client?`, `limit?` | `holders[]{email, given_name, family_name, live, authoritative, via[], lifetime}`, `examined`, `truncated`, `policy_digest` | who holds a group, or reaches a client, right now. The policy says which directory groups count; only the directory knows who is in them. `truncated` is set when the limit cut the list **or** there were more accounts than one answer examines. **Absence is not evidence:** a workspace whose snapshot cannot be read contributes no accounts at all, so a consumer that removes access on absence confirms each account with `Explain` first. Nor is a group the answering policy does not define: it has no holders there, so `policy_digest` must match the consumer's own |
| `SearchPeople` | viewer | `query?`, `workspace_id?`, `domain?`, `account?` (live, suspended), `github?` (linked, not linked), `limit?` | `people[]{email, given_name, family_name, workspace_id, live, github_login}`, `total`, `truncated`, `github_known` | accounts by address or name across every snapshot, or one tenant's accounts, so a console can start from a name and a tenant's page can list who it holds. Every filter is applied here, before the limit, so an answer is the first N that match rather than the matches among the first N. `github_login` is the GitHub account linked to the address, and `github_known` is false where links cannot be read at all — a deployment that keeps none, or a read that failed — which is not the same answer as nobody having linked; narrowing by `github` then fails rather than reporting everyone as unlinked |
| `ListServedDomains` | viewer, installation-wide or over the directory | — | `directories[]{workspace_id, primary_domain, domains[]}` | the domains the hub serves for each connected directory now, lowercased and sorted: what the Slack controller looks a person up by (an address in the owning directory's served domains). A scoped viewer is told only of its own directories |
| `ResolveDirectoryGroups` | viewer, installation-wide | `groups[]` (addresses, at most 200), `users[]` (individual addresses, counted with `groups` against the same ceiling) | `groups[]{email, found, authoritative, workspace_id, members[]{email, given_name, family_name, known, live}, nested[], truncated}`, `users[]{email, workspace_id, found, live}`, `policy_digest` | the question a controller asks to feed a console channel from directory groups, where `ListHolders` asks it of an internal group. Nested groups are expanded; cycles end, depth and size are bounded, and `truncated` means the members are not whole, so nobody may be removed on their absence. A scoped viewer is told `found=false` of a group of a directory it may not view, so the answer never reveals a directory the caller cannot see. `users` answers the individual addresses of a console channel record: `workspace_id` is the directory that serves the address's domain, `found` whether its snapshot holds the account, `live` whether it is active (found and not suspended). `policy_digest` is the answering policy, as on `ListHolders`; a consumer acts only on an answer under its own |
| `ListDirectoryGroups` | viewer | `domain?` | `groups[]{email, domain, workspace_id, members}` | the picker's source: the service's own snapshots |
| `GetDirectoryGroup` | viewer | `email` | `email, domain, workspace_id, found, authoritative, snapshot_at`, `members[]{email, given_name, family_name, known, live}`, `feeds[]{group}` | one directory group: its members as the directory reports them, and the internal groups whose `members` name it — the policy's `groups` table read backwards. The direction an admin who just changed a group in the directory thinks in, and not derivable from the policy alone. A feed's field 2, `layer`, is reserved: there is one layer now |

Errors: `unauthenticated` with no session; `permission_denied` without the
role; `not_found` for an undeclared group; `failed_precondition` for
anything the deployment owns.

## `directoryroster.v1.GitHubService`

The console's view of GitHub organisations. Read-only: the controller
acts, this shows. See [connect/github-organisation.md](../connect/github-organisation.md).

A role below is the installation-wide role, or the same role over the directory
recorded as the owner of the organisation concerned (see
[configuration.md#roles](configuration.md#roles)); the link App and the links
are installation-wide alone.

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `GetGitHubStatus` | viewer | — | `organisations[]{org, bound, reported, report_error, enabled, tick{at, outcome, error, changes, held, waiting}, member_groups[], members[], teams[]{team, bound, member_groups[], maintainer_groups[], members[]}, unlinked[]{login, reason}}`, `reports_available` | every organisation the policy binds **or** the controller reports on, each with its bindings beside its report. A member is `{email, login, role, state, action, reason}`: state is `not-linked`, `pending`, `invited`, `synced`, `leaving` or `held`; action is `invite`, `add`, `set-role` or `remove`, and a held one carries its reason. Where the two sides disagree both show — a bound team nobody has reported, a report for a team the policy no longer binds — and an unreadable report hides no binding. A viewer of one directory sees the organisations that directory owns and no others, because a report names the members of every bound team; the link App and every link are the installation-wide viewer's alone |
| `ListGitHubApps` | viewer | — | `apps[]` (below), `connecting_available`, `linking_available`, `catalogue_available`, `runner_tiers[]`, `bound_organisations[]`, `link_url`, `owner_choices[]`, `may_connect_without_owner` | every App this service keeps a key for or is declared to, in one shape: the link App, one controller App per bound organisation, one runner App per organisation per declared tier, and the catalogue's. An App the deployment no longer declares is listed with `declared` false, so it can be disconnected |
| `GetGitHubApp` | viewer | `id` | `app` | one App by the id the list gives it. `not_found` for an id nothing declares and nothing created |
| `ListGitHubAppTokens` | operator | `id` | `tokens[]{at, subject, proof, grant, repositories[], permissions, outcome, reason}`, `kept`, `kept_since` | the last installation tokens asked of one App, minted or refused, newest first — **never the token**. This service's own memory of them: `kept` per App, since `kept_since`, which is when this replica started, and a restart forgets them. The audit trail is the record and holds every request; this exists because narrowing that trail to one App is a scan. Operator, because a request names who asked. `failed_precondition` for an App that mints none — only the catalogue's do — and for a deployment that mints none here; `unavailable` where the Apps cannot be read, which is never reported as "nothing was asked for" |
| `BeginGitHubAppConnect` | operator | `id`, `owner`, `owner_directory` | `url`, `manifest` | starts creating any of them, or finishing installing one created before, exactly as the per-kind call does — the signed state is the one that kind of App has always used, so a browser part-way through a flow finishes at the same callback even if the service restarts under it. `owner` is the organisation the link App is created under, read for that App alone, which belongs to no one organisation. `owner_directory` is read for the controller App of an organisation not yet connected: the directory that will own it (see below) |
| `DisconnectGitHubApp` | operator | `id` | `uninstalled`, `detail`, `app_settings_url`, `invalidated` | uninstalls where there is an installation, then forgets the record and the key — even when the uninstall fails, which `detail` explains. `invalidated` is how many links became unverifiable, for the link App alone |
| `CheckGitHubApp` | operator | `id` | `app` | asks GitHub again, as the App, what the App and its installation hold, bypassing the minute the list caches it for |
| `BeginGitHubConnect` | operator | `org`, `owner_directory` | `url`, `manifest` | starts connecting an organisation the policy binds, and sets the flow's state cookie. With `manifest` set the browser POSTs it as the form field `manifest` to `url`, GitHub's create page; without, `url` is the App's install page, for an App created and never installed. `failed_precondition` for an unbound organisation, for one already connected and installed, and where the deployment keeps no state in Kubernetes |
| `ChangeGitHubOrganisationOwner` | installation-wide operator | `org`, `owner_directory` (a connected directory's workspace id; empty removes) | — | changes or removes the directory recorded as a connected organisation's owner; the new owner must be a connected directory. Audited as `roster.github_org.owner_changed` |
| `DisconnectGitHubOrganisation` | operator | `org` | `uninstalled`, `detail`, `app_settings_url` | uninstalls the App, then forgets the record and the key — the latter even when the uninstall fails, which `detail` explains. `app_settings_url` is where the owner deletes the App, which the API cannot |
| `BeginGitHubLinkAppConnect` | operator | `owner` | `url`, `manifest` | starts creating the link App under an organisation: public, `emails: read` alone, installed nowhere, calling back to the link callback. `failed_precondition` when one is connected already, or where the deployment keeps no state in Kubernetes |
| `DisconnectGitHubLinkApp` | operator | — | `invalidated`, `app_settings_url` | makes every self-link unverifiable — a profile match or an import stands — then forgets the App |
| `BeginGitHubRunnerAppConnect` | operator | `org`, `tier` | `url`, `manifest` | starts creating a runner App — the App one tier's self-hosted runners register with in one organisation — or finishing installing one; the same two clicks as an organisation's App. `invalid_argument` for a tier the deployment does not declare in `githubRunnerApps.tiers`; `failed_precondition` for an unbound organisation or one whose App for that tier is already installed |
| `DisconnectGitHubRunnerApp` | operator | `org`, `tier` | `uninstalled`, `detail`, `app_settings_url` | uninstalls the runner App and forgets its keys; runners registered with it stop getting jobs |
| `BeginGitHubCatalogueAppConnect` | operator | `id` | `url`, `manifest` | starts creating an App the catalogue declares, under the organisation its entry names, or finishing installing one created before; the same two clicks as an organisation's App. `invalid_argument` for an id the catalogue does not declare; `failed_precondition` for one already installed, and where the deployment keeps no state in Kubernetes. See [connect/github-apps-catalogue.md](../connect/github-apps-catalogue.md) |
| `DisconnectGitHubCatalogueApp` | operator | `id` | `uninstalled`, `detail`, `app_settings_url` | uninstalls the App, then forgets its record and keys — even when the uninstall fails, which `detail` explains. The App stays on GitHub; `app_settings_url` is where its owner deletes it. Works for an App whose entry the catalogue no longer declares |
| `CheckGitHubCatalogueApp` | operator | `id` | `app` | asks GitHub again, as the App, what the App and its installation hold, bypassing the minute `GetGitHubStatus` caches it for |
| `ConfirmGitHubRemovals` | operator | `org`, `fingerprint` | — | lets exactly the removal set the organisation's latest report names go ahead. `failed_precondition` when the report shows a different set. Lapses after a day |
| `ImportGitHubLinks` | operator | `records[]{login, emails[], approved_by, approved_at}`, `origin` | `imported[]` (links), `skipped[]{login, reason}` | adopts approved pairings as links after three checks each: approved, an address the directory vouches for and has live, the account a member of a connected organisation. Never displaces a link the person made. At most 500 records |

An organisation and an App each carry `owner_directory` (the directory's workspace
id, empty for none), `owner_domain` (every domain the owner is authoritative
for) and `can_change_owner`; `GetGitHubStatus` and `ListGitHubApps` carry
`owner_choices[]` (the connected directories the caller may name as an owner)
and `may_connect_without_owner`. The owner is recorded when an organisation is
connected: the installation-wide operator may name any connected directory or
none, an operator of exactly one directory owns what it connects, and an
operator of several chooses among theirs.

`GetGitHubStatus` also carries each organisation's `connection{app_id,
app_slug, installed, html_url, connected_at, connected_by}` — never the
key — and `connecting_available`, false where nothing could keep one; and
`linking_available`, `link_app{app_id, app_slug, owner, html_url,
connected_at, connected_by}`, `link_url` — the page to send people to —
and `links[]{account_id, login, emails[], state, reason, linked_at,
checked_at, changed_at}`, never with a token. A link's state is
`linked`, `lost` or `unverifiable`, and its `source` `self`, `profile` or
`imported`, with a `note` for the latter two. Each organisation also
carries `seats{known, total, filled, pending, free, short}`,
`breaker{affected, members, fingerprint, confirmed}` when a pass would
have removed more than half of it, `removal_confirmation{fingerprint,
confirmed_by, confirmed_at}` while one holds, and
`outside_collaborators[]`, and `ignored[]`, the addresses and logins the
policy says to leave alone. A member's state adds `retrying`, `ignored`
and `reported`; a tick adds `retrying`. `runner_tiers[]` are the tiers
the deployment declares, and `runner_apps[]{org, tier, app_id, app_slug,
installed, html_url, connected_at, connected_by}` every runner App
created — never a key. `catalogue_available` is false where nothing could
keep a catalogue App, and `catalogue_apps[]{id, org, name, description,
public, installation, permissions[]{name, declared, app, installation},
events[], grants[]{group, repositories[], permissions{}, group_declared},
state, html_url, drift[], reason, app_id, app_slug, installation_id,
connected_at, connected_by, checked_at, repository_selection, declared}`
is every declared App and every App created from an entry no longer
declared. `state` is `not_created`, `created`, `installed` or `drifted`;
`drift` says each way GitHub differs from the declaration, and `reason`
why GitHub could not be asked — which never fails the call. What GitHub
said is cached for a minute.

`ListGitHubApps` says all of it, about all four kinds of App, in one
answer, and it is the call the console reads and the one to write new
code against. The four App-shaped fields on `GetGitHubStatus` —
`link_app`, `runner_apps`, `catalogue_apps` and each organisation's
`connection` — are still filled in, so a client generated against an
older proto keeps working; nothing new is added to them.

**One App** is `{id, org, purpose, tier, origin, name, app_slug,
description, public, installation, repository_selection, state,
attention, state_detail, declared, drift[], permissions[]{name, declared,
app, installation}, events[], grants[]{group, repositories[],
permissions{}, group_declared}, html_url, settings_url, app_id,
installation_id, connected_at, connected_by, checked_at, reason, secret,
secret_keys[], linked_accounts}` — never the key. `id` is stable and is
the address of the App's page: `link`, `<org>-controller`,
`<org>-runners-<tier>`, or the catalogue id, which wins a collision and
moves the preset aside behind a `-preset` suffix. `purpose` is `APP_PURPOSE_LINK`,
`_CONTROLLER`, `_RUNNERS` or `_TOKENS`, `origin` `APP_ORIGIN_PRESET` or
`_CATALOGUE`, `state` `APP_STATE_NOT_CREATED`, `_CREATED`, `_INSTALLED`
or `_DRIFTED`, and `attention` `APP_ATTENTION_DONE`, `_NEEDS_YOU`,
`_WAITING_PERSON` or `_WAITING_CONTROLLER`, with the exact state in
`state_detail`. Every App
is checked against its declaration, the presets' taken from the manifest
builder that creates them; the link App is the exception, because it is
used by being authorized rather than as the App and this service keeps no
App key for it — it says so in `reason` and claims no match. `secret` and
`secret_keys` are where the key is kept, empty where the deployment keeps
no state in Kubernetes.

**The link flows** are at the origin root too. `GET
/connect/github/link-app/callback` after the owner creates the link App
keeps its client id and secret. `GET /connect/github/link` is the page a
person starts from: it sets its own flow cookie and links to GitHub's
authorize page. `GET /connect/github/link/callback` redeems the code,
reads the account and its verified addresses, keeps a link for each
address the directory has live and vouches for, and says on the page what
it linked and why anything was not. None of the three needs a session.

**The two GitHub redirects** land at the origin root beside a directory's
consent callback: `GET /connect/github/callback` after Create, which
exchanges the one-time code for the App's key and sends the browser on
to Install under a fresh state; and `GET /connect/github/setup` after
Install, which asks GitHub — as the App — where it is installed, and
ignores the installation id the redirect claims. Both check the flow
cookie against a state signed by this service that names the organisation
and the operator who pressed Connect, and every failure is a page with a
4xx and GitHub's own words. A runner App's two are `GET
/connect/github/runner/callback` and `GET /connect/github/runner/setup`,
the same shape under a state that names the tier as well; a catalogue
App's are `GET /connect/github/catalogue/callback` and `GET
/connect/github/catalogue/setup`, under a state that names its id.

The report is the ConfigMap `<release>-github-status` in the service's
namespace, one key per organisation (`<login>.json`), each a versioned
document. The service creates it; the controller only replaces its data,
which is what lets the controller's Role name that one object.
`reports_available` is false only for a deployment keeping no state in
Kubernetes.

## `directoryroster.v1.SlackService`

The console's view of the Slack workspaces the policy declares, and the calls
that operate a connection. The controller acts; this shows and operates the
connection. See [connect/slack-workspace.md](../connect/slack-workspace.md).

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `GetSlackStatus` | viewer, installation-wide or over the directory that owns the workspace | — | `reports_available`, `connecting_available`, `bot_scopes[]`, `redirect_url`, `owner_choices[]`, `may_connect_without_owner`, `workspaces[]{workspace, team_id, owner, owner_domain, connection_state, connection{app_id, app_settings_url, bot_user_id, granted_scopes[], connected_at, connected_by}, can_operate, can_change_owner, declared, reported, acting, tick{at, outcome, error, changes, held, retrying, waiting}, channels[], leavers[]{email, user_id, channels[], reason}, breaker{affected, total, fingerprint, confirmed}, removal_confirmation{fingerprint, confirmed_by, confirmed_at}, needs_configuration_token, missing_scopes[], pass_requested_at}` | `connection_state` is `not_connected`, `created`, `installed` or `scopes_missing`. `tick.outcome` is `in-sync`, `applied`, `dry-run`, `held`, `retrying`, `waiting` or `failed`. A channel is `{name, id, private, mode, shared, host, state, reason, members[], breaker, removal_confirmation, console, sources[]}`: `state` is `ok`, `will-create`, `will-adopt`, `will-accept`, `waiting` or `held`; `console` marks an ordinary channel managed from the console; `sources` are the internal groups of a channel defined in git. A member is `{person, email, user_id, state, action, reason}`: state `ok`, `will-invite`, `will-remove`, `held`, `retrying`, `reported` or `ignored`; action `create`, `adopt`, `invite`, `remove`, `share-invite` or `share-accept`. A scoped viewer sees only the workspaces its directory owns; a workspace nobody has connected is shown to anyone who could connect it, and one the policy no longer declares but that is still connected has `declared` false. Never a client secret or a bot token |
| `BeginSlackWorkspaceConnect` | operator (see Notes) | `workspace`, `configuration_token?`, `owner?` | `url` | creates the roster's Slack App from its manifest with the pasted app configuration token (used for one call, neither stored nor logged), or prepares a reinstall, and returns Slack's authorize URL carrying signed state; the response sets a cookie pinning the flow to this browser. Not yet connected: the installation-wide operator (who chooses the owning directory or none) or an operator of one or more directories (whose directory becomes the owner; `owner` is required to choose among several). Afterwards: the operator of the recorded owner or the installation-wide operator; the owner never changes here. The configuration token is required to create the App and, afterwards, only when the scopes the roster asks for have grown |
| `RequestSlackPass` | operator of the owner, or installation-wide | `workspace` | `requested_at` | Refresh: leaves a `_pass.<workspace>.json` marker the controller notices at its next look (every 30 seconds). `resource_exhausted` while the workspace's last request is under a minute old. No audit action; the requester is logged |
| `ChangeSlackWorkspaceOwner` | installation-wide operator | `workspace`, `owner` | — | records another connected directory as the owner, or none when `owner` is empty. Audited as `roster.slack_workspace.owner_changed` |
| `DisconnectSlackWorkspace` | operator of the owner, or installation-wide | `workspace`, `forget_anyway?` | `revoked` | revokes the bot token at Slack and forgets the connection. `forget_anyway` forgets it even when Slack would not revoke (the token then stays valid in Slack until the App is deleted there, and the audit record says so). The App itself is deleted in Slack by its owner. Console channel and Slack Connect records are left in place |
| `ConfirmSlackRemovals` | operator | `workspace`, `channel?`, `fingerprint` | — | lets the removal set the latest report names go ahead: the fingerprint must be the report's for that gate (empty `channel` is the workspace-wide breaker). One confirmation satisfies every gate that fingerprint covers; it lapses after a day |

## `directoryroster.v1.SlackChannelService`

Ordinary Slack channels managed on the console, called **console channels**:
one workspace, members from the DIRECTORY groups, and individual addresses, of
the directory that owns the workspace. They live beside the policy's own
channels (fed by internal groups) and never overlap them: a channel the policy
binds is refused as *this channel is defined in git*.

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `ListSlackChannels` | viewer of the workspace's owner | — | `available`, `channels[]{channel{workspace, name, channel_id, private, mode, ignore[], sources[], members[]}, state, reason, can_operate, created_by, created_at, updated_by, updated_at}`, `workspaces[]{key, can_operate, owner, discovered_more}`, `discovered[]{workspace, channel_id, name, private, members, can_manage}`, `source_directories[]{workspace_id, domains[], groups[]{email, members}}` | `state` is `not_reported`, `pending` (the controller will create or adopt it), `active`, `held` or `invalid`. `discovered` is every channel the workspaces' bots can see that no policy binding and no record manages, capped per workspace (`discovered_more` counts the rest) |
| `CreateSlackChannel` | operator of the workspace's owner, or installation-wide | `channel{…}` | `channel` | validates and keeps the record `_channel.<workspace>.<name>.json`. At least one of `sources` (directory groups of the owning directory) and `members` (individual addresses, each an active user of the owning directory) is required; a group typed as a person, a person typed as a group, a repeat, and an address outside the directory are refused. `mode` is `extend` (default) or `strict`; strict needs a private channel. Audited as `roster.slack_console_channel.created` |
| `UpdateSlackChannel` | same | `channel{…}` | `channel` | changes `mode`, `ignore`, `sources` and `members`; `workspace`, `name`, `channel_id` and `private` are immutable. Audited as `roster.slack_console_channel.updated` |
| `DeleteSlackChannel` | same | `workspace`, `name`, `archive?` | `note`, `archived` | forgets the record: the channel stays in Slack and the reconciler stops managing its members. With `archive` it first checks, changing nothing: the workspace's latest report exists and says it acts, and Slack (`conversations.info`, with the workspace's bot token) says the channel is visible to the bot and not shared. `FailedPrecondition` for a dry-run workspace or none reported, a Slack Connect channel, a channel the bot cannot see or whose id is unknown; `Unavailable` when Slack does not answer; the record stays in every case. Then it deletes the record and calls `conversations.archive`, as the console and not as the controller (audited as `roster.slack_channel.archived`, with outcome failure when it fails); when that call fails the record is already deleted and `note` says to archive it by hand. Audited as `roster.slack_console_channel.deleted` |

## `directoryroster.v1.SlackSharedChannelService`

Slack Connect channels between the installation's own workspaces, as records
`_shared.<name>.json`: `name`, `host` (immutable), `with`, `from` (directory
groups of ANY connected directory; the wire name stays `from`), `members`
(individual addresses, each an active user of any connected directory),
`private` or `private_per_side`, and optionally `channel_id` for an existing
channel.

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `ListSlackSharedChannels` | viewer of the host or any `with` workspace | — | `available`, `channels[]{channel, state, reason, can_operate}`, `workspaces[]{key, can_operate, owner}`, `source_directories[]{workspace_id, domains[], groups[]{email, members}}`, `discovered[]{channel_id, host_workspace, host_team, sides[]{workspace, name, privacy, members, seen, listed}, external_teams, managed, managed_as, can_manage}` | `state` is `not_reported`, `pending`, `waiting` (for a guest to accept), `active`, `held` or `invalid`. A side's `privacy` is `public`, `private` or `unknown`; `listed=false` means nothing places the channel in that workspace, so it is unknown, not "not shared" |
| `CreateSlackSharedChannel` | operator of the HOST workspace's owner, or installation-wide | `channel{…}` | `channel` | validates against the policy and the directories and keeps the record; refuses a name already a record, and a channel the policy or a console channel record already defines. At least one of `from` and `members`. Audited as `roster.slack_shared_channel.created` |
| `UpdateSlackSharedChannel` | same | `channel{…}` | `channel` | changes `with`, `from`, `members` and `private` / `private_per_side`; a different `host`, `name` or `channel_id` is refused (create a new channel instead). Audited as `roster.slack_shared_channel.updated` |
| `DeleteSlackSharedChannel` | same | `name` | `note` | forgets the record and nothing else: the channel stays in Slack. Slack Connect channels are never archived from the console. Audited as `roster.slack_shared_channel.deleted` |

## `directoryroster.v1.SlackAppService`

The catalogue of Slack Apps (`slackApps`), mirroring the GitHub App catalogue.
See [connect/slack-apps-catalogue.md](../connect/slack-apps-catalogue.md).

| RPC | Role | Request | Response | Notes |
|---|---|---|---|---|
| `ListSlackApps` | viewer of the installation or of the directory that owns the Slack workspace | — | `available`, `apps[]{id, workspace, team_id, name, description, bot_scopes[], state, declared, app_id, app_settings_url, installed_team_id, installed_team_name, bot_user_id, granted_scopes[], missing_scopes[], created_at, created_by, installed_at, installed_by, needs_configuration_token, can_operate}` | every declared App and every App created from an entry no longer declared, each with where it stands: `state` is `declared`, `created`, `installed` or `scopes_missing`. Never a client secret or a bot token |
| `CreateSlackApp` | operator of the workspace's owner, or installation-wide | `id`, `configuration_token` | `app` | creates the App from the entry's manifest and keeps its client id and secret as "created, not installed". The workspace must already be connected (*connect the workspace first*). Audited as `roster.slack_app.created` |
| `InstallSlackApp` | operator of the workspace's owner, or installation-wide | `id`, `configuration_token?` | `url` | starts an install, or a reinstall of an App whose granted scopes lack declared ones (only then is a configuration token needed, used once and never stored); sets the flow cookie. Audited as `roster.slack_app.installed` or `.install_refused` |

**The Slack redirects** land at the origin root: `GET
/connect/slack/workspace/callback` after a workspace's install and `GET
/connect/slack/catalogue/callback` after a catalogue App's. Both check the flow
cookie against a state signed by this service that names the workspace (or the
App) and the operator who pressed Connect, and ask the role question again for
whoever is signed in then. A refused callback is a 4xx page, is logged (values
through `logsafe`; never the code, a token or a secret) and is audited with its
reason.

The report is the ConfigMap `<release>-slack-status`, one key per workspace,
each a versioned document; the service creates it and the controller only
replaces its data.

## The audit trail

Not a service of this one. access-roster records into an audit
installation ([truvity/audit](https://github.com/truvity/audit)) through its
contracts: it registers its catalogue with the installation's
`audit.v1.RegistryService` at start, and sends records to its
`audit.v1.SinkService`, each with the process's own projected
service-account token. The console's Audit page reads the installation's
`audit.v1.QueryService`, forwarded by the console under `<mount>/audit/`
with a token minted for the person signed in; only that service's methods
pass, and only for somebody signed in. See
[operations/runbook.md](../operations/runbook.md#audit-what-happened-lately).
The actions and what each carries are the catalogue,
[`internal/audit/catalogue/roster.yaml`](../../internal/audit/catalogue/roster.yaml)
(version 1.5.0, with the `roster.slack_*` actions). The GitHub and Slack
controllers record for themselves, each with its own service-account token.

## Installation tokens at `/token`

Not a console service: the issuer's token endpoint, documented here
because it is the contract a job, a script or `accessctl` codes against
when it asks for a GitHub App installation token of a
[catalogue App](../connect/github-apps-catalogue.md#minting-a-token). It
is RFC 8693 token exchange on the same `/token` as every other exchange;
a request is an installation token's when **both**
`requested_token_type` is the type below **and** `audience` starts
`github-app:`. Anything else is an ordinary exchange, handled exactly as
before.

**Request** — `POST /token`, `application/x-www-form-urlencoded`:

| Parameter | Value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `requested_token_type` | `urn:access-roster:params:oauth:token-type:github-installation-token` (Go: `tokens.TypeGitHubInstallationToken`) |
| `audience` | `github-app:<catalogue id>`, exactly one |
| `subject_token` | a GitHub Actions identity token minted for the issuer's URL, a federated cluster's ServiceAccount token, or a sign-in's access token |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:jwt` for the first two, `urn:ietf:params:oauth:token-type:access_token` for a sign-in |
| `repositories` | optional: repository names in the App's organisation, without the owner, space separated; at most 500 |
| `scope` | optional: permissions as `name:level`, space separated, e.g. `contents:read pull_requests:write` |
| `actor_token` | refused: delegation is not served |

**Client.** HTTP Basic, form-encoded as RFC 6749 §2.3.1 requires. A job
presents the audience itself (`github-app%3A<id>` with an empty
password), or nothing; any other client id is authenticated as the
issuer's clients are, and a sign-in is a proof only when presented by the
client it was issued to, which declares `sign_in_exchange: true`.

**Response** — `200`, `Cache-Control: no-store`:

```json
{
  "access_token": "ghs_…",
  "issued_token_type": "urn:access-roster:params:oauth:token-type:github-installation-token",
  "token_type": "N_A",
  "expires_in": 3599,
  "repositories": ["app", "lib-core"],
  "permissions": {"contents": "read", "pull_requests": "write"}
}
```

`access_token` is GitHub's installation token, used as GitHub documents
(`Authorization: Bearer`, or `x-access-token` as a git password).
`token_type` is `N_A` because it is not an OAuth access token of this
issuer. `expires_in` is from GitHub's `expires_at`. `repositories` and
`permissions` are what GitHub says the token carries, not what was asked
for; `repositories` is absent for a token not narrowed to any.

**Decision.** The proof resolves to groups exactly as for any exchange;
of the App's grants for those groups, in catalogue order, the first that
covers **all** of the request is chosen. Named repositories must all
match that one grant; no repositories requires a `["*"]` grant; named
permissions must each be covered by it; no permissions asks for exactly
its permissions. GitHub is sent that narrowing explicitly.

**Errors** — RFC 6749 JSON, `{"error": "...", "error_description": "..."}`:

| `error` | Status | When |
|---|---|---|
| `invalid_request` | 400 | malformed parameters, or `actor_token` |
| `invalid_client` | 401 | a presented client that is not the audience did not authenticate |
| `invalid_grant` | 400 | the subject token is not a proof |
| `invalid_target` | 400 | the App is not declared, not created, not installed or uninstalled; or no grant names a group the proof holds |
| `invalid_scope` | 400 | wider than any one grant the proof holds, or GitHub refused the narrowing (422) |
| `server_error` | 500 | GitHub or the App's key failed |

Every request, minted or refused, is one `roster.github_token.minted`
record ([fields](../connect/github-apps-catalogue.md#audit)); the token
is never in it. The same request is also kept in this service's own
memory, so that the App's page can show the last ten without narrowing
the trail to one App — `ListGitHubAppTokens` above.

## The whoami endpoint

`GET /.access/whoami` on the console's origin. The console's own answer
carries its roles and scopes beside the fields the Go module's
`identity.WhoAmI` serves (`status`, `email`, `name`, `givenName`,
`familyName`, `groups`, `version`):

```json
{
  "status": "signed-in",
  "email": "alice@example.com",
  "name": "Alice Ant",
  "givenName": "Alice",
  "familyName": "Ant",
  "roles": ["operator", "viewer"],
  "scopes": ["C0north"],
  "source": "session",
  "groups": ["prod:k8s:viewer", "all:access-roster:operator"],
  "version": "v1.8.0",
  "signOutUrl": "/logout",
  "issuerUrl": "https://access.example"
}
```

## Calling from a shell

```sh
# From a workload: its projected ServiceAccount token, minted for
# exchange.audience, is the bearer.
TOKEN=$(cat /var/run/secrets/access-roster/token)

# WhoAmI, over GET (Connect's idempotent-GET encoding)
curl -s -H "authorization: Bearer $TOKEN" \
  'http://access-issuer.access-issuer.svc:8080/console/directoryroster.v1.AccessService/WhoAmI?encoding=json&message=%7B%7D'

# ListHolders, over POST
curl -s -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"group":"prod:k8s:viewer"}' \
  http://access-issuer.access-issuer.svc:8080/console/directoryroster.v1.AccessService/ListHolders
```
