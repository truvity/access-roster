# directory-roster — the directory hub

**Status:** accepted 2026-09-06. Successor to
[google-group-sync](https://github.com/truvity/google-group-sync), which is
archived once its consumers have moved.

## Purpose

One deployment that answers, for every corporate directory an installation
owns, two questions: **is this account live**, and **who is in this group**.
It holds every directory credential so that its consumers hold none. Today
the backend is Google Workspace; Microsoft Entra is the next backend behind
the same record and the same contracts.

Consumers reach it over the cluster network: a login-time authorization
webhook (groups → roles) and
[github-roster](https://github.com/truvity/github-roster) (groups → GitHub
teams) are the two it was built for. Only the console goes through the
gateway.

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

- **`DirectoryService`** (ConnectRPC) — unchanged from google-group-sync:
  `Describe`, `Probe`, `GetGroup`, `ListGroups`, `GetAccount`,
  `ResolveAccounts`, `ResolveUser`. `Describe` now lists every served domain
  with its authoritative flag and workspace.
- **REST** — unchanged from google-group-sync (`/users/{email}/groups`,
  `/groups`, `/groups/{email}`, `/health`), routed by domain, so the
  authorization webhook moves by changing one URL.
- **`WorkspaceService`** (ConnectRPC, operator-gated) — `ListWorkspaces`,
  `BeginConnect` (returns the consent URL), `UploadKey`, `Probe`,
  `Reconnect`, `Disconnect`.
- **`SettingsService`** — the OAuth client (id, secret), the freshness
  window, cache settings.

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
   `https://<hub host>/connect/google/callback`.
5. Paste the client id and secret into the hub's Settings once. Nothing else
   reads them.

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

Kubernetes objects in the hub's own namespace; no cloud dependency.

| Object | Holds |
|---|---|
| `Secret workspace-<id>` | the credential (refresh token, or service-account key) |
| `ConfigMap workspace-<id>` | backend, domains, admin, connectedBy/At, last health |
| `Secret hub-oauth-client` | the OAuth client id and secret |
| `ConfigMap hub-settings` | freshness window, probe interval, cache |
| chart-rendered overlay | workspaces declared by the deployment (a key delivered as a Secret, domains listed), read-only in the console, winning on conflict |

The overlay is how an existing installation moves without a Connect step:
its service-account keys are declared, the hub serves them on day one, and
the operator connects through consent later, at which point the declared
workspace is removed from the overlay.

The ServiceAccount holds a namespaced Role on ConfigMaps and Secrets, which
is why the hub has a namespace of its own. Encryption at rest and backup are
the cluster's; the deployment may mirror the Secrets off-cluster (an ESO
`PushSecret`); the export is `kubectl get -o yaml`.

## The console

Built on the shared fleet console stack (gateway-auth library, Vite, MUI,
Connect-Web): a Workspaces view (each with domains, health, authoritative
state, Connect / Reconnect / Disconnect), and Settings (the OAuth client).
Roles `viewer` and `operator` from the groups claim. Nothing about
authentication is editable from the UI.

## Failure semantics

- A failed probe makes a workspace's domains non-authoritative; the last
  known good snapshot is still served, marked stale.
- A domain served by no workspace is "no opinion", never absent.
- A domain claimed by two workspaces is authoritative for neither.
- Group reads are atomic per group — a page failure fails the group, never
  a silent partial.

## What is not carried from google-group-sync

The Lambda and Lambda-extension flavours (single-workspace by construction),
the one-workspace-per-process configuration, and the environment-variable
credential path (replaced by the overlay).

## Build

1. Workspace model, Kubernetes store, overlay.
2. Routing by domain, per-domain authoritative flag, domain discovery,
   probes.
3. `WorkspaceService`, the consent flow, key upload, `SettingsService`.
4. The console.
5. Documentation: architecture, the Connect runbook, the migration note
   from google-group-sync.

Entra is the first change after 1.0: a second backend behind the same
workspace record, with its own consent flow.
