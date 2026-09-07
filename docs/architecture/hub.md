# Architecture

The hub in four views, from the outside in. The static views follow the
C4 model (context, containers, components) and are drawn as Mermaid
flowcharts with C4 styling — Mermaid's native C4 renderer overlaps labels
— so GitHub renders them inline. The design rationale is
[../design/hub.md](../design/hub.md); the contracts are
[../reference/contracts.md](../reference/contracts.md).

## 1. System context

Who talks to the hub, and what the hub talks to. Consumers hold no
directory credential; the hub holds all of them.

```mermaid
flowchart TB
  operator["Operator<br/>[Person]<br/>connects and watches workspaces,<br/>grants roles"]:::person
  admin["Directory admin<br/>[Person]<br/>a role account of one tenant,<br/>consents once"]:::person

  hub["directory-roster<br/>[Software System]<br/>is this account live, who is in this group,<br/>for every connected directory, routed by email domain,<br/>with a per-domain authoritative flag"]:::system

  rolesrc["Whatever computes roles at login<br/>[Software System]<br/>an IdP's login hook today,<br/>the token service later"]:::system
  teamsync["Team-sync service<br/>[Software System]<br/>keeps a code-hosting org's teams<br/>equal to directory groups"]:::system

  gateway["Authenticating gateway<br/>[External, optional]<br/>one proxy in front of every console,<br/>forwards the caller's token"]:::ext
  google["Google Workspace<br/>[External]<br/>Admin SDK: users, groups, members, domains<br/>OIDC: sign-in for the hub's own operators"]:::ext
  entra["Microsoft Entra<br/>[External, next]<br/>same record, same contracts"]:::ext

  operator -- "own login: sign in with the directory<br/>[HTTPS]" --> hub
  operator -. "or through a gateway<br/>[HTTPS]" .-> gateway
  gateway -. "forwarded bearer<br/>[HTTP]" .-> hub
  admin -. "consents to the hub's OAuth client<br/>[browser]" .-> google
  rolesrc -- "ResolveUser<br/>[ConnectRPC, SA token]" --> hub
  teamsync -- "GetGroup, ListGroups, ResolveAccounts<br/>[ConnectRPC, SA token]" --> hub
  hub -- "reads users, groups, members, domains<br/>[Admin SDK, read-only scopes]" --> google
  hub -- "verifies operator sign-ins<br/>[OIDC, openid scopes]" --> google
  hub -. "later<br/>[Graph, read-only]" .-> entra

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#999999,stroke:#6b6b6b,color:#fff
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  classDef store fill:#438dd5,stroke:#2e6295,color:#fff
```

## 2. Containers

One process, two listeners, two stores, in a namespace of its own.

```mermaid
flowchart TB
  operator["Operator<br/>[Person]"]:::person
  gateway["Authenticating gateway<br/>[External, optional]"]:::ext
  consumers["Consumers<br/>[Software Systems]<br/>role computation at login, team-sync service"]:::system
  kapi["Kubernetes API server<br/>[External]<br/>TokenReview"]:::ext
  google["Google Workspace<br/>[External]<br/>Admin SDK + OIDC sign-in"]:::ext

  subgraph ns["namespace: directory-roster"]
    direction TB
    hub["hub<br/>[Container: Go, ConnectRPC]<br/>API listener: DirectoryService<br/>console listener: Workspaces, Settings, Access, login routes, SPA<br/>refresher, prober, router by domain"]:::container
    spa["console<br/>[Container: React SPA, served by the hub]<br/>Workspaces, Settings, Access views"]:::container
    k8s[("Kubernetes API, this namespace<br/>[Secrets + ConfigMaps]<br/>workspace records, credentials, OAuth client,<br/>session key, admin password, console rules,<br/>written by the hub")]:::store
    valkey[("Valkey<br/>[external to the chart]<br/>one snapshot per workspace,<br/>refresh locks, negative cache,<br/>never a credential")]:::store
  end

  operator -- "own login<br/>[HTTPS]" --> hub
  operator -. "[HTTPS]" .-> gateway
  gateway -. "console listener :8081<br/>[forwarded bearer]" .-> hub
  consumers -- "API listener :8080<br/>[ConnectRPC, SA token]" --> hub
  hub -- "[TokenReview]" --> kapi
  hub -- "serves<br/>[same origin]" --> spa
  hub -- "get / watch / write<br/>[namespaced Role]" --> k8s
  hub -- "snapshots, locks<br/>[RESP]" --> valkey
  hub -- "reads · verifies sign-ins<br/>[Admin SDK, OIDC]" --> google

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#999999,stroke:#6b6b6b,color:#fff
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  classDef store fill:#438dd5,stroke:#2e6295,color:#fff
  style ns fill:none,stroke:#444,stroke-dasharray:5 5
```

The two listeners are the privilege boundary: a consumer on the cluster
network can reach `DirectoryService` and nothing else, and only with an
allow-listed ServiceAccount token; an operator RPC exists only on the
console port, behind the hub's own session. NetworkPolicy enforces both
as the second layer. The family-level picture, with the token service
and the relying parties, is [access-roster.md](access-roster.md).

## 3. Components

Inside the hub process.

```mermaid
flowchart TB
  subgraph hub["hub [Container]"]
    direction TB
    dirapi["DirectoryService handlers<br/>[connect-go]<br/>Describe, Probe, GetGroup, ListGroups,<br/>GetAccount, ResolveAccounts, ResolveUser"]:::component
    consauth["Consumer authentication<br/>[TokenReview]<br/>SA token, audience, allow-list"]:::component
    opapi["Operator handlers<br/>[connect-go]<br/>WorkspaceService, SettingsService,<br/>AccessService, role gate from the session"]:::component
    access["Access<br/>[login routes, session, rules]<br/>sign in with the directory / an issuer /<br/>a forwarded bearer / admin, rules to roles"]:::component
    connect["Connect flow<br/>[HTTP]<br/>BeginConnect and callback: state cookie,<br/>code exchange, tenant + domain discovery, first probe"]:::component
    router["Router<br/>[domain → workspace]<br/>email domain to the workspace serving it,<br/>conflict detection, authoritative per domain"]:::component
    fresh["Freshness<br/>[max_age policy]<br/>serve / refresh single-flight /<br/>point read live / miss goes live once"]:::component
    refresher["Refresher + prober<br/>[background loops]<br/>new snapshot every refresh interval,<br/>probe + domain re-read every probe interval,<br/>shared lock"]:::component
    wsstore[("Workspace store<br/>[Kubernetes]<br/>records in ConfigMaps, credentials in Secrets,<br/>overlay merged read-only, console rules")]:::component
    backend["Backend: Google<br/>[Admin SDK client + OIDC verifier]<br/>users.list, groups.list, members.list (atomic per group),<br/>domains.list, token from refresh token or SA key"]:::component
    snap[("Snapshot store<br/>[Valkey or memory]<br/>per-workspace snapshot, snapshot_at,<br/>negative cache")]:::component
  end

  consauth -- "admits" --> dirapi
  access -- "identity + role" --> opapi
  access -- "is the account live, in the group" --> router
  opapi -- "BeginConnect" --> connect
  opapi -- "list / upsert / delete, rules" --> wsstore
  connect -- "store credential + record" --> wsstore
  connect -- "exchange code, discover" --> backend
  dirapi -- "which workspace" --> router
  dirapi -- "how fresh" --> fresh
  router -- "domain claims" --> wsstore
  refresher -- "health, domains" --> wsstore
  refresher -- "full read, probe" --> backend
  refresher -- "replace" --> snap
  fresh -- "full read or point read" --> backend
  fresh -- "read / replace" --> snap

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#999999,stroke:#6b6b6b,color:#fff
  classDef container fill:#438dd5,stroke:#2e6295,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  classDef store fill:#438dd5,stroke:#2e6295,color:#fff
  style hub fill:none,stroke:#444,stroke-dasharray:5 5
```

## 4. Dynamics

The hub's own sign-in and the day-one sequence are drawn in
[access-roster.md](access-roster.md); here, the two flows that are the
hub's alone.

### Connecting a workspace by admin consent

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operator (browser, signed in)
  participant Hub as hub (console listener)
  participant G as Google (OAuth + Admin SDK)
  participant K as Kubernetes Secrets/ConfigMaps

  Op->>Hub: Connect Google Workspace
  Hub->>Hub: session → operator role (rules)
  Hub-->>Op: consent URL + state cookie
  Op->>G: consent screen, signed in as the tenant's admin role account
  G-->>Op: redirect to /connect/google/callback with code and state
  Op->>Hub: callback (same session)
  Hub->>Hub: verify state cookie
  Hub->>G: exchange code → refresh token (offline, forced consent)
  Hub->>G: customers.get → tenant id, domains.list → domains
  Hub->>G: first probe (users.list page, groups.list page)
  Hub->>K: Secret workspace-{id} (refresh token), ConfigMap workspace-{id} (record)
  Hub-->>Op: Workspaces view: domains served, authoritative after the first snapshot
  Note over Op,Hub: behind a gateway the session is minted from the forwarded bearer on the first request, nothing else changes
```

### A login-time lookup with freshness

```mermaid
sequenceDiagram
  autonumber
  participant W as Role computation at login (SA token)
  participant Hub as hub (API listener)
  participant V as Valkey (snapshot)
  participant G as Google Admin SDK

  W->>Hub: ResolveUser(email, max_age=10m)
  Hub->>Hub: domain(email) → workspace, authoritative?
  Hub->>V: snapshot(workspace)
  alt snapshot younger than max_age and account present
    Hub-->>W: groups, suspended, authoritative, snapshot_at
  else snapshot older than max_age, or account missing
    Note over Hub,G: point call - read ONE account live, never a full refresh
    Hub->>G: users.get(email), groups.list(userKey=email)
    alt live read ok
      Hub->>V: patch snapshot entry
      Hub-->>W: fresh answer, authoritative, snapshot_at=now
    else live read fails
      Hub-->>W: stale answer, authoritative=false (a hold, never a removal)
    end
  end
```

### The background loops

```mermaid
sequenceDiagram
  autonumber
  participant R as Refresher (one replica holds the lock)
  participant V as Valkey
  participant G as Google Admin SDK
  participant K as Kubernetes ConfigMaps

  loop every refresh interval, per workspace
    R->>V: SET NX lock:{workspace}
    R->>G: users.list, groups.list, members.list per group (atomic per group)
    alt every page ok
      R->>V: replace snapshot({workspace}), snapshot_at=now
    else any page failed
      Note over R,V: keep the old snapshot - domains turn non-authoritative once it ages past the freshness window
    end
    R->>V: DEL lock
  end
  loop every probe interval, per workspace
    R->>G: token check + domains.list
    R->>K: health, domains on the workspace record
  end
```

## 5. Failure semantics, in one table

| Situation | What consumers see |
|---|---|
| Probe failed, snapshot still young | answers from the snapshot, `authoritative=false` |
| Snapshot older than the freshness window | same |
| Full refresh failed a page | old snapshot kept; nothing partial is ever served |
| Domain claimed by two workspaces | `authoritative=false` for that domain on both |
| Address in no served domain | `in_domain=false`: no opinion |
| Account missing from the snapshot | one live read first; `found=false` only after the backend said so |
| Valkey unreachable | every domain non-authoritative until it returns; the in-memory fallback is for a single replica only |
| Credential revoked or admin suspended | probe fails → non-authoritative; Reconnect is the recovery |
| A signed-in operator's own account turns non-authoritative | last granted role kept for a bounded window; no new identity granted anything |
| Consumer presents no token, a wrong audience, or a foreign ServiceAccount | `unauthenticated`; NetworkPolicy would have stopped most of these earlier |

The rule under all of them: **a consumer removes access only on an
authoritative answer.** Everything that can go wrong on the hub's side
degrades to "hold", never to "gone".
