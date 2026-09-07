# Architecture

The hub in four views, from the outside in. The diagrams are C4 in
Mermaid; GitHub renders them inline. The design rationale is
[../design/hub.md](../design/hub.md); the contracts are
[../reference/contracts.md](../reference/contracts.md).

## 1. System context

Who talks to the hub, and what the hub talks to. Consumers hold no
directory credential; the hub holds all of them.

```mermaid
C4Context
  title System context — the directory hub

  Person(operator, "Operator", "Connects and watches workspaces through the console")
  Person(admin, "Directory admin", "A role account of one tenant; consents once")

  System(hub, "directory-roster", "Answers 'is this account live' and 'who is in this group' for every connected directory, routed by email domain, with a per-domain authoritative flag")

  System(webhook, "Authorization webhook", "At login: groups → roles. Calls ResolveUser")
  System(teamsync, "Team-sync service", "Keeps a code-hosting org's teams equal to directory groups. Calls GetGroup, ListGroups, ResolveAccounts")
  System_Ext(google, "Google Workspace", "Admin SDK Directory API — users, groups, members, domains (read-only)")
  System_Ext(entra, "Microsoft Entra", "Next backend; same record, same contracts")
  System_Ext(gateway, "Gateway + authentication", "Terminates TLS, runs the login, forwards identity and roles")

  Rel(operator, gateway, "console", "HTTPS")
  Rel(gateway, hub, "console listener", "HTTP + identity headers")
  Rel(admin, google, "consents to the hub's OAuth client", "browser")
  Rel(hub, google, "reads users, groups, members, domains", "Admin SDK, read-only scopes")
  Rel(hub, entra, "later", "Graph, read-only")
  Rel(webhook, hub, "ResolveUser", "ConnectRPC, cluster network")
  Rel(teamsync, hub, "GetGroup / ListGroups / ResolveAccounts", "ConnectRPC, cluster network")

  UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

## 2. Containers

One process, two listeners, two stores, in a namespace of its own.

```mermaid
C4Container
  title Containers — the hub namespace

  Person(operator, "Operator")
  System_Ext(gateway, "Gateway + authentication")
  System_Ext(google, "Google Workspace", "Admin SDK")
  System(consumers, "Consumers", "authorization webhook, team-sync service")

  Container_Boundary(ns, "namespace: directory-roster") {
    Container(hub, "hub", "Go, ConnectRPC", "API listener (DirectoryService) and console listener (WorkspaceService, SettingsService, SPA). Refresher, prober, router by domain")
    Container(spa, "console", "React SPA, served by the hub", "Workspaces and Settings views; Connect / Reconnect / Disconnect")
    ContainerDb(k8s, "Kubernetes API (this namespace)", "Secrets + ConfigMaps", "workspace records, credentials, the OAuth client, the state key. Written by the hub")
    ContainerDb(valkey, "Valkey", "external to the chart", "one snapshot per workspace, refresh locks, negative cache. Never a credential")
  }

  Rel(operator, gateway, "HTTPS")
  Rel(gateway, hub, "console listener :8081", "HTTP, identity headers")
  Rel(hub, spa, "serves", "same origin")
  Rel(consumers, hub, "API listener :8080", "ConnectRPC")
  Rel(hub, k8s, "get / watch / write", "namespaced Role")
  Rel(hub, valkey, "snapshots, locks", "RESP")
  Rel(hub, google, "reads", "Admin SDK, read-only")

  UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

The two listeners are the privilege boundary: a consumer on the cluster
network can reach `DirectoryService` and nothing else; an operator RPC
exists only on the port the gateway forwards to. NetworkPolicy enforces
both.

## 3. Components

Inside the hub process.

```mermaid
C4Component
  title Components — inside the hub

  Container_Boundary(hub, "hub") {
    Component(dirapi, "DirectoryService handlers", "connect-go", "Describe, Probe, GetGroup, ListGroups, GetAccount, ResolveAccounts, ResolveUser")
    Component(opapi, "Operator handlers", "connect-go", "WorkspaceService, SettingsService; role gate from identity headers")
    Component(connect, "Connect flow", "HTTP", "BeginConnect / callback: state cookie, code exchange, tenant + domain discovery, first probe")
    Component(router, "Router", "domain → workspace", "email domain to the workspace serving it; conflict detection; authoritative per domain")
    Component(fresh, "Freshness", "max_age policy", "serve / refresh single-flight / point read live / miss goes live once")
    Component(refresher, "Refresher + prober", "background loops", "new snapshot every refresh interval; probe + domain re-read every probe interval; shared lock")
    Component(snap, "Snapshot store", "Valkey or memory", "per-workspace snapshot, snapshot_at, negative cache")
    Component(wsstore, "Workspace store", "Kubernetes", "records in ConfigMaps, credentials in Secrets; overlay merged read-only")
    Component(backend, "Backend: Google", "Admin SDK client", "users.list, groups.list, members.list (atomic per group), domains.list; token from refresh token or SA key")
  }

  Rel(dirapi, router, "which workspace")
  Rel(dirapi, fresh, "how fresh")
  Rel(fresh, snap, "read / replace")
  Rel(fresh, backend, "full read or point read")
  Rel(refresher, backend, "full read, probe")
  Rel(refresher, snap, "replace")
  Rel(refresher, wsstore, "health, domains")
  Rel(opapi, wsstore, "list / upsert / delete")
  Rel(opapi, connect, "BeginConnect")
  Rel(connect, backend, "exchange code, discover")
  Rel(connect, wsstore, "store credential + record")
  Rel(router, wsstore, "domain claims")

  UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

## 4. Dynamics

### Connecting a workspace by admin consent

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operator (browser)
  participant GW as Gateway + auth
  participant Hub as hub (console listener)
  participant G as Google (OAuth + Admin SDK)
  participant K as Kubernetes Secrets/ConfigMaps

  Op->>GW: Connect Google Workspace
  GW->>Hub: BeginConnect (identity headers: operator)
  Hub-->>Op: consent URL + state cookie
  Op->>G: consent screen, signed in as the tenant's admin role account
  G-->>Op: redirect /connect/google/callback?code&state
  Op->>GW: callback
  GW->>Hub: callback (still authenticated)
  Hub->>Hub: verify state cookie
  Hub->>G: exchange code → refresh token (offline, forced consent)
  Hub->>G: customers.get → tenant id; domains.list → domains
  Hub->>G: first probe (users.list page, groups.list page)
  Hub->>K: Secret workspace-<id> (refresh token), ConfigMap workspace-<id> (record)
  Hub-->>Op: Workspaces view: domains served, authoritative after the first snapshot
```

### A login-time lookup with freshness

```mermaid
sequenceDiagram
  autonumber
  participant W as Authorization webhook
  participant Hub as hub (API listener)
  participant V as Valkey (snapshot)
  participant G as Google Admin SDK

  W->>Hub: ResolveUser(email, max_age=10m)
  Hub->>Hub: domain(email) → workspace, authoritative?
  Hub->>V: snapshot(workspace)
  alt snapshot younger than max_age and account present
    Hub-->>W: groups, suspended, authoritative, snapshot_at
  else snapshot older than max_age, or account missing
    Note over Hub,G: point call: read ONE account live, never a full refresh
    Hub->>G: users.get(email); groups.list(userKey=email)
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
    R->>V: SET NX lock:<workspace>
    R->>G: users.list, groups.list, members.list per group (atomic per group)
    alt every page ok
      R->>V: replace snapshot(<workspace>), snapshot_at=now
    else any page failed
      Note over R,V: keep the old snapshot; domains become non-authoritative once it ages past the freshness window
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

The rule under all of them: **a consumer removes access only on an
authoritative answer.** Everything that can go wrong on the hub's side
degrades to "hold", never to "gone".
