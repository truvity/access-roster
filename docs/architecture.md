# Architecture

One page for the whole family: the directory hub, the issuer that comes
after it, the proxy, the libraries and the CLI around them, the relying
parties, and the flows that have to work. Decisions and their reasons
live in the design documents ([hub](design/hub.md),
[issuer](design/access-issuer.md), [proxy](design/access-proxy.md),
[libraries](design/libraries.md), [CLI](design/accessctl.md)); the
contracts in [reference/](reference/). Diagrams
follow the C4 model and are drawn as Mermaid flowcharts, which GitHub
renders inline.

## How operators reach the hub — read this first

The hub's console is reached **the same way as every other console in
the installation: through the authenticating proxy that fronts them
all** — `access-proxy` — which forwards the caller's token from the
installation's issuer (access-issuer once it exists; whatever identity
provider the installation runs until then). The hub verifies that bearer and applies
its policy. That is the normal path, and it is the only path drawn
solid below.

The hub also carries its **own login page**, for exactly two situations:

- a **standalone installation** with no proxy and no issuer, where
  operators sign in with the connected directory itself;
- **break-glass**, the generated admin account, reached by port-forward,
  for day one and for the day the proxy or the issuer is what is broken.

It is drawn dotted, once, and it is never a third parallel path in an
installation that has a proxy.

## 1. Context

```mermaid
flowchart TB
  eng["Engineer / operator<br/>[Person]<br/>browser, kubectl, CLI"]:::person
  admin["Directory admin<br/>[Person]<br/>a role account of one tenant,<br/>consents once"]:::person
  ci["CI job<br/>[External workload]<br/>a signed identity token per run"]:::ext

  ts["access-issuer<br/>[Software System, later]<br/>verifies proofs, asks the hub,<br/>applies the policy, issues tokens"]:::token
  hub["directory-roster<br/>[Software System]<br/>who exists, who is live, who is in which group,<br/>per connected directory, with an authoritative flag"]:::hub
  teamsync["github-roster<br/>[Software System]<br/>directory groups → GitHub teams"]:::system

  proxy["access-proxy<br/>[chart, one per console]<br/>login, session, forwarded bearer,<br/>self-registered client"]:::token
  rp["Relying parties<br/>[External]<br/>Kubernetes API servers, cloud accounts,<br/>consoles behind the proxy"]:::ext
  idp["Corporate IdPs<br/>[External]<br/>Google Workspace tenants, Entra later<br/>sign-in and MFA live here"]:::ext

  eng -- "every console, the hub's included<br/>[HTTPS]" --> proxy
  proxy -- "login<br/>[OIDC]" --> ts
  proxy -- "forwarded bearer<br/>[HTTP]" --> hub
  proxy -- "forwarded bearer" --> rp
  eng -- "kubelogin, accessctl<br/>[OIDC, device flow, token exchange]" --> ts
  eng -. "standalone or break-glass only<br/>[own login]" .-> hub
  ci -- "the exchange action<br/>[RFC 8693]" --> ts
  ts -- "sign-in<br/>[OIDC]" --> idp
  ts -- "ResolveUser at login and refresh<br/>[ConnectRPC, SA token]" --> hub
  ts -. "trusted issuer<br/>[JWKS]" .-> rp
  teamsync -- "GetGroup, ListGroups, ResolveAccounts<br/>[ConnectRPC, SA token]" --> hub
  admin -. "consents to the hub's OAuth client<br/>[browser]" .-> idp
  hub -- "users, groups, members, domains<br/>[Admin SDK, read-only]" --> idp

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#999999,stroke:#6b6b6b,color:#fff
  classDef hub fill:#0E7C7B,stroke:#0A5958,color:#fff
  classDef hubStore fill:#5FA9A7,stroke:#0A5958,color:#fff
  classDef token fill:#4A4FB5,stroke:#33378A,color:#fff
  classDef tokenStore fill:#8A8DD1,stroke:#33378A,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
```

The hub sits behind exactly two callers, access-issuer and github-roster,
plus its own console. Applications read the forwarded bearer through the
Go module or the TypeScript package; they implement no login. Everything else reads claims from the
access-issuer and never sees the hub. Neither component has a database;
neither authenticates anyone.

## 2. Containers

```mermaid
flowchart TB
  eng["Engineer / operator<br/>[Person]"]:::person
  ci["CI job<br/>[External workload]"]:::ext
  proxy["access-proxy + sessions<br/>[chart, one per console, self-registered]"]:::token
  idp["Corporate IdPs<br/>[External]<br/>Admin SDK reads · OIDC sign-in"]:::ext
  kapi["Kubernetes API server<br/>[External]<br/>TokenReview"]:::ext

  subgraph nsTs["namespace: access-issuer (later)"]
    direction TB
    ts["access-issuer<br/>[Container: Go, OpenID Provider library]<br/>verifiers: corporate OIDC, workload OIDC, k8s SA<br/>policy engine · client registry · device flow"]:::token
    policyStore[("policy: groups · claims · lifetimes · clients<br/>[ConfigMaps from the deployment]<br/>self-registrations [own namespace]")]:::tokenStore
    keys[("signing keys<br/>[Secrets]")]:::tokenStore
    tsv[("Valkey<br/>[external to the chart]<br/>codes, refresh, device codes,<br/>last-known groups")]:::tokenStore
  end

  subgraph nsHub["namespace: directory-roster"]
    direction TB
    hub["directory-roster<br/>[Container: Go, ConnectRPC]<br/>API listener: DirectoryService<br/>console listener: Workspaces, Settings, Access, SPA, login routes<br/>refresher, prober, router by domain"]:::hub
    spa["console<br/>[Container: React SPA, served by the hub]<br/>Workspaces · Access · Effective access · Settings"]:::hub
    k8s[("workspace records + credentials<br/>[Secrets + ConfigMaps, this namespace]<br/>refresh tokens, SA keys, OAuth client,<br/>session key, admin password, console memberships")]:::hubStore
    hv[("Valkey<br/>[external to the chart]<br/>one snapshot per workspace, locks")]:::hubStore
  end

  subgraph rp["Relying parties — trust the issuer, read claims"]
    direction LR
    k8sapi["Kubernetes API servers<br/>[one per cluster]<br/>issuer + client id + groups claim"]:::ext
    cloud["Cloud accounts<br/>[IAM OIDC provider each]<br/>trust policy: aud = the role's audience"]:::ext
    consoles["Other consoles<br/>[behind the proxy]<br/>read the groups claim"]:::ext
    roster["github-roster<br/>[sibling service]"]:::ext
  end

  eng -- "[HTTPS]" --> proxy
  proxy -- "login, and self-registration at start<br/>[OIDC, RFC 7591 with SA token]" --> ts
  proxy -- "console listener :8081<br/>[forwarded bearer]" --> hub
  proxy --> consoles
  eng -. "standalone or break-glass<br/>[own login, :8081]" .-> hub
  eng -- "kubelogin, accessctl<br/>[OIDC]" --> ts
  ci -- "exchange action" --> ts
  ts -- "sign-in<br/>[OIDC]" --> idp
  ts -- "ResolveUser<br/>[ConnectRPC, SA token]" --> hub
  ts --> policyStore
  ts --> keys
  ts --> tsv
  ts -. "issuer trusted by<br/>[JWKS, client ids]" .-> rp
  hub -- "serves<br/>[same origin]" --> spa
  hub -- "[TokenReview]" --> kapi
  hub -- "get / watch / write<br/>[namespaced Role]" --> k8s
  hub -- "snapshots, locks<br/>[RESP]" --> hv
  hub -- "reads · verifies standalone sign-ins<br/>[Admin SDK, OIDC]" --> idp
  roster -- "API listener :8080<br/>[ConnectRPC, SA token]" --> hub

  classDef person fill:#08427b,stroke:#052e56,color:#fff
  classDef system fill:#1168bd,stroke:#0b4884,color:#fff
  classDef ext fill:#999999,stroke:#6b6b6b,color:#fff
  classDef hub fill:#0E7C7B,stroke:#0A5958,color:#fff
  classDef hubStore fill:#5FA9A7,stroke:#0A5958,color:#fff
  classDef token fill:#4A4FB5,stroke:#33378A,color:#fff
  classDef tokenStore fill:#8A8DD1,stroke:#33378A,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  style nsTs fill:none,stroke:#4A4FB5,stroke-dasharray:5 5
  style nsHub fill:none,stroke:#0E7C7B,stroke-dasharray:5 5
  style rp fill:none,stroke:#8A93A3,stroke-dasharray:5 5
```

The two hub listeners are the privilege boundary. The API listener admits
only allow-listed ServiceAccount tokens, verified by TokenReview, and
carries DirectoryService alone. The console listener carries the operator
services and the SPA behind the hub's session, which is minted from the
forwarded bearer on the first request or, standalone, by the hub's own
login. NetworkPolicy enforces both as the second layer.

## 3. Components of the hub

```mermaid
flowchart TB
  subgraph hub["directory-roster [Container]"]
    direction TB
    dirapi["DirectoryService handlers<br/>[connect-go]<br/>Describe, Probe, GetGroup, ListGroups,<br/>GetAccount, ResolveAccounts, ResolveUser"]:::component
    consauth["Consumer authentication<br/>[TokenReview]<br/>SA token, audience, allow-list"]:::component
    opapi["Operator handlers<br/>[connect-go]<br/>WorkspaceService, SettingsService,<br/>AccessService, role gate from the session"]:::component
    access["Access<br/>[session, policy, login routes]<br/>forwarded bearer, or standalone sign-in,<br/>or admin; internal groups to roles"]:::component
    connect["Connect flow<br/>[HTTP]<br/>BeginConnect and callback: state cookie,<br/>code exchange, tenant + domain discovery, first probe"]:::component
    router["Router<br/>[domain → workspace]<br/>email domain to the workspace serving it,<br/>conflict detection, authoritative per domain"]:::component
    fresh["Freshness<br/>[max_age policy]<br/>serve / refresh single-flight /<br/>point read live / miss goes live once"]:::component
    refresher["Refresher + prober<br/>[background loops]<br/>new snapshot every refresh interval,<br/>probe + domain re-read every probe interval,<br/>shared lock"]:::component
    wsstore[("Workspace store<br/>[Kubernetes]<br/>records in ConfigMaps, credentials in Secrets,<br/>overlay merged read-only, console memberships")]:::component
    backend["Backend: Google<br/>[Admin SDK client + OIDC verifier]<br/>users.list, groups.list, members.list (atomic per group),<br/>domains.list, token from refresh token or SA key"]:::component
    snap[("Snapshot store<br/>[Valkey or memory]<br/>per-workspace snapshot, snapshot_at,<br/>negative cache")]:::component
  end

  consauth -- "admits" --> dirapi
  access -- "identity + role" --> opapi
  access -- "is the account live, in the group" --> router
  opapi -- "BeginConnect" --> connect
  opapi -- "list / upsert / delete, memberships" --> wsstore
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
  classDef hub fill:#0E7C7B,stroke:#0A5958,color:#fff
  classDef hubStore fill:#5FA9A7,stroke:#0A5958,color:#fff
  classDef token fill:#4A4FB5,stroke:#33378A,color:#fff
  classDef tokenStore fill:#8A8DD1,stroke:#33378A,color:#fff
  classDef component fill:#85bbf0,stroke:#5d82a8,color:#000
  style hub fill:none,stroke:#444,stroke-dasharray:5 5
```

## 4. Who owns what

| | directory-roster | access-issuer | external |
|---|---|---|---|
| credentials held | directory read credentials — the only place they exist | its own signing keys | the IdPs hold users, passwords, MFA |
| knows | who exists, who is live, who is in which group, which domains each tenant owns, and whether that is authoritative | who just proved what | each relying party knows its own roles |
| decides | nothing about access; it answers | what a proof entitles you to | each relying party enforces on claims |
| authenticates | nobody | nobody | Google, Entra, the CI platform |
| issues | nothing | tokens to registered clients and exchanged tokens for workloads | the cloud issues credentials against the audience |
| operator surface | Workspaces, Settings, Access | one read-only page | the proxy, unchanged |
| when down | the issuer keeps last-known groups within a window; github-roster holds removals | no new logins; sessions live to expiry; break-glass is outside | |

## 5. Use cases

### 5.1 An operator opens a console — the hub's console included

```mermaid
sequenceDiagram
  autonumber
  actor E as Operator (browser)
  participant P as proxy (in front of the console)
  participant T as access-issuer
  participant G as Corporate IdP
  participant H as directory-roster
  E->>P: open the console
  P-->>E: redirect to the issuer's /authorize
  E->>T: /authorize, types email
  T-->>E: redirect to the tenant's IdP (routed by email domain)
  E->>G: sign in, MFA
  G-->>E: code
  E->>T: callback with code
  T->>G: exchange code, verify ID token
  T->>H: ResolveUser(email)
  H-->>T: groups, live, authoritative, snapshot_at
  T->>T: policy: directory groups to internal groups to claims
  T-->>E: code for the proxy
  E->>P: callback
  P->>T: exchange code → ID token
  P-->>E: the console, with the bearer forwarded
  Note over P,H: when the console is the hub's own, it verifies the forwarded bearer and resolves the address itself, so the same memberships grant the role
```

Until the access-issuer exists, the issuer in this flow is whatever
identity provider the installation already runs; nothing about the hub's
side changes.

### 5.2 kubectl on a cluster

```mermaid
sequenceDiagram
  autonumber
  actor E as Engineer
  participant C as kubelogin
  participant T as access-issuer
  participant B as Browser + IdP
  participant K as Kubernetes API server
  E->>C: kubectl get pods (exec plugin)
  C->>T: authorization code with PKCE (or device flow)
  T-->>C: redirect to sign in
  E->>B: sign in at the corporate IdP
  B->>T: code
  Note over T: ResolveUser, then the policy: internal groups and the clients they admit
  T-->>C: ID token (aud this cluster, groups) + refresh token
  C->>K: request with bearer
  K->>T: JWKS (cached)
  K->>K: issuer, aud, groups claim → RBAC
  K-->>C: pods
```

### 5.3 Cloud credentials without a directory service on the cloud side

```mermaid
sequenceDiagram
  autonumber
  participant C as CLI (already logged in)
  participant T as access-issuer
  participant S as Cloud STS (account 1111)
  C->>T: token exchange: subject = my token, requested aud = aws:1111:power
  T->>T: policy: does this identity hold a group aws:1111:power requires?
  alt allowed
    T-->>C: token with aud aws:1111:power
    C->>S: AssumeRoleWithWebIdentity(role power, token)
    S->>T: JWKS (cached)
    S->>S: trust policy: iss = the issuer, aud = aws:1111:power
    S-->>C: temporary credentials
  else not allowed
    T-->>C: invalid_target
  end
```

### 5.4 A CI job deploys

```mermaid
sequenceDiagram
  autonumber
  participant W as Workflow (gitops, master)
  participant GH as CI platform OIDC
  participant T as access-issuer
  participant S as Cloud STS
  W->>GH: request id-token (aud the issuer)
  GH-->>W: JWT: sub repo:example-org/gitops:ref:refs/heads/master
  W->>T: token exchange, subject = that JWT, requested aud = aws:1111:gitops-deployer
  T->>GH: JWKS (cached)
  T->>T: verify iss, aud, exp · organisation allow-list · matchers on repository and ref
  T-->>W: token (aud aws:1111:gitops-deployer)
  W->>S: AssumeRoleWithWebIdentity
  S-->>W: temporary credentials
  Note over W,S: same shape for a cluster: requested aud k8s:devel, then kubectl
```

### 5.5 github-roster reconciles teams — no issuer involved

```mermaid
sequenceDiagram
  autonumber
  participant R as github-roster (tick)
  participant H as directory-roster
  participant GH as GitHub org
  R->>H: Describe
  H-->>R: served domains with authoritative flags
  R->>H: GetGroup(team-platform@example.com)
  H-->>R: members, authoritative, snapshot_at
  R->>H: ResolveAccounts(linked emails)
  H-->>R: live / suspended / not found, each with authoritative
  R->>R: derive: links × groups × live → desired teams
  alt every input authoritative
    R->>GH: add and remove memberships
  else any input not authoritative
    R->>GH: add only, hold removals
  end
```

### 5.6 Connecting a workspace by admin consent

```mermaid
sequenceDiagram
  autonumber
  actor Op as Operator (browser, signed in)
  participant Hub as directory-roster (console listener)
  participant G as Google (OAuth + Admin SDK)
  participant K as Kubernetes Secrets/ConfigMaps
  Op->>Hub: Connect Google Workspace
  Hub->>Hub: session to operator role (policy)
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
```

### 5.7 A login-time lookup with freshness

```mermaid
sequenceDiagram
  autonumber
  participant W as Role computation at login (SA token)
  participant Hub as directory-roster (API listener)
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

### 5.8 Day one of a standalone installation

```mermaid
sequenceDiagram
  autonumber
  actor O as Operator
  participant H as directory-roster console
  participant G as Google Workspace
  O->>H: port-forward, sign in as admin (password from the generated Secret)
  O->>H: Settings: OAuth client (or declared by the chart)
  O->>H: Connect Google Workspace
  H-->>O: consent URL
  O->>G: consent as the admin role account
  G-->>H: callback: refresh token, tenant id, domains
  H->>G: first snapshot
  O->>H: Access: directory-admins joins hub-operators (picker over snapshotted groups)
  O->>H: sign out, "Sign in with Google"
  H->>G: OIDC sign-in with the same client, openid scopes only
  H->>H: email → workspace → live and in group → operator
  O->>H: disable admin (chart value)
  Note over O,H: with a proxy in front, steps 1 and 9-11 are replaced by the proxy's login - the memberships are the same, and admin stays as break-glass by port-forward
```

## 6. Failure semantics, in one table

| Situation | What consumers and operators see |
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
| access-issuer is down | no new logins anywhere; existing sessions and tokens live to expiry; break-glass is outside it |
| The hub is down | access-issuer keeps last-known groups within its hold window; github-roster holds removals |

The rule under all of them: **a consumer removes access only on an
authoritative answer.** Everything that can go wrong degrades to "hold",
never to "gone".
