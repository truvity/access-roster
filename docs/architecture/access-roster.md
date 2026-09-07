# Architecture — the family

Two components in one repository, and the relying parties around them.
The hub is [designed here](../design/hub.md) and drawn in detail in
[hub.md](hub.md); the token service is [designed here](../design/token-service.md)
and built later. This page is the picture end to end.

## Containers — C4 level 2

```mermaid
flowchart TB
  eng["Engineer<br/>[Person]<br/>browser and CLI"]:::person
  wf["CI job<br/>[External workload]<br/>a signed identity token per run"]:::ext
  idp["Corporate IdPs<br/>[External]<br/>Google Workspace tenants, Entra later<br/>sign-in and MFA live here"]:::ext

  subgraph nsTs["namespace: token-service (later)"]
    direction TB
    ts["token service<br/>[Container: Go, OpenID Provider library]<br/>verifiers: corporate OIDC, workload OIDC, k8s SA<br/>rules engine · client registry · device flow"]:::token
    rules[("rules + clients<br/>[ConfigMap from the deployment]<br/>groups → claims, gated audiences")]:::tokenStore
    keys[("signing keys<br/>[Secrets]<br/>rotated, JWKS served")]:::tokenStore
    tsv[("Valkey<br/>[external to the chart]<br/>codes, refresh tokens,<br/>device codes, last-known groups")]:::tokenStore
  end

  subgraph nsHub["namespace: directory-roster"]
    direction TB
    hub["directory-roster<br/>[Container: Go, ConnectRPC]<br/>API listener: DirectoryService<br/>console listener: Workspaces, Settings, Access, SPA<br/>refresher, prober, router by domain"]:::hub
    k8s[("workspace records + credentials<br/>[Secrets + ConfigMaps]<br/>refresh tokens, SA keys, OAuth client,<br/>session key, admin password, console rules")]:::hubStore
    hv[("Valkey<br/>[external to the chart]<br/>one snapshot per workspace, locks")]:::hubStore
  end

  subgraph rp["Relying parties — trust the issuer, read claims"]
    direction LR
    k8sapi["Kubernetes API servers<br/>[one per cluster]<br/>issuer + client id + groups claim"]:::ext
    cloud["Cloud accounts<br/>[IAM OIDC provider each]<br/>trust policy: aud equals the role's audience"]:::ext
    gw["authenticating proxy + sessions<br/>[per console]<br/>consoles read the groups claim"]:::ext
    roster["github-roster<br/>[sibling service]<br/>directory groups → GitHub teams"]:::ext
  end

  eng -- "sign in<br/>[browser, redirected by the issuer]" --> idp
  eng -- "authorize, device flow<br/>[OIDC]" --> ts
  wf -- "token exchange<br/>[RFC 8693]" --> ts
  ts -- "verify sign-in<br/>[OIDC code flow]" --> idp
  ts -- "ResolveUser at login and refresh<br/>[ConnectRPC, SA token]" --> hub
  ts --> rules
  ts --> keys
  ts --> tsv
  hub -- "users, groups, members, domains<br/>[Admin SDK, read-only]" --> idp
  hub --> k8s
  hub --> hv
  roster -- "GetGroup, ListGroups, ResolveAccounts<br/>[ConnectRPC, SA token]" --> hub
  ts -. "issuer trusted by<br/>[JWKS]" .-> k8sapi
  ts -. "issuer trusted by<br/>[JWKS]" .-> cloud
  ts -. "issuer trusted by<br/>[client id + secret]" .-> gw

  classDef person fill:#1B2230,stroke:#0B0F16,color:#fff
  classDef hub fill:#0E7C7B,stroke:#0A5958,color:#fff
  classDef hubStore fill:#5FA9A7,stroke:#0A5958,color:#fff
  classDef token fill:#4A4FB5,stroke:#33378A,color:#fff
  classDef tokenStore fill:#8A8DD1,stroke:#33378A,color:#fff
  classDef ext fill:#8A93A3,stroke:#5E6675,color:#fff
  style nsTs fill:none,stroke:#4A4FB5,stroke-dasharray:5 5
  style nsHub fill:none,stroke:#0E7C7B,stroke-dasharray:5 5
  style rp fill:none,stroke:#8A93A3,stroke-dasharray:5 5
```

The hub sits behind exactly two callers and itself. Everything else reads
claims from the token service and never sees the hub. Neither component
has a database; neither authenticates anyone.

## Who owns what

| | directory-roster | token service | external |
|---|---|---|---|
| credentials held | directory read credentials — the only place they exist | its own signing keys | the IdPs hold users, passwords, MFA |
| knows | who exists, who is live, who is in which group, which domains each tenant owns, and whether that is authoritative | who just proved what | each relying party knows its own roles |
| decides | nothing about access; it answers | what a proof entitles you to | each relying party enforces on claims |
| authenticates | nobody | nobody | Google, Entra, the CI platform |
| issues | nothing | tokens to registered clients and exchanged tokens for workloads | the cloud issues credentials against the audience |
| operator surface | Workspaces, Settings, Access | one read-only page | proxies, unchanged |
| when down | the issuer keeps last-known groups within a window; github-roster holds removals | no new logins; sessions live to expiry; break-glass is outside | |

## Use cases

### A person opens a console behind an authenticating proxy

```mermaid
sequenceDiagram
  autonumber
  actor E as Engineer (browser)
  participant P as proxy (console)
  participant T as token service
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
  T->>T: rules: groups → claims
  T-->>E: code for the proxy
  E->>P: callback
  P->>T: exchange code → ID token
  P-->>E: the console, with the groups claim forwarded
```

### kubectl on a cluster

```mermaid
sequenceDiagram
  autonumber
  actor E as Engineer
  participant C as kubelogin
  participant T as token service
  participant B as Browser + IdP
  participant K as Kubernetes API server
  E->>C: kubectl get pods (exec plugin)
  C->>T: authorization code with PKCE (or device flow)
  T-->>C: redirect to sign in
  E->>B: sign in at the corporate IdP
  B->>T: code
  Note over T: ResolveUser → rules → groups, audiences
  T-->>C: ID token (aud this cluster, groups) + refresh token
  C->>K: request with bearer
  K->>T: JWKS (cached)
  K->>K: issuer, aud, groups claim → RBAC
  K-->>C: pods
```

### Cloud credentials without a directory service on the cloud side

```mermaid
sequenceDiagram
  autonumber
  participant C as CLI (already logged in)
  participant T as token service
  participant S as Cloud STS (account 1111)
  C->>T: token exchange: subject = my token, requested aud = aws:1111:power
  T->>T: rules: may this identity have aws:1111:power?
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

### A CI job deploys

```mermaid
sequenceDiagram
  autonumber
  participant W as Workflow (gitops, master)
  participant GH as CI platform OIDC
  participant T as token service
  participant S as Cloud STS
  W->>GH: request id-token (aud the issuer)
  GH-->>W: JWT: sub repo:example-org/gitops:ref:refs/heads/master
  W->>T: token exchange, subject = that JWT, requested aud = aws:1111:gitops-deployer
  T->>GH: JWKS (cached)
  T->>T: verify iss, aud, exp · organisation allow-list · rules on repository and ref
  T-->>W: token (aud aws:1111:gitops-deployer)
  W->>S: AssumeRoleWithWebIdentity
  S-->>W: temporary credentials
  Note over W,S: same shape for a cluster: requested aud k8s:devel, then kubectl
```

### github-roster reconciles teams — no issuer involved

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

### The hub's own console, day one

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
  O->>H: Access: group directory-admins → operator (picker over snapshotted groups)
  O->>H: sign out, "Sign in with Google"
  H->>G: OIDC sign-in with the same client, openid scopes only
  H->>H: email → workspace → live and in group → operator
  O->>H: disable admin (chart value)
  Note over O,H: behind a proxy, the forwarded bearer takes the place of the sign-in and a claim rule grants the roles
```
