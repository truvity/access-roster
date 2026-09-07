# Configuration

How the hub is configured: the chart's boundary, its values, the overlay
format, the Kubernetes objects it owns, the roles, and the two things it
expects the deployment to provide.

## What the chart includes, what it expects

| Included (standard Kubernetes APIs) | Expected to exist |
|---|---|
| Deployment, two Services (API, console), ServiceAccount + namespaced Role/RoleBinding, NetworkPolicy, the overlay ConfigMap, the Gateway API `HTTPRoute` for the console host (console slice) | a **Valkey** to point at; the **gateway authentication** in front of the console host; the Secrets a declared workspace or a declared OAuth client name |

The hub itself reads and writes plain Kubernetes Secrets and ConfigMaps in
its own namespace. It has no dependency on an external-secrets operator, a
cloud parameter store or a backup mechanism. Delivering a *declared* Secret
into the namespace is the deployment's business; an example with
external-secrets is at the end of this page.

## Values

| Value | Default | Meaning |
|---|---|---|
| `replicaCount` | `2` | two replicas need Valkey; one may use the in-memory cache |
| `image.repository` / `tag` | `ghcr.io/truvity/access-roster/directory-roster` / app version | |
| `listeners.api.port` | `8080` | `DirectoryService` — consumers |
| `listeners.console.port` | `8081` | `WorkspaceService`, `SettingsService`, `AccessService`, the SPA, the login routes, the consent callback — operators, own login or a gateway in front |
| `listeners.health.port` | `7070` | `/healthz`, `/readyz` |
| `valkey.address` | `""` | host:port of the snapshot cache; empty selects the in-memory backend |
| `valkey.passwordSecret.name` / `.key` | `""` / `password` | optional Secret with the password |
| `valkey.tls` | `false` | |
| `freshness.refreshInterval` | `15m` | how often the refresher takes a new snapshot per workspace |
| `freshness.freshnessWindow` | `30m` | how old a snapshot may be before its domains stop being authoritative |
| `freshness.probeInterval` | `5m` | how often a credential is probed and the domain list re-read |
| `oauthClient.existingSecret` | `""` | a Secret with `client-id` and `client-secret`; set, the console shows the client read-only |
| `workspaces[]` | `[]` | declared workspaces, see below |
| `consumers[]` | `[]` | `namespace` + `serviceAccount` pairs allowed on the API listener; verified by TokenReview |
| `access.admin.enabled` | `true` | the break-glass account; turn off once a rule grants operator to a real identity |
| `access.login.directory` | `true` | "Sign in with <directory>" using a connected workspace's OAuth client |
| `access.login.oidc.issuer` / `.clientSecretName` | `""` | an external issuer for the hub's own login page; Secret keys `client-id`, `client-secret` |
| `access.login.forwardedBearer.issuer` | `""` | verify a bearer forwarded by a gateway against this issuer |
| `access.rules[]` | `[]` | declared rules, see below |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.apiClients[]` | `[]` | namespaces allowed to reach the API listener |
| `networkPolicy.gatewayNamespace` | `""` | the namespace allowed to reach the console listener |
| `resources`, `podAnnotations`, `nodeSelector`, `tolerations` | | Kubernetes passthrough |

`values.schema.json` is strict at the top level: an unknown key fails the
render.

## Declared workspaces (the overlay)

```yaml
workspaces:
  - id: C0example              # the backend's tenant id (Google: the customer id)
    backend: google
    admin: admin@example.com   # the account the key impersonates
    secretName: example-sa-key # a Secret in this namespace; key `key.json`
```

The chart renders the list into a ConfigMap and mounts each named Secret
read-only. The hub merges declared workspaces with the ones connected
through the console: declared ones are read-only in the console, cannot be
disconnected there (remove them from the values instead) and win when a
domain is claimed twice. Domains are discovered from the backend, exactly
as for a connected workspace.

This is how an installation that already holds service-account keys goes
live on day one, and connects through consent later at its own pace.

## Consumers

A consumer mounts a projected ServiceAccount token with the hub's audience
and sends it as a bearer:

```yaml
volumes:
  - name: directory-roster-token
    projected:
      sources:
        - serviceAccountToken:
            audience: directory-roster
            expirationSeconds: 3600
            path: token
```

and appears in the hub's values:

```yaml
consumers:
  - namespace: identity-system
    serviceAccount: authorization-webhook
```

The chart then creates the one cluster-scoped permission it ever needs, a
ClusterRole allowing `create` on `tokenreviews`, bound to the hub's
ServiceAccount. It reads nothing.

## Access rules

Declared rules live in values and are read-only in the console; rules added
in the console are stored in `ConfigMap hub-access` and evaluated after
them. Evaluation is in order, default deny, operator implies viewer.

```yaml
access:
  rules:
    - id: platform-admins
      directoryGroup: { group: platform-admins@example.com }
      role: operator
    - id: fleet-operators
      claim: { issuer: https://issuer.example, claim: groups, value: "hub:operator" }
      role: operator
    - id: everyone-reads
      emailDomain: example.com
      role: viewer
```

| Subject | Matches | Needs |
|---|---|---|
| `directoryGroup` | live members of a snapshotted group in a served domain; `workspaceId` optional | a connected workspace |
| `claim` | a value in a named claim of a verified token from a named issuer | the OIDC or forwarded source |
| `email` | one address, case-insensitive | nothing |
| `emailDomain` | every address in the domain | nothing |

## Kubernetes objects the hub owns

| Object | Holds | Written by |
|---|---|---|
| `Secret workspace-<id>` | the credential: refresh token, or service-account key | the hub (Connect, UploadKey) |
| `ConfigMap workspace-<id>` | backend, domains, admin, connected by/at, last health, credential type | the hub |
| `Secret hub-oauth-client` | OAuth client id and secret | the hub (`SetOAuthClient`) — or declared via `oauthClient.existingSecret` |
| `Secret hub-session-key` | signs the session cookie and the consent-flow state | the hub, generated on first start; rotate by deleting |
| `Secret hub-admin` | the break-glass password | the hub, generated on first start |
| `ConfigMap hub-access` | console-added rules | the hub |
| `ConfigMap <release>-access` | declared rules, consumers, login sources | the chart |
| `ConfigMap <release>-overlay` | the declared workspaces | the chart |

Labels on every hub-written object: `app.kubernetes.io/name=directory-roster`,
`app.kubernetes.io/managed-by=directory-roster`. Export everything with

```sh
kubectl -n directory-roster get secret,configmap -l app.kubernetes.io/managed-by=directory-roster -o yaml
```

There is no backup mechanism in the hub. A consent credential is cheap to
mint again — Reconnect is the recovery — and a declared Secret is
re-delivered by whatever declared it.

## Environment

The binary is configured by environment variables; the chart sets them
from the values above.

| Variable | From |
|---|---|
| `NAMESPACE` | the pod's namespace (downward API) |
| `API_PORT`, `CONSOLE_PORT`, `HEALTH_PORT` | `listeners.*` |
| `REFRESH_INTERVAL`, `FRESHNESS_WINDOW`, `PROBE_INTERVAL` | `freshness.*` |
| `VALKEY_ADDRESS`, `VALKEY_TLS`, `VALKEY_PASSWORD` | `valkey.*` (absent = in-memory) |
| `OAUTH_CLIENT_SECRET_NAME` | `oauthClient.existingSecret` |
| `OVERLAY_FILE` | set when `workspaces` is non-empty |
| `ACCESS_FILE` | the rendered access configuration: admin, login sources, consumers, declared rules |

## Roles

Two roles, granted by the access rules above, whatever the sign-in source.

| Role | May |
|---|---|
| viewer | `ListWorkspaces`, `GetSettings`, `GetAccessPolicy`, `WhoAmI`, see the console |
| operator | everything: Connect, Reconnect, UploadKey, Probe, Refresh, Disconnect, SetOAuthClient, AddRule, RemoveRule |

Behind a gateway that forwards a token with a groups or roles claim, a
`claim` rule maps that claim to a role; the identity provider mints the
claim, the hub reads it.

## The repository

access-roster ships two components from one repository, each with its own
binary and chart, installable alone: `directory-roster`, this hub, and
later the token service. Shared Go packages — the backends, the Connect
flow, the rules engine, the verifiers — are importable behind storage
interfaces.

## Valkey: a recommendation

Any Valkey or Redis-protocol server reachable from the namespace works.
The hub stores one key set per workspace (the snapshot, its timestamp, a
short negative cache) and a lock per workspace; memory use is the size of
the directories, tens of megabytes at most. Persistence is not required —
a cold cache costs one fetch per workspace.

If the cluster runs the [valkey-operator](https://github.com/hyperspike/valkey-operator),
a single-node cluster in the hub's namespace is enough:

```yaml
apiVersion: hyperspike.io/v1
kind: Valkey
metadata:
  name: directory-roster-cache
  namespace: directory-roster
spec:
  nodes: 1
  replicas: 0
  tls: false
```

Point the chart at its Service (`valkey.address=directory-roster-cache.directory-roster.svc:6379`)
and, if the operator issues a password Secret, at that Secret.

## The gateway: a recommendation

The console listener must only be reachable through an authenticating
gateway that forwards the caller's identity and groups as headers. The
hub ships an `HTTPRoute` (console slice) attaching to a Gateway the
deployment names; the authentication layer (an OIDC-aware proxy or the
gateway's own OIDC filter) is the deployment's. Set
`networkPolicy.gatewayNamespace` so nothing else can reach the port.

## Delivering a declared Secret with external-secrets: an example

Not a dependency of the hub — one way a deployment can put a
service-account key into the namespace for a declared workspace.

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: example-sa-key
  namespace: directory-roster
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: your-store
  target:
    name: example-sa-key
    creationPolicy: Owner
  data:
    - secretKey: key.json
      remoteRef:
        key: /path/in/your/store/example-sa-key-json
```
