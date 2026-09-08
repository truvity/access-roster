# directory-roster — chart and configuration

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
| `listeners.api.audience` | the release name | the audience a consumer's projected token must carry |
| `listeners.console.port` | `8081` | `WorkspaceService`, `SettingsService`, `AccessService`, the SPA, the login routes, the consent callback — operators, own login or a gateway in front |
| `listeners.health.port` | `7070` | `/healthz`, `/readyz` |
| `valkey.address` | `""` | host:port of the snapshot cache; empty selects the in-memory backend |
| `valkey.passwordSecret.name` / `.key` | `""` / `password` | optional Secret with the password |
| `valkey.tls` | `false` | |
| `valkey.cluster` | `true` | speak the cluster protocol; the fleet's Valkeys are ValkeyClusters even at one shard. A plain single server needs `false`, and a mismatch is refused at start |
| `freshness.refreshInterval` | `15m` | how often the refresher takes a new snapshot per workspace |
| `freshness.freshnessWindow` | `30m` | how old a snapshot may be before its domains stop being authoritative |
| `freshness.probeInterval` | `5m` | how often a credential is probed and the domain list re-read |
| `oauthClient.existingSecret` | `""` | a Secret with `client-id` and `client-secret`; set, the console shows the client read-only |
| `workspaces[]` | `[]` | declared workspaces, see below |
| `consumers[]` | `[]` | `namespace` + `serviceAccount` pairs allowed on the API listener, verified by TokenReview. **Empty admits nobody** |
| `route.host` | `""` | the console's hostname on the gateway, and only the console's: the API listener never gets a route, because a consumer that could arrive over the gateway could reach an operator call. Empty renders no Gateway, HTTPRoute or Certificate, which is right for a hub reached by port-forward |
| `route.gatewayClassName`, `route.certificate.*` | `internal`, `internal-ca` | which class the Gateway joins, and who issues its certificate. An empty `issuerName` renders none, for a gateway that brings its own |
| `access.recovery.enabled` | `true` | the way in for the day the ordinary one is broken. In a cluster it stores nothing: recovery is a short-lived ServiceAccount token proving access to the API server, so the authority is the cluster's own RBAC. On by default because it no longer costs a standing credential |
| `access.recovery.serviceAccountName` | `<release>-recovery` | the account recovery proves access as; the chart creates it, bound to nobody. Granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |
| `access.recovery.audience` | `<release>-recovery` | the audience the token must be minted for. Without one, every mounted ServiceAccount token in the cluster would be a recovery token |
| `access.holdWindow` | `4h` | how long a signed-in identity keeps its last granted role while the directory cannot be vouched for |
| `access.login.directory` | `true` | "Sign in with <directory>" using a connected workspace's OAuth client |
| `access.login.oidc.issuer` / `.clientSecretName` | `""` | an external issuer for the hub's own login page; Secret keys `client-id`, `client-secret` |
| `access.login.forwardedBearer.emailHeader` | `""` | trust the address in this header, set by an authenticating gateway in front of the console (`X-Auth-Request-Email` for oauth2-proxy and the fleet's gateway-auth). Empty turns the path off. Only set it where a gateway really does strip and set the header on every request |
| `access.login.forwardedBearer.issuer` | `""` | recorded on the session, so an operator can see where an identity came from |
| `access.sessionLifetime` | `12h` | how long a console session lasts |
| `logLevel` | `info` | debug, info, warn, error |
| `policy` | `{}` | the declared layer of the policy, see below |
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
    serve:                     # optional; omitted serves every domain it owns
      - example.com
```

The chart renders the list into a ConfigMap and mounts each named Secret
read-only. The hub merges declared workspaces with the ones connected
through the console: declared ones are read-only in the console, cannot be
disconnected there (remove them from the values instead) and win when a
domain is claimed twice. Domains are discovered from the backend, exactly
as for a connected workspace.

`serve` narrows a tenant to a subset of the domains it owns. Leave it out
and the hub serves all of them, including ones the company adds later —
the ordinary case. Name a subset and the rest are still discovered and
shown, but nothing routes to them and their accounts are never cached:
that is how one installation reads a single domain of a company whose
other domains are none of its business. A domain named here that the
tenant does not own routes nothing and is reported as no longer owned,
which makes it safe to declare a domain that is about to move between
tenants. For a workspace connected through the console the same choice is
made there, on the directory's page.

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
            audience: directory-roster   # listeners.api.audience
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

## The policy

The hub loads the family's [policy](policy.md): `groups`, `claims`,
`lifetimes` and `memberships`, from the deployment's ConfigMap(s) as the
declared layer and from `ConfigMap <release>-memberships` as the console
layer.
The chart renders the declared layer from `policy:` in values, which is
the same YAML:

```yaml
policy:
  groups:
    hub-operators: { members: [platform-admins@example.com] }
    hub-viewers:   { members: [all@example.com] }
  lifetimes: { default: 12h }
```

## Kubernetes objects the hub owns

Everything an operator adds in the console lives here. `<release>` is the
chart's full name, so two hubs in one namespace do not write over each
other, and `<tenant>` is a readable part of the tenant id followed by a
short hash of it — a tenant id belongs to the backend, not to Kubernetes,
so the hash carries the uniqueness the readable part may have lost.

| Object | Holds | Written by |
|---|---|---|
| `ConfigMap <release>-workspace-<tenant>` | backend, domains, served domains, admin, connected by/at, last health, credential type | the hub |
| `Secret <release>-credential-<tenant>` | the credential: refresh token, or service-account key | the hub (Connect, UploadKey) |
| `Secret <release>-oauth-client` | OAuth client id and secret | the hub (`SetOAuthClient`) — or declared via `oauthClient.existingSecret`, and then read-only |
| `ConfigMap <release>-memberships` | memberships added in the console | the hub |
| `Secret <release>-session-key` | signs the session cookie and the consent-flow state | the hub, generated on first start; rotate by deleting |
| `ConfigMap <release>-policy` | the declared layer of the policy, plus the console's own settings and the consumer allow-list | the chart |
| `ConfigMap <release>-overlay` | the declared workspaces | the chart |

The record and the credential are two objects on purpose. A record is
shown to anyone who may see the console; a credential is written once and
read once, at start. Keeping them apart means the type the console handles
cannot carry a secret by accident, and it makes the failure modes
independent: a record whose credential is missing is a workspace with no
reader, which the console shows as unhealthy with the reason — not a hub
that will not start.

Labels on every hub-written object: `app.kubernetes.io/managed-by=directory-roster`,
`app.kubernetes.io/part-of=<release>`, and
`directory-roster.truvity.com/kind` = `workspace`, `credential` or
`settings`. The workspace id as the backend spells it is the annotation
`directory-roster.truvity.com/workspace-id`. Export everything with

```sh
kubectl -n directory-roster get secret,configmap -l app.kubernetes.io/managed-by=directory-roster -o yaml
```

There is no backup mechanism in the hub. A consent credential is cheap to
mint again — Reconnect is the recovery — and a declared Secret is
re-delivered by whatever declared it.

**`STORE=memory`** turns all of it off: nothing is written, and a restart
is a fresh installation. It is the default for the binary, because a local
run and the demonstration should need no cluster; the chart always sets
`kubernetes`. A hub started on the memory store says so at WARN on its
first line, naming what a restart would lose.

## Environment

The binary is configured by environment variables; the chart sets them
from the values above.

| Variable | From |
|---|---|
| `NAMESPACE` | the pod's namespace (downward API) |
| `STORE` | always `kubernetes` from the chart; `memory` (the binary's default) keeps nothing |
| `RELEASE_NAME` | the chart's full name, which prefixes every object the hub writes |
| `API_PORT`, `CONSOLE_PORT`, `HEALTH_PORT` | `listeners.*` |
| `REFRESH_INTERVAL`, `FRESHNESS_WINDOW`, `PROBE_INTERVAL` | `freshness.*` |
| `VALKEY_ADDRESS`, `VALKEY_TLS`, `VALKEY_CLUSTER`, `VALKEY_PASSWORD` | `valkey.*` (no address = in-memory snapshots, which is correct for one replica and wasteful for more) |
| `OAUTH_CLIENT_SECRET_NAME` | `oauthClient.existingSecret` |
| `OVERLAY_FILE` | set when `workspaces` is non-empty |
| `PUBLIC_URL` | `https://<route.host>` — where a browser reaches the console. **Both OAuth redirect URIs and the setup values are built from it**, so a deployment without `route.host` falls back to localhost and registers a redirect no browser will reach |
| `SECURE_COOKIES` | `true` when `route.host` is set |
| `FORWARDED_EMAIL_HEADER`, `FORWARDED_ISSUER` | `access.login.forwardedBearer.*` |
| `SESSION_LIFETIME` | `access.sessionLifetime` |
| `LOG_LEVEL` | `logLevel` |
| `POLICY_DIR` | the directory the declared layer is mounted in; every YAML file in it merges |
| `HOLD_WINDOW` | `access.holdWindow` |

## Roles

Two roles, held by membership of two declared internal groups.

| Role | Group | May |
|---|---|---|
| viewer | `hub-viewers` | every read: `ListWorkspaces`, `GetSettings`, `GetPolicy`, `WhoAmI`, `Explain`, `ListDirectoryGroups`, `GetDirectoryGroup`, `SearchPeople`, `ListHolders` — the whole console, read-only |
| operator | `hub-operators` | everything: Connect, Reconnect, UploadKey, Probe, Refresh, Disconnect, SetOAuthClient, AddMembership, RemoveMembership |

Behind a gateway that forwards a token, the forwarded identity's email is
resolved through the hub like any other; the groups in the token itself
are not consulted, because the hub is the source they came from.

## The repository

access-roster ships two components from one repository, each with its own
binary and chart, installable alone: `directory-roster`, this hub, and
later the token service. Shared Go packages — the backends, the Connect
flow, the policy engine, the verifiers — are importable behind storage
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
