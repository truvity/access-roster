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

**The convention that follows from that** (decided 2026-09-08): every value
that consumes a Secret this chart did not create lets you name both **the
Secret and the keys inside it**. The producer is free — external-secrets, a
1Password operator, sealed-secrets, a hand `kubectl create secret`, a Job —
because a chart that dictated key names could not read a Secret already
sitting in the namespace. Key names are only ever fixed for a Secret the
hub writes *itself*, where it is the producer and gets to choose.

## Values

| Value | Default | Meaning |
|---|---|---|
| `replicaCount` | `2` | two replicas need Valkey; one may use the in-memory cache. Every replica serves every workspace, including one connected through the console on the other replica: a reader missing locally is opened from the stored credential on first use |
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
| `oauthClient.secret.name` | `""` | a Secret holding the client; set, the console shows it read-only, because a value the deployment states must not be editable in a UI |
| `oauthClient.secret.keys.clientId` / `.clientSecret` | `client-id` / `client-secret` | **what those keys are called in that Secret.** Configurable because the hub does not produce this object: whatever delivers it — external-secrets, a 1Password operator, sealed-secrets, `kubectl create secret` — already had an opinion, and a hub that insisted on two particular names could not read a Secret already in the namespace |
| `workspaces[]` | `[]` | declared workspaces, see below |
| `consumers[]` | `[]` | `namespace` + `serviceAccount` pairs allowed on the API listener, verified by TokenReview — the cluster anchor, for workloads in this cluster. **Empty admits nobody.** A caller from further away presents an issuer token instead: [../design/trust.md](../design/trust.md), [../connect/service-to-service.md](../connect/service-to-service.md) |
| `route.host` | `""` | the console's hostname on the gateway, and only the console's: the API listener never gets a route, because a consumer that could arrive over the gateway could reach an operator call. Empty renders no Gateway, HTTPRoute or Certificate, which is right for a hub reached by port-forward |
| `route.bootstrapPaths` | `[/login, /connect]` | paths served on a **second HTTPRoute**, so a gateway policy attached to the main one does not cover them. This is what makes a console behind an authenticating gateway bootstrappable at all: the operator who connects the FIRST directory is by definition one no directory can vouch for, so a gateway that gates `/login` sends them away to prove themselves against the thing that does not exist yet — and the consent they start comes back to a callback the gateway swallows, which reads as a second login prompt rather than a refusal. None of these is protected *by* the gateway anyway: recovery needs a token the API server vouches for, and an OAuth callback carries a signed state this hub issued. **The corollary: a request on this route carries no gateway identity, by design**, so the consent callback takes its operator from that signed state — established when an operator started the flow on a request the gateway did authenticate. Empty gates everything |
| `route.gatewayClassName`, `route.certificate.*` | `internal`, `internal-ca` | which class the Gateway joins, and who issues its certificate. An empty `issuerName` renders none, for a gateway that brings its own |
| `access.recovery.enabled` | `true` | the way in for the day the ordinary one is broken. In a cluster it stores nothing: recovery is a short-lived ServiceAccount token proving access to the API server, so the authority is the cluster's own RBAC. On by default because it no longer costs a standing credential |
| `access.recovery.serviceAccountName` | `<release>-recovery` | the account recovery proves access as; the chart creates it, bound to nobody. Granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |
| `access.recovery.audience` | `<release>-recovery` | the audience the token must be minted for. Without one, every mounted ServiceAccount token in the cluster would be a recovery token |
| `access.holdWindow` | `4h` | how long a signed-in identity keeps its last granted role while the directory cannot be vouched for |
| `access.login.directory` | `true` | the hub's own sign-in page. Off closes the routes, not just the buttons; connecting a directory is unaffected |
| `access.signOutThroughIssuer` | `false` | render `signOutURL` as the whole sign-out: the proxy's own with the issuer's `end_session` as its `rd`, carrying `client_id` (the forwarded audience) and landing on `https://<route.host>/`. Refused at render without `route.host`, the issuer or the audience — half a chain looks exactly like a whole one and is not. An explicit `signOutURL` wins |
| `access.proxyPrefix` | `/oauth2` | the proxy's path prefix, when the chain above is built |
| `access.login.forwardedBearer.issuer` | `""` | **the path to use.** The issuer whose published keys the gateway's forwarded token is verified against. The console reads `X-Auth-Request-Access-Token` (or an ordinary bearer), fetches discovery and the key set once, and checks signature, issuer and expiry itself |
| `access.login.forwardedBearer.audience` | `""` | this console's client id at that issuer. **Required whenever `issuer` is set — the render fails without it**, because a token minted for another audience is a perfectly valid token, and accepting it would make every service the issuer serves a way in here |
| `access.login.forwardedBearer.emailHeader` | `""` | the weaker path: trust an address read from this header, unverified (`X-Auth-Request-Email` for oauth2-proxy and the fleet's gateway-auth). It asks who can reach the port rather than who signed the token, so it is only as good as the promise that nothing but the gateway can — one NetworkPolicy edit, one port-forward or one sidecar away from false. Where both are set, the signature decides and the header is never read |
| `access.signOutURL` | `""` | where the console's sign-out control goes. Empty is this hub's own `/logout`, which is right only where this hub's own cookie is what signed the person in. **Behind a proxy it is not**: the proxy holds the session and forwards a bearer, so clearing this hub's cookie ends nothing, lands the person on a sign-in page with no way in — this hub's own sign-in being off is the point of having a proxy — and the next request arrives authenticated exactly as before. Name the proxy's own sign-out, `/oauth2/sign_out` for `access-proxy`'s default prefix. A value rather than something derived: the path belongs to the proxy, and where it goes afterwards — an issuer's end-session, a landing page — is the installation's to decide |
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
    secretName: example-sa-key # a Secret in this namespace
    secretKey: key.json        # which key of it holds the JSON; this is the default
    serve:                     # optional; omitted serves every domain it owns
      - example.com
    syncGroups:                # optional; omitted keeps every group in them
      - platform@example.com
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
tenants.

`syncGroups` is the same subtraction applied to groups. A company's
directory holds every mailing list it ever made and an installation's
policy speaks about a handful; naming them keeps the rest out of the
cache, out of the pickers and off the pages. It narrows what is **kept**,
not what is read — the hub still lists the tenant's groups, because that
list is what an operator chooses from, so the saving is in storage and
attention rather than in the directory's quota. Only a group the last
read held may be named. Empty keeps every group in the served domains.

For a workspace connected through the console the choice is made
**at connect time**, before the first snapshot: the consenting
administrator's own domain is pre-selected, the tenant's other domains
are listed and off, and *all, including ones added later* is an explicit
option. It can be changed afterwards on the directory's page.

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
| `Secret <release>-oauth-client` | OAuth client id and secret | the hub (`SetOAuthClient`) — or declared via `oauthClient.secret.name`, and then read-only. The hub names the keys only in the one it writes itself |
| `ConfigMap <release>-memberships` | memberships added in the console | the hub |
| `Secret <release>-session-key` | signs the session cookie and the consent-flow state | the hub, generated on first start; rotate by deleting |
| the issuer's signing key | a PEM private key, mounted as a file | **not the issuer** — cert-manager issues one, or external-secrets delivers one. The issuer reads it and holds no permission to read Secrets; its key id is the key's own RFC 7638 thumbprint, so nothing has to carry one beside it |
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
| `OAUTH_CLIENT_SECRET_NAME`, `OAUTH_CLIENT_ID_KEY`, `OAUTH_CLIENT_SECRET_KEY` | `oauthClient.secret.*` |
| `OVERLAY_FILE` | set when `workspaces` is non-empty |
| `PUBLIC_URL` | `https://<route.host>` — where a browser reaches the console. **Both OAuth redirect URIs and the setup values are built from it**, so a deployment without `route.host` falls back to localhost and registers a redirect no browser will reach |
| `SECURE_COOKIES` | `true` when `route.host` is set |
| `FORWARDED_ISSUER`, `FORWARDED_AUDIENCE` | `access.login.forwardedBearer.{issuer,audience}` — the **verified** path: the console checks the gateway's forwarded token against this issuer's published keys, and refuses one minted for another audience. Setting an issuer without an audience fails the render |
| `FORWARDED_EMAIL_HEADER` | `access.login.forwardedBearer.emailHeader` — the **trusted** path, and weaker: an address read out of a header, unverified. It asks who can reach the port rather than who signed the token. Where both are set, the signature decides and the header is never read |
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
