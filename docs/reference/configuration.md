# access-issuer — chart and configuration

How the service is configured: the chart's boundary, its values, the
overlay format, the Kubernetes objects it owns, the roles, and the two
things it expects the deployment to provide.

**One chart, `charts/access-issuer`, for one service.** It renders the
whole of access-roster — the directory, the policy, the OpenID provider,
the login page and the console (INF-691). The older
`charts/directory-roster` still ships so an installation can move back,
and it is documented by the git history of this page rather than by this
page.

## What the chart includes, what it expects

| Included (standard Kubernetes APIs) | Expected to exist |
|---|---|
| Deployment, Service, ServiceAccount + namespaced Role/RoleBinding (with the Kubernetes store) + a cluster-scoped TokenReview role (with recovery), NetworkPolicy, the policy / overlay / federated-cluster ConfigMaps, a Gateway and two `HTTPRoute`s — one for the issuer's own endpoints and one for the console's path | a **Valkey** to point at; the Secrets a declared workspace, a declared OAuth client or an externally delivered signing key name |

The service itself reads and writes plain Kubernetes Secrets and
ConfigMaps in its own namespace. It has no dependency on an external-secrets operator, a
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
| `issuerURL` | **required** | baked into every token and every relying party's trust. There is no default, because one would be a value nobody chose spread across an estate |
| `replicaCount` | `2` | two replicas need Valkey; one may use the in-memory store. Every replica serves every workspace, including one connected through the console on the other replica: a reader missing locally is opened from the stored credential on first use |
| `image.repository` / `tag` | `ghcr.io/truvity/access-roster/access-issuer` / app version | |
| `listeners.port` | `8080` | everything a browser and a relying party reach: discovery, the key set, the flows, the login page, and the console under `console.mount` |
| `listeners.healthPort` | `7070` | `/healthz`, `/readyz` |
| `valkey.address` | `""` | host:port of the shared store; empty keeps sessions and snapshots in memory, which is one replica only |
| `valkey.passwordSecret.name` / `.key` | `""` / `password` | optional Secret with the password |
| `valkey.tls` | `false` | |
| `valkey.cluster` | `false` | speak the cluster protocol. **Off by default since 2026-09-10**: with one shard it makes the client learn node addresses from `CLUSTER SLOTS` and talk to those, bypassing the Service — the one mechanism whose job is to survive a pod moving. Turn it on when the store has three shards |
| `signingKey.existingSecret` / `.key` | `""` / `tls.key` | a Secret holding a PEM RSA private key. Empty renders a cert-manager `Certificate` instead. **Never minted by the service**: two replicas with two keys hand out tokens half the fleet cannot verify |
| `directory.store` | `kubernetes` | where connected workspaces and their credentials are kept. `memory` makes a restart a fresh installation, which is right for a laptop and nothing else |
| `directory.freshness.refreshInterval` | `15m` | how often the refresher takes a new snapshot per workspace |
| `directory.freshness.freshnessWindow` | `30m` | how old a snapshot may be before its domains stop being authoritative |
| `directory.freshness.probeInterval` | `5m` | how often a credential is probed and the domain list re-read |
| `directory.sessionLifetime` | `12h` | how long the console's own session lasts |
| `directory.login` | `true` | whether the console offers a sign-in of its own, under `<mount>/login`. With `console.client` set it is a second door: the issuer's page is the one people use |
| `directory.workspaces[]` | `[]` | declared workspaces, see below |
| `oauthClient.secret.name` | `""` | a Secret holding the client for sign-in and admin consent. Empty means nobody can sign in and this installation issues tokens to machines only, which is a real posture and is said at start |
| `oauthClient.secret.keys.clientId` / `.clientSecret` | `client-id` / `client-secret` | **what those keys are called in that Secret.** Configurable because the service does not produce this object: whatever delivers it already had an opinion, and a chart that insisted on two names could not read a Secret already in the namespace |
| `console.mount` | `/console` | where the console sits on this origin. A **path** and not a host, because discovery must be at the root of the origin named in every token's `iss`. It is also what the console prefixes onto every link it hands a browser — `/login` resolves against the origin, where the issuer's page is. Empty serves no console |
| `console.client` | `""` | the declared client the console signs people in as (INF-701). Somebody with no session is sent to `/authorize`, signs in at the issuer's page, and comes back with the issuer's session set. Its `redirects` must name this origin plus the mount with a trailing slash. Empty keeps the console's own page, which in a deployment with an issuer beside it is a second door |
| `console.origin` | `""` | the one **other** origin allowed to call `SessionService` from a browser. Obsolete on one origin, which is the shipped shape; it remains for a console served from somewhere else |
| `exchange.audience` | the release name | the audience a workload's ServiceAccount token must be minted for. Without one, every mounted token in every federated cluster would be a proof |
| `exchange.clusters[]` | `[]` | the clusters whose workloads may exchange: `{name, issuer, jwksUri}` per cluster, verified against the key set that cluster publishes (INF-692). **No secret in any row**, and this service holds access to no cluster — including its own, which is a row like any other |
| `github.owners[]` | `[]` | the GitHub organisations whose workflows may exchange. **Empty verifies no CI token at all**, deliberately: anybody may run a workflow in their own repository and get a valid GitHub token, so a list invented by the chart would admit every repository there is |
| `cluster` | `""` | what this cluster is called, which becomes part of a ServiceAccount's subject. Empty keeps the older unqualified form |
| `lifetimes.token` / `.refresh` / `.hold` | | how long a token lives, how long a refresh lives, and how long a signed-in identity keeps its last granted role while the directory cannot vouch |
| `recovery.enabled` | `true` | the way in for the day the ordinary one is broken. It stores nothing: a short-lived ServiceAccount token proving access to the API server, so the authority is the cluster's own RBAC. **The only thing left that asks the cluster anything** |
| `recovery.serviceAccountName` | `<release>-recovery` | the account recovery proves access as; the chart creates it, bound to nobody. Granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |
| `recovery.audience` | `<release>-recovery` | the audience the token must be minted for. Without one, every mounted ServiceAccount token in the cluster would be a recovery token |
| `route.host` | `""` | the hostname on the gateway. Empty renders no Gateway, HTTPRoute or Certificate, which is right for an installation reached by port-forward |
| `route.rootRedirect` | `""` | where a bare GET of the host goes. The issuer serves nothing at `/` — every endpoint it answers is a named one — so point this at `/console/` and somebody who types the domain lands somewhere useful |
| `route.gatewayClassName`, `route.certificate.*` | `internal`, `internal-ca` | which class the Gateway joins, and who issues its certificate |
| `route.sharedWith[]` | `[]` | namespaces besides this one allowed to attach an HTTPRoute to this Gateway. A **gateway-level** admission, not a ReferenceGrant: whether a Gateway accepts a route from another namespace is entirely its own `allowedRoutes` |
| `policy` | `{}` | the declared policy, see [policy.md](policy.md) |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.clients[]` | `[]` | namespaces allowed to reach the service in-cluster: the proxies verifying tokens and the workloads exchanging them |
| `logLevel` | `info` | debug, info, warn, error |

**Two routes, and the second is not tidiness.** A gateway policy attaches
to an `HTTPRoute`, so the console's path is a separate object: anything
put in front of the console on a shared route would also sit in front of
`/token`, `/keys` and discovery, and every relying party in the estate
would be asked to sign in to fetch a key set. The console's route renders
whether or not anything attaches to it.

**The mount is not rewritten away** by the gateway, unlike the older
split chart. The service strips it itself, so a gateway that stripped it
too would hand the console a path it never serves.

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
and the service serves all of them, including ones the company adds later —
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
not what is read — the service still lists the tenant's groups, because that
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

## Consumers of the directory

**There is no API listener.** It went with the merge (INF-691): the
issuer was its only consumer and is now the same process, so the
question a consumer used to ask over the network is a function call.

What the grant model protected is not lost, only unused. It comes back
on this service when something needs it again — the GitHub controller is
the candidate — authenticated by token exchange like every other machine
(INF-696). Until then there is nothing to grant and nothing to admit,
which is the honest state for a listener with no callers.

A service that needs to know who somebody is does not ask the directory
at all: it verifies the issuer's token with the `identity` package and
reads the `groups` claim. That is [../connect/service-to-service.md](../connect/service-to-service.md).

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

## Kubernetes objects the service owns

Everything an operator adds in the console lives here. `<release>` is the
chart's full name, so two hubs in one namespace do not write over each
other, and `<tenant>` is a readable part of the tenant id followed by a
short hash of it — a tenant id belongs to the backend, not to Kubernetes,
so the hash carries the uniqueness the readable part may have lost.

| Object | Holds | Written by |
|---|---|---|
| `ConfigMap <release>-workspace-<tenant>` | backend, domains, served domains, admin, connected by/at, last health, credential type | the service |
| `Secret <release>-credential-<tenant>` | the credential: refresh token, or service-account key | the service (Connect, UploadKey) |
| `Secret <release>-oauth-client` | OAuth client id and secret | declared via `oauthClient.secret.name` and read-only. The console used to be able to write one; it cannot since INF-694, because a credential a console can change is one somebody can change from a browser |
| `Secret <release>-session-key` | signs the session cookie and the consent-flow state | the service, generated on first start; rotate by deleting |
| the signing key | a PEM private key, mounted as a file | **not the issuer** — cert-manager issues one, or external-secrets delivers one. The issuer reads it and holds no permission to read Secrets; its key id is the key's own RFC 7638 thumbprint, so nothing has to carry one beside it |
| `ConfigMap <release>-policy` | the declared layer of the policy, plus the console's own settings and the consumer allow-list | the chart |
| `ConfigMap <release>-overlay` | the declared workspaces | the chart |
| `ConfigMap <release>-clusters` | the clusters whose workloads may exchange, each a name and the URL of the key set it publishes. **No secret in any row** (INF-692) | the chart |

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

There is no backup mechanism here. A consent credential is cheap to
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
| `ISSUER_URL` | `issuerURL` — required, and in every token |
| `NAMESPACE` | the pod's namespace (downward API) |
| `STORE` | `directory.store` |
| `RELEASE_NAME` | the chart's full name, which prefixes every object the service writes and every key it uses in Valkey |
| `PORT`, `HEALTH_PORT` | `listeners.*` |
| `REFRESH_INTERVAL`, `FRESHNESS_WINDOW`, `PROBE_INTERVAL` | `directory.freshness.*` |
| `VALKEY_ADDRESS`, `VALKEY_TLS`, `VALKEY_CLUSTER`, `VALKEY_PASSWORD` | `valkey.*`. No address keeps everything in memory, which is correct for one replica and wrong for more |
| `SIGNING_KEY_FILE` | the mounted key. Read from a FILE, never through the API, so a compromise of this service cannot become a read of every credential in its namespace |
| `OAUTH_CLIENT_ID_FILE`, `OAUTH_CLIENT_SECRET_FILE` | the same client, as files, for signing a person in |
| `OAUTH_CLIENT_SECRET_NAME`, `OAUTH_CLIENT_ID_KEY`, `OAUTH_CLIENT_SECRET_KEY` | the same client, through the API, for the admin-consent flow. One credential read two ways, from one value, so it cannot be half rotated |
| `OVERLAY_FILE` | set when `directory.workspaces` is non-empty |
| `CLUSTERS_FILE` | set when `exchange.clusters` is non-empty |
| `CONSOLE_CLIENT_ID` | `console.client` |
| `CONSOLE_ORIGIN` | `console.origin`, for a console on another host |
| `PUBLIC_URL` | `https://<route.host><console.mount>` — where a browser reaches the console |
| `PUBLIC_ROOT_URL` | `https://<route.host>` — the origin root, which is where the **admin-consent callback** stays. Its redirect URI is registered with every corporate tenant, so moving it under the console's path would mean re-registering it in each of them |
| `SECURE_COOKIES` | `true` when `route.host` is set. The binary's own default follows the scheme of `ISSUER_URL`, so an https issuer marks its cookies Secure whether or not anything sets this. Set it explicitly only for a TLS terminator the URL does not mention |
| `EXCHANGE_AUDIENCE` | `exchange.audience` |
| `GITHUB_OWNERS` | `github.owners` |
| `CLUSTER` | `cluster` |
| `IN_CLUSTER` | `true` when `recovery.enabled` — the one thing left that asks the API server anything |
| `RECOVERY_ENABLED`, `RECOVERY_SERVICE_ACCOUNT`, `RECOVERY_AUDIENCE` | `recovery.*` |
| `TOKEN_LIFETIME`, `REFRESH_LIFETIME`, `HOLD_WINDOW` | `lifetimes.*` |
| `SESSION_LIFETIME` | `directory.sessionLifetime` |
| `LOGIN_DIRECTORY` | `directory.login` |
| `POLICY_DIR` | where the policy is mounted; every YAML file in it merges. **Both halves read this one directory**, and the merged service loads it once and hands the same policy to both — two halves that could disagree about the policy is the failure the merge existed to end |
| `LOG_LEVEL` | `logLevel` |

## Roles

Two roles, held by membership of two declared internal groups.

| Role | Group | May |
|---|---|---|
| viewer | `hub-viewers` | every read: `ListWorkspaces`, `GetSettings`, `GetPolicy`, `WhoAmI`, `Explain`, `ListDirectoryGroups`, `GetDirectoryGroup`, `SearchPeople`, `ListHolders` — the whole console, read-only |
| operator | `hub-operators` | everything: Connect, Reconnect, UploadKey, Probe, Refresh, Disconnect, SetOAuthClient, AddMembership, RemoveMembership |

Behind a gateway that forwards a token, the forwarded identity's email is
resolved through the directory like any other; the groups in the token
itself are not consulted, because the directory is the source they came
from.

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
a single-node cluster in the service's namespace is enough:

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

Not a dependency of this service — one way a deployment can put a
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
