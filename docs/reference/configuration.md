# access-issuer — chart and configuration

How the service is configured: the chart's boundary, its values, the
overlay format, the Kubernetes objects it owns, the roles, and the two
things it expects the deployment to provide.

**One chart, `charts/access-issuer`, for one service.** It renders the
whole of access-roster — the directory, the policy, the OpenID provider,
the login page and the console — and, when enabled, the GitHub
controller beside it. It keeps no audit trail of its own: it records
into an installation of [truvity/audit](https://github.com/truvity/audit)
that the deployment provides, and reads that installation's query service
for the console's Audit page.

## What the chart includes, what it expects

| Included (standard Kubernetes APIs) | Expected to exist |
|---|---|
| Deployment, Service, ServiceAccount + namespaced Role/RoleBinding (with the Kubernetes store) + a cluster-scoped TokenReview role (with recovery), NetworkPolicy, the policy / overlay / federated-cluster / GitHub App catalogue, a Gateway and two `HTTPRoute`s — one for the issuer's own endpoints and one for the console's path — and, only where a `push` block is written, External Secrets `PushSecret`s | a **Valkey** to point at; the Secrets a declared workspace, a declared OAuth client or an externally delivered signing key name; External Secrets and the store each `push` block names |

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
service writes *itself*, where it is the producer and gets to choose.

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
| `signingKey.existingSecret` / `.key` | `""` / `tls.key` | a Secret holding a PEM private key -- RSA, or ECDSA on P-256, P-384 or P-521. Empty renders a cert-manager `Certificate` instead. **Never minted by the service**: two replicas with two keys hand out tokens half the fleet cannot verify |
| `signingKey.certificate.issuerName` / `.issuerKind` | `selfsigned` / `ClusterIssuer` | the cert-manager issuer that produces the key, when no `existingSecret` is named. The certificate is a by-product; only the key is used |
| `signingKey.certificate.algorithm` / `.size` / `.encoding` | `ECDSA` / `384` / `PKCS8` | the key, and so what the issuer signs with: RSA signs RS256, and P-256, P-384 and P-521 sign ES256, ES384 and ES512. It is what discovery advertises, so every relying party has to accept it. ECDSA takes 256, 384 or 521; RSA takes 2048, 3072 or 4096; PKCS1 encodes only RSA. A combination cert-manager would not issue is refused at render. Changing it is just a rotation — the JWKS carries both kinds during the overlap |
| `signingKey.certificate.renewBefore` / `.duration` | `720h` / `8760h` | how long before expiry cert-manager replaces the key, and the certificate's life. A renewal is a **new key** (`rotationPolicy: Always`). `renewBefore` only decides how OFTEN that happens; `signingKey.rotation.overlap` is what has to be kept longer than `lifetimes.token` |
| `signingKey.rotation.pollInterval` / `.activationDelay` / `.overlap` | `30s` / `15m` / `lifetimes.token` + 5m | live rotation, with no restart: each replica polls the mounted file, publishes a newly seen key immediately but signs with it only after `activationDelay` — long enough for every replica's kubelet to have projected the same update and longer than the longest JWKS cache among your verifiers (Envoy's default is 10 minutes) — and keeps a superseded key published for `overlap` before it drops out. The schedule for a given key is decided once and shared through Valkey when one is configured, so a restarted replica does not forget a key still inside its overlap |
| `directory.store` | `kubernetes` | where connected workspaces and their credentials are kept. `memory` makes a restart a fresh installation, which is right for a laptop and nothing else |
| `directory.freshness.refreshInterval` | `15m` | how often the refresher takes a new snapshot per workspace |
| `directory.freshness.freshnessWindow` | `30m` | how old a snapshot may be before its domains stop being authoritative |
| `directory.freshness.probeInterval` | `5m` | how often a credential is probed and the domain list re-read |
| `directory.sessionLifetime` | `12h` | how long the console's own session lasts |
| `directory.login` | `true` | whether the console offers a sign-in of its own, under `<mount>/login`. With `console.client` set it is a second door: the issuer's page is the one people use |
| `directory.workspaces[]` | `[]` | declared workspaces, see below |
| `directory.push` | absent | a **recovery copy** of `Secret <release>-workspace-credentials`: `{secretStore: {name, kind}, remoteKey, refreshInterval}` renders `PushSecret <release>-workspace-copy`, which writes the whole Secret as one JSON object at `remoteKey` — bundled, because the keys inside are `<workspace-id>.json` and a reconnect mints a new id, so a per-key mapping would go stale while reporting healthy. `kind` defaults to `SecretStore`, `refreshInterval` to `1h`; `deletionPolicy` is fixed at `None`, because the case this exists for is the Secret going away. Refused at render without `directory.store: kubernetes`, without a store or a key, or for two pushes sharing one path. It is a push and not an `ExternalSecret` because the service is the writer: a pull would let a stale copy overwrite a freshly connected workspace. What lands there **is** the credential |
| `githubApps.catalogue[]` | `[]` | GitHub Apps declared as data — `{id, org, name, description, public, permissions, events, installation, grants, push}` each — created and installed by an operator on the GitHub page (Apps, then Catalogue). Rendered to `ConfigMap <release>-github-apps-catalogue`; the service refuses to start on a malformed entry or a grant naming a group the policy does not declare. A default set to copy ships as the chart's `examples/github-apps.yaml`. See [connect/github-apps-catalogue.md](../connect/github-apps-catalogue.md) |
| `githubApps.catalogue[].grants[]` | `[]` | who may ask for that App's installation tokens, and for how much: `{group, repositories[], permissions{}}` each. `group` is an internal group the policy declares; `repositories` are names in the App's organisation, `["*"]` for all; `permissions` is `{name: level}`. A request is served by the first grant, in catalogue order, that covers all of it ([contract](contracts.md#installation-tokens-at-token)) |
| `githubApps.catalogue[].push` | absent | copy one App's credential to a secret store: `{secretStore: {name, kind}, remoteKey, refreshInterval, deletionPolicy}` renders `PushSecret <release>-github-app-<id>`, which writes `app_id`, `installation_id` and `private_key` at `remoteKey` — that App's three property keys and nothing else. Off unless written, and refused at render for two entries sharing one path in one store, or without `directory.store: kubernetes`. The copy is a real credential, rotated as one. See [connect/infrastructure-as-code.md](../connect/infrastructure-as-code.md) |
| `githubApps.push` | absent | a **recovery copy** of `Secret <release>-github-apps` — the link App and one App per bound organisation, the identities this service acts as — with the same shape and rules as `directory.push`, rendering `PushSecret <release>-github-apps-copy`. Distinct from `catalogue[].push`, which copies one catalogue App's three keys for a consumer that must act as it; this copies the service's own Apps, and only so they can be restored. An App cannot be re-created with its old id, so losing them means every grant rebinds and every installation is re-authorised by hand |
| `githubRunnerApps.tiers` | `[]` | the runner tiers an operator may create a runner App for on the GitHub page (Apps), one App per bound organisation per tier — e.g. `[preview, stable]`. Empty creates none. The Apps are kept in `Secret <release>-github-runner-apps` for the deployment to hand to its runners |
| `oauthClient.secret.name` | `""` | a Secret holding the client for sign-in and admin consent. Empty means nobody can sign in and this installation issues tokens to machines only, which is a real posture and is said at start |
| `oauthClient.secret.keys.clientId` / `.clientSecret` | `client-id` / `client-secret` | **what those keys are called in that Secret.** Configurable because the service does not produce this object: whatever delivers it already had an opinion, and a chart that insisted on two names could not read a Secret already in the namespace |
| `console.mount` | `/console` | where the console sits on this origin. A **path** and not a host, because discovery must be at the root of the origin named in every token's `iss`. It is also what the console prefixes onto every link it hands a browser — `/login` resolves against the origin, where the issuer's page is. Empty serves no console |
| `console.client` | `""` | the declared client the console signs people in as. Somebody with no session is sent to `/authorize`, signs in at the issuer's page, and comes back with the issuer's session set. Its `redirects` must name this origin plus the mount with a trailing slash. Empty keeps the console's own page, which in a deployment with an issuer beside it is a second door |
| `console.origin` | `""` | the one **other** origin allowed to call `SessionService` from a browser. Obsolete on one origin, which is the shipped shape; it remains for a console served from somewhere else |
| `exchange.audience` | the release name | the audience a workload's ServiceAccount token must be minted for. Without one, every mounted token in every federated cluster would be a proof |
| `exchange.clusters[]` | `[]` | the clusters whose workloads may exchange: `{name, issuer, jwksUri}` per cluster, verified against the key set that cluster publishes. **No secret in any row**, and this service holds access to no cluster — including its own, which is a row like any other |
| `github.owners[]` | `[]` | the GitHub organisations whose workflows may exchange. **Empty verifies no CI token at all**, deliberately: anybody may run a workflow in their own repository and get a valid GitHub token, so a list invented by the chart would admit every repository there is |
| `cluster` | `""` | what this cluster is called, which becomes part of a ServiceAccount's subject. Empty keeps the older unqualified form |
| `lifetimes.token` / `.refresh` / `.hold` | `1h` / `12h` / `4h` | how long a token lives, how long a refresh lives, and how long a signed-in identity keeps its last granted role while the directory cannot vouch. Caps: the policy may ask for shorter |
| `recovery.enabled` | `true` | the way in for the day the ordinary one is broken. It stores nothing: a short-lived ServiceAccount token proving access to the API server, so the authority is the cluster's own RBAC. **The only thing left that asks the cluster anything** |
| `recovery.serviceAccountName` | `<release>-recovery` | the account recovery proves access as; the chart creates it, bound to nobody. Granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |
| `recovery.audience` | `<release>-recovery` | the audience the token must be minted for. Without one, every mounted ServiceAccount token in the cluster would be a recovery token |
| `route.host` | `""` | the hostname on the gateway. Empty renders no Gateway, HTTPRoute or Certificate, which is right for an installation reached by port-forward |
| `route.rootRedirect` | `""` | where a bare GET of the host goes. The issuer serves nothing at `/` — every endpoint it answers is a named one — so point this at `/console/` and somebody who types the domain lands somewhere useful |
| `route.gatewayClassName`, `route.certificate.issuerName` / `.issuerKind` | `internal`, `internal-ca` / `ClusterIssuer` | which class the Gateway joins, and who issues its TLS certificate |
| `route.certificate.privateKey` | `{}` | the key that TLS certificate is issued for: `{algorithm, size, encoding, rotationPolicy}`, cert-manager's own fields. Empty leaves every one to cert-manager's defaults, an RSA 2048 key. Set it when the issuer will only sign one kind of key — a PKI role pinned to an algorithm refuses at issuance, long after the render succeeded, and the listener stays dark with the reason on the `CertificateRequest`. The same combinations as the signing key are refused at render |
| `route.sharedWith[]` | `[]` | namespaces besides this one allowed to attach an HTTPRoute to this Gateway. A **gateway-level** admission, not a ReferenceGrant: whether a Gateway accepts a route from another namespace is entirely its own `allowedRoutes` |
| `route.parentRefs[]` | `[]` | parents for the issuer's routes, written out in full (e.g. a platform `ListenerSet` carrying `route.host`). When set the chart renders **no Gateway and no TLS Certificate**: the parent owns the listener and its certificate, and `gatewayClassName`, `certificate` and `sharedWith` have no effect. Write `group` and `kind` out |
| `policy` | `{}` | the declared policy, see [policy.md](policy.md) |
| `networkPolicy.enabled` | `false` | |
| `networkPolicy.clients[]` | `[]` | namespaces allowed to reach the service in-cluster: the proxies verifying tokens and the workloads exchanging them |
| `networkPolicy.gatewayNamespace` | `""` | the gateway's namespace, admitted to the service's port besides `clients`. Empty admits no gateway, so with the policy enabled nothing with a browser reaches it |
| `serviceAccount.annotations` | `{}` | annotations on the ServiceAccount, which is how a cloud identity reaches this service: an admission webhook (EKS Pod Identity, GKE Workload Identity, the self-hosted `amazon-eks-pod-identity-webhook`) reads one and injects credentials into every pod using the account. Without it a self-hosted installation cannot give the service an AWS identity, and `audit.s3` has nothing to authenticate with; the chart mounts no credential of its own and takes none as a value. On AWS: `eks.amazonaws.com/role-arn: <the role's ARN>` |
| `githubRoster.enabled` | `false` | render the GitHub controller beside the service. Refused without an `exchange.clusters` row for this cluster or a `console.mount`, because either is a controller that can read nothing |
| `githubRoster.actsIn[]` | `[]` | the organisations the controller **changes**. Every other bound organisation is derived and reported, and left alone: an organisation is born disabled |
| `githubRoster.interval` | `15m` | how long between passes |
| `githubRoster.image.repository` / `.tag` | `ghcr.io/truvity/access-roster/github-roster` / app version | from the same release as the service |
| `audit.writer` | `""` | the audit installation's receiver: one address, which takes the records and answers the catalogue's registration on the same port. Set, the service and the controller record into it, each with its own projected token; empty, nothing is kept beyond the log line every record also is. The installation must map both service accounts to the source `roster` |
| `audit.query` | `""` | the installation's query service, for the console's Audit page; empty shows no page |
| `audit.audience` | `audit` | the policy client whose audience the Audit page's tokens carry. The policy must declare it, requiring the groups that may read the trail; the query service's grants must trust this issuer with it |
| `audit.token.audience` / `.expirationSeconds` | `audit` / `3600` | the projected token presented to the receiver |
| `audit.forwardedForTrustedHops` | `0` | how many of the deployment's own proxies append to `X-Forwarded-For` in front of the service. A record's client address is the entry just left of them, read from the right; the left end is whatever a caller sent, so the first entry is never taken. `0` records the connection's peer. Behind an edge that appends the client and a gateway that appends the edge's connector, it is `1` |
| `telemetry.otlpEndpoint` | `""` | the collector's OTLP/HTTP endpoint for metrics, from the service and the controller. Empty exports nothing and opens no listener |
| `image.pullPolicy`, `serviceAccount.name`, `resources`, `podAnnotations`, `nodeSelector`, `tolerations`, `githubRoster.image.pullPolicy`, `githubRoster.resources` | | passthrough |
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
read-only. The service merges declared workspaces with the ones connected
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

**There is no directory API listener.** It went with the merge:
the issuer was its only consumer and is now the same process, so the
question a consumer used to ask over the network is a function call.
What the grant model protected is not lost, only unused; the shape stays
written down in [design/trust.md](../design/trust.md#admission-is-not-authorization)
for the day something needs it.

The one machine that reads the directory's answers today, the GitHub
controller, asks the **console's** API — `Explain`, `ListHolders` — with
its own ServiceAccount token, verified against its cluster's published
key set, and the policy's `service_account` matchers put it in
`all:access-roster:viewer`. Any other workload may do the same.

A service that needs to know who somebody is does not ask the directory
at all: it verifies the issuer's token with the `identity` package and
reads the `groups` claim. That is [../connect/service-to-service.md](../connect/service-to-service.md).

## The policy

The service loads the family's [policy](policy.md) — `groups`,
`claims`, `lifetimes`, `clients` and `github` — from the deployment's
ConfigMap(s). There is one layer: the console is read-only, so
nothing it does can add to what is declared here. The chart renders the
policy from `policy:` in values, which is the same YAML:

```yaml
policy:
  groups:
    all:access-roster:operator: { members: [platform-admins@example.com] }
    all:access-roster:viewer:   { members: [all@example.com] }
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
| `Secret <release>-workspace-credentials` | one entry per console-connected workspace, key `<tenant>.json`: the credential (refresh token, or service-account key) and a copy of the workspace's record without its health | the service (Connect, UploadKey), created empty at start. Releases before 1.7 kept a `Secret <release>-credential-<tenant>` each; start-up moves them in |
| `Secret <release>-oauth-client` | OAuth client id and secret | declared via `oauthClient.secret.name` and read-only. The console used to be able to write one; it cannot since the console became read-only, because a credential a console can change is one somebody can change from a browser |
| `Secret <release>-session-key` | signs the session cookie and the consent-flow state | the service, generated on first start; rotate by deleting |
| the signing key | a PEM private key, mounted as a file | **not the issuer** — cert-manager issues one, or external-secrets delivers one. The issuer reads it from the file, never through the API; its key id is the key's own RFC 7638 thumbprint, so nothing has to carry one beside it |
| `ConfigMap <release>-policy` | the declared layer of the policy, plus the console's own settings and the consumer allow-list | the chart |
| `ConfigMap <release>-overlay` | the declared workspaces | the chart |
| `ConfigMap <release>-clusters` | the clusters whose workloads may exchange, each a name and the URL of the key set it publishes. **No secret in any row** | the chart |
| `ConfigMap <release>-github-apps-catalogue` | the declared GitHub App catalogue, `catalogue.yaml`. **No secret in it** | the chart, when `githubApps.catalogue` is not empty |
| `PushSecret <release>-github-app-<id>` | the instruction to copy one catalogue App's `app_id`, `installation_id` and `private_key` to the store and path its entry names — that App's three property keys and nothing else. **What lands there is the App's key**, a second durable copy, rotated as one | the chart, for each `githubApps.catalogue` entry carrying `push`; External Secrets does the copying |
| `PushSecret <release>-workspace-copy` | the instruction to copy the whole of `Secret <release>-workspace-credentials`, every key as one JSON object, to the store and path `directory.push` names. A recovery copy: restoring is an operator writing it back, deliberately. `deletionPolicy: None`, so the copy outlives the Secret it is for | the chart, when `directory.push` is written; External Secrets does the copying |
| `PushSecret <release>-github-apps-copy` | the same for `Secret <release>-github-apps` — the link App and one App per bound organisation — to where `githubApps.push` names | the chart, when `githubApps.push` is written; External Secrets does the copying |
| `ConfigMap <release>-github-status` | the GitHub controller's last report, one document per organisation | created empty by the service at start; its data replaced by the controller, which is granted this one name |
| `ConfigMap <release>-github-orgs` | one record per connected GitHub organisation: App id and slug, installation, connected by and at | the service (Connect a GitHub organisation), created empty at start |
| `Secret <release>-github-apps` | one credential per connected organisation: the App's id, installation and private key, and a copy of the organisation's record; the link App's likewise | the service (Connect), created empty at start so the controller's volume always has a Secret behind it; read by the service only to uninstall on Disconnect |
| `Secret <release>-github-links` | one link per GitHub account (`<id>.json`): its login, the addresses it proves, its state, the person's token pair | the service, which writes a link; the controller, which rewrites it as it checks — the one Secret its Role may update, by name |
| `Secret <release>-github-runner-apps` | every runner App. An installed App is `<tier>.<org>.github_app_id`, `.github_app_installation_id` and `.github_app_private_key` — the names gha-runner-scale-set's `githubConfigSecret` reads — beside `<tier>.<org>.record.json`. An App created and not yet installed has its record and `<tier>.<org>.pending_private_key` only, so a copy never hands runners an App they cannot register with | the service (a runner App's Create and Install), created empty at start; read by the service only to find the installation and to uninstall on Disconnect. A deployment copies the three keys to its runners, for example with an External Secrets `PushSecret` |
| `Secret <release>-github-catalogue-apps` | every catalogue App, by its catalogue id. An installed App is `<id>.github_app_id`, `<id>.github_app_installation_id` and `<id>.github_app_private_key` beside `<id>.record.json` (`version, id, org, app_id, app_slug, installation_id, html_url, connected_at, connected_by`). An App created and not yet installed has its record and `<id>.pending_private_key` only | the service (a catalogue App's Create and Install), created empty at start; read by the service to ask GitHub, as the App, what the App and its installation hold, and to uninstall on Disconnect. A deployment copies it for backup, for example with an External Secrets `PushSecret`; one App's three property keys are projected to a store by `githubApps.catalogue[].push` |

The record and the credential are two objects on purpose. A record is
shown to anyone who may see the console; a credential is written once and
read once, at start. Keeping them apart means the type the console handles
cannot carry a secret by accident, and it makes the failure modes
independent: a record whose credential is missing is a workspace with no
reader, which the console shows as unhealthy with the reason — not a service
that will not start.

Labels on every service-written object: `app.kubernetes.io/managed-by=directory-roster`,
`app.kubernetes.io/part-of=<release>`, and
`access-roster.truvity.github.io/kind` = `workspace`, `workspace-credentials`,
`settings`, `github-status`, `github-orgs` (both the records ConfigMap and
the Apps Secret), `github-links`, `github-runner-apps`, `github-catalogue-apps`, or `credential`
on a per-workspace Secret a release before 1.7 wrote. The workspace id as the backend spells it is the annotation
`access-roster.truvity.github.io/workspace-id`. Releases before these keys
wrote the kind label and the annotation under an older prefix; the service
moves every object of its release to the keys above when it starts, before
it reads any of them, so an upgrade, or a restore of objects an older
release wrote, needs no step of its own (a rollback past it does: see the
CHANGELOG). Export everything with

```sh
kubectl -n directory-roster get secret,configmap -l app.kubernetes.io/managed-by=directory-roster -o yaml
```

### Restoring from the Secrets alone

Five Secrets hold everything a console added that cannot be minted again,
each under a name a deployment knows in advance:

- `<release>-workspace-credentials`;
- `<release>-github-apps`;
- `<release>-github-links`;
- `<release>-github-runner-apps` and `<release>-github-catalogue-apps`,
  whose records are already beside their keys.

A deployment backs them up by copying those five objects. The chart
renders the copy for two of them — `<release>-workspace-credentials`
through [`directory.push`](#values) and `<release>-github-apps` through
[`githubApps.push`](#values), each an External Secrets `PushSecret` of
the whole Secret under one remote key — because those two are the ones
nothing upstream can re-deliver; the other three are a `PushSecret` of
the deployment's own. Nothing in the service depends on the copy.

Each credential carries a copy of its record. So after the five Secrets
are put back into an empty namespace, the next start does the rest before
reopening anything:

- it restores every console-connected workspace's ConfigMap;
- it restores every GitHub organisation's record and the link App's.

A restored workspace shows as never probed until its first probe. A link
token may have rotated since the copy; that person links again. A
declared Secret is re-delivered by whatever declared it.

**`STORE=memory`** turns all of it off: nothing is written, and a restart
is a fresh installation. It is the default for the binary, because a local
run and the demonstration should need no cluster; the chart always sets
`kubernetes`. A service started on the memory store says so at WARN on its
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
| `SIGNING_KEY_POLL_INTERVAL`, `SIGNING_KEY_ACTIVATION_DELAY`, `SIGNING_KEY_OVERLAP` | `signingKey.rotation.*` — live rotation with no restart; `SIGNING_KEY_OVERLAP` unset falls back to `TOKEN_LIFETIME` |
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
| `GITHUB_RUNNER_TIERS` | `githubRunnerApps.tiers`, comma-separated, set only when not empty |
| `CLUSTER` | `cluster` |
| `IN_CLUSTER` | `true` when `recovery.enabled` — the one thing left that asks the API server anything |
| `RECOVERY_ENABLED`, `RECOVERY_SERVICE_ACCOUNT`, `RECOVERY_AUDIENCE` | `recovery.*` |
| `TOKEN_LIFETIME`, `REFRESH_LIFETIME`, `HOLD_WINDOW` | `lifetimes.*` |
| `SESSION_LIFETIME` | `directory.sessionLifetime` |
| `LOGIN_DIRECTORY` | `directory.login` |
| `POLICY_DIR` | where the policy is mounted; every YAML file in it merges. **Both halves read this one directory**, and the merged service loads it once and hands the same policy to both — two halves that could disagree about the policy is the failure the merge existed to end |
| `AUDIT_WRITER_URL`, `AUDIT_QUERY_URL`, `AUDIT_AUDIENCE`, `AUDIT_FORWARDED_FOR_TRUSTED_HOPS` | `audit.*` |
| `AUDIT_TOKEN_FILE` | the projected token, mounted when an installation is connected. Set on the GitHub controller as well, with its own token |
| `POD_NAME` | the pod's name, from the downward API: names the instance on every audit record |
| `CLIENT_SECRETS_DIR` | where the confidential clients' Secrets are mounted, one file per client |
| `GITHUB_APPS_CATALOGUE_FILE` | the mounted `githubApps.catalogue`, set only when not empty. Read once at start; a malformed catalogue stops the service |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `telemetry.otlpEndpoint`, set only when not empty. Metrics are pushed over OTLP/HTTP; with nothing set, nothing is exported and no listener is opened. Every other `OTEL_*` variable OpenTelemetry defines is honoured too. Set on the GitHub controller as well |
| `LOG_LEVEL` | `logLevel` |

## The GitHub controller's environment

The controller reads its own few, all set by
`templates/github-roster.yaml`:

| Variable | From |
|---|---|
| `RELEASE_NAME` | the chart's full name, so it finds `<release>-github-status` |
| `NAMESPACE` | the pod's namespace |
| `POLICY_DIR` | the same policy ConfigMap the service mounts; its `github` table is the bindings |
| `CONSOLE_URL` | the service's in-cluster address plus `console.mount` |
| `TOKEN_FILE` | the projected ServiceAccount token, for `exchange.audience`, read on every call |
| `APPS_DIR` | the mounted `<release>-github-apps` Secret, one file per connected organisation |
| `INTERVAL` | `githubRoster.interval` |
| `ENABLED_ORGS` | `githubRoster.actsIn` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `telemetry.otlpEndpoint`, set only when not empty |
| `LOG_LEVEL` | `logLevel` |

Its account, `<release>-github-roster`, has two permissions, each by
name: `get`, `update` and `patch` on the ConfigMap
`<release>-github-status` it reports into, and `get` and `update` on the
Secret `<release>-github-links` it rewrites as it checks links. The App
keys are a volume, so it holds no permission to read any other Secret.

## Roles

Two roles, held by membership of two declared internal groups.

| Role | Group | May |
|---|---|---|
| viewer | `all:access-roster:viewer` | every read: `ListWorkspaces`, `GetSettings`, `GetPolicy`, `WhoAmI`, `Explain`, `ListDirectoryGroups`, `GetDirectoryGroup`, `SearchPeople`, `ListHolders`, `GetGitHubStatus`, `ListGitHubApps`, `GetGitHubApp` for anybody else (one's own reach, like `Explain` of oneself, needs no role), and listing one's own sessions — the whole console, read-only |
| operator | `all:access-roster:operator` | everything: Connect, Reconnect, UploadKey, `SetServedDomains`, `SetSyncedGroups`, Probe, Refresh, Disconnect, the GitHub connects and disconnects, `ListGitHubAppTokens` (a request names who asked), `ConfirmGitHubRemovals`, `ImportGitHubLinks`, listing and revoking anyone's sessions |

Behind a gateway that forwards a token, the forwarded identity's email is
resolved through the directory like any other; the groups in the token
itself are not consulted, because the directory is the source they came
from.

## The repository

access-roster ships from one repository: the `access-issuer` chart with
its two images — the service and the GitHub controller — the
`access-proxy` chart, `accessctl`, the GitHub Action, the Go module and
the TypeScript package, all stamped with one tag. Shared Go packages —
the backends, the policy engine, the verifiers, the exchange — are
importable behind interfaces.

## Valkey: a recommendation

Any Valkey or Redis-protocol server reachable from the namespace works.
The service stores one key set per workspace (the snapshot, its timestamp, a
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
service ships an `HTTPRoute` (console slice) attaching to a Gateway the
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
