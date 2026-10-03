# access-issuer — chart and configuration

How the service is configured: the chart's boundary, its values, the
overlay format, the Kubernetes objects it owns, the roles, and the two
things it expects the deployment to provide.

**One chart, `charts/access-issuer`, for one service.** It renders the
whole of access-roster — the directory, the policy, the OpenID provider,
the login page and the console — and, when enabled, the GitHub
controller and the Slack controller beside it. It keeps no audit trail of its own: it records
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

Two things it will not do. **It does not create the signing key** —
cert-manager issues one, or `signingKey.existingSecret` names one (RSA, or
ECDSA on P-256, P-384 or P-521) external-secrets delivered — because a
service that mints its own credential is an exception to how every other
credential in this estate is provisioned. And **it puts no authenticating
proxy in front**: this is the thing that authenticates, and a proxy would
have nowhere to send anyone.

**The convention that follows from that:** every value
that consumes a Secret this chart did not create lets you name both **the
Secret and the keys inside it**. The producer is free — external-secrets, a
1Password operator, sealed-secrets, a hand `kubectl create secret`, a Job —
because a chart that dictated key names could not read a Secret already
sitting in the namespace. Key names are only ever fixed for a Secret the
service writes *itself*, where it is the producer and gets to choose.

## Values

| Value | Default | Meaning |
|---|---|---|
| `config` | see [the file](#the-configuration-file) | **the service's configuration**, rendered as it stands into the ConfigMap `<release>-config` and mounted at `/etc/access-issuer/config.yaml`. Validated by `values.schema.json` against the schema the binary uses. Everything the service decides is here (the issuer URL, lifetimes, the store, Valkey, recovery, audit, the signing key's rotation); `issuerURL` is **required** and has no default, because one would be a value nobody chose spread across an estate |
| `secretEnv[]` | `[]` | the only way a secret reaches a process: `{name, secretName, key, optional}` puts a Secret's key in the variable `name`, which the config names (`valkey.passwordEnv`, `oauthClient.secretEnv`, `adminPasswordEnv`). A secret is never in `config` |
| `secretMounts[]` | `[]` | `{secretName, mountPath}`: a Secret mounted read-only as a directory, for a file the config names by path (`oauthClient.idFile`, `oauthClient.secretFile`). Each key is a file |
| `githubRoster.config` | see [the file](#the-configuration-file) | the GitHub controller's configuration, rendered as it stands into `<release>-github-roster-config`. `consoleURL` is required, and is this release's own Service |
| `slackRoster.config` | see [the file](#the-configuration-file) | the Slack controller's, into `<release>-slack-roster-config` |
| `replicaCount` | `2` | two replicas need Valkey; one may use the in-memory store. Every replica serves every workspace, including one connected through the console on the other replica: a reader missing locally is opened from the stored credential on first use |
| `image.repository` / `tag` | `ghcr.io/truvity/access-roster/access-issuer` / app version | |
| `signingKey.existingSecret` / `.key` | `""` / `tls.key` | a Secret holding a PEM private key -- RSA, or ECDSA on P-256, P-384 or P-521. Empty renders a cert-manager `Certificate` instead. **Never minted by the service**: two replicas with two keys hand out tokens half the fleet cannot verify |
| `signingKey.certificate.issuerName` / `.issuerKind` | `selfsigned` / `ClusterIssuer` | the cert-manager issuer that produces the key, when no `existingSecret` is named. The certificate is a by-product; only the key is used |
| `signingKey.certificate.algorithm` / `.size` / `.encoding` | `ECDSA` / `384` / `PKCS8` | the key, and so what the issuer signs with BY DEFAULT: RSA signs RS256, and P-256, P-384 and P-521 sign ES256, ES384 and ES512. ECDSA takes 256, 384 or 521; RSA takes 2048, 3072 or 4096; PKCS1 encodes only RSA. A combination cert-manager would not issue is refused at render. The default P-384 key means ES384 for every audience that pins no `signing_alg` of its own — for the one relying party that lags (Kargo; EKS's associated OIDC provider; both RS256-only), pin **that audience's** policy row instead of this whole installation's default; see `signingKey.additional` below and [policy.md#signing-algorithm-per-audience](policy.md#signing-algorithm-per-audience). Changing THIS value changes the default for every audience that names none, and is not "just a rotation" the way adding a `signingKey.additional` entry is: every other algorithm now lives on its own track, and this value decides which one is "the default" |
| `signingKey.additional[]` | `[]` | every OTHER algorithm this installation signs with AT THE SAME TIME as the default above: `{algorithm, size, encoding, issuerName, issuerKind, renewBefore, duration}`, one cert-manager `Certificate` and `Secret` per entry, each on its OWN rotation track — renewing one never disturbs another's schedule, including the default's. Two entries (or one entry and the default) naming the same algorithm are refused at render: each algorithm publishes only one key at a time. This is how a client or a resource's `signing_alg` (RS256, ES256 or ES384 — [policy.md#signing-algorithm-per-audience](policy.md#signing-algorithm-per-audience)) has a key to actually sign with; naming an algorithm nothing here configures is refused **at issuer start**, not on the first request that reaches it |
| `signingKey.certificate.renewBefore` / `.duration` | `720h` / `8760h` | how long before expiry cert-manager replaces the key, and the certificate's life. A renewal is a **new key** (`rotationPolicy: Always`). `renewBefore` only decides how OFTEN that happens; `config.signingKey.overlap` is what has to be kept longer than `config.lifetimes.token` |
| `directory.workspaces[]` | `[]` | declared workspaces, see below |
| `directory.push` | absent | a **recovery copy** of `Secret <release>-workspace-credentials`: `{secretStore: {name, kind}, remoteKey, refreshInterval}` renders `PushSecret <release>-workspace-copy`, which writes the whole Secret as one JSON object at `remoteKey` — bundled, because the keys inside are `<workspace-id>.json` and a reconnect mints a new id, so a per-key mapping would go stale while reporting healthy. `kind` defaults to `SecretStore`, `refreshInterval` to `1h`; `deletionPolicy` is fixed at `None`, because the case this exists for is the Secret going away. Refused at render without `directory.store: kubernetes`, without a store or a key, or for two pushes sharing one path. It is a push and not an `ExternalSecret` because the service is the writer: a pull would let a stale copy overwrite a freshly connected workspace. What lands there **is** the credential |
| `githubApps.catalogue[]` | `[]` | GitHub Apps declared as data — `{id, org, name, description, public, permissions, events, installation, grants, push}` each — created and installed by an operator on the GitHub page (the Apps tab: the App's own page). Rendered to `ConfigMap <release>-github-apps-catalogue`; the service refuses to start on a malformed entry or a grant naming a group the policy does not declare. A default set to copy ships as the chart's `examples/github-apps.yaml`. See [connect/github-apps-catalogue.md](../connect/github-apps-catalogue.md) |
| `githubApps.catalogue[].grants[]` | `[]` | who may ask for that App's installation tokens, and for how much: `{group, repositories[], permissions{}}` each. `group` is an internal group the policy declares; `repositories` are names in the App's organisation, `["*"]` for all; `permissions` is `{name: level}`. A request is served by the first grant, in catalogue order, that covers all of it ([contract](contracts.md#installation-tokens-at-token)) |
| `githubApps.catalogue[].push` | absent | copy one App's credential to a secret store: `{secretStore: {name, kind}, remoteKey, refreshInterval, deletionPolicy}` renders `PushSecret <release>-github-app-<id>`, which writes `app_id`, `installation_id` and `private_key` at `remoteKey` — that App's three property keys and nothing else. Off unless written, and refused at render for two entries sharing one path in one store, or without `directory.store: kubernetes`. The copy is a real credential, rotated as one. See [connect/infrastructure-as-code.md](../connect/infrastructure-as-code.md) |
| `githubApps.push` | absent | a **recovery copy** of `Secret <release>-github-apps` — the link App and one App per bound organisation, the identities this service acts as — with the same shape and rules as `directory.push`, rendering `PushSecret <release>-github-apps-copy`. Distinct from `catalogue[].push`, which copies one catalogue App's three keys for a consumer that must act as it; this copies the service's own Apps, and only so they can be restored. An App cannot be re-created with its old id, so losing them means every grant rebinds and every installation is re-authorised by hand |
| `slackState.push` | absent | a **recovery copy** of the Slack state, in the shape of `directory.push` with one more key: `{secretStore: {name, kind}, remoteKey, recordsRemoteKey, refreshInterval}` renders `PushSecret <release>-slack-credentials-copy` (the whole of `Secret <release>-slack-credentials`, at `remoteKey`) and `PushSecret <release>-slack-records-copy` (the whole of `Secret <release>-slack-records`, at `recordsRemoteKey`). Each is bundled under one remote key because the keys inside are `<workspace-id>.json`. `recordsRemoteKey` is required and must differ from `remoteKey`. `kind` defaults to `SecretStore`, `refreshInterval` to `1h`; `deletionPolicy` is fixed at `None`. Refused at render without `directory.store: kubernetes`, without a store or either key, or for two pushes sharing one path. The records are a mirror Secret because they live in a ConfigMap and a `PushSecret` reads Secrets only. What lands there **is** every workspace's credential |
| `slackApps[]` | `[]` | Slack Apps declared as data — `{id, workspace, name, description, botScopes, push}` each — created (with a throwaway app configuration token, used once and never stored) and installed (by an owner of the workspace) by an operator on the console's Slack area (the Apps tab). `id` is `[a-z0-9-]`, at most 32, unique, and never changes; `workspace` is a key of the policy's `slack.workspaces` (lowercase letters, digits and `-`, at most 40, as the policy itself requires); `name` defaults to `<workspace>-<id>`, at most 35; `description` at most 140. Rendered to `ConfigMap <release>-slack-apps-catalogue`; the service refuses to start on a malformed entry or an entry for a workspace the policy does not name. Needs `directory.store: kubernetes`. See [connect/slack-apps-catalogue.md](../connect/slack-apps-catalogue.md) |
| `slackApps[].push` | absent | copy one App's bot token — one key, `bot_token`, never the client secret or the record — to a secret store: `{secretStore: {name, kind}, remoteKey, refreshInterval, deletionPolicy}`, rendering `PushSecret <release>-slack-app-<id>`. Refused at render for two entries sharing one path in one store, or without `directory.store: kubernetes`. The copy is a real credential, rotated as one |
| `console.mount` | `/console` | where the console sits on this origin. A **path** and not a host, because discovery must be at the root of the origin named in every token's `iss`. It is also what the console prefixes onto every link it hands a browser — `/login` resolves against the origin, where the issuer's page is. Empty serves no console |
| `exchange.clusters[]` | `[]` | the clusters whose workloads may exchange: `{name, issuer, jwksUri}` per cluster, verified against the key set that cluster publishes. **No secret in any row**, and this service holds access to no cluster — including its own, which is a row like any other |
| `exchange.aws.accounts[]` | `[]` | the AWS accounts whose IAM roles may exchange their outbound-identity-federation token: `{account, name, issuer, jwksUri, orgId, algs}` per account, verified against the key set that account's issuer publishes. **No secret in any row. Empty verifies no AWS token at all**: any AWS account can mint a valid token for a role of its own, so the row is the trust boundary. See [connect/aws-workloads.md](../connect/aws-workloads.md) |
| `exchange.aws.audience` | the issuer URL | the audience the role must request from `sts:GetWebIdentityToken`; a token for any other is refused |
| `exchange.aws.maxAge` | `5m` | refuse a token whose `iat` is older, whatever its `exp` allows (AWS permits an hour). At most `1h` |
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
| `githubRoster.image.repository` / `.tag` / `.pullPolicy` | `ghcr.io/truvity/access-roster/github-roster` / app version / `IfNotPresent` | from the same release as the service |
| `slackRoster.enabled` | `false` | render the Slack controller beside the service. Refused without an `exchange.clusters` row for this cluster or a `console.mount`, for the same reason. The policy must put the controller's ServiceAccount (`<release>-slack-roster`) in `all:access-roster:viewer`; without it every pass fails on the first read. Roll the console before the controller when upgrading from before 1.42.0 (the controller needs `ListServedDomains`) |
| `slackRoster.image.repository` / `.tag` / `.pullPolicy` | `ghcr.io/truvity/access-roster/slack-roster` / app version / `IfNotPresent` | from the same release as the service |
| `slackRoster.resources` | `{}` | the controller pod's resources |
| `audit.token.audience` / `.expirationSeconds` | `audit` / `3600` | the projected token presented to the receiver |
| `image.pullPolicy`, `serviceAccount.name`, `resources`, `podAnnotations`, `nodeSelector`, `tolerations`, `githubRoster.image.pullPolicy`, `githubRoster.resources` | | passthrough |

**Two routes, and the second is not tidiness.** A gateway policy attaches
to an `HTTPRoute`, so the console's path is a separate object: anything
put in front of the console on a shared route would also sit in front of
`/token`, `/keys` and discovery, and every relying party in the estate
would be asked to sign in to fetch a key set. The console's route renders
whether or not anything attaches to it.

**The mount is not rewritten away** by the gateway, unlike the older
split chart. The service strips it itself, so a gateway that stripped it
too would hand the console a path it never serves.

## Endpoints

**Three grants, and the six things they add up to.** `grant_types_supported`
names exactly `authorization_code`, `refresh_token` and token exchange,
because those are the three grants. The other three of the six — userinfo,
`end_session` and revocation — are ENDPOINTS, and discovery advertises them
in their own fields. They are counted together because they answer the same
question, *what does this issuer serve*, but listing an endpoint under
`grant_types_supported` would be the metadata lying in a new way.

| Path | Standard | Purpose |
|---|---|---|
| `/.well-known/openid-configuration`, `/keys` | OIDC discovery, JWKS | what relying parties read |
| `/authorize`, `/token`, `/userinfo`, `/end_session` | OIDC | login, tokens, RP-initiated logout |
| `/logout` | ours | the same sign-out for a person rather than a relying party, on GET and on POST. It needs no `id_token_hint`, which the console could not supply anyway — it never redeems the code it gets back, so it holds no ID token. The console's sign-out button points here |
| `/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | CI and workload exchange; the requested `audience` is a client, gated by its `requires` |
| `/token`, the same exchange with `requested_token_type=urn:access-roster:params:oauth:token-type:github-installation-token` and `audience=github-app:<id>` | RFC 8693 | a GitHub App installation token of a catalogue App, under its grants ([contract](contracts.md#installation-tokens-at-token)) |
| `/revoke` | RFC 7009 | revokes a refresh token; what Revoke and "sign out everywhere" call underneath |
| `/login`, `/logout`, `/signed-out` | ours | **the whole of the issuer's HTML**: the sign-in chooser — which names the application being signed in to from the client's declared `display_name` and `description`, and the host its redirect returns to, or says a program on this computer is asking when that redirect is loopback ([policy](policy.md#what-the-sign-in-page-calls-a-client)) — the sign-out a person follows, and where a sign-out lands when the client declares no page of its own. Each runs before there is anyone to authorize, which is why none can be a console page. Minimal HTML, same theme |
| `/account` | ours | a redirect into the console's page for the signed-in person. The page itself lived here through 0.11 because it had to be same-origin with `SessionService`; the console is same-origin and now the same process, and its page for a person already lists the sessions and offers *sign out everywhere*. The address stays because it was linked to and bookmarked; the two POSTs behind it are gone |
| `/.access/grants` | ours | the clients the caller's groups admit it to, and which group admits each — read by `accessctl kubeconfig` and `aws-config` so a laptop writes a context per cluster and a profile per role without keeping a list that drifts from the policy. A bearer, and it discloses nothing the caller could not work out from its own token |
| `/.access/simulate` | ours | **not built**: what would this identity get, for somebody other than the caller. The console's Rules page has a simulator that answers it, and `/.access/grants` answers it for the caller's own identity |
| `SessionService` (ConnectRPC): `ListSessions{identity? \| client? \| contains?}` → `{sessions, sign_ins}`, `RevokeSessions{identity, client?, session_id?, sso?}` | ours | sessions per identity and per client, with client, how obtained, issued, expires, last refreshed; revoke per identity, per client, or one. Listing and revoking others is operator; listing and revoking your own is any signed-in identity; listing **every** session (neither identity nor client named) is operator-only, paged by `page_size`/`page_token`, and audited. `contains` reads `identity` and `client_id` as SUBSTRINGS rather than exact values — prefix, suffix and middle — and is **operator-only**, because a substring names an unknown set where an exact identity names the caller's own or nobody's. `RevokeSessions` has no such field: a revoke scoped to *anything containing this* is the control that ends more than its caller meant, with no undo. Authorized by the browser's SSO cookie on a same-origin call — which is what the console is — or by a bearer. The `console.origin` CORS gate is unused on one origin, which is the shipped shape, and stays empty there; it remains for a console served from somewhere else, and is the one other origin admitted |
| back-channel logout | OIDC Back-Channel Logout 1.0 | opt-in per client with `backchannel_logout_uri`: a signed `logout+jwt` POSTed to every such client that signed the person in, by the `sid` it saw, when the sign-in ends |
| not served | RFC 8628 device flow, client credentials, RFC 7523 JWT bearer, RFC 7662 introspection, implicit and hybrid flows, session-management iframe, RFC 7591 dynamic client registration | The first three were served through 0.11 and are gone: the device flow is for a machine with no browser, and both headless cases here — a CI job and a workload — are token exchange; client credentials is a machine with a stored secret, which is the thing this design exists not to have; JWT bearer is token exchange with a different spelling, and two ways to say one thing is two things to keep truthful. Introspection never applied — these are JWTs, verified offline against the key set. RFC 7591 is deliberate and stays refused — the Model Context Protocol deprecated it in favour of Client ID Metadata Documents, which this issuer serves instead when `client_documents` names an origin: no endpoint, nothing stored, and an allow-list that keeps the set of origins answerable by reading the repository |

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
| `Secret <release>-slack-records` | a MIRROR of the Slack records ConfigMap `<release>-slack-workspaces`: exactly its `<workspace>.json` records, `_shared.<name>.json` Slack Connect definitions and `_channel.<workspace>.<name>.json` console channel records, never `_confirm.*` or `_pass.*`. It exists because a `PushSecret` reads Secrets only; nothing reads it but the chart's recovery copy and the service's own start | the service, in the same code path that writes the ConfigMap, and reconciled at start. If the ConfigMap holds no record and this Secret does, start repopulates the ConfigMap from it |
| `ConfigMap <release>-slack-workspaces` | one record per connected Slack workspace (`<workspace>.json`), the Slack Connect records (`_shared.<name>.json`), the console channel records (`_channel.<workspace>.<name>.json`), and the transient operator markers: confirmations (`_confirm.*`), pass requests (`_pass.*`) and consumed install states | the service (Connect, the Slack Connect and channel editors, Refresh, Confirm), created empty at start |
| `Secret <release>-slack-credentials` | one entry per connected workspace, `<workspace-id>.json`: the App's client id and secret and, once installed, the bot token | the service (Connect, the install callback), created empty at start; mounted read-only into the Slack controller |
| `Secret <release>-oauth-client` | OAuth client id and secret | declared via `oauthClient.secret.name` and read-only. The console used to be able to write one; it cannot since the console became read-only, because a credential a console can change is one somebody can change from a browser |
| `Secret <release>-session-key` | signs the session cookie and the consent-flow state | the service, generated on first start; rotate by deleting |
| the signing key | a PEM private key, mounted as a file | **not the issuer** — cert-manager issues one, or external-secrets delivers one. The issuer reads it from the file, never through the API; its key id is the key's own RFC 7638 thumbprint, so nothing has to carry one beside it |
| `ConfigMap <release>-policy` | the declared layer of the policy, plus the console's own settings and the consumer allow-list | the chart |
| `ConfigMap <release>-overlay` | the declared workspaces | the chart |
| `ConfigMap <release>-aws` | the AWS accounts whose roles may exchange, each an account id, a name and the issuer URL AWS gave it. **No secret in any row** | the chart, only when `exchange.aws.accounts` is non-empty |
| `ConfigMap <release>-clusters` | the clusters whose workloads may exchange, each a name and the URL of the key set it publishes. **No secret in any row** | the chart |
| `ConfigMap <release>-github-apps-catalogue` | the declared GitHub App catalogue, `catalogue.yaml`. **No secret in it** | the chart, when `githubApps.catalogue` is not empty |
| `PushSecret <release>-github-app-<id>` | the instruction to copy one catalogue App's `app_id`, `installation_id` and `private_key` to the store and path its entry names — that App's three property keys and nothing else. **What lands there is the App's key**, a second durable copy, rotated as one | the chart, for each `githubApps.catalogue` entry carrying `push`; External Secrets does the copying |
| `PushSecret <release>-workspace-copy` | the instruction to copy the whole of `Secret <release>-workspace-credentials`, every key as one JSON object, to the store and path `directory.push` names. A recovery copy: restoring is an operator writing it back, deliberately. `deletionPolicy: None`, so the copy outlives the Secret it is for | the chart, when `directory.push` is written; External Secrets does the copying |
| `PushSecret <release>-github-apps-copy` | the same for `Secret <release>-github-apps` — the link App and one App per bound organisation — to where `githubApps.push` names | the chart, when `githubApps.push` is written; External Secrets does the copying |
| `PushSecret <release>-slack-credentials-copy` | the instruction to copy the whole of `Secret <release>-slack-credentials` to the store and path `slackState.push` names. `deletionPolicy: None` | the chart, when `slackState.push` is written; External Secrets does the copying |
| `PushSecret <release>-slack-records-copy` | the same for `Secret <release>-slack-records`, to `slackState.push.recordsRemoteKey` | the chart, when `slackState.push` is written; External Secrets does the copying |
| `ConfigMap <release>-slack-status` | the Slack controller's last report, one document per workspace | created empty by the service at start; its data replaced by the controller, which is granted this one name (get, update, patch) |
| `ConfigMap <release>-slack-apps-catalogue` | the declared Slack App catalogue (`slackApps`), without `push`. **No secret in it** | the chart, when `slackApps` is not empty |
| `Secret <release>-slack-catalogue-apps` | every catalogue Slack App: `<id>.client_id`, `<id>.client_secret` and, once installed, `<id>.slack_bot_token`, beside `<id>.record.json` | the service (a catalogue App's Create and Install), created empty at start |
| `PushSecret <release>-slack-app-<id>` | the instruction to copy one catalogue Slack App's bot token (property `bot_token`, nothing else) to the store and path its entry names. What lands there is the token | the chart, for each `slackApps` entry carrying `push` |
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
the Apps Secret), `github-links`, `github-runner-apps`, `github-catalogue-apps`, `slack-workspaces` (the records ConfigMap and the credentials Secret), `slack-records`, `slack-status`, `slack-catalogue-apps`, or `credential`
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

Five Secrets, and the Slack state below, hold everything a console added that
cannot be minted again, each under a name a deployment knows in advance:

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

Slack keeps its state in `<release>-slack-credentials`, `<release>-slack-records`
(a mirror of the records ConfigMap) and `<release>-slack-catalogue-apps`; the
chart renders the copy for the first two through `slackState.push`. Restore:
[runbook, Slack state](../operations/runbook.md#slack-state).

A restored workspace shows as never probed until its first probe. A link
token may have rotated since the copy; that person links again. A
declared Secret is re-delivered by whatever declared it.

**`store: memory`** turns all of it off: nothing is written, and a restart
is a fresh installation. It is the default for the binary, because a local
run and the demonstration should need no cluster; the chart's `config` defaults
to `kubernetes`. A service started on the memory store says so at WARN on its
first line, naming what a restart would lose.

## The configuration file

Each binary is configured by **one YAML file**, given with `--config <file>`,
and by nothing else: `--version` and `--help` are the only other flags.
[0032](../decisions/0032-one-configuration-file-one-binary-one-chart.md) is the
decision, and truvity/policy's
[configuration contract](https://github.com/truvity/policy/blob/master/docs/contracts/config.md)
the rule it follows.

- **Validated before anything starts.** The file is held to its JSON Schema
  (`schemas/config/<binary>.schema.json`, embedded in the binary) first. An
  unknown key, a missing required key or a value of the wrong type refuses to
  start and names the path to it. The chart's `values.schema.json` embeds the
  same schemas under each component's `config`, so the same mistake fails
  `helm install`, and the chart's tests hold what it renders to them.
- **Secrets are the one thing the environment adds, and only the ones the
  file names.** A key ending in `Env` holds the *name* of a variable
  (`valkey.passwordEnv: VALKEY_PASSWORD`), and the process reads exactly the
  variables the file names; an unset or empty one refuses to start, naming the
  variable. A key ending in `File` or `Dir` holds a path. A secret in the file
  is refused: there is no key to put it in, and a URL or address with a password
  in it does not match the schema.
- **Telemetry is not here.** It is OpenTelemetry's own `OTEL_*` environment
  (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, ...), read by the SDK and
  set on the pod by the platform. Nothing in the file restates it.
- **The old environment is refused, not ignored.** A variable of the old
  configuration that is still set (`ISSUER_URL`, `VALKEY_PASSWORD`, ...) stops
  the process at start, naming the key that replaces it. The tables
  [below](#migrating-from-environment-variables) are that list.
- **Durations** are Go duration strings (`30s`, `15m`, `168h`).

The schemas are the exhaustive reference, with every key's description and
default. What follows is the orientation: each key, its default when unset, and
what to know. A key the table gives no default for is unset by default, which
is the binary's own behaviour.

### `access-issuer` (the chart's `config`)

The issuer, the console and the directory hub, one process.

| Key | Default | Meaning |
|---|---|---|
| `issuerURL` | **required** | baked into every token and every relying party's trust. There is no default, because one would be a value nobody chose spread across an estate. An http or https URL with no credentials |
| `release` | `access-issuer` | the name this installation's objects carry (`<release>-github-orgs`, the prefix of its keys in Valkey). **The chart requires it to be the release's full name**, and says what to write |
| `cluster` | unset | what this cluster is called, which becomes part of a ServiceAccount's subject: `<cluster>:k8s:<namespace>:<name>`. Empty keeps the older unqualified form |
| `store` | `memory` (the chart: `kubernetes`) | where connected workspaces and their credentials are kept. `memory` makes a restart a fresh installation, which is right for a laptop and nothing else |
| `listen.address` | `:8080` | everything a browser and a relying party reach: discovery, the key set, the flows, the login page, and the console under `console.mount`. The chart takes the Service's and the routes' port from it, and refuses one outside 1-65535 |
| `probes.address` | `:7070` | `/healthz`, `/readyz` |
| `log.level` | `info` | `debug`, `info`, `warn`, `error` |
| `policyDir` | built-in two groups | the directory the policy is mounted at. The chart requires `/var/run/access-issuer/policy` |
| `overlayFile` | unset | the file of declared workspaces; the chart renders it from `directory.workspaces` |
| `publicURL`, `publicRootURL` | `http://localhost:8081`, `publicURL` | where a browser reaches the console (with its mount) and the origin root, where the admin-consent callback stays. With `route.host` and `console.mount` set the chart requires `https://<host><mount>` and `https://<host>` |
| `secureCookies` | follows the scheme of `issuerURL` | mark session cookies Secure. The chart refuses `false` on a route served over TLS |
| `groupsScoping` | `report` | how far this installation has moved toward per-audience `groups` scoping ([policy.md#groups-in-a-token-scoping](policy.md#groups-in-a-token-scoping)): `off` computes and logs nothing -- quote it (`"off"`), or YAML reads the bare word as a boolean -- `report` logs what would be dropped without changing a token, `enforce` narrows the claim |
| `demo` | `false` | two tenants held in memory, which need no credential and no network |
| `allowInsecure` | `false` | accept a plain-http issuer URL, for a local run |
| `inCluster` | `false` | recovery proves access to the cluster the pod runs in. Required with `recovery.enabled` |
| `clientSecretsDir` | unset | one file per confidential client, named after the client id, each the client's secret; read per call, so a rotated Secret takes effect without a restart. The chart requires `/var/run/access-issuer/clients` when a policy client names a `secret` |
| `adminPasswordEnv` | unset | the *name* of the variable holding the hub's recovery password, for a run outside a cluster. Unset generates one and prints it once |
| `lifetimes.token` / `.refresh` / `.hold` | `1h` / `12h` / `4h` | how long a token lives, how long a refresh lives, and how long a signed-in identity keeps its last granted role while the directory cannot vouch. Caps: the policy may ask for shorter |
| `lifetimes.absolute` | `24h` | the global timeout: no per-client session, and no access or ID token, outlives `auth_time` by more than this, no matter how often it is refreshed. Refused when zero, negative, or shorter than `lifetimes.token`: at render, and at start |
| `lifetimes.session` | `12h` | how long the console's own session lasts, capped at `lifetimes.absolute` |
| `freshness.refreshInterval` / `.freshnessWindow` / `.probeInterval` | `15m` / `30m` / `5m` | how often the refresher takes a new snapshot per workspace, how old a snapshot may be before its domains stop being authoritative, and how often a credential is probed and the domain list re-read |
| `exchange.audience` | `release` | the audience a workload's ServiceAccount token must be minted for. Without one, every mounted token in every federated cluster would be a proof. The controllers' projected tokens are minted for it |
| `exchange.clustersFile` / `.awsFile` | unset | the files naming the federated clusters and AWS accounts; the chart renders them from `exchange.clusters` and `exchange.aws.accounts` and requires the paths where it mounts them |
| `recovery.enabled` | unset: off for the issuer, on for the hub | the way in for the day the ordinary one is broken. It stores nothing: a short-lived ServiceAccount token proving access to the API server, so the authority is the cluster's own RBAC. **The only thing left that asks the cluster anything.** The chart's default is `true` |
| `recovery.serviceAccount` / `.audience` | the chart: `access-issuer-recovery` for both | the account recovery proves access as, which the chart creates and binds to nobody, and the audience its token must be minted for. Granting `create` on `serviceaccounts/token` for the account is how an installation says who may recover |
| `api.audience` / `api.consumersFile` | `directory-roster` / unset | the directory API's guard |
| `login.directory` | `true` | whether the console offers a sign-in of its own, under `<mount>/login`. With `console.client` set it is a second door |
| `login.signOutURL`, `login.forwarded.*` | unset | where sign-out sends the browser, and a sign-in an authenticating proxy has already done |
| `console.client` | unset | the declared client the console signs people in as. Somebody with no session is sent to `/authorize`, signs in at the issuer's page, and comes back with the issuer's session set |
| `console.origin` | unset | the one **other** origin allowed to call `SessionService` from a browser. Obsolete on one origin, which is the shipped shape |
| `oauthClient.*` | unset | the client registered once with the directory backend, for sign-in and admin consent. `idFile` and `secretFile` name files (mount the Secret with `secretMounts`), or `secretEnv` names the variable that holds the secret; `secretName`, `idKey` and `secretKey` name the Kubernetes Secret the console shows as declared. With none, nobody can sign in and this installation issues tokens to machines only, which is a real posture and is said at start |
| `signingKey.file` | unset: a key generated for the process | the primary signing key, provisioned and never minted here. The chart requires `/var/run/access-issuer/signing-key/<signingKey.key>` |
| `signingKey.additionalFiles[]` | unset | one file per `signingKey.additional` entry, in the order they are declared; the chart requires exactly that list |
| `signingKey.pollInterval` / `.activationDelay` / `.overlap` | `30s` / `15m` / `lifetimes.token` + 5m | live rotation, with no restart: how often the mounted file is re-read, how long a newly seen key is published before this replica signs with it (longer than the longest JWKS cache among the verifiers, plus the slowest kubelet projection; refused below `pollInterval`), and how long a superseded key stays published (it must cover `lifetimes.token`) |
| `valkey.address` | unset | host:port of the shared store, with no credentials; unset keeps sessions and snapshots in memory, which is one replica only |
| `valkey.passwordEnv` | unset | the *name* of the variable holding the password |
| `valkey.tls` | `false` | speak TLS to the server |
| `valkey.cluster` | `true` (the chart's guidance: `false`) | speak the cluster protocol. **Leave it off for a single-node Valkey:** with one shard it makes the client learn node addresses from `CLUSTER SLOTS` and talk to those, bypassing the Service -- the one mechanism whose job is to survive a pod moving. Turn it on when the store has three shards with a replica each (see [Valkey: a recommendation](#valkey-a-recommendation)) |
| `github.owners[]` | unset | the GitHub organisations whose workflows may exchange. **Unset verifies no CI token at all**, deliberately: anybody may run a workflow in their own repository and get a valid GitHub token, so a list invented by the chart would admit every repository there is |
| `github.runnerTiers[]` | unset | the runner tiers an operator may create a runner App for on the GitHub page (the Runners tab), one App per bound organisation per tier -- e.g. `[preview, stable]`. Lower-case letters, digits and dashes, at most 16, each once |
| `github.catalogueFile`, `slack.catalogueFile` | unset | the files declaring the GitHub and Slack Apps; the chart renders them from `githubApps.catalogue` and `slackApps`. A malformed one stops the service |
| `audit.writer` | unset | the audit installation's receiver: one address, which takes the records and answers the catalogue's registration on the same port. Set, the service and the controller record into it, each with its own projected token; unset, nothing is kept beyond the log line every record also is |
| `audit.tokenFile` | the chart: `/var/run/audit/token` | the projected token presented to the receiver; the chart requires that path when `audit.writer` is set |
| `audit.queryURL` | unset | the installation's query service, for the console's Audit page; unset shows no page. Needs `audit.writer` |
| `audit.audience` | `audit` | the policy client whose audience the Audit page's tokens carry. The policy must declare it, requiring the groups that may read the trail |
| `audit.forwardedForTrustedHops` | `0` | how many of the deployment's own proxies append to `X-Forwarded-For` in front of the service. A record's client address is the entry just left of them, read from the right; the left end is whatever a caller sent, so it is never taken on its own. `0` records the peer |

### `github-roster` (the chart's `githubRoster.config`)

The GitHub controller: it makes each organisation's teams match the policy's
`github` table. It has no listener.

| Key | Default | Meaning |
|---|---|---|
| `policyDir` | **required** | the same policy ConfigMap the service mounts; its `github` table is the bindings. The chart requires `/var/run/github-roster/policy` |
| `consoleURL` | **required** | the console's API, which answers who holds a group. The chart requires this release's own Service plus `console.mount`, and prints it |
| `release` | `access-issuer` | the name the service's objects carry, so the controller finds `<release>-github-status`. The chart requires the release's full name |
| `tokenFile` | `/var/run/secrets/github-roster/token` | the projected ServiceAccount token, for `exchange.audience`, read on every call |
| `appsDir` | `/var/run/github-roster/apps` | the mounted `<release>-github-apps` Secret, one file per connected organisation |
| `recordsDir` | `/var/run/github-roster/records` | the mounted `<release>-github-orgs` ConfigMap: the organisations' records and the console's requests for a pass. With `appsDir` it is looked at every 30 seconds, and a change (an install, a Refresh) runs a pass at once |
| `catalogueFile` | unset | the GitHub App catalogue, read only so the warning about an internal group nothing consumes does not name a group a grant consumes. Never fatal here |
| `interval` | `15m` | how long between passes. Positive |
| `enabledOrgs[]` | unset | the organisations the controller **changes**. Every other bound organisation is derived and reported, and left alone: an organisation is born disabled. Each must be bound by the policy: the controller refuses to start otherwise, and the chart refuses to render |
| `log.level` | `info` | |
| `audit.writer` / `.tokenFile` | unset | the audit installation; the controller records for itself, as its own workload |

Its account, `<release>-github-roster`, has two permissions, each by
name: `get`, `update` and `patch` on the ConfigMap
`<release>-github-status` it reports into, and `get` and `update` on the
Secret `<release>-github-links` it rewrites as it checks links. The App
keys and the console's records are volumes, so it holds no permission to read
any other Secret or ConfigMap, and watching them for a change takes none.

### `slack-roster` (the chart's `slackRoster.config`)

The Slack controller: it makes each workspace's channels match the policy's
`slack` table. It has no listener, and runs as one replica with `Recreate`: two
controllers would make every change twice.

| Key | Default | Meaning |
|---|---|---|
| `policyDir` | **required** | the same policy ConfigMap the service mounts; its `slack` and `people` tables are the bindings. The chart requires `/var/run/slack-roster/policy` |
| `consoleURL` | **required** | as for `github-roster` |
| `release` | `access-issuer` | as for `github-roster`; it finds `<release>-slack-status` |
| `tokenFile` | `/var/run/secrets/slack-roster/token` | the projected ServiceAccount token, for `exchange.audience`, read on every call |
| `credentialsDir` | `/var/run/slack-roster/credentials` | the mounted `<release>-slack-credentials` Secret, one file per connected workspace; optional |
| `recordsDir` | `/var/run/slack-roster/workspaces` | the mounted `<release>-slack-workspaces` ConfigMap: workspace records, Slack Connect records, console channel records, confirmations and pass requests; optional |
| `interval` | `15m` | the pass interval. Independently, the controller looks at the mounted credentials and records every 30 seconds and passes without waiting for the interval when they change |
| `enabledWorkspaces[]` | unset | the workspaces (the policy's keys) the controller **changes**. Every other declared workspace is derived and reported, and left alone. Naming a key the policy does not declare stops the controller at start, and the chart refuses to render |
| `log.level` | `info` | |
| `audit.writer` / `.tokenFile` | unset | the audit installation; the controller records for itself, as its own workload |

Its account, `<release>-slack-roster`, has one permission, by name: `get`,
`update` and `patch` on the ConfigMap `<release>-slack-status` it reports into.
The credentials and records are volumes, so it holds no permission to read any
Secret or other ConfigMap. See [Connect a Slack
workspace](../connect/slack-workspace.md).

## Migrating from environment variables

Everything the binaries read from the environment is a key of the file, and the
chart's flat values that fed them are now the component's `config`. An old
variable that is still set is **refused at start** with the key that replaces
it; nothing is ignored. The platform-supplied `NAMESPACE` (now read from the
pod's mounted service-account namespace) and `POD_NAME` (now the pod's
hostname, which is the pod's name) are not configuration and the chart no
longer sets them.

### The service

| Old variable | Key of `access-issuer`'s file |
|---|---|
| `ISSUER_URL` | `issuerURL` |
| `PORT` | `listen.address` (`:<port>`) |
| `HEALTH_PORT` | `probes.address` |
| `API_PORT`, `CONSOLE_PORT` | none: the directory's own listeners are not served by `access-issuer`; the console is on the issuer's listener |
| `DEMO` | `demo` |
| `ALLOW_INSECURE` | `allowInsecure` |
| `IN_CLUSTER` | `inCluster` |
| `PUBLIC_URL`, `PUBLIC_ROOT_URL` | `publicURL`, `publicRootURL` |
| `SECURE_COOKIES` | `secureCookies` |
| `STORE` | `store` |
| `OVERLAY_FILE` | `overlayFile` |
| `POLICY_DIR` | `policyDir` |
| `GROUPS_SCOPING` | `groupsScoping` |
| `CLUSTER` | `cluster` |
| `RELEASE_NAME` | `release` |
| `CLIENT_SECRETS_DIR` | `clientSecretsDir` |
| `ADMIN_PASSWORD` | `adminPasswordEnv`, which names the variable that holds it |
| `RECOVERY_ENABLED`, `RECOVERY_SERVICE_ACCOUNT`, `RECOVERY_AUDIENCE` | `recovery.enabled`, `recovery.serviceAccount`, `recovery.audience` |
| `API_AUDIENCE`, `CONSUMERS_FILE` | `api.audience`, `api.consumersFile` |
| `LOGIN_DIRECTORY`, `SIGN_OUT_URL` | `login.directory`, `login.signOutURL` |
| `FORWARDED_EMAIL_HEADER`, `FORWARDED_ISSUER`, `FORWARDED_AUDIENCE` | `login.forwarded.emailHeader`, `.issuer`, `.audience` |
| `CONSOLE_ORIGIN`, `CONSOLE_CLIENT_ID` | `console.origin`, `console.client` |
| `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_ID_FILE` | `oauthClient.id`, `oauthClient.idFile` |
| `OAUTH_CLIENT_SECRET`, `OAUTH_CLIENT_SECRET_FILE` | `oauthClient.secretEnv` (names the variable), `oauthClient.secretFile` |
| `OAUTH_CLIENT_SECRET_NAME`, `OAUTH_CLIENT_ID_KEY`, `OAUTH_CLIENT_SECRET_KEY` | `oauthClient.secretName`, `.idKey`, `.secretKey` |
| `SIGNING_KEY_FILE`, `SIGNING_KEY_FILES` | `signingKey.file`, `signingKey.additionalFiles` |
| `SIGNING_KEY_POLL_INTERVAL`, `SIGNING_KEY_ACTIVATION_DELAY`, `SIGNING_KEY_OVERLAP` | `signingKey.pollInterval`, `.activationDelay`, `.overlap` |
| `TOKEN_LIFETIME`, `REFRESH_LIFETIME`, `ABSOLUTE_LIFETIME`, `HOLD_WINDOW` | `lifetimes.token`, `.refresh`, `.absolute`, `.hold` |
| `SESSION_LIFETIME` | `lifetimes.session` |
| `REFRESH_INTERVAL`, `FRESHNESS_WINDOW`, `PROBE_INTERVAL` | `freshness.refreshInterval`, `.freshnessWindow`, `.probeInterval` |
| `EXCHANGE_AUDIENCE`, `CLUSTERS_FILE`, `AWS_FEDERATION_FILE` | `exchange.audience`, `exchange.clustersFile`, `exchange.awsFile` |
| `VALKEY_ADDRESS`, `VALKEY_TLS`, `VALKEY_CLUSTER` | `valkey.address`, `.tls`, `.cluster` |
| `VALKEY_PASSWORD` | `valkey.passwordEnv`, which names the variable that holds it |
| `GITHUB_OWNERS`, `GITHUB_RUNNER_TIERS`, `GITHUB_APPS_CATALOGUE_FILE` | `github.owners`, `github.runnerTiers`, `github.catalogueFile` |
| `SLACK_APPS_CATALOGUE_FILE` | `slack.catalogueFile` |
| `AUDIT_WRITER_URL`, `AUDIT_TOKEN_FILE` | `audit.writer`, `audit.tokenFile` |
| `AUDIT_QUERY_URL`, `AUDIT_AUDIENCE`, `AUDIT_FORWARDED_FOR_TRUSTED_HOPS` | `audit.queryURL`, `.audience`, `.forwardedForTrustedHops` |
| `LOG_LEVEL` | `log.level` |
| `SECRET_MANAGERS_FILE` | none: the console's secret-store view was removed in v1.30.0 ([0002](../decisions/0002-mission-boundary-tokens-and-memberships.md)) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` (and the other `OTEL_*`) | unchanged: set by the platform, not by the file. The chart's `telemetry.otlpEndpoint` is removed |

### The controllers

| Old variable | `github-roster` | `slack-roster` |
|---|---|---|
| `RELEASE_NAME` | `release` | `release` |
| `POLICY_DIR` | `policyDir` | `policyDir` |
| `CONSOLE_URL` | `consoleURL` | `consoleURL` |
| `TOKEN_FILE` | `tokenFile` | `tokenFile` |
| `APPS_DIR` | `appsDir` | none |
| `CREDENTIALS_DIR` | none | `credentialsDir` |
| `RECORDS_DIR` | `recordsDir` | `recordsDir` |
| `INTERVAL` | `interval` | `interval` |
| `ENABLED_ORGS` | `enabledOrgs` | none |
| `ENABLED_WORKSPACES` | none | `enabledWorkspaces` |
| `GITHUB_APPS_CATALOGUE_FILE` | `catalogueFile` | none |
| `AUDIT_WRITER_URL`, `AUDIT_TOKEN_FILE` | `audit.writer`, `audit.tokenFile` | `audit.writer`, `audit.tokenFile` |
| `LOG_LEVEL` | `log.level` | `log.level` |

### The chart's values

| Old value | Now |
|---|---|
| `issuerURL` | `config.issuerURL` |
| `listeners.port`, `listeners.healthPort` | `config.listen.address`, `config.probes.address` |
| `logLevel` | `config.log.level` |
| `groupsScoping`, `cluster` | `config.groupsScoping`, `config.cluster` |
| `lifetimes.*` | `config.lifetimes.*` |
| `directory.store` | `config.store` |
| `directory.freshness.*`, `directory.sessionLifetime`, `directory.login` | `config.freshness.*`, `config.lifetimes.session`, `config.login.directory` |
| `recovery.enabled`, `.serviceAccountName`, `.audience` | `config.recovery.enabled`, `.serviceAccount`, `.audience`, with `config.inCluster: true` |
| `exchange.audience` | `config.exchange.audience` |
| `valkey.address`, `.tls`, `.cluster` | `config.valkey.address`, `.tls`, `.cluster` |
| `valkey.passwordSecret.name` / `.key` | `config.valkey.passwordEnv` and a `secretEnv` entry |
| `oauthClient.secret.name` / `.keys.*` | `config.oauthClient.{secretName,idKey,secretKey,idFile,secretFile}` and a `secretMounts` entry |
| `github.owners` | `config.github.owners` |
| `githubRunnerApps.tiers` | `config.github.runnerTiers` |
| `console.origin`, `console.client` | `config.console.origin`, `config.console.client` (`console.mount` stays: it is the route's) |
| `signingKey.rotation.*` | `config.signingKey.pollInterval`, `.activationDelay`, `.overlap` |
| `audit.writer`, `.query`, `.audience`, `.forwardedForTrustedHops` | `config.audit.writer`, `.queryURL`, `.audience`, `.forwardedForTrustedHops` (`audit.token.*` stays: it is the chart's) |
| `githubRoster.interval`, `githubRoster.actsIn` | `githubRoster.config.interval`, `githubRoster.config.enabledOrgs` |
| `slackRoster.interval`, `slackRoster.actsIn` | `slackRoster.config.interval`, `slackRoster.config.enabledWorkspaces` |
| `telemetry.otlpEndpoint` | removed: `OTEL_*` is set on the pods by the platform |

The old values are removed, not aliased: an old key is refused at render
(`values.schema.json` names it), so a values file that was not migrated fails
`helm template` and not a rollout. The paths the config names are where the
chart mounts what it renders, and the chart refuses a config that names another:
the defaults in `values.yaml` carry them, so a values file states only what it
changes.

## Roles

Two roles, held by membership of two declared internal groups, and the same two
scoped to one directory.

| Role | Group | May |
|---|---|---|
| viewer | `all:access-roster:viewer` | every read: `ListWorkspaces`, `GetSettings`, `GetPolicy`, `WhoAmI`, `Explain`, `ListDirectoryGroups`, `GetDirectoryGroup`, `SearchPeople`, `ListHolders`, `GetGitHubStatus`, `ListGitHubApps`, `GetGitHubApp`, `GetSlackStatus`, `ListSlackApps`, `ListSlackChannels`, `ListSlackSharedChannels`, `ResolveDirectoryGroups`, `ListServedDomains` (a scoped viewer sees only what its directory owns) for anybody else (one's own reach, like `Explain` of oneself, needs no role), and listing one's own sessions — the whole console, read-only |
| operator | `all:access-roster:operator` | everything: Connect, Reconnect, UploadKey, `SetServedDomains`, `SetSyncedGroups`, Probe, Refresh, Disconnect, the GitHub connects and disconnects, `ListGitHubAppTokens` (a request names who asked), `ConfirmGitHubRemovals`, `ImportGitHubLinks`, `BeginSlackWorkspaceConnect`, `RequestSlackPass`, `DisconnectSlackWorkspace`, `ConfirmSlackRemovals`, `CreateSlackApp`, `InstallSlackApp`, the Slack channel and Slack Connect create, update and delete, `ChangeSlackWorkspaceOwner` and `ChangeGitHubOrganisationOwner` (installation-wide operator only), listing and revoking anyone's sessions |

**Per-directory operators.** Beside the two installation-wide groups,
`<directory-workspace-id>:access-roster:viewer` and `:operator` give the same
roles over what that directory owns: the Slack workspaces and GitHub
organisations connected with it as owner, their Apps and the channels in them.
The owner is recorded at connect (the installation-wide operator may name any
connected directory or none; an operator of one directory owns what it
connects; an operator of several chooses among theirs) and only the
installation-wide operator changes it (*Change owner*). A workspace or
organisation with no owner is operated by the installation-wide operator alone.

Behind a gateway that forwards a token, the forwarded identity's email is
resolved through the directory like any other; the groups in the token
itself are not consulted, because the directory is the source they came
from.

## The repository

access-roster ships from one repository: the `access-issuer` chart with
its three images — the service, the GitHub controller and the Slack
controller — `accessctl`, the GitHub Action, the Go module and the TypeScript
package, all stamped with one tag. Shared Go packages —
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

Point the chart at its Service (`config.valkey.address: directory-roster-cache.directory-roster.svc:6379`)
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
