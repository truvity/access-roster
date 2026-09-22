# access-issuer — configuration and endpoints

## What the chart renders, and what it expects

| Renders | Expects to exist |
|---|---|
| Deployment, Service, ServiceAccount, a namespaced Role for the Secrets and ConfigMaps it writes, the TokenReview ClusterRole (with `recovery.enabled`), NetworkPolicy, the policy, overlay and cluster ConfigMaps, the Gateway API routes for its host, the cert-manager `Certificate` that produces its signing key, and — with `githubRoster.enabled` — a second Deployment for the GitHub controller; an External Secrets `PushSecret` for each catalogue App carrying `push` | a Valkey, for more than one replica; a cert-manager issuer; the Secret holding the OAuth client, if people sign in here; an audit installation of this service's own in the same namespace, if the trail is to be a record; External Secrets and the store named, for a catalogue App carrying `push` |

This page keeps the values that carry a reason, and the endpoints. The
full list is [configuration.md](configuration.md).

Two things it will not do. **It does not create the signing key** —
cert-manager issues one, or `signingKey.existingSecret` names one
(RSA, or ECDSA on P-256, P-384 or P-521)
external-secrets delivered — because a service that mints its own
credential is an exception to how every other credential in this estate is
provisioned. And **it puts no authenticating proxy in front**: this is the
thing that authenticates, and a proxy would have nowhere to send anyone.

| Value | Default | |
|---|---|---|
| `issuerURL` | — | **required.** Baked into every token and every relying party's trust, so it must be stable for the life of the installation |
| `signingKey.existingSecret` | `""` | a Secret external-secrets delivered; empty renders a cert-manager `Certificate` instead |
| `signingKey.certificate.issuerName` / `.issuerKind` | `selfsigned` / `ClusterIssuer` | the certificate is a by-product; only the key is used |
| `signingKey.certificate.algorithm` / `.size` / `.encoding` | `ECDSA` / `384` / `PKCS8` | what the issuer signs with follows from the key: RSA signs RS256, and P-256, P-384 and P-521 sign ES256, ES384 and ES512. It is what discovery advertises, and **every relying party must accept it** — the default P-384 key means ES384 on every token, which a verifier pinned at RS256 (Kargo; kube-apiserver's `--oidc-signing-algs` left at its default) refuses outright. An installation with such a relying party sets `{algorithm: RSA, size: 2048, encoding: PKCS1}`; the chart's own Go and TypeScript verifiers accept whatever is advertised. ECDSA takes 256, 384 or 521; RSA takes 2048, 3072 or 4096; a combination cert-manager would decline is refused at render |
| `oauthClient.secret.name` | `""` | a Secret holding the client. Empty means nobody can sign in and this issuer serves token exchange only, which it says at start |
| `oauthClient.secret.keys.clientId` / `.clientSecret` | `client-id` / `client-secret` | what those keys are called. **Both halves come from the one Secret** — the same shape the proxy uses — so they travel together; a client whose id and secret are configured in two places is one that can be half rotated. Both are mounted as files, never environment variables |
| `cluster` | `""` | what this cluster is called, which becomes part of a ServiceAccount's subject: `<cluster>:k8s:<namespace>:<name>`. A pod cannot discover it, and the same namespace and name exist on every cluster — so without it two different machines are one `sub`. Use the word the estate already uses (`mgmt`, `prod`), the same one that is a group's scope. Empty keeps the older unqualified `k8s:<namespace>:<name>` |
| `exchange.clusters[]` | `[]` | the clusters whose workloads may exchange: `{name, issuer, jwksUri}` per cluster, verified against the key set that cluster publishes. No secret in any row, and this service holds access to no cluster — including its own, which is a row like any other. The TokenReview ClusterRole the chart renders is for recovery, not for this |
| `exchange.audience` | the release name | without one, every mounted ServiceAccount token in the cluster would be an exchange proof |
| `lifetimes.token` / `.refresh` / `.hold` | `1h` / `12h` / `4h` | caps; the policy may ask for shorter |
| `policy` | `{}` | the declared policy ([policy.md](policy.md)); `clients` carry `redirects` **and** `signed_out` |
| `githubRoster.enabled`, `.actsIn[]` | `false`, `[]` | the GitHub controller beside the service, and the organisations it may **change**; every other bound organisation is a dry run the console shows |
| `githubApps.catalogue[]` | `[]` | GitHub Apps declared as data, created and installed from the console, their keys kept in `Secret <release>-github-catalogue-apps`. A default set to copy ships as the chart's `examples/github-apps.yaml` ([guide](../connect/github-apps-catalogue.md)) |
| `githubApps.catalogue[].push` | absent | copy that App's three property keys to a secret store, as an External Secrets `PushSecret` — `{secretStore: {name, kind}, remoteKey, refreshInterval, deletionPolicy}`. Off unless written; what lands there is the App's key, a second durable copy ([guide](../connect/infrastructure-as-code.md)) |
| `githubRunnerApps.tiers[]` | `[]` | the runner tiers an operator may create a runner App for, one per organisation per tier |
| `audit.writer`, `audit.query` | `""` | the audit installation this service records into, and its query service for the console's Audit page. Empty keeps no trail beyond the log line every record also is, and shows no page. This service holds no cloud identity for the trail and writes no object itself: it presents a projected token to the installation, which owns the archive |
| `serviceAccount.annotations` | `{}` | annotations on the ServiceAccount, which is how a cloud identity reaches this service. An admission webhook — EKS Pod Identity, GKE Workload Identity, or the self-hosted `amazon-eks-pod-identity-webhook` — reads the annotation and injects the credentials into every pod using the account. Nothing in this service needs one today: the chart mounts no credential of its own and deliberately takes none as a value, because a long-lived key in Helm values is the thing the webhook exists to avoid. On AWS the key is `eks.amazonaws.com/role-arn` and the value is the role's ARN |
| `github.owners[]` | `[]` | the GitHub organisations (or users) whose workflows may exchange a token. **The trust boundary, not tuning:** anybody may run a workflow in their own repository and get a valid token from GitHub, so signature and expiry prove only that a job ran somewhere; this list is the whole of what makes one of them ours. Empty verifies no CI token at all. The audience a workflow must request is `issuerURL` and is not configurable |
| `route.host` | `""` | empty renders no route, for an issuer reached by port-forward while it is being tried |
| `route.rootRedirect` | `""` | where a bare GET of the host root goes. The issuer serves nothing at `/` — every endpoint it answers is a named one — so somebody who types the domain gets a 404. Where a console shares the host under a path, point this at it (`/console/`). Empty keeps the 404, which is the honest answer for an issuer deployed alone |
| `route.sharedWith[]` | `[]` | namespaces, besides this issuer's own, allowed to attach an HTTPRoute to this Gateway. This is the other half of the one-origin console: the directory console shares this issuer's *hostname*, one origin, so it also has to share this issuer's *Gateway* — two Gateways for one hostname is a duplicate-listener collision, not two independent routes — and the console's HTTPRoutes live in its own chart's namespace. Non-empty renders `allowedRoutes.namespaces` as a `Selector` (`kubernetes.io/metadata.name In [<this namespace>, ...sharedWith]`) rather than the default `from: Same`. **This is a Gateway-level admission, not a ReferenceGrant**: a ReferenceGrant governs a route's `backendRefs` reaching into another namespace, not a route's `parentRefs` reaching a Gateway — the Gateway's own `allowedRoutes` is what decides who may attach to it at all |
| `recovery.enabled` | `true` | the way in when no directory can vouch for anybody. A ServiceAccount token checked by the API server — the same proof this issuer takes from workloads. It grants **nothing by itself**: a recovered sign-in completes as the ServiceAccount *subject*, and the policy's `service_account` matchers decide what that is in, so an installation that names no matcher has an account that can sign in and is admitted nowhere |
| `recovery.serviceAccountName` / `.audience` | `<release>-recovery` | the account a token must be minted for and the audience it must carry. Without an audience every mounted token in the cluster would be a proof. The chart creates the account bound to **nothing**: granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |

`rotationPolicy: Always` on the Certificate is deliberate: a renewal must
be a *new key*, because a renewed certificate over the same key rotates
nothing. A new key is a new key id, so keep `renewBefore` comfortably
longer than `lifetimes.token`.

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
| `SessionService` (ConnectRPC): `ListSessions{identity? \| client? \| contains?}` → `{sessions, sign_ins}`, `RevokeSessions{identity, client?, session_id?, sso?}` | ours | sessions per identity and per client, with client, how obtained, issued, expires, last refreshed; revoke per identity, per client, or one. Listing and revoking others is operator; listing and revoking your own is any signed-in identity; listing **every** session (neither identity nor client named) is operator-only, paged by `page_size`/`page_token`, and audited. `contains` reads `identity` and `client_id` as SUBSTRINGS rather than exact values — prefix, suffix and middle — and is **operator-only**, because a substring names an unknown set where an exact identity names the caller's own or nobody's. `RevokeSessions` has no such field: a revoke scoped to *anything containing this* is the control that ends more than its caller meant, with no undo. Authorized by the browser's SSO cookie on a same-origin call — which is what the console is — or by a bearer. The `console.origin` CORS gate is obsolete on one domain and is removed with the cutover |
| back-channel logout | OIDC Back-Channel Logout 1.0 | opt-in per client with `backchannel_logout_uri`: a signed `logout+jwt` POSTed to every such client that signed the person in, by the `sid` it saw, when the sign-in ends |
| not served | RFC 8628 device flow, client credentials, RFC 7523 JWT bearer, RFC 7662 introspection, implicit and hybrid flows, session-management iframe, RFC 7591 dynamic client registration | The first three were served through 0.11 and are gone: the device flow is for a machine with no browser, and both headless cases here — a CI job and a workload — are token exchange; client credentials is a machine with a stored secret, which is the thing this design exists not to have; JWT bearer is token exchange with a different spelling, and two ways to say one thing is two things to keep truthful. Introspection never applied — these are JWTs, verified offline against the key set. Registration is deliberate: every client is declared, so the set of them is answerable by reading the repository |
