# access-issuer — configuration and endpoints

## What the chart renders, and what it expects

| Renders | Expects to exist |
|---|---|
| Deployment, Service, ServiceAccount, the TokenReview ClusterRole, NetworkPolicy, the policy ConfigMap, the Gateway API route for its host, and the cert-manager `Certificate` that produces its signing key | a directory hub to ask about people; a cert-manager issuer; the Secret holding the OAuth client, if people sign in here |

Two things it will not do. **It does not create the signing key** —
cert-manager issues one, or `signingKey.existingSecret` names one
external-secrets delivered — because a service that mints its own
credential is an exception to how every other credential in this estate is
provisioned. And **it puts no authenticating proxy in front**: this is the
thing that authenticates, and a proxy would have nowhere to send anyone.

| Value | Default | |
|---|---|---|
| `issuerURL` | — | **required.** Baked into every token and every relying party's trust, so it must be stable for the life of the installation |
| `hub.address` | — | **required.** The hub's API listener; this service asks it about every person |
| `hub.audience` | `directory-roster` | the audience of the projected token it presents to the hub |
| `signingKey.existingSecret` | `""` | a Secret external-secrets delivered; empty renders a cert-manager `Certificate` instead |
| `signingKey.certificate.issuerName` / `.issuerKind` | `selfsigned` / `ClusterIssuer` | the certificate is a by-product; only the key is used |
| `signingKey.certificate.size` | `2048` | RSA, because this issuer signs RS256; an EC key is refused at start by name |
| `oauthClient.secret.name` | `""` | a Secret holding the client. Empty means nobody can sign in and this issuer serves token exchange only, which it says at start |
| `oauthClient.secret.keys.clientId` / `.clientSecret` | `client-id` / `client-secret` | what those keys are called. **Both halves come from the one Secret** — the same shape the hub uses — so they travel together; a client whose id and secret are configured in two places is one that can be half rotated. Both are mounted as files, never environment variables |
| `cluster` | `""` | what this cluster is called, which becomes part of a ServiceAccount's subject: `<cluster>:k8s:<namespace>:<name>`. A pod cannot discover it, and the same namespace and name exist on every cluster — so without it two different machines are one `sub`. Use the word the estate already uses (`kernel`, `prod`), the same one that is a group's scope. Empty keeps the older unqualified `k8s:<namespace>:<name>` |
| `exchange.workloadTokens` | `true` | verify Kubernetes ServiceAccount tokens with a TokenReview — the one cluster-scoped permission this chart creates |
| `exchange.audience` | the release name | without one, every mounted ServiceAccount token in the cluster would be an exchange proof |
| `lifetimes.token` / `.refresh` / `.hold` | `1h` / `12h` / `4h` | caps; the policy may ask for shorter |
| `policy` | `{}` | the declared layer, same schema as the hub's; `clients` carry `redirects` **and** `signed_out` |
| `github.owners[]` | `[]` | the GitHub organisations (or users) whose workflows may exchange a token. **The trust boundary, not tuning:** anybody may run a workflow in their own repository and get a valid token from GitHub, so signature and expiry prove only that a job ran somewhere; this list is the whole of what makes one of them ours. Empty verifies no CI token at all. The audience a workflow must request is `issuerURL` and is not configurable |
| `route.host` | `""` | empty renders no route, for an issuer reached by port-forward while it is being tried |
| `recovery.enabled` | `true` | the way in when no directory can vouch for anybody. A ServiceAccount token checked by the API server — the same proof this issuer takes from workloads. It grants **nothing by itself**: a recovered sign-in completes as the ServiceAccount *subject*, and the policy's `service_account` matchers decide what that is in, so an installation that names no matcher has an account that can sign in and is admitted nowhere |
| `recovery.serviceAccountName` / `.audience` | `<release>-recovery` | the account a token must be minted for and the audience it must carry. Without an audience every mounted token in the cluster would be a proof. The chart creates the account bound to **nothing**: granting `create` on `serviceaccounts/token` for it is how an installation says who may recover |

`rotationPolicy: Always` on the Certificate is deliberate: a renewal must
be a *new key*, because a renewed certificate over the same key rotates
nothing. A new key is a new key id, so keep `renewBefore` comfortably
longer than `lifetimes.token`.

## Endpoints

| Path | Standard | Purpose |
|---|---|---|
| `/.well-known/openid-configuration`, `/keys` | OIDC discovery, JWKS | what relying parties read |
| `/authorize`, `/token`, `/userinfo`, `/end_session` | OIDC | login, tokens, RP-initiated logout |
| `/device_authorization` | RFC 8628 | kubelogin, `accessctl`, the Kargo CLI |
| `/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | CI and workload exchange; the requested `audience` is a client, gated by its `requires` |
| `/revoke` | RFC 7009 | revokes a refresh token; what Revoke and "sign out everywhere" call underneath |
| `/register` | RFC 7591 | dynamic client registration, authenticated by a ServiceAccount token |
| `/login`, `/device`, `/signed-out` | ours | the three pages the issuer serves itself: sign-in chooser by domain, device-code entry, signed out. Minimal HTML, same theme; not the console |
| `/account` | ours | the signed-in person's own page: their sessions, and *sign out everywhere*. Unlike the three above it runs **with** a session, same-origin with `SessionService`, so it needs no cross-origin bearer; its buttons are form posts, so it needs no JavaScript |
| `/.access/grants` | ours | the clients the caller's groups admit it to; read by `accessctl kubeconfig` and `aws-config` |
| `/.access/simulate` | ours | what would this identity get. Read-only |
| `SessionService` (ConnectRPC): `ListSessions{identity? \| client?}`, `RevokeSessions{identity, client?, session_id?}` | ours | sessions per identity and per client, with client, how obtained, issued, expires, last refreshed; revoke per identity, per client, or one. Listing and revoking others is operator; listing and revoking your own is any signed-in identity. Reached same-origin from `/account` (the SSO cookie); the `console.origin` CORS gate is the optional path for a console-embedded operator view |
| not served | RFC 7662 introspection, implicit and hybrid flows, back-channel logout, session-management iframe | JWT access tokens are verified offline; the rest has no consumer here |
