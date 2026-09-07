# access-issuer — configuration and endpoints

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
| `/.access/grants` | ours | the clients the caller's groups admit it to; read by `accessctl kubeconfig` and `aws-config` |
| `/.access/simulate` | ours | what would this identity get. Read-only |
| `SessionService` (ConnectRPC): `ListSessions{identity? \| client?}`, `RevokeSessions{identity, client?, session_id?}` | ours | sessions per identity and per client, with client, how obtained, issued, expires, last refreshed; revoke per identity, per client, or one. Listing and revoking others is operator; listing and revoking your own is any signed-in identity |
| not served | RFC 7662 introspection, implicit and hybrid flows, back-channel logout, session-management iframe | JWT access tokens are verified offline; the rest has no consumer here |

## Values

| Value | Meaning |
|---|---|
| `issuer.url` | the public issuer URL; must be stable for the life of the installation |
| `console.origin` | the console's origin, allowed to call `SessionService` from a browser. It is what lets sessions show on a person's page while the hub's own code stays independent of this service |
| `hub.address` | the hub's API Service, `directory-roster.directory-roster.svc:8080` |
| `valkey.address`, `valkey.passwordSecret` | token state; external to the chart |
| `signingKeys.rotation` | rotation period; previous keys stay in JWKS for one token lifetime |
| `policy.configMaps[]` | the declared layer: one or several ConfigMaps in the issuer's namespace, merged |
| `clients.static[]` | `{id, secretName?, redirectUris[], public: bool, audiences[]}` — ArgoCD, Kargo, one per cluster |
| `clients.registration[]` | `{namespace, hostPattern}` — which namespaces may self-register clients for which hosts |
| `proofs.github[]` | `{organisation}` — accepted CI organisations |
| `proofs.corporate.backends[]` | `google`, later `entra`; tenants come from the hub |
| `tokens.idLifetime`, `tokens.refreshLifetime`, `tokens.holdWindow` | token lifetimes the policy does not set, and how long an identity keeps its last grant while the hub cannot be vouched for |
| `networkPolicy.*` | who may reach `/token` and `/register` from inside the cluster |

## What the chart renders and expects

Renders the Deployment, Services, ServiceAccount, the ClusterRole for
TokenReview, the HTTPRoute for the issuer host, NetworkPolicy, and the
ConfigMap/Secret pair per dynamic registration it manages. Expects a
Gateway, a Valkey, DNS and TLS for the issuer host, and the hub.
