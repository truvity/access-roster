# access-issuer — configuration and endpoints

## Endpoints

| Path | Standard | Purpose |
|---|---|---|
| `/.well-known/openid-configuration`, `/keys` | OIDC discovery, JWKS | what relying parties read |
| `/authorize`, `/token`, `/userinfo`, `/end_session` | OIDC | login, tokens, RP-initiated logout |
| `/device_authorization` | RFC 8628 | kubelogin, `accessctl`, the Kargo CLI |
| `/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 | CI and workload exchange; `audience` requested, gated by rules |
| `/register` | RFC 7591 | dynamic client registration, authenticated by a ServiceAccount token |
| `/.access/grants` | ours | the audiences the caller's rules allow; read by `accessctl kubeconfig` and `aws-config` |
| `/.access/simulate` | ours | the one operator page: what would this identity get. Read-only |

## Values

| Value | Meaning |
|---|---|
| `issuer.url` | the public issuer URL; must be stable for the life of the installation |
| `hub.address` | the hub's API Service, `directory-roster.directory-roster.svc:8080` |
| `valkey.address`, `valkey.passwordSecret` | token state; external to the chart |
| `signingKeys.rotation` | rotation period; previous keys stay in JWKS for one token lifetime |
| `policy.configMaps[]` | the declared layer: one or several ConfigMaps in the issuer's namespace, merged |
| `clients.static[]` | `{id, secretName?, redirectUris[], public: bool, audiences[]}` — ArgoCD, Kargo, one per cluster |
| `clients.registration[]` | `{namespace, hostPattern}` — which namespaces may self-register clients for which hosts |
| `proofs.github[]` | `{organisation}` — accepted CI organisations |
| `proofs.corporate.backends[]` | `google`, later `entra`; tenants come from the hub |
| `tokens.idLifetime`, `tokens.refreshLifetime`, `tokens.holdWindow` | lifetimes; the hold window mirrors the rules default |
| `networkPolicy.*` | who may reach `/token` and `/register` from inside the cluster |

## What the chart renders and expects

Renders the Deployment, Services, ServiceAccount, the ClusterRole for
TokenReview, the HTTPRoute for the issuer host, NetworkPolicy, and the
ConfigMap/Secret pair per dynamic registration it manages. Expects a
Gateway, a Valkey, DNS and TLS for the issuer host, and the hub.
