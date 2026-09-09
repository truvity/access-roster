# Connect Kargo

**Anchor:** the issuer; Kargo runs its own OIDC flow. It maps claims to
its own roles and has a CLI that uses the device flow, so it needs two
clients:

```yaml
clients:
  kargo:
    kind: confidential
    secret: kargo-oidc-client
    redirects:  [https://kargo.example.internal/login]
    signed_out: [https://kargo.example.internal/]
    requires:   [cluster-kernel:cluster:admin, cluster-kernel:cluster:viewer]
  kargo-cli:
    kind: public              # device flow + PKCE
    requires:   [cluster-kernel:cluster:admin, cluster-kernel:cluster:viewer]
```

Kargo's values:

```yaml
api:
  oidc:
    enabled: true
    issuerURL: https://issuer.example.internal
    clientID: kargo
    cliClientID: kargo-cli
    additionalScopes: [groups]
    admins: { claims: { groups: [platform:admins] } }
```

Per-project roles bind on the `groups` claim through Kargo's own RBAC.
Keep Kargo's admin account until a policy-granted admin has logged in.
