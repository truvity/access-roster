# Connect Kargo

**Anchor:** the issuer; Kargo runs its own OIDC flow. It maps claims to
its own roles and has a CLI that signs in on a loopback port, so it needs two
clients:

```yaml
clients:
  kargo:
    kind: confidential
    secret: kargo-oidc-client
    redirects:  [https://kargo.example.internal/login]
    signed_out: [https://kargo.example.internal/]
    requires:   [kernel:k8s:admin, kernel:k8s:viewer]
  kargo-cli:
    kind: public              # PKCE; the CLI's redirect is a loopback port
    requires:   [kernel:k8s:admin, kernel:k8s:viewer]
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
    admins: { claims: { groups: [kernel:k8s:admin] } }   # the cluster tier, reused
```

Per-project roles bind on the `groups` claim through Kargo's own RBAC —
`<env>:<project>:approver` is the promotion gate, the same name the
policy mints for the project's approver unit.
Keep Kargo's admin account until a policy-granted admin has logged in.
