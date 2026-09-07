# Connect Kargo

Kargo maps OIDC subjects and claims to its own roles and has a CLI that
uses the device flow, so it needs two clients:

```yaml
clients:
  static:
    - id: kargo
      secretName: kargo-oidc-client
      redirectUris: [https://kargo.example.internal/login]
    - id: kargo-cli
      public: true            # device flow + PKCE
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
Keep Kargo's admin account until a rule-granted admin has logged in.
