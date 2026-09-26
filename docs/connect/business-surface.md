# Expose a business surface to employees for testing

**Anchor:** the issuer, through a gateway in front of the surface. On
Envoy Gateway, use gateway-native OIDC: a `SecurityPolicy` with `oidc:`
against a declared client, any signed-in identity, nothing narrower
([how](envoy-gateway-oidc.md)). On any other gateway, run upstream
oauth2-proxy yourself
([recipe](../design/access-proxy.md),
[why](../decisions/0003-deprecate-access-proxy.md)).

A product surface on a test tier, opened to employees instead of the
product's end-user identity provider, without teaching the product about
the issuer.

The client row in the policy (no authorization model of its own, so just "any
signed-in identity"):

```yaml
clients:
  app.test.example.internal:
    kind: confidential
    secret: app-test-client
    redirects: ["https://app.test.example.internal/oauth2/callback"]
    requires: []  # any signed-in employee
```

The gateway routes the hostname to the console backend, the `SecurityPolicy`
gates on this client, and the bearer forwards to the app. The application
authorizes itself, or ignores the identity entirely. No internal group is needed:
signing in at all is the entitlement.

End users of the product never see this path; their sign-in remains the
product's own identity provider.
