# Expose a business surface to employees for testing

**Anchor:** the issuer, through a proxy in front of the surface — on
Envoy Gateway, gateway-native OIDC by default, or `access-proxy`
(deprecated, and Envoy Gateway only) until it is migrated; on any other
gateway, run upstream oauth2-proxy yourself
([why](../design/access-proxy.md),
[ADR 0003](../decisions/0003-deprecate-access-proxy.md)).

A product surface on a test tier, opened to employees instead of the
product's end-user identity provider, without teaching the product about
the issuer. The `exposure` block below is the `access-proxy` shape,
which runs only on Envoy Gateway; the same admission there — any
signed-in identity, nothing narrower — is now a `SecurityPolicy` with
`oidc:` against a declared client instead.

```yaml
exposure:
  hostname: app.test.example.internal
  backend: { name: app, port: 3000 }
  posture: authenticated
  paths: ["/", "/api/"]
```

`authenticated` passes any signed-in employee and forwards the bearer;
the application authorizes itself, or ignores the identity entirely. Paths
the product must keep public — wallet callbacks, well-known documents —
stay off the list and get no route through the proxy. No internal group is needed:
signing in at all is the entitlement.

End users of the product never see this path; their sign-in remains the
product's own identity provider.
