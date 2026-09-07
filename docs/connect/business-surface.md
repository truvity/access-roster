# Expose a business surface to employees for testing

A product surface on a test tier, opened to employees instead of the
product's end-user identity provider, without teaching the product about
the issuer.

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
