# access-issuer chart

Deploys the token service. Published to `ghcr.io/truvity/charts/access-issuer`
on every `v*` tag of the repository; the tag is the chart's version.

What the chart includes, what it expects and every value are documented in
[docs/reference/access-issuer.md](../../docs/reference/access-issuer.md).
`values.schema.json` is strict at the top level: an unknown key fails the
render.

Two things it will not do for you. It does not create the signing key —
cert-manager issues one, or external-secrets delivers one, because a
service that mints its own credential is an exception to how every other
credential here is provisioned. And it does not put an authenticating
proxy in front of the issuer: this *is* the thing that authenticates, and
a proxy would have nowhere to send anyone.

```sh
helm install access-issuer oci://ghcr.io/truvity/charts/access-issuer \
  --namespace access-issuer --create-namespace \
  --set issuerURL=https://issuer.example \
  --set hub.address=http://directory-roster.directory-roster.svc:8080
```
