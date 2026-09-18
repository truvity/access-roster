# access-issuer chart

Deploys the whole of access-roster: the directory reader, the policy,
the OpenID provider, the login page, the console and the audit trail in
one process, and, with `githubRoster.enabled`, the GitHub controller
beside it. Published to `ghcr.io/truvity/charts/access-issuer` on every
`v*` tag of the repository; the tag is the chart's version.

What the chart includes, what it expects and every value are documented in
[docs/reference/access-issuer.md](../../docs/reference/access-issuer.md).
`values.schema.json` is strict at the top level: an unknown key fails the
render.

Three things it will not do for you. It does not create the signing key
— cert-manager issues one, or external-secrets delivers one, because a
service that mints its own credential is an exception to how every other
credential here is provisioned. It does not put an authenticating proxy
in front of the issuer: this *is* the thing that authenticates, and a
proxy would have nowhere to send anyone. And it does not back up what
the console adds: the four Secrets that hold it are named in
[docs/reference/configuration.md](../../docs/reference/configuration.md#restoring-from-the-secrets-alone),
and copying them is the deployment's job.

Without `audit.writer` and `audit.registry` no audit trail is kept beyond
log lines, and the console has no Audit page; the service says so at
start. The trail is an audit installation of its own, connected as a
plugin: see `audit` in the values.

```sh
helm install access-issuer oci://ghcr.io/truvity/charts/access-issuer \
  --namespace access-issuer --create-namespace \
  --set issuerURL=https://issuer.example
```
