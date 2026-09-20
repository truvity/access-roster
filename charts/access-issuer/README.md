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

Without `audit.s3.bucket` the audit trail stays in one replica's memory,
which is not a record; the service says so at start.

`examples/github-apps.yaml` ships beside the values: a default set of
GitHub Apps an estate can copy — dependency updates split public from
private, a bot that approves pull requests and cuts tags, and one App for
the program that manages the organisation — with what each is for and why
they are separate identities. It is values to read and copy, not a
default: creating an App is an owner of the organisation confirming a
manifest
([guide](../../docs/connect/github-apps-catalogue.md#a-default-set)).

```sh
helm install access-issuer oci://ghcr.io/truvity/charts/access-issuer \
  --namespace access-issuer --create-namespace \
  --set issuerURL=https://issuer.example
```
