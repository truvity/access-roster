# directory-roster chart

Deploys the directory hub. Published to `ghcr.io/truvity/charts/directory-roster`
on every `v*` tag of the repository; the tag is the chart's version.

What the chart includes, what it expects, every value and the overlay
format are documented in
[docs/reference/configuration.md](../../docs/reference/configuration.md).
`values.schema.json` is strict at the top level: an unknown key fails the
render.

```sh
helm install directory-roster oci://ghcr.io/truvity/charts/directory-roster \
  --namespace directory-roster --create-namespace \
  --set valkey.address=valkey.directory-roster.svc:6379
```
