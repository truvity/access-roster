# access-roster chart

Deploys the whole of access-roster: the directory reader, the policy,
the OpenID provider, the login page, the console and the audit trail in
one process, and, with `controllerGithub.enabled` and `controllerSlack.enabled`, the
GitHub and Slack controllers beside it. The chart runs one image, `ghcr.io/truvity/access-roster/access-roster`,
as three Deployments: `access-roster serve`, `access-roster controller github` and
`access-roster controller slack`. Each controller has no listener, and is a dry run for every organisation or
workspace until it is listed in `controllerGithub.config.enabledOrgs` or `controllerSlack.config.enabledWorkspaces`.
Each component is configured by one file, its `config` value, rendered as it
stands and validated against the schema its binary uses; secrets reach a pod only
through `secretEnv`. See [docs/reference/configuration.md](../../docs/reference/configuration.md).
Published to `ghcr.io/truvity/charts/access-roster` on every
`v*` tag of the repository; the tag is the chart's version.

What the chart includes, what it expects and every value are documented in
[docs/reference/access-issuer.md](../../docs/reference/access-issuer.md).
`Moving from the `access-issuer` chart is one release's change, with two values to keep every object's name:
[docs/reference/configuration.md](../../docs/reference/configuration.md#migrating-from-the-access-issuer-chart).
`values.schema.json` is strict at the top level: an unknown key fails the
render.

Three things it will not do for you. It does not create the signing key
— cert-manager issues one, or external-secrets delivers one, because a
service that mints its own credential is an exception to how every other
credential here is provisioned. It does not put an authenticating proxy
in front of the issuer: this *is* the thing that authenticates, and a
proxy would have nowhere to send anyone. And it does not make a second
copy of what the console adds unless you ask it to: the Secrets that hold it are
named in
[docs/reference/configuration.md](../../docs/reference/configuration.md#restoring-from-the-secrets-alone)
(the Slack ones, `<release>-slack-credentials`, `<release>-slack-records` and
`<release>-slack-catalogue-apps`, are named in the values), and
`directory.push`, `githubApps.push` and `slackState.push` render an External
Secrets `PushSecret` for the ones nothing upstream can re-deliver. Copying the
rest is the deployment's job.

`config.exports` copies the secrets the console keeps (a Slack App's bot token, the
runner and catalogue Apps, the seven recovery bundles) into OpenBao, written by the
service itself and never a dependency
([0034](../../docs/decisions/0034-exports-go-to-openbao-directly.md)); `config.ports.export`
says which OpenBao and how to log in, and `exports.openbao.caBundle` and
`exports.openbao.token.audience` mount the CA and project the token the login
presents. On a State adapter this replaces the `push` values, which stay for the
`legacy` storage and are deprecated. See
[docs/reference/configuration.md](../../docs/reference/configuration.md#exports-and-the-export-port).
`alerts.rules.exportFailing` and `exportStale` and a dashboard row cover it.

`telemetry.otlp.endpoint` sets the OpenTelemetry SDK environment on every pod:
`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`protocol`,
`http/protobuf` by default), an `OTEL_SERVICE_NAME` per component
(`access-issuer`, `github-roster`, `slack-roster`) and every `extraEnv` entry
(other `OTEL_*` variables only). Empty, nothing is rendered and nothing is
exported. See [docs/operations/telemetry.md](../../docs/operations/telemetry.md#wiring-it-with-the-chart).

Without `audit.s3.bucket` the audit trail stays in one replica's memory,
which is not a record; the service says so at start. A bucket needs an
identity to write with, and the chart carries no credential of its own:
set `serviceAccount.annotations` and let the cluster's pod-identity
webhook inject one, rather than handing this service a long-lived key.

`examples/github-apps.yaml` ships beside the values: a default set of
GitHub Apps an estate can copy — dependency updates split public from
private, a bot that approves pull requests and cuts tags, and one App for
the program that manages the organisation — with what each is for and why
they are separate identities. It is values to read and copy, not a
default: creating an App is an owner of the organisation confirming a
manifest
([guide](../../docs/connect/github-apps-catalogue.md#a-default-set)).

`slackApps` declares Slack Apps the way `githubApps.catalogue` declares GitHub
Apps: an operator creates each from
the console with a throwaway app configuration token (used once, never
stored), an owner of the workspace installs it, and the bot token is kept in
`<release>-slack-catalogue-apps`. An entry may `push` that one key to a
secret store
([guide](../../docs/connect/slack-apps-catalogue.md)).

`controllerSlack` renders the Slack controller (`enabled`, `resources` and the controller's `config`: `interval`,
`enabledWorkspaces`): it needs `exchange.clusters` to name this cluster and
`console.mount` to be set, and egress to `slack.com:443` from the fleet's own
policy
([guide](../../docs/connect/slack-workspace.md#running-the-controller)).
`slackState.push` is a recovery copy of the Slack state: two `PushSecret`s, one
for `<release>-slack-credentials` at `remoteKey` and one for the mirror
`<release>-slack-records` at `recordsRemoteKey` (the two keys must differ), with
`deletionPolicy` fixed at `None`; it needs `config.store: kubernetes`
([runbook](../../docs/operations/runbook.md#slack-state)).

```sh
helm install access-roster oci://ghcr.io/truvity/charts/access-roster \
  --namespace access-roster --create-namespace \
  --set config.issuerURL=https://issuer.example
```
