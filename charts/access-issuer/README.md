# access-issuer chart

Deploys the whole of access-roster: the directory reader, the policy,
the OpenID provider, the login page, the console and the audit trail in
one process, and, with `githubRoster.enabled` and `slackRoster.enabled`, the
GitHub and Slack controllers beside it. Each controller is a second Deployment
from the same chart with no listener, and is a dry run for every organisation or
workspace until it is listed in `githubRoster.config.enabledOrgs` or `slackRoster.config.enabledWorkspaces`.
Each component is configured by one file, its `config` value, rendered as it
stands and validated against the schema its binary uses; secrets reach a pod only
through `secretEnv`. See [docs/reference/configuration.md](../../docs/reference/configuration.md).
Published to `ghcr.io/truvity/charts/access-issuer` on every
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
proxy would have nowhere to send anyone. And it does not make a second
copy of what the console adds unless you ask it to: the Secrets that hold it are
named in
[docs/reference/configuration.md](../../docs/reference/configuration.md#restoring-from-the-secrets-alone)
(the Slack ones, `<release>-slack-credentials`, `<release>-slack-records` and
`<release>-slack-catalogue-apps`, are named in the values), and
`directory.push`, `githubApps.push` and `slackState.push` render an External
Secrets `PushSecret` for the ones nothing upstream can re-deliver. Copying the
rest is the deployment's job.

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

`slackRoster` renders the Slack controller (`enabled`, `image`, `resources` and the controller's `config`: `interval`,
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
helm install access-issuer oci://ghcr.io/truvity/charts/access-issuer \
  --namespace access-issuer --create-namespace \
  --set config.issuerURL=https://issuer.example
```
