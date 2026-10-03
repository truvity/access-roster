# A catalogue of Slack Apps

> **Built.** Declaring, creating, installing and reinstalling ship; there
> is nothing to disconnect here yet (see [Leaving](#leaving)).

**Anchor:** an **app configuration token**, pasted by an operator for the
one call that creates the App. It is used once and never kept. Everything
after that is two clicks by an owner of the workspace: Slack hands the bot
token to this service, and nothing is typed.

A deployment that acts in Slack needs an App per purpose: one that keeps
channels in step with groups, one that posts notifications. Each is the
same chore by hand: create an App in Slack's console, pick scopes, install
it, copy the bot token somewhere. The Slack catalogue is the
[GitHub App catalogue](github-apps-catalogue.md)'s twin: each App is a
declaration in the deployment's values, and creating and installing it is
done from the console.

## Declaring an App

```yaml
slackApps:
  - id: sync                     # [a-z0-9-], at most 32, unique; never changes
    workspace: acme              # a key of the policy's slack.workspaces
    name: acme-sync              # optional; default <workspace>-<id>, at most 35
    description: Keeps channels in step with groups   # optional; at most 140
    botScopes:                   # the bot token's scopes; at least one
      - channels:read
      - users:read
      - users:read.email
    push:                        # optional; off unless written out
      secretStore: {name: example-store, kind: SecretStore}
      remoteKey: platform/slack-apps/sync
```

| Field | Meaning |
|---|---|
| `id` | the App's name **here**: where it is kept and what the console names. Lower-case letters, digits and dashes, at most 32 |
| `workspace` | a key of the policy's `slack.workspaces` (lowercase letters, digits and `-`, at most 40), **already connected** on the Workspaces tab of the console's Slack area. The App is installed into that workspace, and **only** that one: the install is refused when Slack says the token belongs to another team than the one recorded when the workspace was first installed |
| `name` | the App's name in Slack. Empty is `<workspace>-<id>`, cut to 35 characters; a declared name over 35 is refused |
| `description` | Slack's short description; at most 140 characters |
| `botScopes` | the bot scopes the App asks for, by Slack's names (`channels:read`, `users:read.email`, `conversations.connect:write`, ...). Listed once each |
| `push` | optional: copy this App's bot token to a secret store. See [Projecting one App's bot token](#projecting-one-apps-bot-token-to-a-secret-store) |

The catalogue is rendered into `ConfigMap <release>-slack-apps-catalogue`,
mounted, and read once at start; a change rolls the service out. **The
service refuses to start** on an unknown key, a duplicate id, a scope that
is not a scope name, a name or description Slack would refuse, or an entry
whose `workspace` the policy's `slack.workspaces` does not name. Add the
workspace's key to the policy first, then connect it on the console's Slack
area: the policy never carries its team, owner or domains (see
[where they come from](slack-workspace.md#where-a-workspaces-team-owner-and-domains-come-from)).
Until the workspace is connected, and has recorded its team at its first
install, Create and Install are refused with *connect the workspace first*.

Needs `config.store: kubernetes`: with any other store a bot token would
not survive a restart, and the console says so instead of creating an App.

## The app configuration token

Slack creates an App through its API only for a caller holding an **app
configuration token**. It is not the bot token, and it is not a credential
of this service: it belongs to a person and a workspace, and it expires.

To get one:

1. Open [api.slack.com/apps](https://api.slack.com/apps), signed in to the
   workspace that will own the App.
2. Scroll to **Your App Configuration Tokens** and choose **Generate
   Token**, for that workspace.
3. Copy the **Access Token** (it starts `xoxe.xoxp-`). Ignore the refresh
   token.

It **expires in 12 hours** and this service uses it **once**, for the call
that creates the App (or, for a [reinstall](#reinstalling), the call that
updates it). Paste a fresh one each time; throw it away afterwards.

## Creating and installing

On the **Apps** tab of the console's Slack area (`#/slack/apps`) each declared App is a row with its
state and the step it waits for.

1. **Create.** The operator pastes a configuration token into the dialog.
   The service builds the App's manifest from the entry (the bot user, the
   `botScopes`, the console's callback as the **only** redirect URL, and
   nothing else: no event subscriptions, no interactivity, no socket),
   creates the App in Slack, and keeps its **client id and client secret**
   in the Secret below. The state is *created, not installed*: there is
   no bot token yet.
2. **Install.** The console sends the browser to Slack's authorize page for
   the workspace the entry names. An owner of that workspace approves, and
   Slack sends the browser back to the console, which exchanges the one-time
   code for the **bot token**. The token is kept only if it belongs to the
   team recorded for the entry's `workspace` when it was first installed; a
   token for any other team is revoked and the install is refused, with a
   record in the audit trail. The state is *installed*.

The flow is pinned to the browser that started it by a cookie and a signed
state that carries the operator who began it and the App it is for, exactly
as the GitHub connect flow is. The callback asks the role question again,
of whoever is signed in then.

### Reinstalling

Slack grants scopes only at install time, and changes an App's scopes only
for a configuration token. So when you add a scope to `botScopes` after the
App was created, the row says **scopes missing** and offers **Reinstall**:

- the dialog asks for a configuration token, which updates the App's
  manifest once (Slack keeps the App, its id and its client credentials);
- then an owner approves the new scopes in Slack, and the new bot token
  replaces the old one.

Without the token a reinstall would grant what it granted before, so the
console does not offer to skip it. A reinstall where the App already
carries every declared scope needs no token at all: it is just approved
again.

## Who may do it

Creating, installing and reinstalling need the **operator** role: the
installation-wide operator, or the scoped operator of the directory
workspace recorded as the Slack workspace's owner when it was connected (see
[who owns a Slack workspace](../reference/policy.md#who-owns-a-slack-workspace)).
A workspace connected with no owner is operated by the installation-wide
operator alone. The owner is read from the workspace's connection record, not
from the policy; only the installation-wide operator changes it. A viewer sees the Apps of the workspaces they may view and
nothing else, and each row says whether they may operate it.

## Where the credentials are kept

One Secret, `<release>-slack-catalogue-apps`, created empty at start, holds
every catalogue Slack App under its id:

| Key | Holds | Exists |
|---|---|---|
| `<id>.record.json` | ids, scopes, who and when; **never a credential** | from Create |
| `<id>.client_id` | the App's OAuth client id | from Create |
| `<id>.client_secret` | the App's OAuth client secret | from Create |
| `<id>.slack_bot_token` | the bot token | from Install, and only then |

The bot token key does not exist until the App is installed, so a copy made
in between never hands anybody an empty credential.

**The configuration token is in none of these.** It travels in the body of
one RPC over TLS, is used for one call to Slack, and is dropped: it is not
written to the Secret, not put in the signed state, not in a log line, an
error message or an audit record.

## Projecting one App's bot token to a secret store

> **On a State adapter, use an export.** `push` is **deprecated**: it renders a
> PushSecret over the Kubernetes Secret only the `legacy` storage writes. With
> `ports.adapter` other than `legacy` the service copies the token itself, with
> `exports: [{source: slack-app, app: <id>, path: slack-apps/<id>}]` into an
> OpenBao KV mount, written as `bot_token`, the property `push` wrote
> ([configuration reference](../reference/configuration.md#exports-and-the-export-port),
> [0033](../decisions/0033-exports-go-to-openbao-directly.md)).

`push` makes External Secrets copy **one key**, the bot token, to a store
and path the entry names: a program that acts in the workspace as the bot
cannot ask this service for a short-lived token, because Slack has no token
exchange to ask. What lands in the store **is** the App's token: a second
durable copy, in the blast radius of the App, rotated as one (reinstall the
App to mint a new one).

```yaml
push:
  secretStore: {name: example-store, kind: ClusterSecretStore}   # kind: SecretStore (default) | ClusterSecretStore
  remoteKey: platform/slack-apps/sync
  refreshInterval: 1h          # optional, default 1h
  deletionPolicy: None         # optional: None (default) | Delete
```

A consumer reads the property `bot_token` from `remoteKey`; the name is the
contract. Only that one key is copied: never the record, never the client
id or secret, never another App's keys. Two entries may not push to one
`remoteKey` in one store (the chart refuses), and `push` needs
`config.store: kubernetes`. `push` is a chart-side instruction: it is
stripped from the rendered catalogue the service reads.

## Leaving

There is no *Disconnect* here yet. Slack cannot delete an App through this
flow, so an App you no longer want is deleted in its settings at
`https://api.slack.com/apps/<app id>` (the console links to it), and its
keys are removed from the Secret by hand. An entry removed from `slackApps`
stays listed as *no longer declared*.

## What it leaves behind

| Object | Holds | Written by |
|---|---|---|
| ConfigMap `<release>-slack-apps-catalogue` | the declaration, `catalogue.yaml` | the chart, when `slackApps` is not empty |
| Secret `<release>-slack-catalogue-apps` | every App's record, client credentials and bot token, as above | the service, on Create and Install; created empty at start |
| PushSecret `<release>-slack-app-<id>` | the copy instruction for one App's bot token | the chart, for each entry carrying `push` |

Audit records: `roster.slack_app.created`, `roster.slack_app.installed` and
`roster.slack_app.install_refused`, each naming the App by Slack's id and
the workspace by the policy's key; `installed` carries the team id and the
scopes Slack granted. No record carries a token.

## Errors

| You see | Because |
|---|---|
| *Slack refused to create the App: invalid_auth* | the configuration token expired (12 hours), was revoked, or is for another workspace's tokens: generate a fresh one |
| *Slack refused to create the App: invalid_manifest* | Slack did not accept the declaration; the detail says where, usually a name or a scope |
| *the policy's slack.workspaces does not name workspace ...* | the entry's `workspace` is not a key of the policy. The service refuses this at start, so it means the policy changed under a running service |
| *The App was installed into workspace T... and the policy names T...* | the owner approved the App in another workspace. Nothing was kept. Remove the App from that workspace in Slack, and install again from the right one |
| *declares scopes the App was created without* | a scope was added after Create; paste a configuration token so the App can be updated, then reinstall |
| *This install did not start in this browser* | the callback came back in another browser, profile or window, or after ten minutes: start Install again |
