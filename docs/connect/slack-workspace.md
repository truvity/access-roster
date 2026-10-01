# Connect a Slack workspace

The Slack controller, `slack-roster`, makes each Slack workspace's channels
match the policy's `slack` table: a channel is bound to groups, its wanted
members are those groups' holders, and every pass the controller invites the
people who belong and, where the channel is `strict`, removes the people who do
not. It is a second process from the `access-issuer` chart, like the
[GitHub controller](github-organisation.md), and has no listener.

How a channel is bound (`from`, `mode`, `ignore`, `adopt`, `private`) is the
[policy's Slack section](../reference/policy.md#slack-channels). This page is
what the controller does with it, and how to run it.

## What it does, every pass

For every workspace the policy declares:

1. **Reads Slack whole.** Who the bot token is (checked against the team
   recorded when the workspace was first installed), every channel the bot can see, the members of the channels the
   policy binds, the account for each address the decision needs, and pending
   Slack Connect invitations. A read that is not whole, such as a missing scope,
   a rate limit that outlasts every retry or a page that fails, fails the
   workspace's pass and decides nothing: a partial read must never look like a
   workspace in which nobody has an account.
2. **Asks the console which domains each directory serves**, once per pass:
   a person is looked up in a workspace by their address in the domains of the
   workspace's **owning directory**, and nowhere else (see
   [Where a workspace's team, owner and domains come from](#where-a-workspaces-team-owner-and-domains-come-from)).
   A workspace with no owner holds every person, saying *no owning directory:
   set the owner on the console*; a directory that cannot be read, or is no
   longer connected, fails the workspace's pass and changes nothing.
3. **Asks the directory who holds each bound group**, once per pass for every
   workspace. The console answers under the digest of the policy it computed
   with, and the controller acts only on answers under its own: during a rollout
   the two restart at different moments.
4. **Derives** the wanted state, and **asks the directory to vouch** for each
   address a removal or a leaver report rests on. One question per address per
   pass, however many channels or workspaces name the person. An address the
   directory could not answer for, or answered for under another policy, is not
   vouched for, and its removal waits (row state `retrying`).
5. **Decides**, then acts if the workspace is listed in `slackRoster.actsIn`;
   otherwise it only reports.
6. **Publishes every workspace's report together** into the ConfigMap
   `<release>-slack-status`, one key per workspace.

### Modes

- **`extend`** (the default) only adds. Nobody is ever removed from an
  `extend` channel.
- **`strict`** (private channels only) adds and removes. It never removes
  bots or apps, the bot itself, deactivated users, guests, people of another
  workspace, anybody on the channel's `ignore` list, anybody with no address on
  the account, or anybody the directory has not vouched for.

### Held, retrying and reported rows

| State | Means |
|---|---|
| `held` | something is to be done and is not being done until a person acts. The reason says what: no Slack account yet, the account is deactivated or a bot's, it belongs to another workspace, no address of the person is in the owning directory's served domains, the workspace has no owner, a channel of that name exists and was not made by the bot (adopt it by id), a private channel the bot is not in (invite the bot), the visibility disagrees with the policy |
| `retrying` | a removal the directory could not vouch for this pass, or a change Slack refused (with Slack's words); tried again next pass |
| `reported` | said, never acted on: a guest, an account of another workspace, an account with no address |
| `ignored` | on the channel's `ignore` list |

A hold is recorded in the audit trail once, when it becomes held, as
`roster.slack_action.held`; not every pass, and not again after a restart.

### Breakers

A removal set that is over half of one channel's members, or over half of the
workspace's managed members, removes nobody and is reported with a
**fingerprint** of exactly that set. An operator's confirmation of that
fingerprint lets that set, and no other, go ahead; it lapses after 24 hours.
**One confirmation covers every gate its fingerprint covers**: when one channel
trips both its own breaker and the workspace's on the same set, confirming it
once is enough. A set that changed has a different fingerprint and needs its own
confirmation.

### Leavers

A person gone from the directory (authoritatively: not found, or suspended) who
is still an active member of a managed channel is a **leaver**. The report lists
them with the channels they are in, and the audit trail records
`roster.slack_leaver.reported` once. The controller removes nobody on that
account alone: a strict channel's removal rule is the only thing that removes,
and a leaver in an `extend` channel or a public channel stays there until a
person deals with it.

### Shared channels

Slack Connect channels are not in the policy: the console keeps each as a
record beside the workspaces' records, `_shared.<name>.json`. The controller
validates every one against the policy it runs under. A valid one is acted on,
a refused one is reported on its host workspace as a held channel with the
reason, and acted on by nobody. They are created and edited on the console's
Slack Connect page: see [slack-connect-channels.md](slack-connect-channels.md).

### Dry run until `actsIn`

A workspace is born disabled. Every pass derives it, publishes what WOULD
change, and calls Slack for nothing that changes it and records nothing in the
audit trail. Enabling one is a reviewed change to `slackRoster.actsIn`; removing
it again stops the controller acting in it, and undoes nothing.

### What it never does

- **Create accounts.** A person with no Slack account is a held row until they
  have one.
- **Touch user groups.** Only channel membership.
- **Remove anybody from a public channel.** Slack lets only administrators do
  that; `strict` on a public channel is refused when the policy loads.
- **Change a channel's visibility**, invite guests, or act on a bot, an app or
  a deactivated account.
- **Act on a partial read or on another policy's answer.**

## Failure is per workspace

A workspace that is not connected, is created and not yet installed (no bot
token), or whose read of Slack failed is reported `failed` with the reason over
the last report that had rows, so the page does not blank. It does not stop the
other workspaces' passes.

## Where a workspace's team, owner and domains come from

The policy names a workspace by its **key** and binds channels in it. It does
not say which Slack team the key stands for, which directory owns it or which
domains its people use: access-roster knows each of those already, and a
second copy in a file would only drift from the first. A policy that still
carries `team_id`, `domains` or `owner` is refused at load, with a message
saying so.

| Fact | Where it comes from | How to change it |
|---|---|---|
| **owner**: the connected directory the workspace belongs to | chosen when the workspace is connected, and recorded in its connection record | the installation-wide operator's **Change owner** on the workspace's card |
| **team**: the Slack workspace the key stands for | the team `oauth.v2.access` reports at the **first install**; every later install or reconnect must match it (a token for another team is revoked and refused) | disconnect and connect again |
| **domains** a person is looked up by | the domains the **owning directory serves**, read from the console every pass | change what the directory serves (the directory's own page) |

Who may connect a workspace nobody has connected yet, and who then owns it:

- the **installation-wide operator** chooses the owning directory from the
  connected directories, or *none*;
- an operator of **exactly one** connected directory owns what they connect:
  the form shows that directory and asks nothing;
- an operator of **several** connected directories chooses among theirs;
- anybody else, and anybody who names a directory they do not operate, is
  refused.

The owner is recorded with the connect audit record
(`roster.slack_workspace.connected` carries `owner`). Once recorded it is
changed only by the installation-wide operator, and the change is its own
audit record (`roster.slack_workspace.owner_changed`, with the previous and
new owner). The page shows the owner by its primary domain, not its id.

## Connect a workspace from the console

The **Slack** page lists every workspace the policy declares
(`slack.workspaces`) that you may view, with where it stands and what the
controller last did there. Connecting one is three steps, and the only thing
you type is a throwaway token (and, where you have a choice, the owning
directory):

1. **Generate an app configuration token.** Open
   [api.slack.com/apps](https://api.slack.com/apps), scroll to **Your App
   Configuration Tokens** and press **Generate Token** for the workspace that
   will own the App. It is one word starting `xoxe.`, it expires in **12
   hours**, and the console uses it **once**: it creates (or updates) the App
   and is dropped. It is not written to the Secret or a record, not put in the
   signed state, and not in any log line, audit record or error.
2. **Press Connect** on the workspace's card, choose the owning directory
   where the form offers a choice, and paste the token into the password field
   (the field is cleared before the call). The console builds the
   App's manifest (the bot user, the scopes below, and its own callback as the
   only redirect URL: nothing that receives a request from Slack), creates the
   App, and keeps its client id and secret as **created, not installed**. You
   are then sent to Slack.
3. **An owner of the workspace approves the App** on Slack's page. Slack sends
   the browser back to `/connect/slack/workspace/callback`; the console
   exchanges the code for the bot token and keeps it, in the Secret
   `<release>-slack-credentials`. The **first** install records the team Slack
   reports; a **later** install is kept only if it belongs to that same team.
   Any other team is refused: the token is **revoked** (`auth.revoke`) and
   dropped, nothing is kept, and `roster.slack_workspace.connect_refused` is
   recorded (so is a first install into a team already connected under another
   key). A successful install records `roster.slack_workspace.connected`.

The bot scopes are one list, `connection.BotScopes`, each for a method the
controller calls:

| Scope | For |
|---|---|
| `users:read` | `users.info` |
| `users:read.email` | `users.lookupByEmail`, and the address in `users.info` |
| `channels:read` | `conversations.list`, `.info` and `.members` of public channels |
| `groups:read` | the same, for private channels the bot is in |
| `channels:manage` | `conversations.create`, `.invite` and `.kick` in public channels |
| `groups:write` | `conversations.create`, `.invite` and `.kick` in private channels |
| `channels:join` | `conversations.join`, which adopts a public channel |
| `conversations.connect:write` | `conversations.inviteShared`, `.acceptSharedInvite` |
| `conversations.connect:manage` | `conversations.listConnectInvites` |

**Reconnect** approves the App again (to rotate the token, or to grant scopes a
later release asks for). When the roster now asks for a scope the App was
created without, the card shows **scopes missing** and Reconnect asks for a
fresh configuration token first, because Slack changes an App's scopes only for
one; it updates the manifest with it, then sends an owner to Slack.

**Disconnect** (with a confirm dialog) revokes the bot token, deletes the
credential, the record and any confirmation, and records
`roster.slack_workspace.disconnected`. The controller then reports the
workspace as not connected. If Slack will not revoke the token the connection is
kept and the dialog offers **Forget anyway**, which forgets it and says in the
audit record that the token was not revoked; remove the App in its Slack
settings then. The App itself stays in Slack until it is deleted there.

A workspace's connection is an **owner's** to operate: the installation-wide
operator, or the operator of the directory workspace recorded as its owner. A viewer sees the page and no buttons; every
row carries `can_operate`, the server's answer. A deployment that keeps no state
in Kubernetes cannot connect a workspace: a bot token would not survive a
restart.

### What the page shows

Per workspace: the connection (**not connected**, **created, not installed**,
**installed**, **scopes missing**), whether the controller **acts** or is in a
**dry run**, and when its last pass was. Per channel: its mode, privacy, whether
it will be created or adopted or is held, and each person as in step, **will
invite**, **will remove**, **held** (with the reason), **retrying** or
**reported**. Leavers are listed apart. Nothing on the page is a credential.

### Confirming a breaker from the console

A workspace or channel whose pass would remove more than half of its members
shows a red banner with the set's fingerprint behind a **Confirm** button
(operators only). Confirming writes `_confirm.<workspace>.json`, or
`_confirm.<workspace>.<channel>.json` for a channel's own breaker, into the
records ConfigMap, records `roster.slack_removals.confirmed`, and lapses after
24 hours. The console refuses a fingerprint that is not the latest report's for
that gate: a set that changed since the page was loaded needs looking at again.

The API behind the page is `SlackService` (`GetSlackStatus`,
`BeginSlackWorkspaceConnect`, `ChangeSlackWorkspaceOwner`,
`DisconnectSlackWorkspace`, `ConfirmSlackRemovals`). The catalogue's [Slack Apps](slack-apps-catalogue.md)
are separate: they create Apps for other purposes; this page's App is the
roster's own.

## Running the controller

```yaml
slackRoster:
  enabled: true
  actsIn: []            # born disabled: nothing is changed until a workspace is listed
exchange:
  clusters:
    - name: prod        # this cluster: the service verifies the controller's token against its key set
      issuer: https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE
      jwksUri: https://oidc.eks.eu-central-1.amazonaws.com/id/EXAMPLE/keys
```

and the policy puts its account in the group that reads who holds a group:

```yaml
groups:
  all:access-roster:viewer:
    matchers:
      - service_account: { cluster: prod, namespace: access-issuer, name: access-issuer-slack-roster }
```

The chart refuses to render the controller without an `exchange.clusters` row or
a console mount. The controller records what it did into the audit trail itself,
with its own token, when `audit.*` is set; the installation must map the
account `<release>-slack-roster` to the source `roster`.

**Egress.** The controller calls Slack's API at `slack.com:443`. The chart
cannot open that: a Kubernetes NetworkPolicy cannot name a host, and the chart's
policy governs the service's ingress only (as for `api.github.com` and the GitHub
controller). Allow `slack.com:443` for the controller's pods,
`app.kubernetes.io/name: access-issuer-slack-roster`, in the cluster's egress
policy. The chart does admit the controller to the service's port, for reading
the console's API, when `networkPolicy.enabled`.

**What it reads.** The console's API (with its own ServiceAccount token): who
holds each group (`ListHolders`), whether the directory vouches for an address
(`Explain`) and which domains each directory serves (`ListServedDomains`, a
viewer's read: the controller's account is in the group the chart grants it,
and sees every directory). The rest are mounted volumes, so the account needs no permission to
read any Secret or other ConfigMap through the API: the Secret
`<release>-slack-credentials` (one `<workspace>.json` per workspace: app id,
client id and secret, the bot token once installed) and the ConfigMap
`<release>-slack-workspaces` (each workspace's record, `_shared.*` shared
channels, `_confirm.*` confirmations). Both are optional: before anything is
connected the controller reports each declared workspace as not connected. Keys
that start with an underscore are other documents and are never read as a
workspace.

**Deploy the controller and the console together**, as the chart does: every
answer carries the digest of the policy it was computed under, and a pass under
another policy changes nothing and is tried again within seconds.

### Enabling a workspace

1. The workspace is declared in the policy, connected, installed, and the
   controller runs with it *not* in `slackRoster.actsIn`.
2. Read its report after a pass. `tick.outcome` says `dry-run`; the rows say
   exactly what enabling would do. Look for anybody you did not expect to be
   removed, and for held rows: each carries its reason.
3. Add the key to `slackRoster.actsIn` and roll out. The next pass acts; its
   changes appear in the audit trail as `roster.slack_*`.

### Metrics

Pushed over OTLP like the GitHub controller's: `slack_roster.passes` (by
workspace and outcome), `slack_roster.changes` (by action and whether Slack
accepted it), `slack_roster.breaker_trips`, `slack_roster.rows` and
`slack_roster.channels` (by state), `slack_roster.leavers` and
`slack_roster.shared_invalid`.
