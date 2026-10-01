# Connect a Slack workspace

The Slack controller, `slack-roster`, makes each Slack workspace's channels
match the policy's `slack` table: a channel is bound to groups, its wanted
members are those groups' holders, and every pass the controller invites the
people who belong and, where the channel is `strict`, removes the people who do
not. It is a second process from the `access-issuer` chart, like the
[GitHub controller](github-organisation.md), and has no listener.

There are three kinds of channel. A **policy channel** is bound in git, to
internal groups. A **console channel** is an ordinary channel kept as a record
on the console, fed by directory groups and individual addresses. A **Slack
Connect channel** is a channel shared between your own workspaces, also kept as
a record on the console. A channel is one kind and is managed one way. The
console has an area for all three, under SYSTEMS, Slack: see
[What the Slack area shows](#what-the-slack-area-shows).

How a channel is bound (`from`, `mode`, `ignore`, `adopt`, `private`) is the
[policy's Slack section](../reference/policy.md#slack-channels). This page is
what the controller does with it, and how to run it.

## What it does, every pass

For every workspace the policy declares:

1. **Reads Slack whole.** Who the bot token is (checked against the team
   recorded when the workspace was first installed), every channel the bot can
   see, the members of the channels it manages, the account for each address
   the decision needs, and pending Slack Connect invitations. A read that is not whole, such as a missing scope,
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
   workspace, and **who is in each directory group** the console channels and
   Slack Connect channels name (see [Console channels](#console-channels-ordinary-channels-managed-on-the-console)). The console answers under the digest of the policy it computed
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

### Channels: created if missing, otherwise adopted by name

A bound channel is an **idempotent upsert**. When no channel of the declared
name is visible to the bot it is created; when one is, it is **adopted**: a
public channel is joined, then managed; a private channel the bot is in is
managed. Each adoption is recorded once as `roster.slack_channel.adopted`.
`adopt: <id>` stays as an optional disambiguation for a renamed channel or two
candidates. The roster never converts a channel, never unarchives one and never
makes a second channel under another name; each of those is **held**, with the
reason on the channel:

| Found | Held as |
|---|---|
| the channel's visibility differs from the declared `private` | *the channel is public in Slack but the policy says private* (or the reverse): change one of them |
| an archived channel has the name | *archived: unarchive it in Slack or rename it* |
| Slack refuses to create it as `name_taken` and no such channel is visible | *a private channel named X exists that the bot cannot see; invite the bot to it* (or unarchive it, if that is what it is) |
| the name is a Slack Connect channel | managed as a shared channel, not bound here |
| `adopt: <id>` names a channel the bot cannot see | *adopt X: the bot cannot see that channel; if it is private, invite the bot first, otherwise check the id* |
| `adopt: <id>` names a Slack Connect channel | *it is managed as a shared channel, not bound here* |
| a private channel is visible but the bot is not in it | *the bot is not in this private channel: invite the bot first* |
| the policy channel and a console record define the same channel (the same name, or the same channel id adopted) | *defined in both git and the console: held and unchanged until one definition is removed*, in the controller's report of the policy channel AND of the record; nothing on it changes in Slack. The console's own row for the record reads *invalid*, with the reason it gives for refusing a write |

A `strict` adopted channel removes only after the usual vouching and breakers:
the first pass after adopting it is subject to the breaker like any other, so a
channel that holds many people the policy does not name is held for an
operator's confirmation, never emptied.

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
| `held` | something is to be done and is not being done until a person acts. The reason says what: no Slack account yet, the account is deactivated or a bot's, it belongs to another workspace, no address of the person is in the owning directory's served domains, the workspace has no owner, a private channel of that name exists that the bot cannot see (invite the bot to it), an archived channel has that name (unarchive it or rename it), the visibility disagrees with the policy |
| `retrying` | a removal the directory could not vouch for this pass, or a change Slack refused (with Slack's words); tried again next pass |
| `reported` | said, never acted on: a guest, an account of another workspace, an account with no address |
| `ignored` | on the channel's `ignore` list |

A row held only because the person has no Slack account yet is shown on the
console as *waiting for them*: only the person can move it forward. Every other
hold is *needs you*.

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

### Console channels: ordinary channels managed on the console

Two kinds of channel are fed by two kinds of group, and never mixed on one
channel:

| Kind | Where it is declared | Fed by |
|---|---|---|
| **Policy channel** | `slack.workspaces[k].channels` in git | **internal** groups. For channels the infrastructure owns, such as alert channels |
| **Console channel** | a record on the console, `_channel.<workspace>.<name>.json` | **directory** groups (IdP groups, by address), and individual addresses |

A console channel is **ordinary**: one workspace. A channel shared between
workspaces is the third kind, a **Slack Connect channel** (see
[Shared channels](#shared-channels)). Both kinds of record are created and
edited on the console, audited, and backed up with the workspaces' own records
(`Secret <release>-slack-records`). The controller reconciles a console channel
with **the same rules as a policy channel**: created when missing, otherwise
adopted by name (or by the record's `channel_id`),
`extend` or `strict`, the directory vouches before anybody is removed, the
breakers hold a large removal set, and a hold is recorded once. Visibility is
never converted.

**The groups.** A source is a **directory group address** such as
`team@example.com`, of a directory access-roster has connected. An ordinary
channel takes groups of **its workspace's owning directory** only (the
directory recorded as the workspace's owner when it was connected). Members are
resolved **through nested groups**: a member of a group that is itself a group
in a connected directory is expanded, each group once, so a cycle ends, to a
bounded depth. A chain the console cannot expand whole is reported as cut short
and the channel is refused for that pass, because nobody may be added or
removed on a read that is not whole. A member of a directory the console does
not read is not live and is not invited.

**Individual addresses.** Beside `sources`, a record may list `members`: people
by address, for the few who belong without being in any group. At least one of
`sources` and `members` is set; both may be. An ordinary channel takes users of
**its workspace's owning directory** only, by domain, and the directory must
actually know the user and the account must be active when the record is
written. Addresses are lowercased and none repeats. The console refuses, with
the reason: an address that is a **group** (enter it under *Directory groups*),
a group address entered as a person (enter it under *Individual addresses*), a
repeat, an address of another directory (*<address> is not a user of the
directory that owns this workspace (<owner id>) — individual addresses come
from the directories this channel draws from*), an address the directory does
not know, and an address that is suspended (only an active user can be listed).
The controller asks again at every pass and refuses the record
when an address is of another directory than the owner's. The people wanted are
the **union** of the groups' members and the individuals, mapped to people
exactly as group members are: the `people` aliases, the per-workspace address
choice, `users.lookupByEmail`, so somebody in a group and listed individually is
one person, invited once. An individual who is suspended or deleted in the
directory is a **leaver** like a group member: never added, reported on an
`extend` channel, removed by a `strict` one on the directory's say. One with no
Slack account yet is held, *no Slack account yet*, as a group member is. On the
console, the channel page and the Channels rows show both ("2 groups, 3
people"), and a person's page lists the channels that name them *individually*.

**Removals ask about the directory groups.** Where a policy channel asks the
directory whether somebody still holds an internal group, a strict console
channel asks whether they are still in one of its directory groups, or in a
group those nest. Somebody the directory still finds there is never removed,
however the member list came out; somebody it cannot vouch for waits (`retrying`).

**What is refused** (by the console when the record is written, and again by
the controller at every pass, because a directory can be disconnected or an
owner changed afterwards; the refusal is a held channel on the workspace's
report, with the reason, acted on by nobody):

- a source that is not a group of a connected directory, or, for an ordinary
  channel, of another directory than the workspace's owner;
- a channel the **policy already defines**, the same name in the workspace or
  the same channel id adopted by a binding: *this channel is defined in git;
  remove it there to manage it here*. If one gets through (the policy entry
  came later), both are held as *defined in both git and the console*;
- `strict` on a public channel, or an `ignore` list without `strict`;
- a workspace with no owning directory yet;
- a channel that is already managed the other way (an ordinary record and a
  Slack Connect record of the same host and name or id).

**What an edit may change.** An edit may change `mode`, `ignore`, the directory
groups and the individual addresses. It cannot change the workspace, the name,
the channel id or the visibility; the console refuses such a request and says to
create a new record and delete this one. Two people saving at once do not
overwrite each other: the write is made under the ConfigMap's version, and the
console says to reload when it cannot land. Saving a record wakes the controller: it takes
effect within a couple of minutes (see
[A pass runs promptly after an install](#a-pass-runs-promptly-after-an-install)).

**Discovery.** Every pass the report lists, per workspace, every channel the
bot can see that **neither a policy binding nor a record manages**: public
channels, and private ones the bot is in. `#general` and archived channels are
left out. The list is by name and capped at 500 per workspace, with a count of
the rest. On the Slack area's **Discovered** tab (`#/slack/discovered`) they are listed
with **Manage**, which opens the form prefilled with the workspace, the name,
the channel id and the visibility as seen; you choose the directory groups and
the mode. The tab also lists Slack Connect channels, and its filters (`kind`,
`visibility`, `sort`) are described under
[Slack Connect channels](slack-connect-channels.md#adopting-a-channel-that-is-already-shared).

**Archiving.** Deleting a record leaves the channel in Slack. When the
workspace's controller reports that it acts (it is in `slackRoster.actsIn`), the
delete dialog has an opt-in, *Also archive #name in Slack* (off by default);
for a dry-run workspace the dialog says to archive in Slack by hand instead.
Before anything is changed the console checks, in order: the latest report says
the workspace acts (no report, an unreadable one, or a dry run refuses); the
channel's Slack id is known (the record's `channel_id`, else the report's);
and Slack itself, asked with `conversations.info` and the workspace's bot token,
says the channel is not shared. A Slack Connect channel (Slack's `is_ext_shared`,
or any other sharing flag it sets) is refused, because archiving closes it for
every organisation in it, whoever hosts it; so is a channel the bot cannot see
(a private one it is not in), and a Slack that does not answer. A refusal is
`FailedPrecondition` (or `Unavailable` when Slack did not answer), changes
nothing and leaves the record in place; you archive the channel in Slack by hand.
Only then is the record deleted and the bot's `conversations.archive` called,
audited as `roster.slack_channel.archived`. If that call still fails (the App
lacks the scope, or the workspace forbids a bot archiving), the record is
already deleted, the failed attempt is audited with outcome failure, and the
note says to archive the channel in Slack by hand.

**Who may.** Create, edit and delete: the operator over the workspace's owning
directory, or the installation-wide operator. A viewer sees the records and what
was discovered. Every change is audited as
`roster.slack_console_channel.created`, `.updated` or `.deleted`, with the
directory groups as targets of type `directory_group` and the individual addresses as
targets of type `directory_user` (audit catalogue 1.5.0; the data counts them as
`members`, and an edit's `changes` says `members: 2 -> 3 people (1 added, 0 removed)`).

#### Moving a policy channel to the console

To move a channel from git to the console: **remove it from the policy, then
Manage it from Discovered.** The console never manages a channel the policy
defines, and there is no take-over.

1. **Remove it from the policy in git** (the `channels` entry under its
   workspace). It becomes **unmanaged**: nothing is added to or removed from it
   while it is, and no removals happen.
2. After the next pass it appears on the Slack area's **Discovered** tab,
   because the bot is in it.
3. **Manage** it. The form is prefilled with the workspace, the name, the id and
   *private*; choose the mode (the same one keeps its behaviour), set its
   `ignore` list if it had one, and pick the directory groups as the sources.

Do these in this order. The form refuses a channel the policy still defines
(*this channel is defined in git; remove it there to manage it here*), and the
server refuses it the same way. If a record and a policy entry end up defining
the same channel anyway (the entry was added later, or the record is older),
**no mixing**: both are reported **held** (*defined in both git and the
console*) and nothing on the channel changes until one of the definitions is
removed. A record that still carries the retired `supersedes_policy: true`
loads with the field ignored and is never written with it again; once git no
longer defines the channel it is a plain console channel. If the new record's
group holds fewer people than the old internal group did, a strict channel will
remove the difference only once the directory vouches for each, and never past
the breaker: the first pass after the move is subject to it like any other.

### Shared channels

Slack Connect channels are not in the policy: the console keeps each as a
record beside the workspaces' records, `_shared.<name>.json`, fed by **directory
groups and individual addresses of any connected directory**: each resolved
person joins on the side whose workspace's owning directory serves their
address. A Slack Connect channel is always `extend`: nobody is ever removed from
one. The controller validates every one against the policy it runs under and
asks the console who is in its groups. A valid one is acted on,
a refused one is reported on its host workspace as a held channel with the
reason, and acted on by nobody. A record written before shared channels were fed
by directory groups, with internal groups in `from`, is reported invalid with a
message that says to edit it and pick directory groups; its names are never
reread as directory groups. They are created and edited on the console's
Slack Connect tab: see [slack-connect-channels.md](slack-connect-channels.md),
including how a guest workspace's side is found
([Guest sides and the probe](slack-connect-channels.md#guest-sides-and-the-probe)).

### Dry run until `actsIn`

A workspace is born disabled. Every pass derives it, publishes what WOULD
change, and calls Slack for nothing that changes it and records nothing in the
audit trail. Enabling one is a reviewed change to `slackRoster.actsIn`; removing
it again stops the controller acting in it, and undoes nothing. The console's
own Slack calls (connect, disconnect, revoke) are not part of a pass and are not
gated by `actsIn`. Archiving on delete follows the switch: it is offered, and
accepted, only for a workspace whose controller reports that it acts. Remove a
workspace from `actsIn` before removing it from the policy: the controller
refuses to start naming a key the policy does not declare, and the chart refuses
to render it.

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

A workspace that is not connected, or is created and not yet installed (no bot
token), is reported `waiting` with no error over the last report that had rows:
it is a state a workspace passes through, not a fault, and the console shows a
neutral note. A workspace whose read of Slack failed, whose owning directory
cannot be read or is not connected, or whose bot token belongs to another team
than the one recorded, is reported `failed` with the reason over the last report
that had rows, so the page does not blank. Neither stops the other workspaces'
passes.

## Where a workspace's team, owner and domains come from

The policy names a workspace by its **key** and binds channels in it. A key is
lowercase letters, digits and `-`, at most 40, starting and ending with a
letter or digit. It does
not say which Slack team the key stands for, which directory owns it or which
domains its people use: access-roster knows each of those already, and a
second copy in a file would only drift from the first. A policy that still
carries `team_id`, `domains` or `owner` is refused at load, with a message
saying so.

| Fact | Where it comes from | How to change it |
|---|---|---|
| **owner**: the connected directory the workspace belongs to | chosen when the workspace is connected, and recorded in its connection record | the installation-wide operator's **Change owner**, on the workspace's card on the Workspaces tab |
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
new owner). The console names an owning directory by its workspace id and every
domain it is authoritative for, for example `C0example — acme.example,
globex.example`; served domains that are not authoritative are left out.

Connecting a workspace nobody has connected records the **connecting
operator's directory** as its owner: whoever connects it first owns it. That
is a rule about who operates the connection inside access-roster; Slack itself
still requires an owner or administrator of the target workspace to approve
the App, so the console grants nothing in Slack. The installation-wide
operator can change the owner afterwards, and the change is audited.

## Connect a workspace from the console

The **Workspaces** tab of the Slack area lists every workspace the policy
declares (`slack.workspaces`) that you may view, with where it stands and what
the controller last did there. A workspace the policy no longer declares but
that is still connected stays listed, marked *no longer declared*, so it can be
disconnected. Connecting one is three steps, and the only thing
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

### A pass runs promptly after an install

Besides its 15-minute interval (`slackRoster.interval`), the controller looks
every 30 seconds at the mounted credentials and records. When a workspace's own
credential or record, or a console channel or Slack Connect record, changed (a new bot token after an install, a reconnect), it
runs a full pass without waiting for the interval. Allow up to about two
minutes: the look is every 30 seconds, and the kubelet takes up to about a
minute to project a changed Secret or ConfigMap into the pod. Until a report
newer than the connection exists, the card says *Installed - waiting for the
first pass*.

**Refresh** on an installed workspace's card (operators only) asks for a pass
over that workspace now: the console writes a marker `_pass.<workspace>.json`
into the records ConfigMap and the controller notices it at its next look. A
second request less than 60 seconds after the first is refused. The card says
*Pass requested* until a newer report exists. The marker is not a record: it is
left out of the recovery copy, and there is no audit action for it (the
requester is logged). Saving a console channel or a Slack Connect record
starts a pass the same way: the controller's look at the records includes them,
and saves made close together are answered by one pass.

The bot scopes are one list, `connection.BotScopes`, each for a method the
roster calls:

| Scope | For |
|---|---|
| `users:read` | `users.info` |
| `users:read.email` | `users.lookupByEmail`, and the address in `users.info` |
| `channels:read` | `conversations.list`, `.info` and `.members` of public channels |
| `groups:read` | the same, for private channels the bot is in |
| `channels:manage` | `conversations.create`, `.invite`, `.kick` and `.archive` in public channels |
| `groups:write` | `conversations.create`, `.invite`, `.kick` and `.archive` in private channels |
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
workspace as not connected, within a couple of minutes, and carries nothing over
from the old connection: the Channels and People views stop showing its channels
and members. If Slack will not revoke the token the connection is
kept and the dialog offers **Forget anyway**, which forgets it and says in the
audit record that the token was not revoked; remove the App in its Slack
settings then. The App itself stays in Slack until it is deleted there.
Disconnect leaves the workspace's console channel records
(`_channel.<workspace>.*`) and the Slack Connect records it hosts in place:
delete them first, or they apply to whichever Slack team is connected under that
key next (the dialog says so). Their definitions are not reviewed for a
different team, so delete them when the key is reused for one.

A workspace's connection is an **owner's** to operate: the installation-wide
operator, or the operator of the directory workspace recorded as its owner. A viewer sees the page and no buttons; every
row carries `can_operate`, the server's answer. A deployment that keeps no state
in Kubernetes cannot connect a workspace: a bot token would not survive a
restart.

### What the Slack area shows

SYSTEMS, Slack is one entry with five tabs: Workspaces, Channels, Slack Connect,
Discovered and Apps.

**Workspaces** (`#/slack`) shows, per workspace, the connection (*not
connected*, *created, not installed*, *installed*, *scopes missing*), the team
once recorded, the owning directory, whether the controller **acts** or is in a
**dry run**, when its last pass was, how many channels it manages (a link to the
Channels tab), a breaker banner with **Confirm**, and the leavers.

**Channels** (`#/slack/channels`) lists every managed channel of every
workspace in one list (policy channels, console channels and Slack Connect
channels), with *New channel* for operators. It narrows by workspace (any side
of a channel), kind (policy, console, Slack Connect), state (ok, pending,
waiting, held, invalid, not reported; *pending* is a channel the controller is
about to create, adopt or accept) and a name or Slack-id search, reads "N of M
shown" when a filter hides some, and keeps every selection in the address
(`#/slack/channels?workspace=&kind=&state=&q=`).

**Slack Connect** (`#/slack/connect`) and **Discovered** (`#/slack/discovered`)
are described on [Slack Connect channels](slack-connect-channels.md), and
**Apps** (`#/slack/apps`) on [Slack Apps](slack-apps-catalogue.md). The old
addresses `#/slack-apps` and `#/slack-connect` still open the matching tab.

Every managed channel has a page of its own,
`#/slack/channels/<workspace>/<name>` (or by Slack id): what feeds it (internal
groups for a policy channel; directory groups and individual addresses for a
console or Slack Connect channel), its mode, each person's state and why, each
side of a Slack Connect channel, the removal breaker with its **Confirm**, and
its history from the audit trail. The pages of a directory group, an internal
group and a person link back: a directory group lists the Slack channels it
feeds and how its people stand there; an internal group lists the policy
channels that name it; a person's page has a Slack section with each channel's
state and reason, and marks the channels that list them individually. Nothing on
these pages is a credential.

Per channel the page says its mode, privacy, whether it will be created or
adopted or is held, and each person as in step, **will invite**, **will
remove**, **held** (with the reason), **retrying** or **reported**.

### Confirming a breaker from the console

A workspace or channel whose pass would remove more than half of its members
shows a red banner with the set's fingerprint behind a **Confirm** button
(operators only). Confirming writes `_confirm.<workspace>.json`, or
`_confirm.<workspace>.<channel>.json` for a channel's own breaker, into the
records ConfigMap, records `roster.slack_removals.confirmed`, and lapses after
24 hours. The console refuses a fingerprint that is not the latest report's for
that gate: a set that changed since the page was loaded needs looking at again.

The API behind the area is `SlackService` (`GetSlackStatus`,
`BeginSlackWorkspaceConnect`, `RequestSlackPass`, `ChangeSlackWorkspaceOwner`,
`DisconnectSlackWorkspace`, `ConfirmSlackRemovals`), `SlackChannelService` for
console channels (`ListSlackChannels`, `CreateSlackChannel`,
`UpdateSlackChannel`, `DeleteSlackChannel`), `SlackSharedChannelService` for
Slack Connect records (`ListSlackSharedChannels`, `CreateSlackSharedChannel`,
`UpdateSlackSharedChannel`, `DeleteSlackSharedChannel`) and `SlackAppService`
for catalogue Apps (`ListSlackApps`, `CreateSlackApp`, `InstallSlackApp`). The
directory side is `AccessService.ListServedDomains` and
`ResolveDirectoryGroups`; every call is in the
[contracts](../reference/contracts.md). The catalogue's
[Slack Apps](slack-apps-catalogue.md) are separate: they create Apps for other
purposes; this page's App is the roster's own.

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

The other values are `slackRoster.interval` (the pass interval, default 15m),
`slackRoster.image` and `slackRoster.resources`. The controller refuses to start
when `slackRoster.actsIn` names a workspace the policy does not declare.

The policy puts its account in the group that reads who holds a group:

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
holds each group (`ListHolders`), who is in each directory group and each
individually listed address (`ResolveDirectoryGroups`), whether the directory
vouches for an address (`Explain`) and which domains each directory serves (`ListServedDomains`, a
viewer's read: the controller's account is in the group the chart grants it,
and sees every directory). The rest are mounted volumes, so the account needs no permission to
read any Secret or other ConfigMap through the API: the Secret
`<release>-slack-credentials` (one `<workspace>.json` per workspace: app id,
client id and secret, the bot token once installed) and the ConfigMap
`<release>-slack-workspaces` (each workspace's record, `_channel.*` console
channels, `_shared.*` Slack Connect channels, `_confirm.*` confirmations and
`_pass.*` pass requests). Both are optional: before anything is
connected the controller reports each declared workspace as not connected. Keys
that start with an underscore are other documents and are never read as a
workspace.

The service also keeps `<release>-slack-records`, a mirror Secret of the
records ConfigMap, for the recovery copy `slackState.push` renders; the
controller does not read it. See [Slack state](../operations/runbook.md#slack-state).

**Deploy the controller and the console together**, as the chart does: every
answer carries the digest of the policy it was computed under, and a pass under
another policy changes nothing and is tried again within seconds.

### Enabling a workspace

1. The workspace is declared in the policy, connected, installed, and the
   controller runs with it *not* in `slackRoster.actsIn`. After an install, a
   pass runs within a couple of minutes; **Refresh** asks for another.
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

### Audit

Every action is in the audit catalogue (`internal/audit/catalogue/roster.yaml`,
version 1.5.0). The controller records for itself; the console records what it
does:

| Recorded by | Actions |
|---|---|
| the controller | `roster.slack_channel.created`, `.adopted`; `roster.slack_member.invited`, `.removed`; `roster.slack_shared.invited`, `.accepted`; `roster.slack_action.held`; `roster.slack_leaver.reported` |
| the console | `roster.slack_workspace.connected`, `.owner_changed`, `.connect_refused`, `.disconnected`; `roster.slack_app.created`, `.installed`, `.install_refused`; `roster.slack_console_channel.created`, `.updated`, `.deleted`; `roster.slack_shared_channel.created`, `.updated`, `.deleted`; `roster.slack_channel.archived`; `roster.slack_removals.confirmed` |
