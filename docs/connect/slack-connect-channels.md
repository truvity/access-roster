# Slack Connect channels

> **Built.** Creating, editing and deleting Slack Connect channels between the
> installation's own Slack workspaces ships on the Slack Connect tab of the
> console's Slack area.

**Anchor:** a record on the console, not a line in the policy. An operator
says which workspace hosts a channel, which others share it and which
**directory groups** and individual addresses feed it; the Slack controller does
the rest.

A Slack Connect channel is one channel that several Slack workspaces take
part in. Declaring each by hand in a values file means a rollout for every
new partner channel, and the people who know which workspaces should share
what are the workspaces' own operators. So these channels are created and
edited **interactively on the console**, and every change is audited.

## A record

| Field | Meaning |
|---|---|
| `name` | the channel's Slack name: lowercase letters, digits, `-` and `_`, at most 80. Unique among the records, and it never changes |
| `host` | the workspace (a key of the policy's `slack.workspaces`) that **creates and owns** the channel. **Immutable** after creation |
| `with` | the other workspaces that share it, in order. Order decides where a person with no host-domain address joins from. At least one; none repeats; never the host |
| `from` (`sources` in the stored record) | the **directory groups**, by address, of **any connected directory**, whose members belong, on whichever side. Never an internal group |
| `members` | **individual addresses**, each an active user of **any connected directory**, who belong too, on whichever side. At least one of `from` and `members`. Lowercased, none repeats; a group address entered here, or a person's address entered as a group, is refused with a message saying where it goes |
| `channel_id` | optional: the Slack id of a channel that already exists and is already shared, which the record adopts; set when a record is created with **Manage** from Discovered, the same on every side, and **immutable** |
| `private` | one visibility for every side, or one per side (Slack lets each organisation choose its own side's). A per-side choice names the host and every `with` workspace, exactly |

The console checks a record against the policy in force and the directories
before it writes it: the workspaces are declared, every source is a group of a
connected directory, the host's policy does not already bind a channel of that
name or adopt that channel id (*this channel is defined in git*), no console
channel of the host already manages it (*a channel is managed one way*), the
host is declared and is not among `with`, `with` is not empty, and the privacy
names the host and every side, exactly. The controller checks again under the policy it runs with, and asks the
console who is in the groups, so a record the policy or the directories no
longer accept is reported `invalid` with the reason, and acted on by nobody.

**Where the people land.** A person joins on the side whose workspace's
**owning directory** serves their address's domain (the host first, then each
`with` workspace in order); somebody with an address on no side is held. A
group is chosen from any connected directory, so the form shows, for each
side, which of the chosen groups land there, and **warns about a group whose
directory owns no side of this channel**: its members would have no account
path on any side and would be held. That is allowed, and said. Members of a
group are resolved through nested groups, as for an ordinary
[console channel](slack-workspace.md#console-channels-ordinary-channels-managed-on-the-console).

**A record from before directory groups.** A record written when `from` named
internal groups cannot be read as directory groups, and is not. It is listed
`invalid` with a message that says so, to the operators of its host, who edit
it and pick directory groups (or delete it); the controller reports it held on
its host and acts on nothing until then.

## What the reconciler then does

1. The **host** workspace's controller creates the channel, with the host's
   visibility, and adds the people its `from` groups hold there.
2. It **invites the guest workspace's bot** to the channel as a Slack Connect
   invitation (audited as `roster.slack_shared.invited`).
3. The **guest** workspace's controller **accepts** the invitation (audited as
   `roster.slack_shared.accepted`). Until it does, the record shows **waiting
   for acceptance**, and nobody needs to act.
4. From then on **each side adds its own people**, from the same groups and
   addresses. A Slack Connect channel is always `extend`: nobody is ever removed
   from it, by this record or by a change in the directory. A person who left the
   directory and is still in the channel is reported as a **leaver**
   (`roster.slack_leaver.reported`), and somebody has to remove them in Slack.

A workspace only acts where `slackRoster.actsIn` names it; every other one is
derived and reported, and left alone. See
[slack-workspace.md](slack-workspace.md).

The **Slack Connect** tab of the Slack area (`#/slack/connect`) shows, for each
record, what the host's controller last reported: *not reported* (nothing yet), *pending* (it will create, adopt or
accept on the next pass), *waiting for acceptance*, *active*, *needs you*
(held until a person acts) or *invalid* (the policy refuses it).

## Who may

- **Create, edit, delete:** the operator over the **host** workspace's owner
  (the directory recorded as the host's owner when it was connected, see
  [slack-workspace.md](slack-workspace.md#where-a-workspaces-team-owner-and-domains-come-from)),
  or the installation-wide operator. The
  operator of a **guest** workspace's owner alone may not: a channel is owned
  by its host.
- **See:** a viewer of the host or of any `with` workspace sees the record and
  its state; it cannot change it.

The form offers only the workspaces the caller operates as hosts.

## Editing

An edit may change `with`, `from` (the directory groups), `members` (the
individual addresses) and `private`, and is audited as an update. It **cannot change the host or
the name**: both are where the channel lives in Slack. A request that does is
refused, with the instruction to create a new channel. To move a channel to
another host, create a new one there, and delete the old record.

Two people saving at once do not overwrite each other: the write is made under
the ConfigMap's version, retried against what the other left, and refused
cleanly (the console says to reload) when it cannot land. Saving a record wakes the
controller and takes effect within a couple of minutes (see
[slack-workspace.md](slack-workspace.md#a-pass-runs-promptly-after-an-install)).

## Adopting a channel that is already shared

A channel can exist long before the roster does: made by a person in one
workspace, shared with others, each side naming it and choosing its own
visibility. The controller finds these (a console channel that is not shared
is found the same way; see
[slack-workspace.md](slack-workspace.md#console-channels-ordinary-channels-managed-on-the-console)).
For every connected workspace it lists
the Slack Connect channels its bot **can see** (public ones, and private ones
the bot is a member of) and publishes them in the workspace's report as
`discovered_shared`: the channel id, the name and privacy on that side, the
member count, the host team (Slack's `conversation_host_id`) and the teams the
channel reaches. A channel is marked **managed** when a record matches it, by
channel id, else by host and name. Nothing is changed by finding a channel.

The **Discovered** tab narrows by `workspace`, `kind` (`ordinary` or `shared`),
`visibility` (`public`, `private`, `unknown`), `q` (a name or channel id) and
`sort` (`members`; the default is workspace, then name); the **Slack Connect**
tab narrows by `host`, `side` (a workspace on either end), `state` (`active`,
`waiting`, `pending`, `held`, `invalid`, `not_reported`) and `q`. Each is a
query parameter of the tab's address, for example
`#/slack/discovered?workspace=<key>&kind=shared&q=ops`. A workspace whose own
report lists a channel is a prefilled side of **Manage** with the privacy it
reported (a managed channel's guest sides are also found by the probe, below);
a side nobody saw has no default and must be chosen.
A held record whose Slack visibility differs from its record shows a
*visibility mismatch* hint on its row and page: **Edit** the record.

On the **Discovered** tab (`#/slack/discovered`) the Slack Connect rows merge the reports into one row
per channel: its name and privacy on each connected side, members per side,
the host workspace and whether it is managed. **Every connected workspace is a
side.** One whose bot cannot see the channel shows as **unknown**: it is private
there and the bot is not in it, or public and not joined, or not shared with
that workspace, and Slack does not say which. Slack names only the host among a
channel's teams when the host's list is read, and a guest bot lists a private
channel only once it is in it, so a side no report mentions leaves no trace; it
is shown as unknown, never dropped as if the channel were not shared there, and
**Manage** does not prefill it (add it by hand if the channel is shared there;
the sides Slack or a bot places the channel in are prefilled). A team that
is not a connected workspace is only counted, never named, and a channel it
hosts shows as **external, not managed** and cannot be managed.

**Manage** (the same rule as creating a record: an operator of the host
workspace's owner, or of the installation) opens the create form prefilled: the
name on the host's side, the host, the other connected workspaces the channel
is placed in, and each side's privacy as seen. A side nobody could see is a
required choice. The operator picks the directory groups; the record is a normal one, and it also
keeps the discovered channel's id in `channel_id` so the reconciler adopts
exactly that channel. The console accepts an id only when the host workspace's
own report lists it as hosted there. Viewers see the list and nothing more.

What the reconciler then does for a record with `channel_id`:

- **Host side:** adopts the channel by that id. A public channel the bot is
  not in is joined; a private one the bot is not in is **held** ("invite the
  bot"). A side that is already connected is never invited again. The channel
  need not have been made by the roster.
- **Guest side that is already connected:** the channel is visible there, so
  nothing waits for an invitation to accept. A public side is joined; a private
  side the bot is not in is held until somebody invites the bot (until then it
  is not visible, and the side reports that it is waiting and what to do). Then
  the side's own people are added, as for any shared channel.
- **A team that is not a connected workspace** is ignored: never invited,
  asked or touched.
- Nobody is ever removed: an adopted channel is `extend`, whoever is in it
  stays.

A record without `channel_id` behaves as before: the host creates the channel
(or adopts one of that name the roster made, or that is already shared),
invites each guest's bot and the guest accepts. `channel_id` cannot be changed
afterwards.

### Guest sides and the probe

A bot lists a Slack Connect channel that is public on its side only sometimes,
and one it has not joined often not at all. For a channel that a record
**manages**, the controller therefore asks each connected workspace that did not
list it, with `conversations.info` by channel id, at most once per channel and
workspace per pass. When Slack names a connected guest workspace besides the
host, only those named are asked; when Slack names none (a bot is often told
nothing but its own team), exactly the workspaces the record names as sides
(host and `with`) are asked. An answer is published as that side (privacy as it
says, bot not joined). `channel_not_found` or `not_in_channel` is expected (a
private side whose bot is not in it, or a workspace not in the channel), is
logged at debug and leaves the side unknown; any other error is logged as a
warning and never fails the pass. Each pass logs one `guest-side probe` line
with the `probed`, `visible` and `invisible` counts. A channel no record manages
is **never probed**: on the Discovered tab only the workspaces whose own report
lists it are prefilled sides, and a side no report lists is unknown and must be
added by hand on Manage.

## Deleting is not archiving

Deleting removes the **record only**. The channel stays in Slack, in every
workspace that has it, and is not archived. The reconciler stops managing it:
nobody is added or removed any more, and the people already in it stay until
someone removes them in Slack. Archive a channel in Slack itself if it should
end. The console never archives a Slack Connect channel, whoever hosts it:
archiving closes it for every organisation in it. (For an ordinary console
channel the delete dialog has an opt-in *Also archive*; see
[Archiving](slack-workspace.md#console-channels-ordinary-channels-managed-on-the-console).)

## Where it is kept

Each record is the versioned document `_shared.<name>.json` in
`ConfigMap <release>-slack-workspaces`, beside the workspaces' own records; the
controller mounts that ConfigMap and reads it on every pass. It is also in the
`Secret <release>-slack-records` mirror that the recovery copy pushes. Needs
`directory.store: kubernetes`: with any other store a record would not survive
a restart, and the console says so instead of writing one.

## Audit

| Action | When | Targets | Data |
|---|---|---|---|
| `roster.slack_shared_channel.created` | a record is created | the host workspace, the channel, each directory group (type `directory_group`) and each individual address (type `directory_user`) | `name`, `with`, `privacy`, `members` (a count) |
| `roster.slack_shared_channel.updated` | an edit changed something | the same | the same, and `changes`: `with: a -> a,b; sources: 1 -> 2 groups (1 added, 0 removed); private: ...` |
| `roster.slack_shared_channel.deleted` | a record is deleted | the same | the record as it was |

A directory group's address, and an individual's, is an identifier, never data: they are
targets, and an edit's `changes` counts them (`members: 2 -> 3 people (1 added, 0 removed)`).
Like a console channel's record, a Slack Connect record's data counts them as `sources` and
`members` (since catalogue 1.6.0 for `sources`); the groups and addresses themselves are targets.
Audit catalogue 1.5.0 added the `directory_user` target type and the `members` count. Audit catalogue 1.2.0 added the
`directory_group` target type and the console channel actions, see
[slack-workspace.md](slack-workspace.md#console-channels-ordinary-channels-managed-on-the-console).

The actor is the person. An edit that changes nothing writes and records
nothing.
