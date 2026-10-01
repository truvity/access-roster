# Slack Connect channels

> **Built.** Creating, editing and deleting shared channels between the
> installation's own Slack workspaces ships on the console's Slack Connect
> page.

**Anchor:** a record on the console, not a line in the policy. An operator
says which workspace hosts a channel, which others share it and which groups
feed it; the Slack controller does the rest.

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
| `from` | the policy **groups** whose holders belong, on whichever side. At least one. Members come **only** from groups: there is no way to name an individual |
| `private` | one visibility for every side, or one per side (Slack lets each organisation choose its own side's). A per-side choice names the host and every `with` workspace, exactly |

The console checks a record against the policy in force before it writes it:
the workspaces and groups are declared, the host does not already bind a
channel of that name in its own `channels`, and the privacy names exactly the
sides. The controller checks again under the policy it runs with, so a record
the policy no longer accepts is reported `invalid` with the reason, and acted
on by nobody.

## What the reconciler then does

1. The **host** workspace's controller creates the channel, with the host's
   visibility, and adds the people its `from` groups hold there.
2. It **invites the guest workspace's bot** to the channel as a Slack Connect
   invitation (audited as `roster.slack_shared.invited`).
3. The **guest** workspace's controller **accepts** the invitation (audited as
   `roster.slack_shared.accepted`). Until it does, the record shows **waiting
   for acceptance**, and nobody needs to act.
4. From then on **each side manages its own people**: the host adds and, where
   the workspace's rules allow, removes its own, and each guest does the same
   for its own, from the same groups.

A workspace only acts where `slackRoster.actsIn` names it; every other one is
derived and reported, and left alone. See
[slack-workspace.md](slack-workspace.md).

The Slack Connect page shows, for each record, what the host's controller last
reported: *not reported* (nothing yet), *pending* (it will create, adopt or
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

The page offers only the workspaces the caller operates as hosts.

## Editing

An edit may change `with`, `from` and `private`. It **cannot change the host or
the name**: both are where the channel lives in Slack. A request that does is
refused, with the instruction to create a new channel. To move a channel to
another host, create a new one there, and delete the old record.

Two people saving at once do not overwrite each other: the write is made under
the ConfigMap's version, retried against what the other left, and refused
cleanly (the console says to reload) when it cannot land.

## Taking over a channel that is already shared

A channel can exist long before the roster does: made by a person in one
workspace, shared with others, each side naming it and choosing its own
visibility. The controller finds these. For every connected workspace it lists
the Slack Connect channels its bot **can see** (public ones, and private ones
the bot is a member of) and publishes them in the workspace's report as
`discovered_shared`: the channel id, the name and privacy on that side, the
member count, the host team (Slack's `conversation_host_id`) and the teams the
channel reaches. A channel is marked **managed** when a record matches it, by
channel id, else by host and name. Nothing is changed by finding a channel.

On `#/slack-connect` the **Discovered** section merges the reports into one row
per channel: its name and privacy on each connected side, members per side,
the host workspace and whether it is managed. A side whose bot cannot see the
channel shows as **unknown**: it is private there and the bot is not in it, or
it is not shared with that workspace, and Slack does not say which. A team that
is not a connected workspace is only counted, never named, and a channel it
hosts shows as **external, not managed** and cannot be managed.

**Manage** (the same rule as creating a record: an operator of the host
workspace's owner, or of the installation) opens the create form prefilled: the
name on the host's side, the host, the other connected workspaces that have the
channel, and each side's privacy as seen. A side nobody could see is a required
choice. The operator picks the groups; the record is a normal one, and it also
keeps the discovered channel's id in `channel_id` so the reconciler takes over
exactly that channel. The console accepts an id only when the host workspace's
own report lists it as hosted there. Viewers see the list and nothing more.

What the reconciler then does for a record with `channel_id`:

- **Host side:** takes over the channel by that id. A public channel the bot is
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
- Nobody is ever removed: a taken-over channel is `extend`, whoever is in it
  stays.

A record without `channel_id` behaves as before: the host creates the channel
(or takes over one of that name the roster made, or that is already shared),
invites each guest's bot and the guest accepts. `channel_id` cannot be changed
afterwards.

## Deleting is not archiving

Deleting removes the **record only**. The channel stays in Slack, in every
workspace that has it, and is not archived. The reconciler stops managing it:
nobody is added or removed any more, and the people already in it stay until
someone removes them in Slack. Archive a channel in Slack itself if it should
end.

## Where it is kept

Each record is the versioned document `_shared.<name>.json` in
`ConfigMap <release>-slack-workspaces`, beside the workspaces' own records; the
controller mounts that ConfigMap and reads it on every pass. Needs
`directory.store: kubernetes`: with any other store a record would not survive
a restart, and the console says so instead of writing one.

## Audit

| Action | When | Targets | Data |
|---|---|---|---|
| `roster.slack_shared_channel.created` | a record is created | the host workspace, the channel | `name`, `with`, `from`, `privacy` |
| `roster.slack_shared_channel.updated` | an edit changed something | the same | the same, and `changes`: `with: a -> a,b; from: ...; private: ...` |
| `roster.slack_shared_channel.deleted` | a record is deleted | the same | the record as it was |

The actor is the person. An edit that changes nothing writes and records
nothing.
