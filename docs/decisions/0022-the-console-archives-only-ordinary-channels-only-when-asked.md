# 0022 — The console archives only ordinary channels, only when asked

**Status:** Accepted; refines [0017](0017-the-slack-reconciler-membership-only.md)
**Date:** 2026-10-01

## Context

Forgetting a console channel's record leaves the channel in Slack. Operators
asked for the channel to be archived at the same time. Archiving is the one
Slack action that cannot be undone from here, and on a Slack Connect channel it
closes the channel for every organisation in it.

## Decision

The delete dialog of a console channel has an opt-in, off by default: "Also
archive #name in Slack". Ticked, the bot calls `conversations.archive` after the
record is forgotten, under the same operator role as the delete, and the action
is audited as `roster.slack_channel.archived`. If the bot cannot (it is not in the
channel, or Slack or the workspace settings refuse), the record is still deleted
and the note says to archive it by hand. A Slack Connect channel is **never**
archived from the console, whoever hosts it; the server refuses the request with
nothing changed. A channel the policy defines cannot be deleted from the console at
all. The reconciler itself never archives.

## Consequences

Archiving a shared channel is a manual act in Slack, by someone who sees the
other organisations. The record deletion and the archive are two audit records.

## Alternatives considered

**Archive whenever a record is deleted.** Rejected: a default that destroys.

**Allow archiving a Slack Connect channel for its host.** Rejected: the host
should not be able to close another organisation's channel from a delete button.
