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
archive #name in Slack". It is offered only for a workspace whose controller
reports that it acts (a dry run, or no report, is archived by hand). Ticked, the
server first checks, with nothing changed on a refusal, that the workspace acts
and asks Slack (`conversations.info`) whether the channel is shared; only then
does it delete the record and call `conversations.archive`, under the same
operator role as the delete, audited as `roster.slack_channel.archived`. A Slack
Connect channel is **never** archived from the console, whoever hosts it: Slack
is asked, not the controller's report, so a held record whose channel became
shared is caught too. A channel the bot cannot see, or a Slack that does not
answer, is refused the same way. If the archive call itself then fails, the
record is already deleted and the note says to archive it by hand. A channel the policy defines cannot be deleted from the console at
all. The reconciler itself never archives.

## Consequences

Archiving a shared channel is a manual act in Slack, by someone who sees the
other organisations. The record deletion and the archive are two audit records.
The archive option costs one `conversations.info` call and needs a fresh enough
report: with none, the operator archives by hand.

## Alternatives considered

**Archive whenever a record is deleted.** Rejected: a default that destroys.

**Allow archiving a Slack Connect channel for its host.** Rejected: the host
should not be able to close another organisation's channel from a delete button.
