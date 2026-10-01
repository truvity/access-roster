# 0023 — The guest-side probe asks only about managed Slack Connect channels

**Status:** Accepted; refines [0021](0021-slack-connect-channels-are-console-records.md)
**Date:** 2026-10-01

## Context

A bot lists a Slack Connect channel that is public on its side only sometimes, and
a private one it has not joined often not at all, so a channel one workspace
discovered can look "not listed" in another that has it. v1.46.1 asked every
other connected workspace, by id, once per pass, for every discovered shared
channel. That spent a call per workspace per unmanaged channel per pass, and
logged noise at warning because the expected "not visible" answer was matched
the wrong way round.

## Decision

The probe (`conversations.info`, bot token, `include_num_members`) runs only for
channels a record manages. It asks the workspaces Slack names as guests when it
names any besides the host and the reporters, otherwise exactly the workspaces
the record names as sides (host and `with`). It never fails a pass. An expected
`channel_not_found` or `not_in_channel` is a side the bot cannot see, logged at
debug; a real error warns; each pass logs one `guest-side probe` summary at info.

## Consequences

For a channel nobody manages yet, the Manage form can only prefill the sides that
workspaces' own reports list; a side nobody listed must be chosen by the operator
(private there and the bot not in it, or not shared). The cost is bounded by the
number of records, not by what Slack shows.

## Alternatives considered

**Probe everything, rate-limit the calls.** Rejected: unbounded in the size of the
workspace list.

**Remove the probe.** Rejected: a managed channel's invisible side would show
as unknown forever.
