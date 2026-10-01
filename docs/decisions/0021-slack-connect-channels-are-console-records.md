# 0021 — Slack Connect channels are console-managed, audited records

**Status:** Accepted; refines [0019](0019-two-kinds-of-slack-channel-never-mixed.md)
**Date:** 2026-10-01

## Context

A Slack Connect channel between the installation's own workspaces spans more
than one workspace and so more than one owning directory. Policy is the wrong
home: no single workspace key owns it, and its members come from any connected
directory.

## Decision

A Slack Connect channel is a **record** (`_shared.<name>.json`): `name`, `host`
(the workspace that creates and owns it; **immutable**), `with` (the other
workspaces), `private` (one value, or one per side), and members as directory
groups of any connected directory and individual addresses of active users of any
connected directory. A person joins on the side whose owning directory serves
their address, host first. Changing the host or the name is refused: create a
new channel. The operator of the host's owner, or the installation-wide
operator, may write a record; viewers of any workspace it touches see it.
Channels are always `extend`. The controller of the host creates the channel and
invites each guest workspace's bot; a guest accepts only invitations for that
channel from that host. Deleting a record forgets it; the channel stays in Slack
and the reconciler stops managing it.

## Consequences

A Slack Connect channel can never remove anybody. A leaver stays until removed by
hand. Operators of a guest workspace's directory can see a record that touches
their workspace but not edit it.

## Alternatives considered

**Policy entries on the host's workspace.** Rejected: the host's key owns the
channel but the members belong to others.

**Strict Slack Connect channels.** Rejected for now: archiving or removal across
organisations closes the channel for everyone in it.
