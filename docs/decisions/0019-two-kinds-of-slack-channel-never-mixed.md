# 0019 — Two kinds of Slack channel, never mixed

**Status:** Accepted; refines [0017](0017-the-slack-reconciler-membership-only.md)
**Date:** 2026-10-01

## Context

The policy is in git and speaks internal groups, which is right for channels
that infrastructure owns (an alert channel fed by an on-call group). Most
Slack channels are owned by the people in them: they are created, renamed and
retired by teams, their members are directory (identity-provider) groups or
individuals, and nobody wants a pull request to add a channel. Forcing both
through git makes the second kind unmanageable; letting git groups feed it
would put a second vocabulary beside the directory's.

## Decision

A channel is **one of two kinds**, and a channel is managed one way:

- a **policy channel** is bound in `slack.workspaces.<key>.channels`, in git, to
  **internal groups**;
- a **console channel** is a record written on the console
  (`_channel.<workspace>.<name>.json`), fed by **directory groups** of the
  workspace's owning directory and by **individual addresses** that are active
  users of that directory. It is audited, backed up with the other Slack records,
  and operated by the owning directory's scoped operator.

Never mixed: directory groups never feed a policy channel, internal groups never
feed a console channel, and a channel defined both ways is **held** on both
sides ("defined in both git and the console") until one definition is removed
([0020](0020-hold-on-double-definition-instead-of-taking-over.md)). The console
refuses to manage a channel git defines.

Console records never grant access to infrastructure; they do not name an
internal group. They are the one place the console writes membership
definitions, and the audit trail, not git, is their history.

## Consequences

`git log` is no longer the complete history of who is in every Slack channel,
only of the channels the infrastructure owns. The console must show both kinds
side by side, with the kind on every row, so an operator is never asked to
reason about a channel without knowing where it is defined.

## Alternatives considered

**Everything in git.** Rejected for the reasons above.

**Everything on the console.** Rejected: alert and incident channels are part of
the infrastructure's definition and should be reviewed with it.

**Let a channel take both kinds of source.** Rejected: two vocabularies on one
channel, with no rule for which wins when they disagree.
