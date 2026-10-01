# 0017 — The Slack reconciler keeps channel membership and nothing else

**Status:** Accepted; applies [0002](0002-mission-boundary-tokens-and-memberships.md)
**Date:** 2026-10-01

## Context

[0002](0002-mission-boundary-tokens-and-memberships.md) named "a chat workspace's
channel membership" as the next system that cannot read a claim and so gets a
reconciler rather than a token. Slack is that system. Slack offers much more
than channel membership (accounts, user groups, workspace roles, guests,
retention), and each piece pulls this repository toward owning Slack's own
authorization model, which 0002 rules out. The bounds therefore have to be
decided before the reconciler is, not discovered through incidents.

## Decision

The Slack controller (`slack-roster`) makes the members of channels equal to
who holds the groups bound to them, and does nothing else in Slack:

- it acts with one **bot token per workspace**, obtained by the console's
  connect flow (a throwaway app configuration token pasted once, never stored
  or logged, then OAuth install). It holds no user token and no administrator
  credential;
- it **never creates an account**. A person with no Slack account yet is
  waiting, and is invited on the pass after the account exists;
- it **never touches user groups, workspace roles or settings**, never invites
  or removes a **guest**, and never removes anybody from a **public** channel
  (Slack lets only administrators do that, so `strict` is private-only and
  refused at load otherwise);
- it **never converts** a channel's visibility, **never unarchives**, and never
  creates a second channel under another name: each of those is a hold with its
  reason;
- removal is the one action that needs a second question: a person is removed
  only from a `strict` private channel and only when the directory vouches for
  that address; an unreadable directory removes nobody;
- two **breakers** (a channel, and the workspace's managed members) stop a
  removal set over half until an operator confirms its fingerprint; one
  confirmation satisfies every gate that fingerprint covers and lapses in 24
  hours;
- every workspace is a **dry run** until the chart lists it in
  `slackRoster.actsIn`; removing it from the list is the emergency stop;
- it is built on the rails the GitHub controller already uses
  (see [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md)).

## Consequences

An installation that wants user-group sync, account provisioning (SCIM) or
guest management does it with the tools Slack provides; this repository will
not grow them. A leaver stays in an `extend` channel until someone removes them
by hand, and is reported (`roster.slack_leaver.reported`). A public channel is
add-only forever.

## Alternatives considered

**Provision accounts as well**, so a new joiner is in their channels on day
one. Rejected: account creation is an identity-provider and Slack-plan
decision, needs administrator scopes, and would make this the second source of
who exists.

**Sync Slack user groups instead of channels.** Rejected: user groups do not
confer channel membership, and per-group handles are a Slack-side concept this
product would then have to model.

**Remove from public channels with an admin token.** Rejected: it needs a
credential far wider than the job, for the one case Slack itself restricts.
