# 0033 — A longer absolute limit for read-only resources

**Status:** Accepted; amends [0001](0001-sessions-and-an-absolute-limit.md)
**Date:** 2026-10-03

## Context

[0001](0001-sessions-and-an-absolute-limit.md) ends every session 24 hours
after `auth_time`, however often it is refreshed, and enforces that at refresh
and at a silent `/authorize`. For a console that is the right dial: a person
who leaves a tab open must meet the limit.

It is the wrong dial for one kind of relying party. The observability MCP
connectors are [resources](../reference/policy.md#resources--what-a-token-is-for)
(RFC 8707) whose only reach is to **read** metrics, logs, traces and
dashboards. Their clients are the claude.ai connector and Claude Code, both
self-described under `client_documents`. With a 24-hour limit each makes the
person sign in again every day, for a token that can change nothing. That
friction is paid daily, by everyone who uses the connectors, and buys almost
no security: the limit exists to bound what a stolen or forgotten credential
can do, and this credential can only read.

## Decision

A **resource may carry its own absolute limit**, `absolute_cap`, and a
resource that declares itself `read_only: true` may make it **longer than the
installation's `lifetimes.absolute`, up to seven days** (168h) from
`auth_time`. Everything else in 0001 stands: the clock is `auth_time`, there
is still no idle timeout at the issuer, and the limit is still enforced at
refresh and at a silent `/authorize`, and still caps the access token's `exp`.

```yaml
resources:
  https://mcp.example/:
    requires: [rung:engineer]
    ttl_cap: 15m
    read_only: true
    absolute_cap: 168h
```

**The rule for a refresh chain** is the shortest limit among every resource it
has been used for, where the client's own audience, and any resource without
an `absolute_cap`, counts as the installation's `lifetimes.absolute`. A chain
touched only by extended resources gets the shortest of their caps; a chain
that ever touches anything else falls back to the global limit. Extension is
therefore the product of every resource agreeing to it, never of one. Today a
chain is bound to the one resource it was opened for (a refresh never changes
it, and the audience of a refreshed token is that resource), so the set has one
member; the rule is stated over the set so that it stays true if that changes.
The resource is recorded on the session, which is where the chain lives.

**What is refused at load:**

- an `absolute_cap` above 168h;
- zero or a negative value;
- an `absolute_cap` above `lifetimes.absolute` on a resource that does not say
  `read_only: true`.

A cap below the installation's limit needs no `read_only`: shortening is
always allowed. `read_only` is a claim by whoever declares the resource; the
issuer cannot verify it, which is why it is written next to the cap.

**What does not change.** Revocation is untouched, and a longer limit does not
make a chain harder to end. Sign-out ends it at once. Removal or suspension
in the roster ends it at the next refresh, as for any session, because the
entitlement is re-checked there. Reuse of a spent refresh token is refused
and still revokes. An `absolute_cap` removed from the policy shortens the
chain at its next refresh. A silent `/authorize` that finds a browser session
older than the global limit ends that browser session for any request that is
not extended, and does not revoke, or send Back-Channel Logout for, an
extended chain that is still inside its own limit.

**The refresh window still bounds idle time.** A chain ends at
`min(now + lifetimes.refresh, auth_time + limit)`. `lifetimes.refresh` defaults
to 12 hours, so a chain idle for longer than that ends before its seven days
do. An installation that wants the seven days to be usable across a weekend or
a closed laptop sets `lifetimes.refresh` to `168h`. That raises the idle window
for every client, and for the browser session, which shares the value, but not
any other client's end: those still stop at 24 hours from `auth_time`. This
decision does not change the default.

## Why seven days, and why only read-only

The holders of these refresh tokens are the connector's servers on the
provider's side and the developer's own laptop. Neither is a place this
installation can see into, and the issuer has no activity signal to key an
idle timeout on (0001). Seven days is long enough that the connector survives
a weekend and short enough that a leaver, or a lost laptop that is not reported
at once, is never more than a week from the end of a chain even if the roster
were never consulted. The roster is consulted at every refresh, so in practice
it is the next one. The reach is read-only telemetry; the same people can
already read every one of those stores.

The restriction to read-only is the point. A longer absolute limit on a
resource that can change something would make the daily sign-in, which is the
one control that proves a person is still present, optional for a write path.
That trade is not made here, and a resource that cannot honestly say
`read_only` gets nothing longer than the global limit.

## Alternatives considered

**Raise `lifetimes.absolute` for everyone to seven days.** Rejected: it
extends every console, every CLI and every write path to the connectors' needs.

**An idle timeout in place of the absolute limit for these clients.**
Rejected for the reason in 0001: the issuer has nothing to measure idleness
with, and a connector that refreshes in the background looks permanently
active.

**A per-client cap rather than a per-resource one.** Rejected: the claude.ai
connector and Claude Code also ask for other resources, and whether a longer
limit is safe is a property of what the token reaches, not of who asks.

**Dropping the limit for read-only resources entirely.** Rejected: seven days
keeps a bound, and a bound is what lets a stolen refresh token be reasoned
about.

## Consequences

An installation sets `read_only` and `absolute_cap` on the rows that qualify;
nothing changes for a resource that sets neither. A relying party that checks
`exp` sees tokens that are as short as before (`ttl_cap`) and refreshes that
keep working for up to a week. Changing a resource from `read_only` to
anything that writes means removing the cap in the same change, and the chain
it governed ends at its next refresh.
