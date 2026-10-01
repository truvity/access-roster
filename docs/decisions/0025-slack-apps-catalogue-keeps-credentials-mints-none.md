# 0025 — The Slack Apps catalogue keeps credentials but mints none

**Status:** Accepted; applies [0008](0008-credentials-only-where-we-govern-membership.md) and [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md)
**Date:** 2026-10-01

## Context

Besides its own App, the roster creates and installs Slack Apps the deployment
declares as data (`slackApps`: an alert-posting App, for example), and keeps their
bot tokens. 0008 and 0014 allow the issuer to *mint* a credential for another
system only where membership there is governed here; Slack now is such a system,
but a catalogue App's bot token is not minted per request, it is obtained once
from Slack's own install.

## Decision

The Slack Apps catalogue **keeps** the token Slack issued at install
(`<id>.slack_bot_token` in `<release>-slack-catalogue-apps`) and nothing issues a
token for a caller at request time. `push` copies only that bot token to a secret
store, one `PushSecret` per entry. An install is refused unless Slack says it
belongs to the team recorded for that workspace. The roster's own reconciler
token is never exposed through the catalogue.

## Consequences

A consumer reads a long-lived bot token from a secret store, rotated as one; Slack,
not this issuer, decides its scopes. If a request-time token minter for Slack is
ever wanted, it needs its own record against 0008.

## Alternatives considered

**An endpoint like `/token` for a Slack catalogue token.** Rejected: it turns the
catalogue into a minter without a governance reason.
