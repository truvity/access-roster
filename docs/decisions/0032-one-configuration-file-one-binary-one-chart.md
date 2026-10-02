# 0032 — One configuration file, one binary, one chart

**Status:** Accepted; applies [0007](0007-breaking-changes-inside-1x.md), [0018](0018-do-not-configure-what-the-product-knows.md)
**Date:** 2026-10-02

## Context

The services read about a hundred environment variables, three binaries are
shipped (`access-issuer`, `github-roster`, `slack-roster`) and the chart is
named after one of them. Environment variables are not validated as a whole, an
unknown one is ignored silently, and a secret and a tuning knob look the same.
The policy rule that only declared secrets travel in the environment
([0002](0002-mission-boundary-tokens-and-memberships.md)) is broken by the
count alone.

## Decision

- **Configuration is one file, validated against a schema.** An unknown key
  refuses to start and names its replacement, as 0007 already requires of the
  policy. The chart passes `config` through to the file.
- **Only declared secrets come from the environment**, each named in the schema.
- **Telemetry is configured by the OpenTelemetry `OTEL_*` variables only**, read
  by the SDK; nothing restates them. A trace carries no personal data in a span
  or a label.
- **The hundred environment variables are retired.**
- **One binary, `access-roster`,** with subcommands `serve` (the issuer, console
  and hub), `tick` (a reconciler's `Tick`, for one target or all) and `migrate`
  ([0031](0031-a-generic-migration-tool.md)). **One chart, `access-roster`.**

This is a **breaking change**, shipped in a 1.x minor release as 0007 allows and
named `**Breaking:**` in the CHANGELOG with the migration spelled out: the old
binaries, the old chart name and every retired variable go in one release, and a
retired variable that is still set is refused at start, not ignored.

## Consequences

An installation rewrites its values once. A removed binary is not kept as an
alias. The reference for the file, generated from the schema, replaces the
environment tables in [reference/configuration.md](../reference/configuration.md).

## Alternatives considered

**Keep the environment and add a file beside it.** Rejected: two sources of
truth, and the old one's silence about unknown names stays.

**Keep three binaries with a shared file.** Rejected: three images to release
and pin for one product, and `tick` on Lambda is the same binary as `serve`.

**Accept retired variables with a warning for a release.** Rejected for the
reason 0007 gives: a warning that no pipeline surfaces is silence.
