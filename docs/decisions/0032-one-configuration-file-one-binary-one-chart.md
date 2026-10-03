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

## Implementation note: the command surface

Shipped in two changes. The configuration file came first (v1.53.0); the one
binary and the one chart came second, and `tick` is a third, with the leases
of [0029](0029-ticks-per-target-under-a-lease.md).

```
access-roster serve --config <file>               the issuer, the hub and the console
access-roster controller github --config <file>   the GitHub reconciler's loop
access-roster controller slack --config <file>    the Slack reconciler's loop
access-roster migrate                             reserved for 0031: prints "not yet available", exits non-zero
access-roster --version | --help
```

**`controller <target>` is the loop, `tick <target>` is one pass.** The
Deployments the chart renders today are loops (an interval, a watch, one
replica, no lease), and calling them `tick` would promise a lease and a single
pass that do not exist yet. They are named for what they are, `controller`, and
`tick <target>` will be added beside them when 0029's lease is built, calling
the same reconciler `Tick`; `controller <target>` then becomes the loop that
calls it on an interval, and nothing about it is renamed. The ADR's `tick` for
"one target or all" is the later command; there is no rename to make now.

Each command reads one file with its own schema: `serve.schema.json`,
`controller-github.schema.json` and `controller-slack.schema.json` under
`schemas/config/`, replacing `access-issuer`, `github-roster` and `slack-roster`
(the Go types are `config.Serve`, `config.ControllerGitHub` and
`config.ControllerSlack`). The chart's values follow: `config` is `serve`'s,
and `controllerGithub.config` and `controllerSlack.config` are the controllers'.
The chart's Deployments run the one image with the command as their first
arguments.

The chart keeps what an installation's objects are named from, so the move is a
rollout and not a re-creation: the controllers' objects are still
`<full name>-github-roster` and `<full name>-slack-roster`, the paths the chart
mounts are unchanged, and the telemetry service names are unchanged. The one
change of name an installation must act on is the chart's own, which is part of
every object's name; `nameOverride` and `fullnameOverride` keep it, and the
migration is in
[reference/configuration.md](../reference/configuration.md#migrating-from-the-access-issuer-chart).
The old binaries, the three images and the `access-issuer` chart are not
published after this change: as the decision says, no alias is kept.
