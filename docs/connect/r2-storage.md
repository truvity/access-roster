# Connect an R2 credential broker

**Anchor:** the issuer; a separate R2 credential broker service trusts it
on a standard OIDC audience and mints **short-lived, prefix-scoped
object-storage credentials** — nothing specific to access-roster, any
OIDC provider that shapes a token the same way could stand in its place
([ADR 0014](../decisions/0014-minting-third-party-credentials-only-where-membership-is-governed.md)).
`accessctl r2 [flags] [-- <args…>]` authenticates and runs the real
`r2broker` binary unchanged, the same shape
[ADR 0013](../decisions/0013-openbao-access-through-the-bao-cli.md)
already ships for `accessctl bao`
([reference](../reference/accessctl.md#r2-authenticate-then-run-the-real-r2broker-cli-unchanged)).

**access-roster carries no R2 logic at all.** No bucket, no prefix, no
permission is decided here — the broker holds the parent credential and
maps a token's **group** (and only its group) to a bucket, a set of
prefixes and a permission; which group a caller's token carries is this
repository's own policy question, decided the same way any other
audience is.

## The shape

```
accessctl              the issuer                 r2broker                 R2
  sign-in ──exchange──▶ aud=r2-broker ──bearer───▶ /v1/credentials ──mint─▶ temporary
  (or a job's                                      (or an in-process       credentials
   own token)                                       --config mint)
```

`accessctl r2` never sees a bucket name or a permission — those are
`r2broker`'s own arguments, passed straight through after `--`. It signs
in (or takes a job's own identity), exchanges for the broker's audience,
and hands the resulting bearer token to `r2broker` in its environment
alone (`R2BROKER_TOKEN`), never on the command line.

## Policy

A client of kind `exchange` for the broker's audience, gated by whichever
groups the broker's own configuration maps to a grant — the same pattern
[ADR 0008](../decisions/0008-credentials-only-where-we-govern-membership.md)
already uses for CI job identity:

```yaml
groups:
  ci-cache-reader: { matchers: [{ github: { repository: example/app, event_name: pull_request } }] }
  ci-cache-writer: { matchers: [{ github: { repository: example/app, ref: refs/heads/main } }] }
clients:
  r2-broker: { kind: exchange, requires: [ci-cache-reader, ci-cache-writer] }
```

The broker's own config then maps `ci-cache-reader`/`ci-cache-writer` to
a bucket, a prefix list and a permission — this repository never sees
that mapping, and the broker never sees a `repository`, a `ref` or an
`event_name`. Splitting the decision any other way is exactly the "two
decision engines" risk ADR 0014 exists to avoid.

## Person or job side

`r2broker` speaks the AWS `credential_process` protocol (version 1), so
any S3-compatible tool that already reads an AWS profile needs nothing
new:

```ini
[profile ci-cache]
credential_process = accessctl r2 --service-url https://r2-broker.example.com -- \
    credentials --bucket example-bucket --prefix nix/
```

`--service-url` (or `$ACCESSCTL_R2_SERVICE_URL`) points at the
centrally-deployed broker; a standalone installation with no broker
service in front of it runs `r2broker credentials --config broker.yaml`
directly (no `accessctl r2` needed at all in that case — the broker CLI
takes any OIDC token from any issuer on its own).

`r2broker` must be on `PATH` — the same dependency `accessctl bao` already
has on the real `bao` binary. `--audience` defaults to `r2-broker`
(`$ACCESSCTL_R2_AUDIENCE` overrides it, for an installation whose broker
answers to a different name).

## Job side

The same line works unchanged in a GitHub Actions job granted
`id-token: write`: `accessctl r2` asks GitHub for the job's identity
token, exchanges it for the broker's audience, and the rest is identical
— see
[docs/reference/accessctl.md#in-a-job](../reference/accessctl.md#in-a-job).

## What this is not

Not a second S3 integration: an object store reachable through
`AssumeRoleWithWebIdentity` needs no broker at all — that is `accessctl
aws` today, unchanged
([aws-account.md](aws-account.md)). This page is only for a store with no
OIDC federation of its own, where R2 (Cloudflare's temporary-credentials
API) is the public example the broker was designed against.
