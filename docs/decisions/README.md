# Architecture decisions

One record per decision that shapes this repository from the outside —
what a relying party must do, what an installation must accept, what a
release removes. The design pages under [`../design/`](../design/) say
how the shipped thing works; a record here says why it is shaped that
way, what was weighed against it, and what follows from choosing it. When
the two disagree, the design pages describe what actually shipped and a
record here is read as the reasoning that got there.

A record is never edited to reverse a decision. A changed mind gets a new
record that supersedes the old one, so the index below stays a true
timeline and nothing is silently rewritten under an old date.

## Index

| ADR | Decision |
|---|---|
| [0001](0001-sessions-and-an-absolute-limit.md) | Sessions and an absolute limit |
| [0002](0002-mission-boundary-tokens-and-memberships.md) | Mission boundary: tokens and memberships |
| [0003](0003-deprecate-access-proxy.md) | Deprecate and remove the access-proxy chart |
| [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) | SSH: opkssh for people, the secret store's SSH CA for hosts |
| [0005](0005-es384-signing-algorithm.md) | ES384 is the signing algorithm |
| [0006](0006-groups-claim-scoped-per-audience.md) | The groups claim is scoped per audience, by default |
| [0007](0007-breaking-changes-inside-1x.md) | Breaking changes inside 1.x |
| [0008](0008-credentials-only-where-we-govern-membership.md) | Credentials only where we govern membership |
| [0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md) | A default signing algorithm, and per-audience exceptions |
| [0010](0010-a-declared-vocabulary.md) | A declared vocabulary: things, scopes, roles, inheritance and mapping wildcards |
| [0011](0011-ssh-people-opkssh-machines-and-hosts-openbao.md) | SSH: people on opkssh, machines and hosts on the secret store's OpenBAO |
| [0012](0012-per-role-scopes-in-the-vocabulary.md) | Per-role scopes in the vocabulary |
| [0013](0013-openbao-access-through-the-bao-cli.md) | OpenBAO access through the `bao` CLI |
| [0014](0014-minting-third-party-credentials-only-where-membership-is-governed.md) | Minting third-party credentials: only where membership is governed, brokers elsewhere |
| [0015](0015-a-per-audience-groups-delimiter-for-opkssh.md) | A per-audience groups delimiter, for opkssh's colon-splitting bug |
| [0016](0016-a-managed-known-hosts-file-for-ssh-host-cas.md) | A managed known_hosts file for SSH host CAs, distinct from `accessctl bao` |
| [0017](0017-the-slack-reconciler-membership-only.md) | The Slack reconciler keeps channel membership and nothing else |
| [0018](0018-do-not-configure-what-the-product-knows.md) | Do not configure what the product already knows |
| [0019](0019-two-kinds-of-slack-channel-never-mixed.md) | Two kinds of Slack channel, never mixed |
| [0020](0020-hold-on-double-definition-instead-of-taking-over.md) | A channel defined twice is held, not taken over |
| [0021](0021-slack-connect-channels-are-console-records.md) | Slack Connect channels are console-managed, audited records |
| [0022](0022-the-console-archives-only-ordinary-channels-only-when-asked.md) | The console archives only ordinary channels, only when asked |
| [0023](0023-guest-side-probe-only-for-managed-slack-connect-channels.md) | The guest-side probe asks only about managed Slack Connect channels |
| [0024](0024-reconciler-rails-are-shared-pieces-not-a-framework.md) | Reconciler rails are shared pieces, not a framework |
| [0025](0025-slack-apps-catalogue-keeps-credentials-mints-none.md) | The Slack Apps catalogue keeps credentials but mints none |
| [0026](0026-two-platforms-permanently-kubernetes-and-aws-lambda.md) | Two platforms, permanently: Kubernetes and AWS Lambda |
| [0027](0027-the-state-port-nats-jetstream-and-dynamodb.md) | The State port: NATS JetStream on Kubernetes, DynamoDB on AWS |
| [0028](0028-nothing-writes-configmaps-or-secrets.md) | Nothing writes ConfigMaps or Secrets; written secrets are sealed |
| [0029](0029-ticks-per-target-under-a-lease.md) | Ticks per target, under a lease |
| [0030](0030-workload-identity-on-both-platforms.md) | Workload identity: both mechanisms on both platforms |
| [0031](0031-a-generic-migration-tool.md) | A generic migration tool, and the order of the move |
| [0032](0032-one-configuration-file-one-binary-one-chart.md) | One configuration file, one binary, one chart |
| [0033](0033-exports-go-to-openbao-directly.md) | Exports: the service copies its secrets into OpenBao itself |

## Template

Start a new record from this shape. Keep it tight — long enough to make
the reasoning checkable, short enough that the next reader finishes it.

```markdown
# NNNN — <a decision, stated as a decision>

**Status:** Proposed | Accepted | Accepted; amended by [NNNN](NNNN-slug.md) | Accepted; partly superseded by [NNNN](NNNN-slug.md) | Superseded by [NNNN](NNNN-slug.md)
**Date:** YYYY-MM-DD

## Context

The situation that made a decision necessary, and the constraint that
ruled some answers out before the rest were compared.

## Decision

What was decided, stated so a reader could act on it without reading
anything else. Include the shape of the mechanism, not just its name.

## Consequences

What this costs, what it forecloses, and what a relying party or an
operator must now do differently. Say the honest boundary out loud —
the case this decision does not cover — rather than leaving it to be
discovered.

## Alternatives considered

Each one named, with the specific reason it was not chosen. "We didn't
think of it" is a fine thing to be able to write here later; do not
retrofit reasons no one had at the time.
```

Use `refines`, `extends` or `amends` on the newer record, and add the matching
`amended by`, `refined by` or `extended by` to the older one's Status line only.
The older record's text is never edited.
