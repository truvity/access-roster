# access-roster

[![CI](https://github.com/truvity/access-roster/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/access-roster/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Identity for infrastructure, self-contained.** Two services and the
batteries around them, so that an installation with several corporate
directories can put people and machines in front of clusters, cloud
accounts, consoles and code hosts — under one rule: **nothing here
authenticates anyone.** Sign-in stays with the corporate identity
providers; this repository verifies the result, knows the directory, and
applies the policy.

> **Status: running; the first directory is connected.** The hub and the
> issuer are deployed, and the hub's own console sits behind `access-proxy`
> against the issuer — the first consumer of both. One Google Workspace is
> connected. The Go module, the TypeScript package and the three charts
> are published from every tag; `accessctl` and the Action are still to
> come. [CHANGELOG.md](CHANGELOG.md) says what exists at each version.
> The design documents describe the target state and mark, as *(0.8)*,
> what the first live connect showed still has to change.
>
> Start with [why this exists](docs/why.md), then the
> [helicopter view of every integration](docs/integrations.md), then
> [the architecture](docs/architecture.md).

## The batteries

Grouped by kind of artifact. The full table with status and who uses
what is in [docs/integrations.md](docs/integrations.md#the-batteries-by-kind-of-artifact).

| Kind | Battery | Use it when |
|---|---|---|
| Service + chart | **directory-roster** — the directory hub: holds every directory credential, snapshots every tenant, answers *is this account live* and *who is in this group* with an **authoritative** flag | you have corporate directories and anything that must react to leavers and groups |
| Service + chart | **access-issuer** — the token service: verifies a corporate sign-in, a CI token or a workload token, asks the hub, applies the policy, issues tokens | clusters, cloud accounts, a CD system or consoles must trust one issuer |
| Helm chart | **access-proxy** — oauth2-proxy and its wiring in front of one console: login against the issuer, sessions, forwarded bearer, two postures, self-registered client | you put a web UI behind the gateway |
| Go module | `github.com/truvity/access-roster` — `identity` with net/http, fiber v3, gRPC and connect adapters; `authz`; `directory`; `tokens`; `policy` | you write a service or a console in Go |
| TypeScript package | `access-roster` — `useIdentity()` and `<UserBadge/>` over the standard `/.access/whoami` | you write a console UI |
| CLI | **accessctl** — `login`, `setup` (kubeconfig contexts and AWS profiles for everything you are granted), `aws` as a credential process, `kube-token`, `whoami`; people only | a person needs kubectl or cloud credentials |
| GitHub Action | `truvity/access-roster@v1` — shell only: exchanges the job's token at the issuer, writes a kubeconfig and AWS profiles; ECR, CodeArtifact and the rest run on top with AWS's own tooling | a workflow deploys, pushes or installs |
| File format | **the policy** — groups, claims, lifetimes, clients, memberships; one schema for both services, versioned, tested | always |

## I want to…

| Goal | Read |
|---|---|
| connect a corporate directory (Google Workspace) | [operations/connect-runbook.md](docs/operations/connect-runbook.md) |
| put a console behind the gateway | [connect/console-app.md](docs/connect/console-app.md) |
| let people `kubectl` into a cluster | [connect/kubernetes-cluster.md](docs/connect/kubernetes-cluster.md) |
| give people and jobs cloud credentials without SSO | [connect/aws-account.md](docs/connect/aws-account.md) |
| let a workflow deploy with no stored secret | [connect/github-actions.md](docs/connect/github-actions.md) |
| push to ECR or install from CodeArtifact, on a laptop or in a job | [connect/registries-and-artifacts.md](docs/connect/registries-and-artifacts.md) |
| sign in to ArgoCD or Kargo with the issuer | [connect/argocd.md](docs/connect/argocd.md), [connect/kargo.md](docs/connect/kargo.md) |
| expose a business surface to employees for testing | [connect/business-surface.md](docs/connect/business-surface.md) |
| keep GitHub teams equal to directory groups | [github-roster](https://github.com/truvity/github-roster), a consumer of the hub |
| write the policy | [reference/policy.md](docs/reference/policy.md) |
| add a backend, a proof kind, a matcher, an adapter | [development/extending.md](docs/development/extending.md) |
| move off an identity provider you run for infrastructure | [operations/migration-from-an-idp.md](docs/operations/migration-from-an-idp.md) |

## How it fits together, in one paragraph

An operator connects a workspace by clicking through the directory's
admin consent, or by uploading a service-account key. The hub discovers
the tenant's domains, snapshots its accounts and groups every fifteen
minutes, and answers every read from that snapshot, saying which snapshot
and whether the domain is authoritative right now. The issuer never reads
a directory: at every login it asks the hub, applies the policy, and mints
a token whose `groups` name the roles relying parties already read and
whose audiences carry the decisions a cloud trust policy can see. A
console sits behind `access-proxy` and reads the forwarded bearer through
the Go or TypeScript library; a cluster trusts the issuer and a client id;
a cloud account trusts the issuer and an audience; a workflow exchanges
its own token; a person runs `accessctl`. Anything that goes wrong on the
directory side degrades to "not authoritative" — *provisional*, in the
console's word — never to "gone".

## Documentation

| Read | For |
|---|---|
| [docs/why.md](docs/why.md) | motivation, principles, what it is not |
| [docs/integrations.md](docs/integrations.md) | the helicopter view: fourteen integration points, case by case — parties, trust, flow, what you configure, what you get |
| [docs/concepts.md](docs/concepts.md) | the ten words used precisely |
| [docs/architecture.md](docs/architecture.md) | context, containers, the hub's components, who owns what, use cases, failure semantics |
| [docs/design/](docs/design/) | one design per battery: [hub](docs/design/hub.md), [issuer](docs/design/access-issuer.md), [proxy](docs/design/access-proxy.md), [libraries](docs/design/libraries.md), [CLI and action](docs/design/accessctl.md) |
| [docs/reference/](docs/reference/) | contracts, the policy, values of each chart, the Go module, the TypeScript package, the CLI |
| [docs/connect/](docs/connect/) | one guide per kind of relying party |
| [docs/operations/](docs/operations/) | day one, the connect runbook, the runbook, migrations |
| [docs/development/](docs/development/) | testing, extension points |

## Developing

`devbox shell` (or direnv), then `just check`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the layout, the conventions, the
console build order and the demonstration mode, and where the next
phase starts.

## License

[MIT](LICENSE).
