# access-roster

[![CI](https://github.com/truvity/access-roster/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/access-roster/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Identity for infrastructure, self-contained.** Two services and the
batteries around them, so that an installation with several corporate
directories can put people and machines in front of clusters, cloud
accounts, consoles and code hosts — under one rule: **nothing here
authenticates anyone.** Sign-in stays with the corporate identity
providers; this repository verifies the result, knows the directory, and
applies rules.

> **Status: design under review; nothing runs yet.** Documentation first,
> services second. The directory hub is built first; the issuer and the
> batteries follow. [Why this exists](docs/why.md) · [the architecture](docs/architecture.md)

## The batteries

| Battery | What it is | Use it when |
|---|---|---|
| **directory-roster** — service + chart | the directory hub: holds every directory credential, snapshots every tenant, answers *is this account live* and *who is in this group* with an **authoritative** flag | you have one or more corporate directories and anything that must react to leavers and groups |
| **access-issuer** — service + chart | the token service: verifies a corporate sign-in, a CI token or a workload token, asks the hub, applies the rules, issues tokens | clusters, cloud accounts, a CD system or consoles must trust one issuer |
| **access-proxy** — chart | the proxy in front of a console: login against the issuer, sessions, forwarded bearer, two postures | you put a web UI behind the gateway |
| **Go module** `github.com/truvity/access-roster` | `identity` (who is calling, from a forwarded bearer or a ServiceAccount token) with net/http, fiber v3, gRPC and connect adapters; `directory` client with the authoritative rule built in; `tokens` for exchange and refresh; `rules` | you write a service or a console in Go |
| **TypeScript package** `access-roster` | `useIdentity()` and the `UserBadge`, fed by the standard `/.access/whoami` every Go adapter serves | you write a console UI |
| **accessctl** — CLI | `login`, `aws` as a credential process, `kube-token` as a kubeconfig exec plugin, `kubeconfig` and `aws-config` to write the files for everything you are granted, `exchange`, `whoami`. For people; machines never run it | a person needs cloud credentials or kubectl |
| **GitHub Action** `truvity/access-roster/actions/exchange` | shell only: exchanges the job's identity token at the issuer for the audiences its rules allow, writes the kubeconfig and the cloud profile | a workflow deploys to a cluster or a cloud account |
| **the rules file** | subject → grant, once, versioned, tested. The only place where "who may do what" is written | always |

## I want to…

| Goal | Read |
|---|---|
| connect a corporate directory (Google Workspace) | [operations/connect-runbook.md](docs/operations/connect-runbook.md) |
| put a console behind the gateway | [connect/console-app.md](docs/connect/console-app.md) |
| let people `kubectl` into a cluster | [connect/kubernetes-cluster.md](docs/connect/kubernetes-cluster.md) |
| give people and jobs cloud credentials without SSO | [connect/aws-account.md](docs/connect/aws-account.md) |
| let a workflow deploy with no stored secret | [connect/github-actions.md](docs/connect/github-actions.md) |
| sign in to ArgoCD or Kargo with the issuer | [connect/argocd.md](docs/connect/argocd.md), [connect/kargo.md](docs/connect/kargo.md) |
| expose a business surface to employees for testing | [connect/business-surface.md](docs/connect/business-surface.md) |
| keep GitHub teams equal to directory groups | [github-roster](https://github.com/truvity/github-roster), a consumer of the hub |
| write the rules | [reference/rules.md](docs/reference/rules.md) |
| add a backend, a proof kind, a subject, an adapter | [development/extending.md](docs/development/extending.md) |
| move off an identity provider you run for infrastructure | [operations/migration-from-an-idp.md](docs/operations/migration-from-an-idp.md) |

## How it fits together, in one paragraph

An operator connects a workspace by clicking through the directory's
admin consent, or by uploading a service-account key. The hub discovers
the tenant's domains, snapshots its accounts and groups every fifteen
minutes, and answers every read from that snapshot, saying which snapshot
and whether the domain is authoritative right now. The issuer never reads
a directory: at every login it asks the hub, applies the rules, and mints
a token whose `groups` name the roles relying parties already read and
whose audiences carry the decisions a cloud trust policy can see. A
console sits behind `access-proxy` and reads the forwarded bearer through
the Go or TypeScript library; a cluster trusts the issuer and a client id;
a cloud account trusts the issuer and an audience; a workflow exchanges
its own token; a person runs `accessctl`. Anything that goes wrong on the
directory side degrades to "not authoritative", never to "gone".

## Documentation

| Read | For |
|---|---|
| [docs/why.md](docs/why.md) | motivation, principles, what it is not |
| [docs/concepts.md](docs/concepts.md) | the ten words used precisely |
| [docs/architecture.md](docs/architecture.md) | context, containers, the hub's components, who owns what, use cases, failure semantics |
| [docs/design/](docs/design/) | one design per battery: [hub](docs/design/hub.md), [issuer](docs/design/access-issuer.md), [proxy](docs/design/access-proxy.md), [libraries](docs/design/libraries.md), [CLI and action](docs/design/accessctl.md) |
| [docs/reference/](docs/reference/) | contracts, the rules language, values of each chart, the Go module, the TypeScript package, the CLI |
| [docs/connect/](docs/connect/) | one guide per kind of relying party |
| [docs/operations/](docs/operations/) | day one, the connect runbook, the runbook, migrations |
| [docs/development/](docs/development/) | testing, extension points |

## Developing

`devbox shell` (or direnv), then `just check`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the layout and the conventions.

## License

[MIT](LICENSE).
