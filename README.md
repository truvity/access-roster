# access-roster

[![CI](https://github.com/truvity/access-roster/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/access-roster/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Identity for infrastructure, in two components that share one rule:
**nothing here authenticates anyone.** Sign-in is always the corporate
identity provider's; these services verify the result, know the
directory, and apply rules.

| Component | Is | Status |
|---|---|---|
| **directory-roster**, the directory hub | one deployment holding every corporate-directory credential so that its consumers hold none. Answers *is this account live* and *who is in this group* over ConnectRPC, routed by email domain, with a per-domain **authoritative** flag that says when a consumer may act on a removal. Google Workspace today, Microsoft Entra next. | design under review, prototype next |
| **the token service** | a security token service: verifies corporate sign-ins and workload tokens, asks the hub, applies rules, and issues the tokens clusters, cloud accounts and consoles trust. No users, no passwords, no database. | designed, built after the hub |

> **Status: design under review.** Documentation first, service second.
> Nothing here runs yet; the hub's binary exits with a pointer to the
> design. The hub succeeds
> [google-group-sync](https://github.com/truvity/google-group-sync).

## The hub in one paragraph

An operator connects a workspace by clicking through the directory's
admin consent (the way a SaaS integration does) or by uploading a
service-account key. The hub discovers the tenant's domains, takes a
snapshot of its users and groups every fifteen minutes, and answers
every read from that snapshot — saying which snapshot, and whether the
domain is authoritative right now. A consumer may ask for a fresher
answer (`max_age`); a login-time lookup never waits behind a full
directory read. Anything that goes wrong on the hub's side degrades to
"not authoritative", never to "gone". The hub's own operators sign in
with the connected directory and are authorized from its groups, so a
standalone installation needs no identity provider for the hub's sake.

## Contracts

| Service | Listener | For |
|---|---|---|
| `directory.v1.DirectoryService` | API (`:8080`, cluster network, ServiceAccount tokens) | consumers: `Describe`, `Probe`, `GetGroup`, `ListGroups`, `GetAccount`, `ResolveAccounts`, `ResolveUser` |
| `directoryroster.v1.WorkspaceService` | console (`:8081`) | operators: `ListWorkspaces`, `BeginConnect`, `Reconnect`, `UploadKey`, `Probe`, `Refresh`, `Disconnect` |
| `directoryroster.v1.SettingsService` | console | `GetSettings`, `SetOAuthClient` |
| `directoryroster.v1.AccessService` | console | `WhoAmI`, `GetAccessPolicy`, `AddRule`, `RemoveRule` |

Proto under [`proto/`](proto); reading guide in
[docs/reference/contracts.md](docs/reference/contracts.md).

## Documentation

| Read | For |
|---|---|
| [docs/architecture.md](docs/architecture.md) | one page: how operators reach the hub, context, containers, the hub's components, who owns what, eight use cases, failure semantics |
| [docs/design/hub.md](docs/design/hub.md) | the hub: the model, the decisions, access to the hub itself, what is not carried |
| [docs/design/token-service.md](docs/design/token-service.md) | the token service: purpose, guardrail, verifiers, rules, what it issues, the spike |
| [docs/reference/contracts.md](docs/reference/contracts.md) | every RPC, authentication on both listeners, `max_age`/`snapshot_at`, authority, errors |
| [docs/reference/configuration.md](docs/reference/configuration.md) | what the chart includes vs expects, values, the overlay, consumers, access rules, Kubernetes objects, a Valkey recommendation |
| [docs/operations/connect-runbook.md](docs/operations/connect-runbook.md) | the one-time OAuth client, the per-workspace consent step, the key path |
| [docs/operations/runbook.md](docs/operations/runbook.md) | day one, health, reconnect, lost operator access, rotation, export |
| [docs/operations/migration-from-google-group-sync.md](docs/operations/migration-from-google-group-sync.md) | overlay first, consumers moved, consent later, retire |
| [docs/development/testing.md](docs/development/testing.md) | unit, fakes, acceptance |

## Quick start (once released)

```sh
helm install directory-roster oci://ghcr.io/truvity/charts/directory-roster \
  --namespace directory-roster --create-namespace \
  --set valkey.address=directory-roster-cache.directory-roster.svc:6379
```

Then the [runbook's day one](docs/operations/runbook.md#day-one).

## Developing

`devbox shell` (or direnv), then `just check`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
