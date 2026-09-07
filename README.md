# directory-roster

[![CI](https://github.com/truvity/directory-roster/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/directory-roster/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

The directory hub: one deployment holding every corporate-directory
credential so that its consumers hold none. It answers two questions for
every directory an installation owns — **is this account live**, and **who
is in this group** — over ConnectRPC, routed by email domain, with a
per-domain **authoritative** flag that tells a consumer when it may act
on a removal. Google Workspace today; Microsoft Entra next, behind the
same record and the same contracts.

> **Status: design under review.** The documentation is written first and
> the service second. Nothing here runs yet; the binary exits with a
> pointer to the design. Successor to
> [google-group-sync](https://github.com/truvity/google-group-sync).

## How it works, in one paragraph

An operator connects a workspace by clicking through the directory's
admin consent (the way a SaaS integration does) or by uploading a
service-account key. The hub discovers the tenant's domains, takes a
snapshot of its users and groups every fifteen minutes, and answers
every read from that snapshot — saying which snapshot, and whether the
domain is authoritative right now. A consumer may ask for a fresher
answer (`max_age`); a login-time lookup never waits behind a full
directory read. Anything that goes wrong on the hub's side degrades to
"not authoritative", never to "gone".

## Contracts

| Service | Listener | For |
|---|---|---|
| `directory.v1.DirectoryService` | API (`:8080`, cluster network) | consumers: `Describe`, `Probe`, `GetGroup`, `ListGroups`, `GetAccount`, `ResolveAccounts`, `ResolveUser` |
| `directoryroster.v1.WorkspaceService` | console (`:8081`, behind the gateway) | operators: `ListWorkspaces`, `BeginConnect`, `Reconnect`, `UploadKey`, `Probe`, `Refresh`, `Disconnect` |
| `directoryroster.v1.SettingsService` | console | `GetSettings`, `SetOAuthClient` |

Proto under [`proto/`](proto); reading guide in
[docs/reference/contracts.md](docs/reference/contracts.md).

## Documentation

| Read | For |
|---|---|
| [docs/design/hub.md](docs/design/hub.md) | why it is shaped this way: the model, the decisions, what is not carried |
| [docs/architecture/hub.md](docs/architecture/hub.md) | C4 context, containers, components; the connect flow and a lookup as sequence diagrams; failure semantics |
| [docs/reference/contracts.md](docs/reference/contracts.md) | every RPC, `max_age`/`snapshot_at`, authority, errors, compatibility with google-group-sync |
| [docs/reference/configuration.md](docs/reference/configuration.md) | what the chart includes vs expects, values, the overlay, Kubernetes objects, roles, a Valkey recommendation |
| [docs/operations/connect-runbook.md](docs/operations/connect-runbook.md) | the one-time OAuth client, the per-workspace consent step, the key path |
| [docs/operations/runbook.md](docs/operations/runbook.md) | health, reconnect, rotation, export |
| [docs/operations/migration-from-google-group-sync.md](docs/operations/migration-from-google-group-sync.md) | overlay first, consumers moved, consent later, retire |
| [docs/development/testing.md](docs/development/testing.md) | unit, fakes, acceptance |

## Quick start (once released)

```sh
helm install directory-roster oci://ghcr.io/truvity/charts/directory-roster \
  --namespace directory-roster --create-namespace \
  --set valkey.address=directory-roster-cache.directory-roster.svc:6379
```

Then the [connect runbook](docs/operations/connect-runbook.md).

## Developing

`devbox shell` (or direnv), then `just check`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE).
