# Contributing

## Layout

One repository, one tag, several deliverables, each installable or
importable alone:

```
cmd/directory-roster      the directory hub
cmd/access-issuer         the token service (later)
cmd/accessctl             the CLI (later)
charts/directory-roster   the hub's chart
charts/access-issuer      the issuer's chart (later)
charts/access-proxy       the console exposure chart (later)
actions/exchange          the GitHub Action (later)
identity/ authz/ directory/ tokens/ rules/ connect/ backend/ proof/
                          the Go module's public packages; framework
                          adapters under identity/<framework>mw
ts/                       the TypeScript package (later)
proto/  gen/              contracts and committed generated code
docs/                     why, concepts, architecture, design per
                          battery, reference, connect guides,
                          operations, development
```

Public Go packages stay free of Kubernetes and framework specifics
except in the adapters and the store implementations; anything a product
might import lives behind a storage interface.

## Toolchain

Everything comes from [devbox](https://www.jetify.com/devbox): `devbox shell`
(or direnv with the shipped `.envrc`) gives you Go, buf, golangci-lint,
helm, just and lefthook at the pinned versions. Never install the tools by
hand next to it.

`just check` runs exactly what CI runs: build, test, lint, chart-lint,
vuln. The pre-push hook (installed by devbox's init hook) runs the same.

## Conventions

- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:` …). The
  history is the changelog's source.
- **Rebase-merge only.** Branch from `master`, never stack pull requests.
- **Generated code is committed.** `just generate` rebuilds `gen/` from
  `proto/`; CI does not run buf. A contract change and its generated code
  land in the same commit.
- **Contracts are additive.** `buf breaking` guards `proto/`; a field is
  added, never renumbered or removed, so every existing client stays valid.
- **The docs are generic.** This repository describes an installation, not
  a company: no tenant names, hostnames or account names in the docs.
- **The chart's `version` stays `0.0.0`.** The git tag is the version
  authority; the release workflow stamps it at package time.

## Releasing

Push a `v*` tag. The release workflow builds the binary, the image
(`ghcr.io/truvity/access-roster/directory-roster`) and the chart
(`ghcr.io/truvity/charts/directory-roster`), all stamped with the tag.
