# Contributing

## Layout

One repository, one tag, several deliverables, each installable or
importable alone:

```
cmd/directory-roster      the directory hub
cmd/access-issuer         the token service
cmd/accessctl             the CLI (later)
charts/directory-roster   the hub's chart
charts/access-issuer      the issuer's chart
charts/access-proxy       the console exposure chart
action.yml                the GitHub Action, at the root so `uses: truvity/access-roster@v1` works (later)
policy/ backend/          the Go module's public packages today: the
                          five-table policy, the directory backend
                          interface and its in-memory fake
identity/ authz/ directory/ tokens/ connect/ proof/
                          the rest of the public module (later);
                          framework adapters under identity/<framework>mw
internal/                 the hub: hub (snapshots, routing, authority),
                          access (roles, sessions, Explain), server
                          (ConnectRPC handlers, HTTP), demo (fixtures)
frontend/                 the console: Vite + React + MUI, committed
                          dist/ embedded into the binary by go:embed
ts/                       the TypeScript package; dist/ committed so a
                          git install needs no toolchain
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

## Working on the console

The console is a SPA embedded in the hub binary, so three builds happen
in order and skipping one is the usual mistake:

```
just generate              # proto → gen/ (Go) and frontend/src/gen (TS)
cd frontend && npm ci && npm run build   # → frontend/dist, committed
go build ./cmd/directory-roster          # embeds frontend/dist
```

A running `go run` keeps the bundle it started with; restart it after a
frontend build. To see every mechanic without a credential:

```
DEMO=1 FORWARDED_EMAIL_HEADER=X-Auth-Request-Email FORWARDED_ISSUER=https://issuer.example \
  go run ./cmd/directory-roster
```

Behind a real gateway the header carries the caller; in a local run, put
any reverse proxy that adds `X-Auth-Request-Email: ada@north.example` in
front of `:8081`, or sign in with the recovery password the process
prints. The demonstration tenants and policy live in `internal/demo`.

The console's rules are in the hub design, under "The console": two
mirrored sides, every name a link, one meaning per visual form (a name is
a link, a chip is a state and nothing else, facts are a label over a
value, two-column data is a list), list pages explain concepts and object
pages state facts, and no page needs a second call to finish a sentence —
when a page does, change the contract, not the page. The vocabulary is
`frontend/src/ui.tsx`; write new pages against it rather than beside it.

Screenshots for review: headless Chrome with a fresh `--user-data-dir`
every time (it caches the previous bundle otherwise), and read the DOM
rather than the pixels for anything animated.

## Start here, for the next phase

The documents are the authority and the Linear issues carry the
decisions and their dates; when the two disagree, the document wins and
the issue gets a comment. `docs/design/*` says what each battery is and
why; `docs/reference/*` says exactly what it exposes; `CHANGELOG.md`
says what exists today. As of 2026-09-09 the hub and the issuer run on a
cluster, the hub's console is behind `access-proxy`, and three
directories are connected. Everything the first live connect showed is
built and released: nothing slow on the request path, every replica
knowing every workspace, the connect-time domain choice, *provisional*
with a reason, a role scoped to one workspace. The remaining work lives
with the project's issues.

Four things are not fixes and must not be reached for, each because it
was the first idea and the wrong one: raising the gateway's route
timeout, asking for a fifth Google scope, answering a browser with a 5xx
it will never see, and clearing this hub's own cookie to sign somebody
out of a session the proxy holds.

## Releasing

Push a `v*` tag. The release workflow builds the binary, the image
(`ghcr.io/truvity/access-roster/directory-roster`) and the chart
(`ghcr.io/truvity/charts/directory-roster`), all stamped with the tag.
