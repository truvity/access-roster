# Contributing

## Layout

One repository, one tag, several deliverables, each installable or
importable alone:

```
cmd/access-issuer         the whole service: the directory, the policy,
                          the OpenID provider, the login page, the console
cmd/directory-roster      the pre-0.12 directory service, kept so an
                          installation can move back; goes once nothing
                          points at it
cmd/accessctl             the CLI (later)
charts/access-issuer      the chart
charts/directory-roster   the pre-0.12 chart, kept for the same reason
charts/access-proxy       the console exposure chart
action.yml                the GitHub Action, at the root so `uses: truvity/access-roster@v1` works (later)
policy/ backend/          the Go module's public packages today: the
                          five-table policy, the directory backend
                          interface and its in-memory fake
identity/ authz/ directory/ tokens/ connect/ proof/
                          the rest of the public module (later);
                          framework adapters under identity/<framework>mw
internal/                 hub (snapshots, routing, authority), issuer
                          (the OpenID surface, sessions, exchange),
                          access (roles, sessions, Explain), server
                          (ConnectRPC handlers, HTTP), verify (the
                          proofs), demo (fixtures). app and issuerapp
                          assemble the two halves; rosterapp is the
                          wiring that makes them one process
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
go build ./cmd/access-issuer             # embeds frontend/dist
```

A running `go run` keeps the bundle it started with; restart it after a
frontend build. To see every mechanic without a credential:

```
DEMO=1 STORE=memory ALLOW_INSECURE=true \
  ISSUER_URL=http://localhost:8099 PUBLIC_URL=http://localhost:8099/console \
  PORT=8099 HEALTH_PORT=7099 \
  go run ./cmd/access-issuer
```

Then open `http://localhost:8099/console/` and take *Continue with the
demonstration directory*. Two demonstration tenants are adopted with no
credential and no network; they live in `internal/demo`, and one account
is suspended because a leaver is the case the whole design turns on.

Discovery and the key set answer at `http://localhost:8099/`, because the
issuer owns the origin root and the console takes a path beside it. What
a demonstration run cannot do is sign anybody in **at the issuer**: that
needs a real corporate OAuth client, so the code flow and token exchange
are exercised by the tests rather than by hand.

The console's rules are in
[docs/design/access-roster.md](docs/design/access-roster.md), under "The
console": two
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
the issue gets a comment. Read in this order: `docs/design/trust.md`
(the rule under everything — two trust anchors chosen by scope, `groups`
as the one vocabulary), `docs/connect/service-to-service.md` (the how-to
that rule produces), `docs/integrations.md` (every case with its
anchor), then the design of whatever you touch. `docs/reference/*` says
exactly what each battery exposes; `CHANGELOG.md` says what exists today.

As of 2026-09-09 (evening) the hub and the issuer run on a cluster at
0.9.x, the hub's console is behind `access-proxy`, three directories are
connected, the policy is rendered from the installation's access matrix,
sign-out ends the issuer session, CI tokens verify, and the session
index is shared across replicas. The road to 1.0 is written as issues
under the issuer's 1.0 epic — sessions in the console, identity claims,
`/register`, the conformance run — and **1.0 is not tagged without a
conversation first.** The rewiring order after it is consoles, then clusters, then
AWS, then CI.

Things that are not fixes and must not be reached for, each because it
was the first idea and the wrong one: raising the gateway's route
timeout; asking for a fifth Google scope; answering a browser with a 5xx
it will never see; clearing this hub's own cookie to sign somebody out of
a session the proxy holds; putting an exchange in front of a same-cluster
call; verifying another cluster's key set directly; minting a structured
roles claim beside `groups`; re-mapping group names in a library; a
ConfigMap watch instead of a `checksum/policy` rollout; a group name that
is not `<scope>:<thing>:<role>` (or `rung:`/`emp:`, which are not
grants).

## Releasing

Push a `v*` tag. The release workflow builds the binary, the image
(`ghcr.io/truvity/access-roster/directory-roster`) and the chart
(`ghcr.io/truvity/charts/directory-roster`), all stamped with the tag.
