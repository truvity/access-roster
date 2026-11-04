# Recipes for the sluis.id website (Astro Starlight, source in site/, content in
# docs/). Run them inside the devbox shell (`devbox shell`, or `devbox run -- just <recipe>`).

set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# Install the site's dependencies exactly as the lockfile says.
site-install:
    cd site && yarn install --immutable

# The site on http://localhost:4321 with live reload.
site-dev: site-install
    cd site && yarn dev

# A strict build into site/dist: no warnings, no broken internal link, and the
# built output has what it must (search index, Mermaid, llms.txt, the landing text).
site-build: site-install
    site/scripts/strict-build.sh
    site/scripts/check-built.sh site/dist

# a Proposed note that links its issue on every page in docs/, and the requirements
# registered open-decision ids on every page in docs/, and the requirements
# catalogue in docs/requirements/ (schema, statement rules, traceability, public safety).
site-lint: site-install check-requirements
    site/scripts/check-descriptions.mjs
    site/scripts/check-status.mjs

# The requirements catalogue in docs/requirements/: every file valid against
# requirements.schema.json (ids REQ-<AREA>-NNN), ids unique across files, and the
# statement, traceability and public-safety rules of the script's header.
check-requirements: site-install
    site/scripts/check-requirements.mjs

# Rewrite the generated coverage block on docs/standards/conformance.md from the
# requirements catalogue. `just site-lint` fails while the block is stale.
site-coverage: site-install
    site/scripts/check-requirements.mjs --write-coverage

# Every link in the built site, internal and external (lychee.toml). Needs `just site-build`.
#
# lychee has been seen to run for ever without a line of output (2026-11-01, every run of
# the job for 20 minutes until its timeout), and `--no-progress` left nothing to say on
# which link. Each try is bounded to 4 minutes (a normal run takes well under one), is
# verbose so that the log names the link it stopped at, and a try that hit the bound is
# repeated, twice. A run that ends in lychee's own failure (a dead link) is not repeated.
site-links:
    #!/usr/bin/env bash
    set -euo pipefail
    for attempt in 1 2 3; do
      rc=0
      timeout --foreground 240 lychee --config lychee.toml --root-dir "$PWD/site/dist" --no-progress -v 'site/dist/**/*.html' || rc=$?
      [ "$rc" -eq 124 ] || exit "$rc"
      echo "site-links: lychee did not finish in 240 s (try $attempt of 3)" >&2
    done
    echo "site-links: lychee did not finish in 3 tries" >&2
    exit 1

# Open the built site in headless Chrome and assert that every Mermaid diagram is
# drawn (an <svg> in each pre.mermaid), the explorers' script ran and the console
# is clean, in light and dark mode. Needs Chrome or Chromium (CHROME, or
# google-chrome / chromium on PATH) and `just site-build`. Screenshots: pass a
# directory, `just site-render site/dist /tmp/shots`.
site-render dist='site/dist' shots='':
    site/scripts/check-render.mjs {{ dist }} {{ shots }}

# What a pull request must pass.
site-check: site-lint site-build site-render site-links

# Refresh v1-src from the newest stable v1 release tag (or the tag given) and build
# the v1 documentation into site/dist/v1. The Site workflow picks the tag by the
# same rule (site/scripts/latest-v1-tag.sh). Needs python3, jq, curl.
site-v1 tag='':
    #!/usr/bin/env bash
    set -euo pipefail
    tag='{{ tag }}'
    [ -n "$tag" ] || tag=$(site/scripts/latest-v1-tag.sh origin | cut -d' ' -f1)
    echo "v1 documentation: $tag"
    git fetch --quiet --no-tags origin "+refs/tags/$tag:refs/tags/$tag"
    rm -rf v1-src && mkdir v1-src
    git archive "$tag" | tar -x -C v1-src
    site/scripts/build-v1.sh v1-src site/dist
    site/scripts/check-built.sh site/dist

# Everything the Site workflow builds: the site and v1 under /v1/.
site-all: site-check site-v1

# The Cloudflare Workers build (ADR 0014), as the deploy job of site.yaml makes it, and
# a dry-run deploy that uploads nothing and needs no Cloudflare credential: the strict
# build for the Worker into site/dist/client, v1 under /v1/ when v1-src holds a v1 tag
# (see site-v1), the build checks (headers, redirects, Git LFS), the Worker's tests and
# `wrangler deploy --dry-run` on the generated configuration, which bundles the Worker.
# The KV id is a fake one: the real id is a secret of the deploy environment.
site-workers: site-install site-test-worker
    SLUIS_TARGET=workers SLUIS_STATUS_KV_ID=ffffffffffffffffffffffffffffffff site/scripts/strict-build.sh
    if [ -d v1-src ]; then site/scripts/build-v1.sh v1-src site/dist/client; fi
    site/scripts/check-built.sh site/dist/client
    cd site && WRANGLER_SEND_METRICS=false yarn wrangler deploy --dry-run

# The tests of the site's Worker (site/src/worker/: the status API, the webhook and CI
# checks, the KV write rules), in Node with GitHub and KV faked. No network, no credential.
site-test-worker: site-install
    site/scripts/check-worker.mjs

# Deploy the Workers build in site/dist/client to Cloudflare. Only the deploy job of
# site.yaml runs this, on an output that was built with the real KV id in
# SLUIS_STATUS_KV_ID. Needs CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID. `secrets` is
# a JSON file of Worker secrets to upload with the version (absolute path); the deploy job
# writes it from GitHub secrets and deletes it afterwards.
site-deploy secrets='':
    cd site && WRANGLER_SEND_METRICS=false yarn wrangler deploy {{ if secrets != '' { '--secrets-file ' + quote(secrets) } else { '' } }}

# Repository rules (tools/checks/). Each check fails when it finds nothing to check.

# Decision records in docs/decisions/: NNNN-kebab-case.md names, the template's
# fields and sections in order, a status the README allows, every road not taken
# with its pros, cons and reason, and a README index row per record with its status.
check-decisions:
    tools/checks/decisions.mjs

# Public content of every tracked text file: no account-id-shaped number other than
# a documented placeholder, no private key block, no well-known token prefix, and no
# term of the private deny-list (PUBLIC_CONTENT_DENYLIST, a repository secret; the
# check skips that part, saying so, when the variable is empty, and fails instead
# when REQUIRE_DENYLIST=true).
check-public:
    tools/checks/public-content.mjs

# The same scan over the commit messages of BASE..HEAD (BASE defaults to origin/main)
# and the pull request title and body in PR_TITLE and PR_BODY. Not part of
# check-rules: on `main` itself the range is empty, and an empty sweep fails.
check-messages:
    tools/checks/public-messages.mjs

# YAML files use .yaml, except the names a tool requires (.github/ISSUE_TEMPLATE/config.yml, .yarnrc.yml).
check-yaml-ext:
    tools/checks/yaml-ext.mjs

# Markdown everywhere; MDX only for a page that places components: every docs/**/*.mdx imports
# a component and places it ("Page format" in docs/contributing/pages.md).
check-mdx-pages:
    tools/checks/mdx-pages.mjs

# Every path that AGENTS.md, CLAUDE.md, .claude/skills/*/SKILL.md and .claude/agents/*.md
# point to exists. Fails when AGENTS.md is missing or CLAUDE.md does not import it.
check-agent-links:
    tools/checks/agent-links.mjs

# The actor registry, docs/architecture/actors.yaml: the four families, the credential holders, the
# ports, calls and egress, against the decision records that name actors, the identity explorer's
# roles, the requirement records' `actors:` and the generated tables on docs/reference/actors.md. Each
# actor has the GitHub label `actor:<name>` that the registry lists. A decision record that does not name
# an actor only warns; `--strict-adrs` makes it an error.
check-actors *args: site-install
    tools/checks/actors.mjs {{ args }}

# Rewrite the generated tables on docs/reference/actors.md from the registry.
actors-write: site-install
    tools/checks/actors.mjs --write

# The kind registry (docs/architecture/kinds.yaml), the key registry (docs/architecture/keys.yaml) and the
# actor registry against each other: one writer per kind except the declared self-scoped kinds, every writer
# and reader an actor, a time to live on every temp kind, no tenant scope on a config or secret kind, the AWS
# baseline of one symmetric key and five P-384 keys, and the card slot plan without a collision.
# Every key purpose an actor uses is defined in keys.yaml with the ops it allows.
check-registries: site-install
    tools/checks/registries.mjs

# The generated pages, each a block between markers on a page with a hand-written introduction. The
# check fails while the block is stale; the -write recipe rewrites it. Links to decision records on the
# page are checked too: a record or heading that does not exist is an error.

# The vocabulary page, docs/concepts/index.md, from docs/glossary.yaml: the terms by category and the retired terms.
check-glossary-page: site-install
    tools/checks/glossary-page.mjs

# Rewrite the generated block of docs/concepts/index.md.
glossary-write: site-install
    tools/checks/glossary-page.mjs --write

# The kinds page, docs/reference/kinds.md, from the kind registry: class, scope, treatment, profile, writer,
# readers, time to live, exportable, backed up, the layered groups and what is not data.
check-kinds-page: site-install
    tools/checks/kinds-page.mjs

# Rewrite the generated block of docs/reference/kinds.md.
kinds-write: site-install
    tools/checks/kinds-page.mjs --write

# The rules page, docs/reference/rules.md, from the kind registry (actor x kind x verb) and the actor registry (the call graph).
check-rules-page: site-install
    tools/checks/rules-page.mjs

# Rewrite the generated block of docs/reference/rules.md.
rules-write: site-install
    tools/checks/rules-page.mjs --write

# The keys page, docs/reference/keys.md, from the key registry and the actor registry: purposes per algorithm, the
# AWS baseline, the purposes enabled on use, the data keys and the board slot plan.
check-keys-page: site-install
    tools/checks/keys-page.mjs

# Rewrite the generated block of docs/reference/keys.md.
keys-write: site-install
    tools/checks/keys-page.mjs --write

# Rewrite every generated page of the registries (actors, vocabulary, kinds, rules, keys).
pages-write: actors-write glossary-write kinds-write rules-write keys-write

# An exception is a path exclude or skip_records rule of the glossary's `lint` section, a rule's
# context_allow, or `terms-allow: <id>` on the line or the line before it. `--quiet` prints the summary only.
# The retired terms of docs/glossary.yaml in the docs and the site content, in ERROR mode: a hit fails the run.
check-terms *args: site-install
    tools/checks/terms.mjs --error {{ args }}

# Example files shown on a page (a fenced block after `<!-- example: <path> -->` in docs/) equal
# the files themselves, such as the local installation's example install file.
check-examples:
    tools/checks/examples.mjs

# The example installations under tests/installations/: every upstream's `org` names a company
# boundary, the vocabulary file has the shape of docs/reference/vocabulary.md, and every grant name
# in a client's `requires`, a policy file, the links and the test vectors is declared in it.
check-installations: site-install
    tools/checks/installations.mjs

# The checks above against scratch repositories that must pass or must fail.
check-selftest: site-install
    tools/checks/selftest.mjs

# Every repository rule.
check-rules: check-selftest check-decisions check-requirements check-actors check-registries check-glossary-page check-kinds-page check-rules-page check-keys-page check-terms check-examples check-installations check-public check-yaml-ext check-mdx-pages check-agent-links

# Everything a pull request must pass.
check: check-rules site-check site-workers

# Code: the Go module (go.mod) and the Cargo workspace (Cargo.toml). CI runs `check-code`.

# Build every Go package.
go-build:
    go build ./...

# Test every Go package with the race detector, uncached. The tag sluis_test adds the test seams (the name
# resolver of kits/go/rpc) that a normal build does not contain.
# The run is verbose so that a test that skips shows its `SKIP: <reason>` line in the log (a skip is not a pass).
# The lines of passing tests (RUN, PAUSE, CONT, NAME, PASS) are dropped, which keeps the output about as long as
# before; failures, skips, logs and the package lines stay. The exit status is that of go test.
go-test:
    #!/usr/bin/env bash
    set -euo pipefail
    go test -race -count=1 -v -tags sluis_test ./... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/'

# Lint the Go module.
go-lint:
    golangci-lint run ./...

# Build the Cargo workspace.
rust-build:
    cargo build --workspace

# Test the Cargo workspace.
rust-test:
    cargo test --workspace

# Format check and Clippy over the Cargo workspace.
rust-lint: rust-feature-guard
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# The test-only feature `test-identities` of sluis-kit (the name resolver seam) must never be on a
# normal dependency edge: only a dev-dependency may turn it on, so no product binary has it.
# `-e normal` leaves the dev edges out. An empty sweep is a failure: the tree must show sluis-kit.
rust-feature-guard:
    #!/usr/bin/env bash
    set -euo pipefail
    tree=$(cargo tree --workspace -e normal --prefix none -f '{p} [{f}]')
    grep -q '^sluis-kit v' <<<"$tree" || { echo "::error::cargo tree -e normal does not list sluis-kit: the guard checked nothing" >&2; exit 1; }
    if grep -n 'test-identities' <<<"$tree"; then
        echo "::error::the feature test-identities is on a normal dependency edge" >&2
        exit 1
    fi
    echo "rust-feature-guard: test-identities is on no normal edge"

# The pinned rqlite release (v10.6.6) for the tests of the rqlite driver: the linux-amd64 and
# linux-arm64 archives from the GitHub release, verified against the SHA-256 written here, unpacked
# to .cache/rqlite/linux-<arch>/ (rqlited and rqlite). Idempotent: an archive that is there and
# verifies is not downloaded again. rqlite runs as a plain process, never in a container.
#
# The digests are the ones GitHub publishes for the release assets (MEASURED 2026-11-04, `gh release
# view v10.6.6 -R rqlite/rqlite --json assets`). The release has no checksum file of its own.
rqlite-fetch:
    #!/usr/bin/env bash
    set -euo pipefail
    version=v10.6.6
    declare -A sums=(
        [amd64]=b0fdc2d526b03c0d933e27bf84f53d447791d1a6e331e74fa2013750bf621aba
        [arm64]=8da274ea338e156522c00ec63650c1a3cdd1db1c3dd127b43fe955f221009c21
    )
    dir=.cache/rqlite
    mkdir -p "$dir"
    for arch in amd64 arm64; do
        name="rqlite-$version-linux-$arch"
        archive="$dir/$name.tar.gz"
        if [ -x "$dir/linux-$arch/rqlited" ] && [ -f "$archive" ] \
            && echo "${sums[$arch]}  $archive" | sha256sum --check --status; then
            echo "rqlite-fetch: $arch is there"
            continue
        fi
        curl --fail --silent --show-error --location --retry 3 --output "$archive.part" \
            "https://github.com/rqlite/rqlite/releases/download/$version/$name.tar.gz"
        echo "${sums[$arch]}  $archive.part" | sha256sum --check --status \
            || { echo "::error::$name.tar.gz does not match its SHA-256" >&2; rm -f "$archive.part"; exit 1; }
        mv "$archive.part" "$archive"
        rm -rf "$dir/linux-$arch" "$dir/$name"
        tar -xzf "$archive" -C "$dir"
        mv "$dir/$name" "$dir/linux-$arch"
        [ -x "$dir/linux-$arch/rqlited" ] || { echo "::error::$name.tar.gz holds no rqlited" >&2; exit 1; }
        echo "rqlite-fetch: $arch fetched"
    done

# Every code check, in the order CI runs them. An empty sweep is a failure: the Go module and
# the Cargo workspace must each hold a package. The proto and registry steps run once their
# recipes exist.
check-code: rqlite-fetch
    #!/usr/bin/env bash
    set -euo pipefail
    go_packages=$(go list ./... | wc -l)
    [ "$go_packages" -gt 0 ] || { echo "::error::go list ./... found no package" >&2; exit 1; }
    rust_packages=$(cargo metadata --format-version 1 --no-deps | jq '.workspace_members | length')
    [ "$rust_packages" -gt 0 ] || { echo "::error::cargo metadata found no workspace member" >&2; exit 1; }
    echo "$go_packages Go packages, $rust_packages Rust packages"
    for step in proto-check registry-check; do
        if just --summary | tr ' ' '\n' | grep -qx "$step"; then
            just "$step"
        else
            echo "SKIP: $step not yet defined"
        fi
    done
    # CI must run the rqlite driver's tests, never skip them for want of the binary (rqlite-fetch).
    SLUIS_REQUIRE_RQLITED=1 just go-lint go-test rust-lint rust-test

# Registry codegen: the enforcement tables of the three registries (docs/architecture/actors.yaml,
# kinds.yaml and keys.yaml) as kits/go/registry/zz_registry.go and
# kits/rust/sluis-registry/src/generated.rs. Run it after a registry changes.
registry-gen:
    go run ./tools/gen/registry

# The generated registry files are current, and the uid list only grew. Fails while a generated file
# differs from the registries or is not committed. The uid list is compared with main's, which CI
# fetches first (a shallow checkout has no origin/main); a failed fetch fails the recipe, and only a main
# that has no uids.yaml yet makes the test print SKIP.
registry-check:
    #!/usr/bin/env bash
    set -euo pipefail
    just registry-gen
    paths="kits/go/registry/zz_registry.go kits/rust/sluis-registry/src/generated.rs"
    # shellcheck disable=SC2086
    git diff --exit-code -- $paths
    # shellcheck disable=SC2086
    [ -z "$(git ls-files --others --exclude-standard -- $paths)" ] || { echo "::error::a generated registry file is not committed" >&2; exit 1; }
    git rev-parse -q --verify refs/remotes/origin/main >/dev/null || git fetch -q --depth=1 origin main:refs/remotes/origin/main
    go test -count=1 -v -run 'TestUIDsAppendOnly' ./tools/gen/registry

# Contracts: the Protobuf services under proto/ and the Go code generated from them (gen/go/).

# Lint proto/ and regenerate gen/go/ (Protobuf and Connect). Rust is generated by its own build.
proto-gen:
    buf lint
    buf generate

# proto-gen must leave no difference: the committed gen/go/ is what the generators make.
proto-check: proto-gen
    git diff --exit-code -- gen/go proto
    @test -z "$(git ls-files --others --exclude-standard -- gen/go proto)" || { echo "proto-check: untracked generated files" >&2; exit 1; }

# The boards: cross-compile for arm64, generate the systemd units, and put them on the boards over SSH.
# The hosts are never in the repository: SLUIS_BOARDS and SLUIS_BOARD_SSH_USER (and SLUIS_BOARD_SSH_AUTH_SOCK)
# come from the environment, the run.env of the build. See deploy/boards/boards.sh.

# Every executable of actors/, drivers/ and cli/ for the boards (Go with CGO off, Rust through zig, static musl)
# into dist/arm64/, each checked to be a statically linked ARM aarch64 ELF.
build-arm64:
    deploy/boards/build-arm64.sh

# The systemd units, users and directories of the boards, from the registries, into deploy/boards/units/.
# `go test ./tools/gen/units` (part of go-test) fails while the committed files differ from what this makes.
units-gen:
    go run ./tools/gen/units

# Copy the executables that exist in dist/arm64, with their units, to every board; verify; start in order.
# Idempotent. SLUIS_BOARDS_DRY_RUN=1 stages and prints the plan without touching a board.
boards-deploy:
    deploy/boards/boards.sh deploy

# Remove what boards-deploy added, as the board's manifest lists it. Never sluis-rqlite, the user sluis,
# /opt/sluis/bin/rqlited or /var/lib/sluis. The state of the units stays unless SLUIS_PURGE_STATE=1.
boards-undeploy:
    deploy/boards/boards.sh undeploy

# Read only: the units of boards-deploy on every board, and whether they are active.
boards-status:
    deploy/boards/boards.sh status

# The local installation (docs/runtimes/local.md): Docker Compose on this workstation, every actor and driver as its
# pinned uid, config signed by the harness. Needs Docker, and SLUIS_UPSTREAM_TARGET and SLUIS_KEYCLOAK_SECRETS in the
# environment (the run.env of the build); the repository names neither. Run them as `devbox run -- just local-up`.

# Generate deploy/local/compose.yaml and init.sh from the registries. `go test ./tools/gen/compose` (part of go-test)
# fails while the committed files differ from what this makes.
compose-gen:
    go run ./tools/gen/compose

# Build the executables and the images, make the state of the run (harness CA, signed config, credentials) and start the
# project; it returns when every service that has a health check is healthy.
local-up: rqlite-fetch
    deploy/local/local.sh up

# Stop the project and delete its volumes and the state of the run (the CA, the publisher key, the credentials).
local-down:
    deploy/local/local.sh down

# Each service of the project with its uid, its state and its health.
local-status:
    deploy/local/local.sh status

# The logs of the project, or of the services named: `just local-logs store key`.
local-logs *services:
    deploy/local/local.sh logs {{ services }}

# The smoke step of store@'s verification: with one signed document changed, store@ refuses to start. Needs `local-up`.
local-smoke-tamper:
    deploy/local/local.sh tamper

# The M1 proof against the running local installation (`just local-up` first): a client under the uid of exchange asks
# policy for a token.exchange decision and signer for a token; the token is checked against /jwks through the forwarder
# (trusting only the harness CA), the records of the run are found in the audit log, `sluis audit verify` checks the log,
# and SigningRing and DataKeyWrap are read through store@. Exits non-zero on any failure. Needs Docker; CI does not run it.
local-smoke:
    CGO_ENABLED=0 go build -o dist/local/spine ./tests/e2e/spine
    SSL_CERT_FILE=.cache/local/ca/ca.pem dist/local/spine
