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

# Every link in the built site, internal and external (lychee.toml). Needs `just site-build`.
#
# lychee has been seen to run for ever without a line of output (2026-11-01, every run of
# the job for 20 minutes until its timeout), and `--no-progress` left nothing to say on
# which link. Each try is bounded to 4 minutes (a normal run takes well under one), is
# verbose so that the log names the link it stopped at, and a try that hit the bound is
# repeated, twice. A run that ends in lychee's own verdict (a dead link) is not repeated.
#
# lychee writes a JSON report and site/scripts/links-report.mjs judges it. lychee sends one
# request for a 5xx (its max_retries covers network errors and timeouts only, with a growing
# wait), so the links of an external host that failed on a 5xx, a network error or a timeout
# are checked again here, after 15 s and then 45 s. What still fails then depends on
# SLUIS_LINKS_MODE (strict when unset; the Checks workflow sets lenient for a pull request and
# the merge queue, strict for main):
#   lenient: a 5xx, a network error or a timeout from an external host is a warning, reported
#            and not failing (kubernetes.io failed four pull requests on 2026-11-06 and passed
#            on a rerun);
#   strict:  a 5xx from github.com or raw.githubusercontent.com is a warning (those hosts
#            answered 504 to CI runners on 2026-11-05 for pages that loaded a moment later);
#            a 5xx from another host, a network error and a timeout fail.
# In both: a 4xx (a 404, a 410) and every internal link fail.
site-links:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="$(mktemp -d)"
    trap 'rm -rf "$dir"' EXIT
    check() { # check <timeout s> <report> <input or option>...: lychee's exit status, 124 when it hit the bound
      local bound="$1" report="$2" rc=0
      shift 2
      timeout --foreground "$bound" lychee --config lychee.toml --root-dir "$PWD/site/dist" --no-progress -v --format json --output "$report" "$@" || rc=$?
      return "$rc"
    }
    for attempt in 1 2 3; do
      rc=0
      check 240 "$dir/r1.json" 'site/dist/**/*.html' || rc=$?
      if [ "$rc" -eq 124 ]; then
        echo "site-links: lychee did not finish in 240 s (try $attempt of 3)" >&2
        continue
      fi
      args=("$dir/r1.json" "$rc")
      last="$dir/r1.json"
      for round in 2 3; do
        site/scripts/links-report.mjs retry-urls "$last" > "$dir/urls$round.txt"
        [ -s "$dir/urls$round.txt" ] || break
        echo "site-links: checking $(wc -l < "$dir/urls$round.txt") links again after a server error, network error or timeout (round $round of 3)" >&2
        sleep $((round == 2 ? 15 : 45))
        rrc=0
        check 240 "$dir/r$round.json" --cache=false "$dir/urls$round.txt" || rrc=$?
        if [ "$rrc" -eq 124 ]; then
          echo "site-links: the repeated check did not finish in 240 s" >&2
          # a pull request judges what the rounds so far found; main does not let it pass
          [ "${SLUIS_LINKS_MODE:-strict}" = lenient ] && break
          exit 1
        fi
        args+=("$dir/r$round.json" "$rrc")
        # the next round repeats what is still a 5xx after the merge so far
        site/scripts/links-report.mjs merge "${args[@]}" > "$dir/m$round.json"
        last="$dir/m$round.json"
      done
      exec site/scripts/links-report.mjs judge "${args[@]}"
    done
    echo "site-links: lychee did not finish in 3 tries" >&2
    exit 1

# The self-test of the link check's judgement (site/scripts/links-report.test.mjs): a 404 on
# any host fails, a 504 on github.com warns, a 504 on another host fails in strict mode and
# warns in lenient mode, as do a network error and a timeout; an internal link always fails.
# Fake reports, no network, no lychee.
site-test-links:
    node --test site/scripts/links-report.test.mjs

# Open the built site in headless Chrome and assert that every Mermaid diagram is
# drawn (an <svg> in each pre.mermaid), the explorers' script ran and the console
# is clean, in light and dark mode. Needs Chrome or Chromium (CHROME, or
# google-chrome / chromium on PATH) and `just site-build`. Screenshots: pass a
# directory, `just site-render site/dist /tmp/shots`.
site-render dist='site/dist' shots='':
    site/scripts/check-render.mjs {{ dist }} {{ shots }}

# What a pull request must pass.
site-check: site-lint site-test-links site-build site-render site-links

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
# when REQUIRE_DENYLIST=true). No tracked file is over 1 MiB or a compiled executable.
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

# No tracked text file holds a committed conflict marker (a line that starts with seven < or seven > and a space).
check-conflict-markers:
    tools/checks/conflict-markers.mjs

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
# baseline of one symmetric key, four P-384 keys and the audit log's P-256 key, and the card slot plan without a collision.
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
check-rules: check-selftest check-decisions check-requirements check-actors check-registries check-glossary-page check-kinds-page check-rules-page check-keys-page check-terms check-examples check-installations check-public check-yaml-ext check-conflict-markers check-mdx-pages check-agent-links

# Everything a pull request must pass.
check: check-rules site-check site-workers

# Code: the Go module (go.mod) and the Cargo workspace (Cargo.toml). CI runs `check-code`.

# Build every Go package.
go-build:
    go build ./...

# Build the sluis command-line tool into bin/sluis, with the flags and the version stamp of the release build
# (deploy/local/build.sh), so that `sluis` on PATH inside devbox is this checkout's code. SLUIS_VERSION sets the
# version; without it the build says 0.0.0-dev, as the release build does.
build-cli:
    mkdir -p bin
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/truvity/sluis/v2/kits/go/version.Version=${SLUIS_VERSION:-0.0.0-dev}" -o bin/sluis ./cli/sluis

# Test every Go package with the race detector, uncached. The tag sluis_test adds the test seams (the name
# resolver of kits/go/rpc) that a normal build does not contain.
# The run is verbose so that a test that skips shows its `SKIP: <reason>` line in the log (a skip is not a pass).
# The lines of passing tests (RUN, PAUSE, CONT, NAME, PASS) are dropped, which keeps the output about as long as
# before; failures, skips, logs and the package lines stay. The exit status is that of go test.
go-test: rust-toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    go test -race -count=1 -v -tags sluis_test ./... 2>&1 \
      | awk '!/^=== (RUN|PAUSE|CONT|NAME)/ && !/^[[:space:]]*--- PASS/ && !/^PASS$/'

# Run the Go fuzz target of the audit canonicaliser for a bounded time (default 30 s). `just go-test` already
# runs its seeds, the vector files and the RFC 8785 corpus on every run; this explores beyond them.
go-fuzz time="30s":
    go test ./kits/go/audit -run '^$' -fuzz '^FuzzCanonical$' -fuzztime {{time}}

# Run the Go fuzz targets of session's client parameters for a bounded time each (default 30 s): the authorization
# request's strings (scope, state, nonce, challenge, redirect_uri) and the token request's (code, verifier). `just go-test`
# already runs their seeds on every run.
go-fuzz-session time="30s":
    go test -tags sluis_test ./actors/session/internal/sessiond -run '^$' -fuzz '^FuzzAuthorizeParameters$' -fuzztime {{time}}
    go test -tags sluis_test ./actors/session/internal/sessiond -run '^$' -fuzz '^FuzzTokenParameters$' -fuzztime {{time}}

# Lint the Go module.
go-lint:
    golangci-lint run ./...

# Build the Cargo workspace.
rust-build: rust-toolchain
    cargo build --workspace

# Test the Cargo workspace.
rust-test: rust-toolchain
    cargo test --workspace

# Check each Rust package with a binary that a change since `base` can affect, alone: `cargo check --package P`, as the release
# builds it (`cargo zigbuild --package P`), so Cargo resolves the features of P without those a sibling would add. The packages
# are the ones whose directory holds a changed file, and all of them when the lock file, the toolchain or a crate below kits/rust
# changed (tools/release rust-changed). With nothing to check it says so.
rust-check-isolated base: rust-toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    mapfile -t pkgs < <(go run ./tools/release rust-changed -base "{{ base }}")
    if [ "${#pkgs[@]}" -eq 0 ]; then
        echo "rust-check-isolated: no Rust package with a binary is affected by the change"
        exit 0
    fi
    for p in "${pkgs[@]}"; do
        echo "rust-check-isolated: cargo check --package $p"
        cargo check --locked --package "$p"
    done

# Format check and Clippy over the Cargo workspace.
rust-lint: rust-toolchain rust-feature-guard
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

# The test-only feature `test-identities` of sluis-kit (the name resolver seam) must never be on a
# normal dependency edge: only a dev-dependency may turn it on, so no product binary has it.
# `-e normal` leaves the dev edges out. An empty sweep is a failure: the tree must show sluis-kit.
rust-feature-guard: rust-toolchain
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

# The OCSF toolkit and the schema it checks against, for `just ocsf-check` (REQ-AUDIT-100): a virtualenv with the schema
# compiler, the OCSF schema at the pinned commit compiled to one file, and the toolkit binary, all below .cache/ocsf and
# nothing installed globally. The pins, with their digests, are in tools/ocsf/pins.env and tools/ocsf/requirements.txt (pip
# runs with --require-hashes). Needs Python 3.14 or later (devbox has it), git, curl and network.
ocsf-fetch:
    #!/usr/bin/env bash
    set -euo pipefail
    source tools/ocsf/pins.env
    dir=.cache/ocsf
    mkdir -p "$dir"
    # The schema compiler, hash-pinned, in a virtualenv of its own.
    if [ ! -x "$dir/venv/bin/ocsf-schema-compiler" ]; then
        rm -rf "$dir/venv"
        python3 -m venv "$dir/venv"
        "$dir/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes --no-deps --only-binary=:all: -r tools/ocsf/requirements.txt
    fi
    # The OCSF schema at the pinned commit, and its compiled form.
    if [ ! -f "$dir/schema/.pinned-$OCSF_SCHEMA_COMMIT" ]; then
        rm -rf "$dir/schema"
        git init -q "$dir/schema"
        git -C "$dir/schema" fetch -q --depth=1 https://github.com/ocsf/ocsf-schema.git "$OCSF_SCHEMA_COMMIT"
        git -C "$dir/schema" checkout -q FETCH_HEAD
        [ "$(git -C "$dir/schema" rev-parse HEAD)" = "$OCSF_SCHEMA_COMMIT" ] || { echo "::error::the OCSF schema is not at the pinned commit" >&2; exit 1; }
        grep -q "\"version\": \"$OCSF_SCHEMA_VERSION\"" "$dir/schema/version.json" || { echo "::error::the pinned commit is not OCSF $OCSF_SCHEMA_VERSION" >&2; exit 1; }
        touch "$dir/schema/.pinned-$OCSF_SCHEMA_COMMIT"
        rm -f "$dir/compiled.json"
    fi
    if [ ! -f "$dir/compiled.json" ]; then
        "$dir/venv/bin/ocsf-schema-compiler" "$dir/schema" > "$dir/compiled.json.part" 2> "$dir/compile.log" \
            || { cat "$dir/compile.log" >&2; exit 1; }
        [ "$(jq -r .version "$dir/compiled.json.part")" = "$OCSF_SCHEMA_VERSION" ] \
            || { echo "::error::the compiled schema is not OCSF $OCSF_SCHEMA_VERSION" >&2; exit 1; }
        mv "$dir/compiled.json.part" "$dir/compiled.json"
    fi
    # The toolkit, by the sha256 that GitHub publishes for the asset.
    case "$(uname -m)" in
        x86_64) arch=amd64; sum=$OCSF_TOOLKIT_SHA256_AMD64 ;;
        aarch64|arm64) arch=arm64; sum=$OCSF_TOOLKIT_SHA256_ARM64 ;;
        *) echo "::error::no OCSF toolkit pin for $(uname -m)" >&2; exit 1 ;;
    esac
    if [ ! -x "$dir/toolkit/ocsf-toolkit" ] || [ ! -f "$dir/toolkit/.pinned-$OCSF_TOOLKIT_VERSION-$arch" ]; then
        archive="$dir/ocsf-toolkit_${OCSF_TOOLKIT_VERSION}_linux_${arch}.tar.gz"
        curl --fail --silent --show-error --location --retry 3 --output "$archive.part" \
            "https://github.com/ocsf/ocsf-toolkit/releases/download/$OCSF_TOOLKIT_VERSION/$(basename "$archive")"
        echo "$sum  $archive.part" | sha256sum --check --status \
            || { echo "::error::$(basename "$archive") does not match its SHA-256" >&2; rm -f "$archive.part"; exit 1; }
        mv "$archive.part" "$archive"
        rm -rf "$dir/toolkit" "$dir/toolkit.part"
        mkdir "$dir/toolkit.part"
        tar -xzf "$archive" -C "$dir/toolkit.part" --strip-components=1
        [ -x "$dir/toolkit.part/ocsf-toolkit" ] || { echo "::error::the archive holds no ocsf-toolkit" >&2; exit 1; }
        touch "$dir/toolkit.part/.pinned-$OCSF_TOOLKIT_VERSION-$arch"
        mv "$dir/toolkit.part" "$dir/toolkit"
    fi
    echo "ocsf-fetch: OCSF $OCSF_SCHEMA_VERSION ($OCSF_SCHEMA_COMMIT), toolkit $OCSF_TOOLKIT_VERSION"

# The example record of every action of the table, checked by the OCSF toolkit against the pinned OCSF schema
# (REQ-AUDIT-100). Fails on an error finding that tools/ocsf/known-findings.tsv does not list (or lists with a smaller
# count), on a listed finding that no longer appears, and on a change that adds a line or raises a count against main's copy
# of that file, which CI fetches first (a failed fetch or a failed read fails the recipe; only a main without the file makes the test say so, a tolerance to drop once this has landed).
ocsf-check: ocsf-fetch
    #!/usr/bin/env bash
    set -euo pipefail
    git rev-parse -q --verify refs/remotes/origin/main >/dev/null || git fetch -q --depth=1 origin main:refs/remotes/origin/main
    base=$(mktemp)
    trap 'rm -f "$base"' EXIT
    # Main has the file or it does not; any other failure of git is a failure of the recipe, not "no baseline yet".
    if git cat-file -e origin/main:tools/ocsf/known-findings.tsv 2>/dev/null; then
        git show origin/main:tools/ocsf/known-findings.tsv > "$base"
    else
        rm -f "$base"
    fi
    SLUIS_REQUIRE_OCSF=1 SLUIS_OCSF_DIR="$PWD/.cache/ocsf" SLUIS_OCSF_BASE_FILE="$base" go test -count=1 -v ./tools/ocsf

# Every code check, in the order CI runs them. An empty sweep is a failure: the Go module and
# the Cargo workspace must each hold a package. The proto and registry steps run once their
# recipes exist.
check-code: rust-toolchain rqlite-fetch
    #!/usr/bin/env bash
    set -euo pipefail
    go_packages=$(go list ./... | wc -l)
    [ "$go_packages" -gt 0 ] || { echo "::error::go list ./... found no package" >&2; exit 1; }
    rust_packages=$(cargo metadata --format-version 1 --no-deps | jq '.workspace_members | length')
    [ "$rust_packages" -gt 0 ] || { echo "::error::cargo metadata found no workspace member" >&2; exit 1; }
    echo "$go_packages Go packages, $rust_packages Rust packages"
    for step in proto-check registry-check audit-check audit-compat config-schema-check config-schema-compat ocsf-check; do
        if just --summary | tr ' ' '\n' | grep -qx "$step"; then
            just "$step"
        else
            echo "SKIP: $step not yet defined"
        fi
    done
    # CI must run the rqlite driver's tests, never skip them for want of the binary (rqlite-fetch).
    SLUIS_REQUIRE_RQLITED=1 just go-lint go-test rust-lint rust-test

# The advisory gate (REQ-SUPPLY-030), as the job `advisories` of checks.yaml runs it: govulncheck over every Go module
# (the default build, and the card driver with the tag sluis_card), cargo audit over every Cargo.lock and osv-scanner over
# the lock files (go.mod, Cargo.lock, site/yarn.lock). It fails on a known advisory that affects us, unless
# tools/advisories/ignore.yaml lists it with a reason and an expiry date. Needs the network (vuln.go.dev, api.osv.dev, the
# RustSec database), and for the card build gcc, pkg-config and libpcsclite-dev on the host; `just check-advisories
# -skip-card` leaves that scan out and says so. `-only go` runs one scan of go, rust, osv.
check-advisories *args: rust-toolchain
    go run ./tools/advisories {{ args }}

# The licence rule for Rust (REQ-SUPPLY-045): `cargo deny check licenses` over Cargo.lock, with the allow list of deny.toml,
# which is the list on docs/reference/approved-libraries.md. About a second, no network. Go is not checked yet (a follow-up,
# see "The check" on that page). The `advisories` job of checks.yaml runs it.
check-licenses: rust-toolchain
    cargo deny --locked check licenses

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

# The audit action table (docs/architecture/audit-actions.yaml, ADR 0030): the JSON Schema of the audit records, one
# example record for each action, and the table with its schemas as Go and Rust code for the emitters.
# Run it after the table changes.
audit-gen:
    go run ./tools/gen/audit

# The files audit-gen makes are what the table makes, and the Go and Rust emitters read the same schemas the same way
# (REQ-AUDIT-114). Fails while a generated file differs from the table or is not committed.
audit-check:
    #!/usr/bin/env bash
    set -euo pipefail
    go run ./tools/gen/audit -check
    paths="kits/conformance/audit/schema kits/conformance/audit/action-vectors.json kits/go/audit/zz_table.go kits/rust/sluis-audit/src/generated.rs"
    # shellcheck disable=SC2086
    [ -z "$(git ls-files --others --exclude-standard -- $paths)" ] || { echo "::error::a generated audit file is not committed" >&2; exit 1; }

# The table does not remove or retype a member of unmapped.sluis against the table of the newest stable release tag of the same
# major version, or the newest pre-release before there is a stable one (tools/checks/baseline-tag.sh; REQ-AUDIT-119). With no release tag yet it says so and does not pass: a check that cannot run is
# reported as not run.
audit-compat:
    #!/usr/bin/env bash
    set -euo pipefail
    tag=$(tools/checks/baseline-tag.sh)
    if [ -z "$tag" ]; then
        echo "::notice::audit-compat: NOT RUN, there is no release tag v2.* yet to compare the table with"
        echo "audit-compat: NOT RUN, there is no release tag v2.* yet to compare the table with"
        exit 0
    fi
    old=$(mktemp)
    trap 'rm -f "$old"' EXIT
    git show "$tag:docs/architecture/audit-actions.yaml" > "$old"
    go run ./tools/gen/audit -against "$old"
    echo "audit-compat: the table is compatible with $tag"

# The JSON Schema of the configuration files (ADR 0004, "Schemas are Protobuf"), generated from their Protobuf messages into
# schema/<name>/<version>/<name>.schema.json: the golden files that CI compares, the public identifiers of the schemas, and what
# every binary embeds. Run it after a message of tools/gen/configschema/schema.go (roots) changes. It runs `buf build`.
config-schema-gen:
    go run ./tools/gen/configschema

# The schemas are what the messages make (REQ-DATA-037): fails while a committed schema differs from the messages, no message
# makes a committed schema, or a generated schema is not committed.
config-schema-check:
    #!/usr/bin/env bash
    set -euo pipefail
    go run ./tools/gen/configschema -check
    [ -z "$(git ls-files --others --exclude-standard -- schema)" ] || { echo "::error::a generated schema is not committed" >&2; exit 1; }

# The published schemas do not change (REQ-DATA-040): against the schema directory of the newest stable release tag of the same
# major version (the newest pre-release before there is a stable one: tools/checks/baseline-tag.sh), every schema is still there with the same $id, and accepts whatever the release's accepted. A key may be added and a
# bound loosened; anything else is a new version under a new path, beside the old one. With no release tag yet it says so and
# does not pass: a check that cannot run is reported as not run.
config-schema-compat:
    #!/usr/bin/env bash
    set -euo pipefail
    tag=$(tools/checks/baseline-tag.sh)
    if [ -z "$tag" ]; then
        echo "::notice::config-schema-compat: NOT RUN, there is no release tag v2.* yet to compare the schemas with"
        echo "config-schema-compat: NOT RUN, there is no release tag v2.* yet to compare the schemas with"
        exit 0
    fi
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    if ! git cat-file -e "$tag:schema" 2>/dev/null; then
        echo "config-schema-compat: $tag published no schema, so nothing can have changed"
        exit 0
    fi
    git archive "$tag" schema | tar -x -C "$dir"
    go run ./tools/gen/configschema -against "$dir/schema"
    echo "config-schema-compat: the schemas are compatible with $tag"

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
build-arm64: rust-toolchain
    deploy/boards/build-arm64.sh

# The executables that link a C library (deploy/boards/native.list: the card driver, which talks to pcscd through
# libpcsclite) for arm64, built natively inside an Ubuntu 22.04 userland with docker buildx and QEMU, into
# dist/native/arm64/. `build-arm64` leaves them out of its cross-compile (CGO off) and picks this output up. CI builds
# the same on a hosted arm64 runner (the job native-arm64 of checks.yaml).
build-arm64-native:
    deploy/boards/build-arm64-native.sh

# The systemd units, users and directories of the boards, from the registries, into deploy/boards/units/.
# `go test ./tools/gen/units` (part of go-test) fails while the committed files differ from what this makes.
units-gen:
    go run ./tools/gen/units

# The release train (ADR 0013, docs/distribution/packages.md). .goreleaser.yaml is generated from the tree: one build and
# one archive per executable, for amd64 and arm64. `go test ./tools/gen/release` (part of go-test) fails while the committed
# file differs from what this makes.
release-gen:
    go run ./tools/gen/release

# A quick dry run of the archives: GoReleaser builds every archive and the checksums into dist/release, and nothing is
# published and no image is built (that is `release-rehearsal`, which needs Docker). It needs no tag (the version is
# v2.0.0-alpha.0 and the commit), no token and no network beyond the module caches. Then `tools/release` checks what came
# out against the configuration: every archive, its hash in SHA256SUMS and in its .sha256, a static ELF of the
# architecture, the version stamped.
release-snapshot: rust-toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    export GORELEASER_CURRENT_TAG=v2.0.0-alpha.0
    # GoReleaser runs the SBOM command in dist/, so it is found on PATH.
    export PATH="$PWD/tools/release:$PATH"
    goreleaser release --snapshot --clean --skip=publish,announce,validate --config .goreleaser.yaml
    go run ./tools/release check-dist -config .goreleaser.yaml -dist dist/release

# The build half of a release: GoReleaser builds every executable, the archives, the checksums and the SBOMs of the archives into
# dist/release. It publishes nothing and it holds no credential: the build runs the build scripts and macros of every
# dependency, so the tokens are taken out of its environment (the job `build` of release.yaml gives it none, and the rehearsal has
# none). The version is that of GORELEASER_CURRENT_TAG, v2.0.0-alpha.0 when unset; `skip` is what GoReleaser leaves out, and a
# release leaves out `validate` only if it must not check the tag against HEAD.
release-build skip="announce,publish,validate": rust-toolchain
    #!/usr/bin/env bash
    set -euo pipefail
    export GORELEASER_CURRENT_TAG=${GORELEASER_CURRENT_TAG:-v2.0.0-alpha.0}
    unset GITHUB_TOKEN GH_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
    # GoReleaser runs the SBOM command in dist/, so it is found on PATH.
    export PATH="$PWD/tools/release:$PATH"
    goreleaser release --clean --skip={{ skip }} --config .goreleaser.yaml
    go run ./tools/release check-dist -config .goreleaser.yaml -dist dist/release

# The publish half of a release, from the dist/release that `release-build` made (the job `release` of release.yaml downloads
# it). In order: check the archives again, refuse a version that is already published, push the image of every actor and driver
# and the engine, write release-images.txt, run the release test of the images against the registry, make the SBOM of each image
# from the registry, add the list and the SBOMs to SHA256SUMS (the one anchor of trust of an unsigned release), and check them.
# SLUIS_PUBLISH_PREFIX is where the images go (ghcr.io/truvity/sluis by default); SLUIS_PUBLISH_FRESH=1 says the registry is a
# throwaway one (a rehearsal: no GitHub release, no credential, the version is its only tag). Otherwise this is a release: it
# needs GITHUB_REF_NAME (the tag, which names the version of the build), GITHUB_TOKEN and `docker login ghcr.io`, refuses a tag
# that already has a release (a draft included), then creates the GitHub release as a draft with every file, and makes it public
# only when all of it is there. A failure after the first push leaves images in the registry and, at the end, a draft: the
# published tag is never overwritten, so the next attempt needs the next version (docs/distribution/packages.md, "Releasing").
release-publish: rqlite-fetch
    #!/usr/bin/env bash
    set -euo pipefail
    dist=dist/release
    prefix=${SLUIS_PUBLISH_PREFIX:-ghcr.io/truvity/sluis}
    fresh=${SLUIS_PUBLISH_FRESH:-}
    host=${prefix%%/*}
    repo_prefix=${prefix#*/}
    case "$host" in localhost*|127.0.0.1*) base="http://$host" ;; *) base="https://$host" ;; esac
    version=$(jq -r .version "$dist/metadata.json")
    if [ -z "$fresh" ]; then
        : "${GITHUB_TOKEN:?release-publish: GITHUB_TOKEN is not set}"
        : "${GITHUB_REPOSITORY:?release-publish: GITHUB_REPOSITORY is not set}"
        tag=${GITHUB_REF_NAME:?release-publish: GITHUB_REF_NAME (the tag) is not set}
        [ "$tag" = "v$version" ] || { echo "release-publish: the tag $tag is not v$version, the version of the build" >&2; exit 1; }
        # metadata.json comes out of the build job, which runs the code of every dependency: the commit it names must be the
        # commit of the tag, and a full one (it is a label of every image and an argument of git).
        commit=$(jq -r .commit "$dist/metadata.json")
        [ "$commit" = "${GITHUB_SHA:?release-publish: GITHUB_SHA is not set}" ] || { echo "release-publish: the build says it built $commit, not the tag's commit $GITHUB_SHA" >&2; exit 1; }
        [ "$prefix" = ghcr.io/truvity/sluis ] || { echo "release-publish: a release publishes to ghcr.io/truvity/sluis, not $prefix" >&2; exit 1; }
        export SLUIS_REGISTRY_TOKEN="$GITHUB_TOKEN" SLUIS_REGISTRY_USER="${GITHUB_ACTOR:-token}"
        notes=$(mktemp)
        awk -v v="$version" '$0 ~ "^## \\[?" v "\\]?( |$)" {on=1; next} /^## / {on=0} on' CHANGELOG.md >"$notes"
        grep -q '[^[:space:]]' "$notes" || { echo "release-publish: CHANGELOG.md has no section '## $version' with text: rename '## Unreleased' in the pull request that merges before the tag" >&2; exit 1; }
        releases=$(gh api --paginate "repos/$GITHUB_REPOSITORY/releases" --jq '.[].tag_name') || { echo "release-publish: could not list the releases" >&2; exit 1; }
        if grep -Fxq "$tag" <<<"$releases"; then
            echo "release-publish: $tag already has a release (a draft counts): a release is never overwritten" >&2; exit 1
        fi
        buildkit_image='moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
        builder="sluis-release-builder-$$"
        trap 'docker buildx rm --force "$builder" >/dev/null 2>&1 || true' EXIT
        docker buildx create --name "$builder" --driver docker-container --driver-opt "image=$buildkit_image" >/dev/null
        export BUILDX_BUILDER="$builder"
    fi
    go run ./tools/release check-dist -config .goreleaser.yaml -dist "$dist"
    # The audit catalogue of this release, from the table of this commit (here, not in the build job: it is made by this
    # repository's own code from the tagged tree, and nothing of it comes out of the build). Without a catalogue for the
    # version, the writer of an installation refuses every record that the release's emitters send (REQ-AUDIT-146), so the
    # release stops here, before anything is pushed.
    go run ./tools/gen/audit -catalogue "$dist/audit-catalogue.yaml" -release "$version"
    go run ./tools/release check-catalogue -dist "$dist"
    go run ./tools/release preflight -dist "$dist" -prefix "$prefix"
    go run ./tools/release publish-images -dist "$dist" -prefix "$prefix"
    go run ./tools/release release-images -dist "$dist"
    go run ./tools/release check-images -dist "$dist" -registry "$base" -repo-prefix "$repo_prefix" ${fresh:+-fresh}
    if [ -n "$fresh" ]; then export SLUIS_SBOM_INSECURE=1; fi
    tools/release/sbom-images.sh "$dist/release-images.txt" "$dist"
    sboms=()
    for f in "$dist"/*.sbom.spdx.json; do
        case "$f" in *.tar.gz.sbom.spdx.json) ;; *) sboms+=("$(basename "$f")") ;; esac
    done
    go run ./tools/release sums-add -dist "$dist" release-images.txt audit-catalogue.yaml "${sboms[@]}"
    go run ./tools/release check-sums -dist "$dist"
    go run ./tools/release check-sboms -config .goreleaser.yaml -dist "$dist" -sboms "$dist"
    if [ -z "$fresh" ]; then
        # Every file of the release: the archives with their checksums and SBOMs, SHA256SUMS, the list of images, the image SBOMs, the audit catalogue.
        assets=("$dist"/*.tar.gz "$dist"/*.tar.gz.sha256 "$dist"/*.sbom.spdx.json "$dist"/SHA256SUMS "$dist"/release-images.txt "$dist"/audit-catalogue.yaml)
        pre=()
        case "$version" in *-*) pre=(--prerelease) ;; esac
        gh release create "$tag" --draft --verify-tag --title "$tag" --notes-file "$notes" ${pre[@]+"${pre[@]}"} "${assets[@]}"
        have=$(gh release view "$tag" --json assets --jq '.assets | length')
        [ "$have" -eq "${#assets[@]}" ] || { echo "release-publish: the draft holds $have of ${#assets[@]} files; it stays a draft" >&2; exit 1; }
        gh release edit "$tag" --draft=false
    fi

# The whole release, rehearsed against a throwaway registry (CI runs this on every pull request: the job `release` of
# checks.yaml). It is the two halves of a release, `release-build` and `release-publish`, in one job: GoReleaser builds with no
# credential, and the images are pushed to a registry that this recipe starts on a free loopback port and removes at the end,
# with no credential, no token and no GitHub release. It needs Docker, and no tag (the version is v2.0.0-alpha.0). The checks
# are those of a release: the archives, the list of images, the release test of the images (the version tag alone, both platforms,
# every layer by its hash, the executable of its archive), the SPDX SBOMs, and SHA256SUMS. With SLUIS_REHEARSAL_LOCAL=1 it also
# starts the local installation from these images and runs the two smokes.
release-rehearsal: rqlite-fetch
    #!/usr/bin/env bash
    set -euo pipefail
    # Pinned by digest (MEASURED 2026-11-07): the registry that holds the images of the run, and the BuildKit that builds
    # them. The default Docker builder cannot build a multi-platform image on every runner, so a builder of its own is made;
    # it shares the host's network, which is how it reaches the registry on the loopback address.
    registry_image='registry:3@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c'
    buildkit_image='moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5'
    port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    registry="sluis-release-registry-$$"
    builder="sluis-release-builder-$$"
    project_up=
    cleanup() {
        local rc=$?
        if [ -n "$project_up" ]; then
            [ "$rc" -eq 0 ] || { deploy/local/local.sh status >&2 || true; deploy/local/local.sh logs >&2 || true; }
            deploy/local/local.sh down >/dev/null 2>&1 || true
        fi
        docker buildx rm --force "$builder" >/dev/null 2>&1 || true
        docker rm --force "$registry" >/dev/null 2>&1 || true
    }
    trap cleanup EXIT
    just release-build
    docker run --detach --name "$registry" --publish "127.0.0.1:$port:5000" "$registry_image" >/dev/null
    docker buildx create --name "$builder" --driver docker-container --driver-opt network=host --driver-opt "image=$buildkit_image" >/dev/null
    for _ in $(seq 1 30); do
        curl --fail --silent "http://127.0.0.1:$port/v2/" >/dev/null && break
        sleep 1
    done
    curl --fail --silent "http://127.0.0.1:$port/v2/" >/dev/null || { echo "release-rehearsal: the throwaway registry does not answer" >&2; exit 1; }
    export BUILDX_BUILDER="$builder"
    SLUIS_PUBLISH_PREFIX="localhost:$port/sluis" SLUIS_PUBLISH_FRESH=1 just release-publish
    # With SLUIS_REHEARSAL_LOCAL set, the last proof: the local installation starts under Compose from these images, pinned by the
    # digests of release-images.txt and pulled from the throwaway registry, with nothing built, and both smokes pass against
    # it. That is the first "done when" line of the first working version, run against the images of this commit. It needs the
    # upstream the smokes need (SLUIS_UPSTREAM_TARGET and SLUIS_KEYCLOAK_SECRETS, as the job smokes of checks.yaml makes them).
    if [ -n "${SLUIS_REHEARSAL_LOCAL:-}" ]; then
        export SLUIS_LOCAL_IMAGES=release SLUIS_RELEASE_IMAGES="$PWD/dist/release/release-images.txt" SLUIS_RELEASE_CATALOGUE="$PWD/dist/release/audit-catalogue.yaml"
        project_up=1
        # The smokes mount their executable into any image of the project: the release's signer image, by digest.
        SLUIS_SMOKE_IMAGE=$(grep -m1 '/actor-signer:' dist/release/release-images.txt)
        export SLUIS_SMOKE_IMAGE
        # The command-line tool of the release: its tarball, unpacked where the hand-off at the end of `up` and the smokes look
        # for it. The hand-off runs it (the real `sluis key request` and `key install` against key@ of the release's image).
        arch=$(go env GOARCH)
        mkdir -p dist/local/bin/cli
        tar -xzf "dist/release/sluis_2.0.0-alpha.0_linux_$arch.tar.gz" -C dist/local/bin/cli sluis
        deploy/local/local.sh up
        just local-smoke
        just local-person-smoke
        just local-handoff-check
    fi

# Sign the boards' config with the boards' own publisher key and make the seed that boards-deploy installs (the bootstrap
# file that pins the key, the credentials). The state is below .cache/boards and never committed.
boards-prepare:
    deploy/boards/prepare.sh

# Install rqlite on every board of SLUIS_BOARDS from the upstream release package (v10.6.6), pinned by sha256 in
# deploy/boards/rqlite.pins: apt-get install on Ubuntu, dnf install on Rocky. A drop-in of rqlited.service sets the board's HTTP and
# Raft addresses and, on every node, -bootstrap-expect N and -join with the Raft addresses of all N boards (SLUIS_BOARDS), so that a
# node without state never forms a cluster of its own; it starts all nodes, then waits until each is a ready voter and /nodes
# holds N nodes. The first step on a fresh board, before boards-deploy. No TLS and no authentication: see deploy/boards/rqlite.sh.
# SLUIS_BOARDS_DRY_RUN=1 prints the plan.
boards-rqlite:
    deploy/boards/rqlite.sh

# Copy the executables that exist in dist/arm64, with their units, to every board; verify; start in order. It refuses
# a seed that was signed before the header named the kind ("re-sign: just boards-prepare"); it does not sign by itself.
# Idempotent. SLUIS_BOARDS_DRY_RUN=1 stages and prints the plan without touching a board. SLUIS_BOARDS_PROFILE=m1 deploys the
# twelve units of the M1 spine. It ends with boards-avc.
boards-deploy:
    deploy/boards/boards.sh deploy

# Remove what boards-deploy added, as the board's manifest lists it, then stop and disable rqlited. The package, the drop-in and
# /var/lib/rqlite stay, and so does the state of the units, unless SLUIS_PURGE_STATE=1.
boards-undeploy:
    deploy/boards/boards.sh undeploy

# Give the PIN of the card to the card driver of ONE board: `SLUIS_BOARDS=<board> just boards-unlock` on a terminal asks for the PIN
# without echo; from a script, pipe it in from where it is kept. Either way the PIN is read from standard input and reaches `sudo
# /opt/sluis/bin/cli/sluis node unlock <host> --boundary dev` on the board through ssh's standard input; it is never an argument
# and never printed. The host key of the board must be known already: run `boards-status` for it once first, without the PIN.
boards-unlock:
    deploy/boards/boards.sh unlock

# Read only: on a board where SELinux is enforcing, the AVC and USER_AVC records since boot; it fails on an enforced denial in the
# domain of the units or the card service, of an executable of the deploy, or on a sluis or rqlite path, and when auditd is not
# recording. boards-deploy and boards-smoke run it at their end.
boards-avc:
    deploy/boards/boards.sh avc

# The M1 proof on every board of SLUIS_BOARDS in turn, over SSH (deploy/boards/smoke): a client under the uid of exchange asks
# policy for a token.exchange decision and signer for a token; the token is checked against /jwks of entry, the records of
# the run are found in the audit log, `sluis audit verify` checks the log, and SigningRing and DataKeyWrap are read through
# store@. From the second board on it must find the earlier boards' items, which shows the shared store. Run `just
# build-arm64` and `just boards-deploy` first. Exits non-zero on any failure, and when the AVC check that follows it (boards-avc)
# fails. CI builds it and does not run it.
boards-smoke:
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/arm64/smoke/spine ./tests/e2e/spine
    CGO_ENABLED=0 go build -trimpath -o dist/boardsmoke ./deploy/boards/smoke
    dist/boardsmoke && smoke=0 || smoke=$?; deploy/boards/boards.sh avc || smoke=1; exit "$smoke"

# Read only: the units of boards-deploy on every board, whether they are active, and rqlite (its unit, and whether its node is a ready
# voter), and whether the rqlite firewall is present and kept (boards-firewall); a board without it fails the run.
boards-status:
    deploy/boards/boards.sh status

# The peer-only firewall of rqlite (deploy/boards/firewall.sh, docs/runtimes/bare-metal.md "The rqlite firewall"): on ONE board named in
# SLUIS_FIREWALL_BOARDS (SLUIS_BOARDS stays all the boards, which are the peers), a table of its own that admits TCP 4002 from the
# loopback interface, the boards and SLUIS_FIREWALL_ADMIN_HOST (empty: no access for it), TCP 4001 from the loopback interface and the
# administration host alone, and drops both from everyone else; no other port, table or zone is touched. It loads the rules and arms a
# dead-man timer (SLUIS_FIREWALL_CONFIRM_SECONDS, 300) that takes them back; nothing is kept until boards-firewall-confirm.
# SLUIS_BOARDS_DRY_RUN=1 prints the exact rules and commands. No TLS and no authentication yet.
boards-firewall:
    deploy/boards/firewall.sh apply

# Prove, on the one board named, that ssh works, rqlite is a whole cluster (all voters, one leader), every other board reaches its Raft port and
# times out on its client port, and the administration host reaches both; only then keep the rules: the unit that loads them at boot, before rqlited, is started and enabled
# and the dead-man timer stopped. A failed proof keeps nothing.
boards-firewall-confirm:
    deploy/boards/firewall.sh confirm

# Take the rules back from the boards named (default all): no table, no unit, no timer, no file. Idempotent; the way out when a confirm does not
# pass and the timer is not awaited.
boards-firewall-remove:
    deploy/boards/firewall.sh remove

# Read only: the board check of REQ-DEPLOY-046. The rules are kept, the cluster is whole, the other boards and the administration host reach
# the ports they may, and a host that is not admitted (SLUIS_FIREWALL_OUTSIDE_HOST, or this workstation when no administration host is
# set) times out while the table's drop counter rises. With an administration host and no outside host there is no stranger: it fails, as not proven.
boards-firewall-check:
    deploy/boards/firewall.sh check

# Reboot ONE board (SLUIS_FIREWALL_BOARDS) and prove it comes back with the rules loaded before rqlited started, and a whole cluster, then
# run the check. With an administration host and no outside host it does not fail for the missing stranger: it says that half was not run.
# A card board comes back locked: boards-unlock it after.
boards-firewall-reboot-check:
    deploy/boards/firewall.sh reboot-check

# The hand-off of a board's intermediate, on the admin host (deploy/boards/handoff.sh; docs/runtimes/local.md, "A board's intermediate").
# `boards-handoff-root` makes the throwaway root for the boards' names, `boards-handoff-plan BOARD` prints the commands for the board
# run, `boards-handoff-certify BOARD` certifies the request of a board's card after checking its attestation. None of them touches a board.
boards-handoff-root:
    deploy/boards/handoff.sh root

boards-handoff-plan board:
    deploy/boards/handoff.sh plan {{ board }}

boards-handoff-certify board:
    deploy/boards/handoff.sh certify {{ board }}

# Read only: the id (RFC 7638 thumbprint) of the wrapping key of key@ on every board, by running its check, into the file that
# `boards-prepare` signs into the KeyPlan as the wrap recipients. The second step of the first deploy; see boards.sh.
boards-recipients:
    deploy/boards/boards.sh recipients

# Read only: key@'s own check on every board, printed as it is. It fails while a board's wrapping key is not in the KeyPlan or the
# wrap set is incomplete: the check after a switch of the key driver, before the next board; see boards.sh.
boards-key-check:
    deploy/boards/boards.sh check

# The local installation (docs/runtimes/local.md): Docker Compose on this workstation, every actor and driver as its
# pinned uid, config signed by the harness. Needs Docker, and SLUIS_UPSTREAM_TARGET and SLUIS_KEYCLOAK_SECRETS in the
# environment (the run.env of the build); the repository names neither. Run them as `devbox run -- just local-up`.

# Generate deploy/local/compose.yaml and init.sh from the registries. `go test ./tools/gen/compose` (part of go-test)
# fails while the committed files differ from what this makes.
compose-gen:
    go run ./tools/gen/compose

# Build the executables and the images, make the state of the run (harness CA, signed config, credentials) and start the
# project; it returns when every service that has a health check is healthy.
local-up: rust-toolchain rqlite-fetch
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

# The upstream identity provider for a run that signs people in: a Keycloak container with the realm of
# tests/installations/local/idp/realm.json (alice, with a password and a one-time password) and a secrets file of random
# values, for SLUIS_KEYCLOAK_SECRETS. `just local-idp .cache/idp.env`, then `SLUIS_KEYCLOAK_SECRETS=$PWD/.cache/idp.env`.
# It serves port 8180 (SLUIS_IDP_PORT); the container is `sluis-idp` (SLUIS_IDP_NAME), and `docker rm -f sluis-idp` removes it.
local-idp secrets:
    mkdir -p "$(dirname "{{ secrets }}")"
    tests/installations/local/idp/start.sh "{{ secrets }}"

# The smoke step of store@'s verification: with one signed document changed, store@ refuses to start. Needs `local-up`.
local-smoke-tamper:
    deploy/local/local.sh tamper

# The hand-off of the boundary's intermediate (docs/runtimes/local.md, "The first start"), which `local-up` ends with: the real
# `sluis key request` against key@, a throwaway root of the run certifies the request (tools/harness/certifier), the real
# `sluis key install` installs the answer. Run on its own it changes nothing once the intermediate is installed. Needs `local-up`.
local-handoff:
    deploy/local/local.sh handoff

# The proof that a second hand-off changes nothing: the request and the certificate keep their bytes, and `key install` says
# already-installed. Exits non-zero on any difference. Needs `local-up`. The job `smokes` of CI runs it.
local-handoff-check:
    deploy/local/local.sh handoff-check

# The proof that the published key set carries the chain: every key of /jwks has an x5c chain of the token certificate, the
# intermediate and the root, which verifies to the root of the hand-off (REQ-PKI-034). `local-up` runs it with a wait; this runs it
# once. Needs `local-up`. The job `smokes` of CI runs it through `local-up`.
local-keyset-check:
    deploy/local/local.sh keyset-check

# The Rust toolchain that rust-toolchain.toml pins (channel, components, targets), installed on its own and checked. Nothing
# else installs it: devbox.json sets RUSTUP_AUTO_INSTALL=0, so a `cargo` or `rustc` that finds no toolchain fails at once and
# starts no download. That setting is the fix of "detected conflict: 'bin/cargo-clippy'" (2026-11): the python package of devbox
# makes .venv on the first `devbox run` of a checkout, and pip runs `rustc --version` with a timeout of 0.5 s to put the
# compiler in its user agent. In this directory that `rustc` is rustup's, and rustup installed the pinned toolchain by itself;
# pip killed it half way, which left bin/cargo-clippy without rustup's record of it, and the next install said "downloading 4
# components" and failed (a new worktree, or a CI job that starts with .venv missing: about one in fifty jobs).
#
# It is safe to run at any time and in parallel: a complete toolchain is a check of a fraction of a second; one that is not
# complete is installed under a lock, by one process at a time; a half-made one (a killed install, an older checkout) is named,
# removed and made again, up to three times. A run that ends without cargo, clippy, rustfmt and every pinned target fails here
# and not later in a recipe. The recipes that run cargo depend on it.
#
# Install and check the pinned Rust toolchain (`devbox run -- just rust-toolchain`).
rust-toolchain:
    #!/usr/bin/env bash
    set -euo pipefail
    home=${RUSTUP_HOME:?RUSTUP_HOME is not set (run it as: devbox run -- just rust-toolchain)}
    channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
    [ -n "$channel" ] || { echo "::error::rust-toolchain.toml names no channel" >&2; exit 1; }
    targets=$(grep -o '[a-z0-9_]*-[a-z0-9_]*-[a-z0-9_-]*' <<<"$(sed -n 's/^targets *= *//p' rust-toolchain.toml)")
    [ -n "$targets" ] || { echo "::error::rust-toolchain.toml names no target; the check below would check nothing" >&2; exit 1; }
    export RUSTUP_AUTO_INSTALL=0
    # What a complete toolchain lacks, on one line; nothing when it is complete.
    missing() {
        local m="" installed t
        cargo --version >/dev/null 2>&1 || m="$m cargo"
        rustc --version >/dev/null 2>&1 || m="$m rustc"
        cargo clippy --version >/dev/null 2>&1 || m="$m clippy"
        cargo fmt --version >/dev/null 2>&1 || m="$m rustfmt"
        installed=$(rustup target list --installed 2>/dev/null || true)
        for t in $targets; do grep -qx "$t" <<<"$installed" || m="$m target:$t"; done
        echo "${m# }"
    }
    done_line() { echo "rust-toolchain: $(rustc --version), targets: $(echo $targets)"; }
    if [ -z "$(missing)" ]; then done_line; exit 0; fi
    # One installer at a time (mkdir is atomic and portable); a lock whose process is gone is stale.
    mkdir -p "$home"
    lock="$home/.install.lock"
    waited=0
    until mkdir "$lock" 2>/dev/null; do
        holder=$(cat "$lock/pid" 2>/dev/null || true)
        if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then rm -rf "$lock"; continue; fi
        [ "$waited" -lt 600 ] || { echo "::error::rust-toolchain: $lock has been held by pid ${holder:-?} for ten minutes; if no rust-toolchain runs, remove it" >&2; exit 1; }
        [ "$waited" -ne 0 ] || echo "rust-toolchain: waiting for the install that pid ${holder:-?} runs" >&2
        sleep 1
        waited=$((waited + 1))
    done
    echo $$ >"$lock/pid"
    trap 'rm -rf "$lock"' EXIT
    # The install we waited for may have finished the job.
    if [ -z "$(missing)" ]; then done_line; exit 0; fi
    for attempt in 1 2 3; do
        if ls -d "$home/toolchains/$channel"-* >/dev/null 2>&1; then
            echo "::warning::rust-toolchain: the toolchain $channel in $home is not complete (missing: $(missing)); a killed or interrupted install leaves it so. Removing it and installing again." >&2
            rm -rf "$home/toolchains/$channel"-* "$home/downloads" "$home/tmp" "$home/update-hashes"
        fi
        if rustup toolchain install && [ -z "$(missing)" ]; then
            done_line
            exit 0
        fi
        echo "::warning::rust-toolchain: attempt $attempt failed; the rustup, cargo and rustc processes now:" >&2
        ps -eo pid,etimes,args | grep -E '[r]ustup|[c]argo|[r]ustc' >&2 || echo "(none)" >&2
        sleep $((attempt * 3))
    done
    echo "::error::rust-toolchain: the toolchain $channel could not be installed in three attempts (still missing: $(missing)); remove $home and run it again" >&2
    exit 1

# The deny matrix (ADR 0002, "Enforcement is tested"): for every caller and every socket of the local installation,
# a probe as the caller's uid checks that the call graph is enforced at the socket and at the guard. It starts a Compose
# project of its own, sluis-deny, and removes it; a `local-up` project is left alone. Exit 1 on any violation.
local-deny: rust-toolchain
    tests/deny/run.sh

# The M1 proof against the running local installation (`just local-up` first): a client under the uid of exchange asks
# policy for a token.exchange decision and signer for a token; the token is checked against /jwks through the forwarder
# (trusting only the harness CA), the records of the run are found in the audit log, `sluis audit verify` checks the log,
# and SigningRing and DataKeyWrap are read through store@. Exits non-zero on any failure. Needs Docker. The job `smokes` of CI runs it.
local-smoke:
    CGO_ENABLED=0 go build -o dist/local/spine ./tests/e2e/spine
    SSL_CERT_FILE=.cache/local/ca/ca.pem dist/local/spine

# The smoke of the sluis command-line tool against the running local installation (`just local-up` first): the release build
# of the CLI runs `sluis doctor` on this host and as root in a container of the installation, and the output and the exit
# code are checked. It writes nothing. Exits non-zero on any failure. The job `smokes` of CI runs it.
local-cli-smoke:
    CGO_ENABLED=0 go build -o dist/local/cli-smoke ./tests/e2e/cli
    dist/local/cli-smoke

# The OpenID Foundation conformance suite against the running local installation (`just local-up` first, with the identity
# provider of `just local-idp`): the suite in containers, every image pinned by digest, alice signing in where it asks a person to,
# each module judged against tests/conformance/expected.yaml, then the gate of requirement tests. The first version runs the suite
# as a public client, which is not the certification profile (docs/standards/conformance.md). The workflow Conformance runs it.
local-conformance:
    tests/conformance/run.sh

# Search the audit log through the audit front of the running local installation (`just local-up` first): `just
# local-audit-search 'action:signer.sign since:2m'`. A word like key:value is a filter (action, status, actor, trace,
# record, project, tenant, since), any other word is free text; the tenant is the grant that is asked for, acme by default.
# The records appear a few seconds after the event: the writer seals every 5 s and the indexer follows.
local-audit-search *query:
    go run ./tools/harness/audit-search -ca .cache/local/ca/ca.pem {{ query }}

# The sign-in of `sluis login --issuer https://sluis.dev.local.test` for one user of the test identity provider (alice by
# default), headless: the harness fills in the identity provider's form and computes the TOTP code from the user's secret
# (SLUIS_KEYCLOAK_SECRETS), where a browser and an authenticator would. Prints what the CLI printed. Needs `local-up`.
local-login-headless user='alice':
    CGO_ENABLED=0 go build -o dist/local/person ./tests/e2e/person
    SSL_CERT_FILE=.cache/local/ca/ca.pem dist/local/person login {{ user }}

# The M2 proof against the running local installation (`just local-up` first): the CLI signs alice in through the forwarder,
# entry, session, the upstream adapter and the identity provider; `sluis token --audience example-app` has exchange
# do the RFC 8693 exchange. It prints the claims of the ID token (sub pairwise, acr and amr as the upstream gave them) and of
# the exchanged token (groups narrowed to the audience), checks both against /jwks, finds the records of every step in the
# audit log and runs `sluis audit verify` on it. Exits non-zero on any failure. Needs Docker. The job `smokes` of CI runs it.
local-person-smoke:
    CGO_ENABLED=0 go build -o dist/local/person ./tests/e2e/person
    SSL_CERT_FILE=.cache/local/ca/ca.pem dist/local/person smoke
