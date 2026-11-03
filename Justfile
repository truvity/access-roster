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

# The actor registry, docs/architecture/actors.yaml, against the ADRs that name actors, the
# architecture explorer's data, the requirement records' `actors:` and the generated tables on
# docs/reference/actors.md. Each actor has the GitHub label `actor:<name>` that the registry lists.
check-actors: site-install
    tools/checks/actors.mjs

# Rewrite the generated tables on docs/reference/actors.md from the registry.
actors-write: site-install
    tools/checks/actors.mjs --write

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
check-rules: check-selftest check-decisions check-requirements check-actors check-examples check-installations check-public check-yaml-ext check-mdx-pages check-agent-links

# Everything a pull request must pass.
check: check-rules site-check site-workers
