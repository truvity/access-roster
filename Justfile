# Development commands for access-roster. Tools come from devbox
# (`devbox shell`, or direnv); CI runs each recipe as its own job.

# Disable go.work (a parent workspace interferes with standalone module builds)
export GOWORK := "off"

charts := "access-issuer access-proxy"

# Format all Go files
fmt:
    golangci-lint fmt ./...

# Build (compile check)
build: fmt console cross
    go build ./...

# Compile accessctl for every platform the release builds it for.
#
# `go build ./...` proves the host platform and nothing else, so a call
# that does not exist elsewhere — syscall.Flock, which Windows has no
# equivalent name for — compiles here, passes CI, merges, and is first
# refused by goreleaser, with the change already on master and a version
# already burned on the tag (2026-09-22, v1.25.1).
#
# Only accessctl: it is the one binary .goreleaser.yaml builds for
# Windows, on the grounds that a laptop is a laptop. The rest are Linux
# and macOS, which `go build ./...` plus CI's own runner already cover.
cross:
    #!/usr/bin/env bash
    set -euo pipefail
    for target in windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
        GOOS="${target%%/*}" GOARCH="${target##*/}" go build -o /dev/null ./cmd/accessctl
    done

# Run unit tests
# `console` first, and the same on every recipe that COMPILES Go: CI
# runs each recipe as its own job in a fresh checkout, so nothing else
# has built the bundle the binary embeds. Locally this is invisible --
# `check` runs `build` first and the bundle is already there -- and in CI
# it is `pattern all:dist: no matching files found`, four jobs at once.
test: console
    go test ./... -coverprofile=coverage.out

# Run linters. `config verify` first: `run` accepts unknown top-level keys
# silently, so a settings block in the wrong place is otherwise invisible.
lint: console
    golangci-lint config verify
    golangci-lint run ./...
    # A `;` inside a mermaid sequenceDiagram is a STATEMENT SEPARATOR, not
    # punctuation: it splits the message text in half, the second half
    # parses as a statement with no arrow, and GitHub renders "Unable to
    # render rich display" in place of the whole diagram. Nothing in the
    # normal build reads these files, so the first reader to notice is
    # somebody looking at the documentation.
    ! grep -rn --include=*.md -E '^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*-?->>?.*;' docs/

# Run Go vulnerability check
vuln: console
    govulncheck ./...

# Regenerate gen/ from proto/ (buf + protoc-gen-go + protoc-gen-connect-go,
# all from devbox). Generated code is COMMITTED so the module is
# `go get`-able without buf installed.
generate:
    buf lint
    buf generate

# Acceptance against a real API server, in a throwaway kind cluster.
#
# Everything else runs against fakes, and the fakes are silent about the
# three things this checks: a real API server validates object names,
# refuses a create that raced another, and is the only thing that can
# answer a TokenReview — which is what recovery and the API listener's
# guard are built on.
acceptance: console
    kind create cluster --name access-roster-acceptance
    kubectl --context kind-access-roster-acceptance create namespace acceptance
    go run ./cmd/acceptance -namespace acceptance -kubeconfig ""
    kind delete cluster --name access-roster-acceptance

# Check the release configuration without cutting one.
# The release path, as far as it can be exercised without a tag.
#
# `goreleaser check` validates the config and `build --single-target`
# proves it compiles, but NEITHER reaches the archives stage — which is
# where v0.12.0 failed, four minutes into a tagged run, publishing
# nothing. So the archive shapes are checked here by reading the same
# file goreleaser reads.
release-check: console
    ./hack/check-archives.py
    goreleaser check
    goreleaser build --snapshot --clean --single-target

# The cheap half of release-check, for `check`: it reads a file and
# needs no compiler, so it costs nothing to run on every push.
archive-check:
    ./hack/check-archives.py

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Every Go symbol the documentation names must exist. Nothing compiles a
# code block in a Markdown file, so a rename leaves the old name in the
# guide and the first person to notice is a stranger following it.
docs-check:
    ./hack/check-docs-symbols.py

# Run go mod tidy
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -rf dist/ frontend/dist/ ts/dist/ coverage.out

# Lint both charts, compare their golden renders, and render every
# negative fixture.
#
# The schema is part of the lint: an unknown key must fail the render,
# not be silently ignored. Everything a schema cannot express -- a value
# the service cannot start without, a posture that admits nobody, one
# route described twice -- is refused by the chart's own render-time
# validation. Every rule of either kind has a fixture under
# tests/invalid/<chart>/ that must FAIL, and fail for the reason on its
# second line (`# error: ...`): a fixture that fails for some other
# reason proves nothing about its own rule.
#
# The golden renders (tests/cases -> tests/golden, `just golden` to
# regenerate) pin every byte of output. The checks after them are the
# properties a regenerated golden could lose without anyone noticing in
# review.
chart-lint:
    #!/usr/bin/env bash
    set -euo pipefail
    for chart in {{ charts }}; do
      # Bare first: the shipped values must satisfy their own schema, or
      # anyone who lints the chart as published gets a failure.
      helm lint "charts/$chart"
      helm lint "charts/$chart" -f "tests/cases/$chart/minimal/values.yaml"
      # `if`, not `!`: under `set -e` a negated command that fails does
      # not stop the script, so `! cmd` would check nothing.
      if helm template x "charts/$chart" --set bogusKey=1 >/dev/null 2>&1; then
        echo "$chart: an unknown key rendered" >&2
        exit 1
      fi
      for values in tests/invalid/"$chart"/*.yaml; do
        if err="$(helm template invalid "charts/$chart" -f "$values" 2>&1 >/dev/null)"; then
          echo "RENDERED BUT SHOULD HAVE FAILED: $values" >&2
          exit 1
        fi
        want="$(sed -n '2s/^# error: //p' "$values")"
        if [ -z "$want" ]; then
          echo "NO '# error:' LINE: $values" >&2
          exit 1
        fi
        if ! grep -qF -- "$want" <<<"$err"; then
          printf 'FAILED FOR ANOTHER REASON: %s\n  want: %s\n  got:  %s\n' "$values" "$want" "$err" >&2
          exit 1
        fi
      done
      # Every example the chart SHIPS must render on top of its own
      # minimal values. An example is something a reader copies, so one
      # that no longer renders is a broken instruction found by a
      # stranger; nothing else in this repository reads these files.
      for example in charts/"$chart"/examples/*.yaml; do
        [ -e "$example" ] || continue
        helm template x "charts/$chart" \
          -f "tests/cases/$chart/minimal/values.yaml" -f "$example" >/dev/null
      done
      echo "$chart: schema and $(ls tests/invalid/"$chart"/*.yaml | wc -l | tr -d ' ') negative fixtures OK"
    done
    hack/golden.sh
    # `push` is a chart-side instruction to External Secrets and not part
    # of an App's declaration: the service's loader refuses a key it does
    # not know, so an entry's push block reaching the rendered catalogue
    # would stop the service at start.
    if grep -n '^      push:' tests/golden/access-issuer/*.yaml; then
      echo "a catalogue entry's push block reached the rendered catalogue" >&2
      exit 1
    fi
    # "/console" and "/console/" are the same place: both spellings must
    # render the same, and never a route to "/console//".
    diff tests/golden/access-issuer/route.yaml tests/golden/access-issuer/route-trailing-slash.yaml
    if grep -l 'console//' tests/golden/access-issuer/*.yaml; then exit 1; fi
    # EVERY SecurityPolicy must ask Envoy for the session cookie. An HTTP
    # ext_authz service is sent only Host, Method, Path, Content-Length
    # and Authorization by default, and a policy missing `cookie` loops
    # forever through a login that succeeds and is never seen again.
    for golden in tests/golden/access-proxy/*.yaml; do
      test "$(grep -c '^kind: SecurityPolicy$' "$golden")" = "$(grep -c '^      - cookie$' "$golden")"
    done
    # Every backendRefs entry writes `weight` out. A desired/live
    # comparison normalises core-API defaults but not CRDs, so a field the
    # API server fills in is a permanent diff. Routes and policies alike.
    for golden in tests/golden/*/*.yaml; do
      test "$(yq ea '[.. | select(tag == "!!map" and has("backendRefs")) | .backendRefs[] | select(has("weight") | not)] | length' "$golden")" = "0"
    done
    # Every PushSecret dataTo entry carries its own storeRef. external-
    # secrets validates this with a CEL rule in the CRD, so nothing that
    # only RENDERS can see it: helm template, the values schema and the
    # golden diff all pass on a manifest the API server refuses outright
    # with "storeRef must specify either name or labelSelector". It
    # shipped that way once, and Argo retried the rejected task forever
    # while the resource simply never existed.
    for golden in tests/golden/*/*.yaml; do
      test "$(yq ea '[.. | select(tag == "!!map" and has("dataTo")) | .dataTo[] | select(has("storeRef") | not)] | length' "$golden")" = "0"
    done

# Regenerate the golden renders -- review the diff before committing.
golden:
    hack/golden.sh update

# Install every toolchain dependency, on both sides. Separate from the
# builds because `npm ci` is the slow part and it does not change
# between them.
#
# `tidy` first: downloading what go.mod asks for is not much use if
# go.mod is missing something the code imports, and the two together are
# what "my dependencies are in order" means.
#
# This does NOT touch gen/. Code generated from proto/ stays committed:
# it is Go source, small and diffable, and it is what makes the module
# `go get`-able without buf installed. That is a different argument from
# a minified bundle, which is neither small nor diffable.
deps: tidy
    go mod download
    cd ts && npm ci
    cd frontend && npm ci

# Build the TypeScript package into ts/dist.
#
# NOT committed, and FIRST: the console's package.json depends on it as
# `file:../ts`, and resolves through the root manifest's `main`, which
# points into ts/dist. Build the console before this and it resolves an
# import to a directory that is not there yet.
#
# The release builds it the same way and publishes the root package to
# GitHub Packages; nothing builds it on install.
ts-package: deps
    cd ts && npx tsc -p tsconfig.build.json

# Typecheck and test the TypeScript package.
ts: ts-package
    cd ts && npx tsc --noEmit && npx vitest run

# Build the console SPA into frontend/dist, which the Go binary embeds.
#
# NOT committed, and `build` depends on it so the embed always has
# something current to read. There is no drift check any more because
# drift is not possible: the bundle is produced from the lockfile every
# time, and if it is absent the compiler says so.
#
# The console's own unit tests run first: the pure models its pages read
# (which App needs you, what a page's first line says) and the router's
# moved addresses. They need no browser.
console: ts-package
    cd frontend && npm test
    cd frontend && npm run build

# The audit catalogue against the audit component's own toolchain, at the
# version go.mod pins: the document is valid, and every action the code
# emits is declared and every declared one emitted. A name built at run
# time is invisible to it, which is why every action is spelled once, in
# internal/audit/events.go.
audit-catalogue:
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(go list -m -f '{{{{.Version}}' github.com/truvity/audit)
    audit="go run github.com/truvity/audit/cmd/audit@${version}"
    $audit validate internal/audit/catalogue/roster.yaml
    # The Go code only: the console carries every action name in its
    # generated sentences, which would pass for emitting them.
    $audit check-emitters internal --catalogue internal/audit/catalogue/roster.yaml
    # The console's copy of the sentences is generated from the same
    # document, and a diff here is a catalogue changed without it.
    just audit-sentences
    git diff --exit-code -- frontend/src/auditSentences.ts

# The catalogue's sentences for the console's Audit page, generated from
# internal/audit/catalogue/roster.yaml by the audit component's toolchain.
audit-sentences:
    #!/usr/bin/env bash
    set -euo pipefail
    version=$(go list -m -f '{{{{.Version}}' github.com/truvity/audit)
    {
        echo '// Code generated by `just audit-sentences` from internal/audit/catalogue/roster.yaml. DO NOT EDIT.'
        echo 'import type { Sentences } from "@truvity/audit";'
        echo
        printf 'export const roster: Sentences = '
        go run "github.com/truvity/audit/cmd/audit@${version}" messages internal/audit/catalogue/roster.yaml
    } > frontend/src/auditSentences.ts

# Run all checks (build + test + lint + chart-lint + leak-canary + vuln)
# Everything CI runs, so that the pre-push hook catches what CI would.
#
# `ts` is in here despite being slow: it typechecks and tests the
# published package, which nothing else does. `console` arrives through
# `build`, which needs it.
check: build test lint chart-lint archive-check docs-check leak-canary audit-catalogue ts vuln
