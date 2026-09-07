# Development commands for directory-roster. Tools come from devbox
# (`devbox shell`, or direnv); CI runs each recipe as its own job.

# Disable go.work (a parent workspace interferes with standalone module builds)
export GOWORK := "off"

# Format all Go files
fmt:
    golangci-lint fmt ./...

# Build (compile check)
build: fmt
    go build ./...

# Run unit tests
test:
    go test ./... -coverprofile=coverage.out

# Run linters. `config verify` first: `run` accepts unknown top-level keys
# silently, so a settings block in the wrong place is otherwise invisible.
lint:
    golangci-lint config verify
    golangci-lint run ./...

# Run Go vulnerability check
vuln:
    govulncheck ./...

# Regenerate gen/ from proto/ (buf + protoc-gen-go + protoc-gen-connect-go,
# all from devbox). Generated code is COMMITTED so the module is
# `go get`-able without buf installed.
generate:
    buf lint
    buf generate

# Run go mod tidy
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -rf dist/ coverage.out

# Render the chart with the shipped values plus a fully-featured set;
# prove the schema rejects an unknown key (values.schema.json is the
# contract — a typo must fail the render, not be silently ignored).
chart-lint:
    helm lint charts/directory-roster
    helm template directory-roster charts/directory-roster >/dev/null
    helm template directory-roster charts/directory-roster \
        --set valkey.address=valkey.example.svc:6379 \
        --set networkPolicy.enabled=true \
        --set 'workspaces[0].id=C0example' \
        --set 'workspaces[0].backend=google' \
        --set 'workspaces[0].admin=admin@example.com' \
        --set 'workspaces[0].secretName=example-sa-key' \
        --set 'consumers[0].namespace=example-ns' \
        --set 'consumers[0].serviceAccount=example-sa' \
        --set 'access.rules[0].id=admins' \
        --set 'access.rules[0].role=operator' \
        --set 'access.rules[0].directoryGroup.group=platform-admins@example.com' >/dev/null
    ! helm template directory-roster charts/directory-roster --set bogusKey=1 >/dev/null 2>&1

# Rebuild the console SPA into frontend/dist (committed). Needs Node; CI
# does not run this, which is why dist/ is in the repository.
console:
    cd frontend && npm ci && npm run build

# Run all checks (build + test + lint + chart-lint + vuln)
check: build test lint chart-lint vuln
