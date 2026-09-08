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

# Acceptance against a real API server, in a throwaway kind cluster.
#
# Everything else runs against fakes, and the fakes are silent about the
# three things this checks: a real API server validates object names,
# refuses a create that raced another, and is the only thing that can
# answer a TokenReview — which is what recovery and the API listener's
# guard are built on.
acceptance:
    kind create cluster --name access-roster-acceptance
    kubectl --context kind-access-roster-acceptance create namespace acceptance
    go run ./cmd/acceptance -namespace acceptance -kubeconfig ""
    kind delete cluster --name access-roster-acceptance

# Check the release configuration without cutting one.
release-check:
    goreleaser check
    goreleaser build --snapshot --clean --single-target

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
        --set 'policy.version=1' \
        --set 'policy.groups.hub-operators.members[0]=platform-admins@example.com' >/dev/null
    ! helm template directory-roster charts/directory-roster --set bogusKey=1 >/dev/null 2>&1
    # A forwarded issuer without an audience accepts every token that
    # issuer mints, for every service it serves. That must fail the
    # RENDER, not be discovered in the console's logs.
    ! helm template directory-roster charts/directory-roster \
        --set access.login.forwardedBearer.issuer=https://issuer.example >/dev/null 2>&1
    helm template directory-roster charts/directory-roster \
        --set access.login.forwardedBearer.issuer=https://issuer.example \
        --set access.login.forwardedBearer.audience=directory-console >/dev/null
    # Bare first: the shipped values must satisfy their own schema, or
    # anyone who lints the chart as published gets a failure.
    helm lint charts/access-issuer
    helm lint charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set hub.address=http://directory-roster.example.svc:8080
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set hub.address=http://directory-roster.example.svc:8080 >/dev/null
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set hub.address=http://directory-roster.example.svc:8080 \
        --set route.host=issuer.example \
        --set networkPolicy.enabled=true \
        --set 'networkPolicy.clients[0]=example-ns' \
        --set oauthClient.secret.name=oauth-client \
        --set signingKey.existingSecret=delivered-by-eso \
        --set valkey.address=valkey.example.svc:6379 \
        --set 'policy.groups.platform.members[0]=platform@example.com' >/dev/null
    ! helm template access-issuer charts/access-issuer --set bogusKey=1 >/dev/null 2>&1
    # The two settings without which the service refuses to start must
    # fail the render too, not the pod.
    ! helm template access-issuer charts/access-issuer >/dev/null 2>&1

    # access-proxy: the shipped values must satisfy their own schema, and
    # every guard that exists to stop a working-looking install that locks
    # everyone out must fail the RENDER.
    helm lint charts/access-proxy
    helm template access-proxy charts/access-proxy \
        --set exposure.hostname=console.example \
        --set exposure.gateway.name=internal --set exposure.gateway.namespace=envoy-gateway-system \
        --set exposure.posture=authenticated --set exposure.attachRouteName=console \
        --set issuer.url=https://issuer.example --set client.secret.name=client \
        --set session.cookieSecret.name=cookie --set session.valkey.address=valkey.example.svc:6379 >/dev/null
    # `groups` with an empty allow-list renders a policy that admits
    # NOBODY. `required` does not catch an empty list.
    ! helm template access-proxy charts/access-proxy \
        --set exposure.hostname=console.example \
        --set exposure.gateway.name=internal --set exposure.gateway.namespace=envoy-gateway-system \
        --set exposure.backend.name=console \
        --set issuer.url=https://issuer.example --set client.secret.name=client \
        --set session.cookieSecret.name=cookie --set session.valkey.address=valkey.example.svc:6379 >/dev/null 2>&1
    ! helm template access-proxy charts/access-proxy --set bogusKey=1 >/dev/null 2>&1
    # Several protected routes on one host, each attaching to a route
    # something else owns -- the shape a business surface needs, where a
    # demo path is open to any employee and the app behind it is not.
    helm template access-proxy charts/access-proxy -f hack/access-proxy-multiroute.yaml >/dev/null
    # Describing one route twice, once with the single-route fields and
    # once in the list, silently ignores one of them -- and the ignored
    # one would be the protection somebody thought they configured.
    ! helm template access-proxy charts/access-proxy -f hack/access-proxy-multiroute.yaml \
        --set exposure.backend.name=app >/dev/null 2>&1

# Typecheck, test and build the TypeScript package. dist/ is COMMITTED so
# that `npm install github:truvity/access-roster#vX` needs no toolchain —
# the same reason frontend/dist is.
ts:
    cd ts && npm ci && npx tsc --noEmit && npx vitest run && npx tsc -p tsconfig.build.json

# Rebuild the console SPA into frontend/dist (committed). Needs Node; CI
# does not run this, which is why dist/ is in the repository.
console:
    cd frontend && npm ci && npm run build

# Run all checks (build + test + lint + chart-lint + vuln)
check: build test lint chart-lint vuln
