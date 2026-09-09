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
    # A `;` inside a mermaid sequenceDiagram is a STATEMENT SEPARATOR, not
    # punctuation: it splits the message text in half, the second half
    # parses as a statement with no arrow, and GitHub renders "Unable to
    # render rich display" in place of the whole diagram. Nothing in the
    # normal build reads these files, so the first reader to notice is
    # somebody looking at the documentation.
    ! grep -rn --include=*.md -E '^[[:space:]]*[A-Za-z][A-Za-z0-9_]*[[:space:]]*-?->>?.*;' docs/

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
    # An exposed console renders TWO routes: the gated one, and the
    # bootstrap surface a gateway policy must not cover -- or the first
    # directory can never be connected from a browser.
    test "$(helm template directory-roster charts/directory-roster \
        --set route.host=console.example | grep -c '^kind: HTTPRoute')" = "2"
    test "$(helm template directory-roster charts/directory-roster \
        --set route.host=console.example --set 'route.bootstrapPaths=null' \
        | grep -c '^kind: HTTPRoute')" = "1"
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
    # EVERY policy must ask Envoy for the session cookie. An HTTP ext_authz
    # service is sent only Host, Method, Path, Content-Length and
    # Authorization by default, and a policy missing `cookie` loops
    # forever through a login that succeeds and is never seen again.
    helm template access-proxy charts/access-proxy -f hack/access-proxy-multiroute.yaml > /tmp/access-proxy-routes.yaml
    test "$(grep -c '^kind: SecurityPolicy$' /tmp/access-proxy-routes.yaml)" = "$(grep -c '^      - cookie$' /tmp/access-proxy-routes.yaml)"
    # Every backendRefs entry must write `weight` out. ArgoCD normalises
    # core-API defaults but NOT CRDs, so a field the API server fills in
    # is a PERMANENT OutOfSync -- which counts unhealthy and gates every
    # later wave. One `weight` per backend, in routes and policies alike.
    test "$(grep -c '^      backendRefs:$' /tmp/access-proxy-routes.yaml)" = "$(grep -c '^          weight: 1$' /tmp/access-proxy-routes.yaml)"
    # BOTH services read their policy file once, at start. A chart that
    # renders a policy ConfigMap and no checksum annotation is a chart
    # where a grant lands in git, in the ConfigMap and in ArgoCD's
    # "Synced" -- and never in the running service, until something
    # unrelated restarts it. Found live on 2026-09-09: the issuer had the
    # annotation, the hub did not, and the hub answered from the policy it
    # booted with for as long as its pods lived.
    test "$(helm template t charts/directory-roster --set 'policy.groups.g.members[0]=a@example.com' | grep -c 'checksum/policy:')" = "1"
    test "$(helm template t charts/access-issuer --set issuerURL=https://i.example --set hub.address=http://h.example:8080 --set 'policy.groups.g.members[0]=a@example.com' | grep -c 'checksum/policy:')" = "1"
    # Half a sign-out is worse than none: the proxy's cookie goes, the
    # issuer keeps the session, and the next click is admitted with no
    # password -- a failure that looks exactly like success. So asking for
    # the chain without the issuer it would end must fail the RENDER.
    ! helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true >/dev/null 2>&1
    helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true --set access.login.forwardedBearer.issuer=https://iss.example --set access.login.forwardedBearer.audience=console | grep -q 'end_session'

# Typecheck, test and build the TypeScript package. dist/ is COMMITTED so
# that `npm install github:truvity/access-roster#vX` needs no toolchain —
# the same reason frontend/dist is.
ts:
    cd ts && npm ci && npx tsc --noEmit && npx vitest run && npx tsc -p tsconfig.build.json
    # Committed for the same reason and drifts the same way: the package
    # is installed straight from a git tag, so what ships is whatever is
    # in the tree rather than whatever a build would produce.
    git diff --exit-code -- ts/dist
    git diff --cached --exit-code -- ts/dist
    test -z "$(git ls-files --others --exclude-standard ts/dist)"

# Rebuild the console SPA into frontend/dist (committed). Needs Node; CI
# does not run this, which is why dist/ is in the repository.
console:
    cd frontend && npm ci && npm run build
    # The bundle is COMMITTED, and the Go binary embeds it. So a build
    # that changes it and is not committed ships a console nobody's
    # package.json describes -- which is exactly what a dependency bump
    # does, because a bot edits package.json and package-lock.json and
    # has no way to rebuild what they produce. Found after react 19 went
    # in: the repository declared 19 and carried an 18 bundle.
    git diff --exit-code -- frontend/dist
    git diff --cached --exit-code -- frontend/dist
    test -z "$(git ls-files --others --exclude-standard frontend/dist)"

# Run all checks (build + test + lint + chart-lint + vuln)
check: build test lint chart-lint vuln
