# Development commands for directory-roster. Tools come from devbox
# (`devbox shell`, or direnv); CI runs each recipe as its own job.

# Disable go.work (a parent workspace interferes with standalone module builds)
export GOWORK := "off"

# Format all Go files
fmt:
    golangci-lint fmt ./...

# Build (compile check)
build: fmt console
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
# The release path, as far as it can be exercised without a tag.
#
# `goreleaser check` validates the config and `build --single-target`
# proves it compiles, but NEITHER reaches the archives stage — which is
# where v0.12.0 failed, four minutes into a tagged run, publishing
# nothing. So the archive shapes are checked here by reading the same
# file goreleaser reads.
release-check:
    ./hack/check-archives.py
    goreleaser check
    goreleaser build --snapshot --clean --single-target

# The cheap half of release-check, for `check`: it reads a file and
# needs no compiler, so it costs nothing to run on every push.
archive-check:
    ./hack/check-archives.py

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
    # route.pathPrefix (INF-687): empty is today's shape exactly -- no
    # URLRewrite filter anywhere, and the console matches "/" same as
    # before.
    helm template directory-roster charts/directory-roster \
        --set route.host=console.example > /tmp/directory-roster-noprefix.yaml
    ! grep -q 'type: URLRewrite' /tmp/directory-roster-noprefix.yaml
    ! grep -q 'PUBLIC_ROOT_URL' /tmp/directory-roster-noprefix.yaml
    grep -q 'value: /$' /tmp/directory-roster-noprefix.yaml
    # Set, ONLY the console's own route gains the filter that strips it.
    # The bootstrap surface -- /login, /connect -- keeps matching the
    # host's ROOT with NO rewrite: their OAuth redirect URIs are
    # registered with the provider at that literal, unprefixed address
    # (the real Google client registered exactly
    # https://.../connect/google/callback at the root), and a prefixed
    # bootstrap route would render fine and fail only the first time
    # somebody connects a directory. PUBLIC_URL, the console's own
    # address, carries the prefix; PUBLIC_ROOT_URL, printed in the setup
    # steps for the bootstrap redirects, does not.
    helm template directory-roster charts/directory-roster \
        --set route.host=console.example --set route.pathPrefix=/console \
        > /tmp/directory-roster-prefix.yaml
    test "$(grep -c 'type: URLRewrite' /tmp/directory-roster-prefix.yaml)" = "1"
    test "$(grep -c 'replacePrefixMatch: /$' /tmp/directory-roster-prefix.yaml)" = "1"
    grep -q 'value: /console/$' /tmp/directory-roster-prefix.yaml
    grep -q 'value: "/login"' /tmp/directory-roster-prefix.yaml
    grep -q 'value: "/connect"' /tmp/directory-roster-prefix.yaml
    ! grep -q '/console/login\|/console/connect' /tmp/directory-roster-prefix.yaml
    grep -q 'value: https://console.example/console$' /tmp/directory-roster-prefix.yaml
    grep -q 'PUBLIC_ROOT_URL' /tmp/directory-roster-prefix.yaml
    grep -q 'value: https://console.example$' /tmp/directory-roster-prefix.yaml
    # A trailing slash or a bare "/" is not a path prefix worth having --
    # it is either what empty already means or a double slash away from
    # one, and the schema is the contract: a typo here must fail the
    # RENDER, not be discovered as a 404 behind the gateway.
    ! helm template directory-roster charts/directory-roster \
        --set route.host=console.example --set route.pathPrefix=/console/ >/dev/null 2>&1
    ! helm template directory-roster charts/directory-roster \
        --set route.host=console.example --set route.pathPrefix=/ >/dev/null 2>&1
    # route.gateway (INF-687): the other half of pathPrefix. Unset, this
    # chart still owns exactly one Gateway (and one Certificate) as
    # today. Set, it owns NEITHER -- two Gateways declaring a listener
    # for the same route.host is a duplicate-listener collision, not two
    # independent routes -- and both HTTPRoutes' parentRefs point at the
    # named one instead, across namespaces.
    helm template directory-roster charts/directory-roster \
        --set route.host=console.example > /tmp/directory-roster-owngw.yaml
    test "$(grep -c '^kind: Gateway$' /tmp/directory-roster-owngw.yaml)" = "1"
    test "$(grep -c '^kind: Certificate$' /tmp/directory-roster-owngw.yaml)" = "1"
    helm template directory-roster charts/directory-roster \
        --set route.host=console.example \
        --set route.gateway.name=access-issuer --set route.gateway.namespace=issuer-ns --set route.gateway.sectionName=issuer \
        > /tmp/directory-roster-attach.yaml
    test "$(grep -c '^kind: Gateway$' /tmp/directory-roster-attach.yaml)" = "0"
    test "$(grep -c '^kind: Certificate$' /tmp/directory-roster-attach.yaml)" = "0"
    test "$(grep -c '      name: access-issuer$' /tmp/directory-roster-attach.yaml)" = "2"
    test "$(grep -c '      namespace: issuer-ns$' /tmp/directory-roster-attach.yaml)" = "2"
    # A Gateway in another namespace with no namespace given is a render
    # that looks fine and a parentRef that resolves inside THIS chart's
    # own namespace instead -- silently attaching to nothing, or to
    # something else entirely that happens to share the name.
    ! helm template directory-roster charts/directory-roster \
        --set route.host=console.example --set route.gateway.name=access-issuer >/dev/null 2>&1
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
        --set issuerURL=https://issuer.example
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example >/dev/null
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set route.host=issuer.example \
        --set networkPolicy.enabled=true \
        --set 'networkPolicy.clients[0]=example-ns' \
        --set oauthClient.secret.name=oauth-client \
        --set signingKey.existingSecret=delivered-by-eso \
        --set valkey.address=valkey.example.svc:6379 \
        --set 'policy.groups.platform.members[0]=platform@example.com' >/dev/null
    # One service (INF-691). The chart used to render an issuer that
    # dialled a hub; it now renders the whole of access-roster. Three
    # things have to be true of that render, and each of them was a way
    # the split could come back by accident:
    #
    #   - nothing dials a hub any more, and no ServiceAccount token is
    #     projected for one;
    #   - the directory's own store is wired, so an operator's connected
    #     workspaces survive a restart;
    #   - the console is told where it sits, because the prefix the
    #     gateway used to strip is also what every link the console hands
    #     a browser has to carry.
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example \
        --set route.host=access.example \
        --set 'directory.workspaces[0].backend=google' \
        --set 'directory.workspaces[0].admin=admin@example.com' \
        --set 'directory.workspaces[0].secretName=example-key' \
        > /tmp/access-issuer-merged.yaml
    ! grep -q 'HUB_ADDRESS\|HUB_TOKEN_FILE\|hub-token' /tmp/access-issuer-merged.yaml
    grep -q 'name: STORE' /tmp/access-issuer-merged.yaml
    grep -q 'value: https://access.example/console$' /tmp/access-issuer-merged.yaml
    grep -q 'value: https://access.example$' /tmp/access-issuer-merged.yaml
    grep -q 'name: OVERLAY_FILE' /tmp/access-issuer-merged.yaml
    grep -q 'secretName: example-key' /tmp/access-issuer-merged.yaml
    # "/console" and "/console/" are the same place, and the chart used
    # to render the second as a route to "/console//" -- a path the
    # console does not serve, from a value nothing rejects. Our own
    # configuration writes it both ways, so both must render the same.
    for mount in /console /console/; do \
        helm template access-issuer charts/access-issuer \
            --set issuerURL=https://access.example \
            --set route.host=access.example \
            --set console.mount="$mount" \
            --set console.client=directory-console \
            > "/tmp/access-issuer-mount$(echo "$mount" | tr / -).yaml"; \
    done
    diff /tmp/access-issuer-mount-console.yaml /tmp/access-issuer-mount-console-.yaml
    ! grep -q 'console//' /tmp/access-issuer-mount-console-.yaml
    # The namespaced Role comes with the Kubernetes store and only with
    # it: a deployment keeping nothing needs no permission to write.
    test "$(grep -c '^kind: Role$' /tmp/access-issuer-merged.yaml)" = "1"
    test "$(helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set directory.store=memory \
        | grep -c '^kind: Role$')" = "0"
    # The console is not mounted without a mount, and PUBLIC_URL then has
    # nothing to say.
    ! helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set route.host=access.example \
        --set console.mount= | grep -q 'PUBLIC_URL'

    # The console gets its own HTTPRoute, and that is not tidiness: a
    # gateway policy attaches to a ROUTE, so anything put in front of the
    # console on a shared route would also sit in front of /token, /keys
    # and discovery -- every relying party in the estate asked to sign in
    # to fetch a key set. It renders whether or not anything attaches to
    # it, because discovering at cutover that there is nothing to attach
    # to leaves only the bad option.
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set route.host=access.example \
        > /tmp/access-issuer-console-route.yaml
    test "$(grep -c '^kind: HTTPRoute$' /tmp/access-issuer-console-route.yaml)" = "2"
    grep -q 'name: access-issuer-console$' /tmp/access-issuer-console-route.yaml
    grep -q 'value: "/console/"' /tmp/access-issuer-console-route.yaml
    # The prefix is NOT rewritten away: the service strips it itself, so a
    # gateway that stripped it too would hand the console a path it never
    # serves.
    ! grep -q 'ReplacePrefixMatch' /tmp/access-issuer-console-route.yaml
    # No console, no second route.
    test "$(helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set route.host=access.example \
        --set console.mount= | grep -c '^kind: HTTPRoute$')" = "1"

    # The console signs people in as a CLIENT of the issuer (INF-701),
    # which is what makes one binary mean one door. No client declared,
    # no entry -- and then the console keeps a sign-in page of its own,
    # which in a deployment with an issuer beside it is a second door.
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set console.client=directory-console \
        | grep -q 'CONSOLE_CLIENT_ID'
    ! helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example | grep -q 'CONSOLE_CLIENT_ID'

    # Federated clusters (INF-692). No row is a secret, and the point of
    # the render is that the service ends up holding no cluster access at
    # all: IN_CLUSTER is recovery's, never a workload's.
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example \
        --set 'exchange.clusters[0].name=devel' \
        --set 'exchange.clusters[0].issuer=https://oidc.eks.example/id/ABC' \
        > /tmp/access-issuer-federated.yaml
    grep -q 'name: CLUSTERS_FILE' /tmp/access-issuer-federated.yaml
    grep -q 'checksum/clusters:' /tmp/access-issuer-federated.yaml
    grep -q 'issuer: "https://oidc.eks.example/id/ABC"' /tmp/access-issuer-federated.yaml
    # No cluster declared, no file and no ConfigMap: a mount of nothing is
    # a pod that will not start.
    ! helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example | grep -q 'CLUSTERS_FILE'
    # The TokenReview permission belongs to recovery and to nothing else.
    test "$(helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set recovery.enabled=false \
        | grep -c 'tokenreviews')" = "0"
    test "$(helm template access-issuer charts/access-issuer \
        --set issuerURL=https://access.example --set recovery.enabled=false \
        | grep -c 'name: IN_CLUSTER')" = "0"

    # route.sharedWith (INF-687): the other half of the console's
    # pathPrefix. Empty keeps `from: Same`; naming a namespace renders a
    # Selector over it AND this issuer's own -- dropping its own would
    # lock this chart's own HTTPRoute out of the Gateway it just rendered.
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set route.host=issuer.example --namespace issuer-ns \
        > /tmp/access-issuer-noshare.yaml
    grep -q 'from: Same' /tmp/access-issuer-noshare.yaml
    ! grep -q 'from: Selector' /tmp/access-issuer-noshare.yaml
    helm template access-issuer charts/access-issuer \
        --set issuerURL=https://issuer.example \
        --set route.host=issuer.example --set 'route.sharedWith[0]=hub-ns' --namespace issuer-ns \
        > /tmp/access-issuer-shared.yaml
    grep -q 'from: Selector' /tmp/access-issuer-shared.yaml
    ! grep -q 'from: Same' /tmp/access-issuer-shared.yaml
    grep -q '"hub-ns"' /tmp/access-issuer-shared.yaml
    grep -q '"issuer-ns"' /tmp/access-issuer-shared.yaml
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
    test "$(helm template t charts/access-issuer --set issuerURL=https://i.example --set 'policy.groups.g.members[0]=a@example.com' | grep -c 'checksum/policy:')" = "1"
    # Half a sign-out is worse than none: the proxy's cookie goes, the
    # issuer keeps the session, and the next click is admitted with no
    # password -- a failure that looks exactly like success. So asking for
    # the chain without the issuer it would end must fail the RENDER.
    ! helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true >/dev/null 2>&1
    helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true --set access.login.forwardedBearer.issuer=https://iss.example --set access.login.forwardedBearer.audience=console | grep -q 'end_session'
    # And it must carry client_id. There is no id_token_hint in a plain
    # `rd` redirect, so without a client the issuer has no `signed_out`
    # list to match: it ends the session and lands the person on its OWN
    # page. Verified live on 2026-09-09 -- the first render did exactly
    # that.
    helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true --set access.login.forwardedBearer.issuer=https://iss.example --set access.login.forwardedBearer.audience=console | grep -q 'client_id'
    ! helm template t charts/directory-roster --set route.host=dir.example --set access.signOutThroughIssuer=true --set access.login.forwardedBearer.issuer=https://iss.example >/dev/null 2>&1
    # The console's assets are referenced RELATIVELY so one committed
    # bundle serves at any mount point -- which only works on a page
    # reached WITH the trailing slash, because "./assets/..." at
    # "/console" resolves against the root and asks the issuer. So the
    # bare prefix must redirect to itself with the slash, and an Exact
    # match is what outranks the PathPrefix rule.
    helm template t charts/directory-roster --set route.host=a.example \
        --set route.pathPrefix=/console \
        --set route.gateway.name=iss --set route.gateway.namespace=iss \
        > /tmp/dr-prefix-redirect.yaml
    grep -q 'type: Exact' /tmp/dr-prefix-redirect.yaml
    grep -q 'replaceFullPath: "/console/"' /tmp/dr-prefix-redirect.yaml
    # And with no prefix there is nothing to redirect.
    ! helm template t charts/directory-roster --set route.host=dir.example \
        | grep -q 'RequestRedirect'
    # The issuer's root: a bare GET of the host lands somewhere useful
    # when a console shares it, and 404s honestly when one does not.
    helm template t charts/access-issuer --set issuerURL=https://a.example \
        --set route.host=a.example \
        --set route.rootRedirect=/console/ | grep -q 'replaceFullPath: "/console/"'
    # Said with console.mount emptied, because the console's own route
    # always redirects its bare prefix to the trailing slash — a different
    # rule on a different object, and not the root redirect under test.
    ! helm template t charts/access-issuer --set issuerURL=https://a.example \
        --set route.host=a.example --set console.mount= \
        | grep -q 'RequestRedirect'
    # Under a path prefix the WHOLE sign-out chain moves with the
    # console, and both halves are the kind that fail silently. The
    # proxy's own paths are under the prefix -- /oauth2 at the root
    # belongs to the issuer -- so a link to the root's /oauth2/sign_out
    # is a button that 404s. And post_logout_redirect_uri must be the
    # console's page under the prefix, matching the client's `signed_out`
    # character for character, or the issuer ends the session and lands
    # the person on its OWN page: a sign-out that worked and reads as
    # though it did not.
    helm template t charts/directory-roster --set route.host=access.example         --set route.pathPrefix=/console         --set route.gateway.name=iss --set route.gateway.namespace=iss         --set access.signOutThroughIssuer=true         --set access.login.forwardedBearer.issuer=https://access.example         --set access.login.forwardedBearer.audience=console         | grep -q '"/console/oauth2/sign_out'
    helm template t charts/directory-roster --set route.host=access.example         --set route.pathPrefix=/console         --set route.gateway.name=iss --set route.gateway.namespace=iss         --set access.signOutThroughIssuer=true         --set access.login.forwardedBearer.issuer=https://access.example         --set access.login.forwardedBearer.audience=console         | grep -q 'post_logout_redirect_uri%3Dhttps%253A%252F%252Faccess.example%252Fconsole%252F'
    # And with no prefix it is exactly what it has always been.
    helm template t charts/directory-roster --set route.host=dir.example         --set access.signOutThroughIssuer=true         --set access.login.forwardedBearer.issuer=https://iss.example         --set access.login.forwardedBearer.audience=console         | grep -q '"/oauth2/sign_out'
    # CI identity is opt-in by naming the organisations. A chart that
    # rendered GITHUB_OWNERS from nothing would admit every repository on
    # GitHub, because anybody may run a workflow in their own and get a
    # valid token: the verifier refuses to run without the list, and the
    # chart must not invent one.
    ! helm template t charts/access-issuer --set issuerURL=https://iss.example | grep -q GITHUB_OWNERS
    helm template t charts/access-issuer --set issuerURL=https://iss.example --set 'github.owners={truvity}' | grep -q GITHUB_OWNERS

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
# A git install builds it through the `prepare` script in the root
# package.json, which npm runs for a git dependency after installing
# devDependencies -- so the toolchain the committed copy existed to
# avoid needing is there anyway, at the one moment it matters.
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
console: ts-package
    cd frontend && npm run build

# Run all checks (build + test + lint + chart-lint + vuln)
# Everything CI runs, so that the pre-push hook catches what CI would.
#
# `ts` is in here despite being slow: it typechecks and tests the
# published package, which nothing else does. `console` arrives through
# `build`, which needs it.
check: build test lint chart-lint archive-check docs-check ts vuln
