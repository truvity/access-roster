# Go module `github.com/truvity/access-roster`

> **Not built yet, as of v0.9.x.** This page is the design of the package,
> written in the present tense because that is how the interface will
> read. What exists is the policy engine (`policy`) and the backend
> interface (`backend`); the verifiers below already exist as the hub's
> own code (`internal/server/forwarded.go`, `internal/verify`) and are
> lifted into the module, not rewritten. The shape follows
> [../design/trust.md](../design/trust.md): **exactly two verifiers**,
> one per anchor, and one `Identity` whichever proved the caller.


```go
import (
    "github.com/truvity/access-roster/identity"
    "github.com/truvity/access-roster/identity/httpmw"
    "github.com/truvity/access-roster/authz"
    "github.com/truvity/access-roster/directory"
    "github.com/truvity/access-roster/policy"
    "github.com/truvity/access-roster/tokens"
)
```

## A console behind access-proxy — the issuer anchor

```go
verifier, _ := identity.NewIssuerVerifier(ctx, identity.IssuerConfig{
    Issuer:   "https://issuer.example.internal",
    Audience: "roster.example.internal", // this console's client id at the issuer
})
mux := http.NewServeMux()
mux.Handle("/", httpmw.Require(verifier)(app))       // sets Identity in context, serves /.access/whoami
mux.Handle("/admin/", httpmw.Require(verifier, authz.Role("operator"))(admin))
```

Fiber v3: `fibermw.Require(verifier)`. gRPC: `grpcmw.Unary(verifier)`,
`grpcmw.Stream(verifier)`. connect: `connectmw.Interceptor(verifier)`.
Handlers read `identity.FromContext(ctx)`.

## A service on the cluster network — the cluster anchor

Server side, admitting ServiceAccount tokens from workloads in this
cluster:

```go
cluster, _ := identity.NewClusterVerifier(ctx, identity.ClusterConfig{
    Audience: "directory-roster",
    Allow:    []identity.ServiceAccountRef{{Namespace: "identity-system", Name: "authorization-webhook"}},
})
mux.Handle("/directory.v1.DirectoryService/", connectmw.Interceptor(cluster).Wrap(handler))
```

When the same listener must also admit callers from further away —
another cluster, a laptop — give the interceptor both verifiers. The
handler sees one `Identity` either way, and keys any grant of its own by
the principal, never by which verifier answered:

```go
mux.Handle("/directory.v1.DirectoryService/", connectmw.Interceptor(cluster, verifier).Wrap(handler))
```

There is no third verifier. The worked example, with the decision of
which anchor a caller presents, is
[../connect/service-to-service.md](../connect/service-to-service.md).

Client side, calling the hub as yourself:

```go
src := tokens.ServiceAccountSource("/var/run/secrets/directory-roster/token") // projected, refreshing
dir := directory.New("http://directory-roster.directory-roster.svc:8080", src)
live, authoritative, err := dir.Live(ctx, "alice@example.com", directory.MaxAge(10*time.Minute))
if authoritative && !live { /* remove */ }
```

## Exchange for an audience

```go
tok, err := tokens.Exchange(ctx, issuerURL, subjectToken, "aws:111122223333:power")
```

## Policy

```go
declared, _ := policy.LoadDeclared("/etc/access-roster/policy")  // a file or a directory
set, _ := policy.NewSet(declared)                                 // validated once, at load
_ = set.SetConsole(consoleMemberships)                            // the second layer

result := set.Evaluate(policy.Input{
    Email:           "alice@example.com",
    DirectoryGroups: groups,   // what the hub confirmed
    Authoritative:   true,     // membership grants nothing without it
})
result.Has("all:access-roster:operator")  // the internal groups held, <scope>:<thing>:<role>
result.Claims                // the deep-merged fragments
result.Lifetime              // shortest across the held groups
```

Full API on pkg.go.dev once tagged.
