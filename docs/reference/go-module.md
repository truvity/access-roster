# Go module `github.com/truvity/access-roster`

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

## A console behind access-proxy

```go
verifier, _ := identity.NewBearerVerifier(ctx, identity.Config{
    Issuer:   "https://issuer.example.internal",
    Audience: "roster.example.internal", // the exposure's hostname
})
mux := http.NewServeMux()
mux.Handle("/", httpmw.Require(verifier)(app))       // sets Identity in context, serves /.access/whoami
mux.Handle("/admin/", httpmw.Require(verifier, authz.Role("operator"))(admin))
```

Fiber v3: `fibermw.Require(verifier)`. gRPC: `grpcmw.Unary(verifier)`,
`grpcmw.Stream(verifier)`. connect: `connectmw.Interceptor(verifier)`.
Handlers read `identity.FromContext(ctx)`.

## A service on the cluster network

Server side, admitting ServiceAccount tokens:

```go
sa, _ := identity.NewServiceAccountVerifier(ctx, identity.ServiceAccountConfig{
    Audience: "directory-roster",
    Allow:    []identity.ServiceAccountRef{{Namespace: "identity-system", Name: "authorization-webhook"}},
})
mux.Handle("/directory.v1.DirectoryService/", connectmw.Interceptor(sa).Wrap(handler))
```

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
result.Has("hub-operators")  // the internal groups held
result.Claims                // the deep-merged fragments
result.Lifetime              // shortest across the held groups
```

Full API on pkg.go.dev once tagged.
