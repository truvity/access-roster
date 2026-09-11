# Go module `github.com/truvity/access-roster`

What a Go service behind the gateway imports. The shape follows
[../design/trust.md](../design/trust.md): **exactly two verifiers**, one
per anchor, and one `Verified` whichever proved the caller — so a handler
never learns which anchor answered and cannot come to depend on it.

access-roster uses this itself rather than keeping a copy. A library its
own author does not use is a library nobody has tested against a real
listener.

```go
import (
    "github.com/truvity/access-roster/identity"
    "github.com/truvity/access-roster/policy"
    "github.com/truvity/access-roster/tokens"
)
```

## A console behind access-proxy — the issuer anchor

```go
issuer := &identity.Issuer{
    URL:      "https://access.example",
    Audience: "roster.example",   // this console's client id at the issuer
}

mux := http.NewServeMux()
mux.Handle(identity.WhoAmIPath, identity.WhoAmI(version))
mux.Handle("/admin/", identity.Require("all:roster:operator")(admin))

http.ListenAndServe(":8080", identity.Middleware(issuer)(mux))
```

**A struct rather than a constructor, and no context.** A service must
start whether or not the issuer is reachable, and an issuer that is down
must not be a service that will not boot. Discovery is lazy and cached:
the first request after the issuer returns is the one that pays for it,
and the key set refetches itself when a signature names a key it has not
seen, which makes rotation a non-event.

**`Middleware` establishes; `Require` refuses.** They are separate
because a listener serves pages that run before anybody is established —
a health endpoint, a login page, a landing page — and a middleware that
refused for them is one every such route has to be excluded from. Wrap
everything in `Middleware`, and put `Require` on the routes that need it.
`Require` with no group means *any caller this installation vouches for*,
which is a real posture where the issuer's `requires` is already the gate.

A refusal never names the group that would have worked: a caller learning
which group opens a door has learned something it had no way to ask.

## A service on the cluster network — the cluster anchor

For a workload calling a service in the **same** cluster. Anything
further away exchanges its token at the issuer first and arrives as an
ordinary bearer.

```go
cluster := &identity.Cluster{
    Review:   kube.ReviewToken,          // yours, or client-go's
    Audience: "the-service",
    Name:     "kernel",
    Groups:   []string{"kernel:k8s:admin"},
}

http.ListenAndServe(":8080", identity.Middleware(cluster, issuer)(mux))
```

**`Review` is supplied, not built.** Otherwise every consumer that only
needs the issuer would inherit Kubernetes client libraries for a code
path it never runs.

**`Groups` is stated by the listener**, because a TokenReview says *who*
and never *what they may do* — the policy is not reachable from here. A
token the issuer signed carries its groups; a ServiceAccount token does
not.

Several verifiers are tried in order and the first that answers wins. A
verifier that could not **reach** the issuer stops the chain rather than
falling through, because trying the next one would turn an outage into
*your token is bad* and send a legitimate caller to authenticate again,
repeatedly.

## What it never does

**No group re-mapping, anywhere.** The name in the policy is the name in
the token is the name in the role check. A second vocabulary is a second
place for access to mean something different.

**No token parsing in a browser.** That is the TypeScript package's rule
and this one's corollary: the browser asks the application, and the
application answers from what it verified.

## Exchange, and the two credential shapes

```go
exchanger := &tokens.Exchanger{Issuer: "https://access.example", ClientID: "local-dev"}
token, err := exchanger.Exchange(ctx, subject, tokens.TypeJWT, "aws:111122223333:power")
```

The client is presented in **HTTP Basic**: the issuer reads an exchange's
client from Basic alone and never from a posted `client_id`, so getting
that wrong is refused as *invalid client* — an error about the client
rather than about the mistake. A refusal comes back as
`tokens.ErrRefused`, carrying the issuer's own sentence, which names the
audience and the groups the proof holds.

```go
tokens.WriteExecCredential(os.Stdout, apiVersion, token)   // kubectl reads this
creds, _ := tokens.AssumeRoleWithWebIdentity(ctx, nil, roleARN, who, token.AccessToken)
tokens.WriteCredentialProcess(os.Stdout, creds)            // the AWS SDKs read this
```

`AssumeRoleWithWebIdentity` is **unsigned**, which is why the AWS path
needs no stored key: the token is the proof, and the account's trust
policy decides what it opens.

## Policy

```go
declared, _ := policy.LoadDeclared("/etc/access-roster/policy")  // a file or a directory
set, _ := policy.NewSet(declared)                                // validated once, at load

result := set.Evaluate(policy.Input{
    Email:           "alice@example.com",
    DirectoryGroups: groups,      // what the directory confirmed
    Authoritative:   true,        // and whether that answer may be acted on
})
```

One layer. There was a second that a console could write; it is gone
(INF-694), because a console that can disagree with git is a second
source of truth and a merge to reconcile them.

## Not built yet

`authz` (role helpers over `Verified`), `directory` (a client for the
endpoint that returns when something needs it again), and the adapters
for fiber, gRPC and connect. Each is additive: they sit on the same
`Verified` and change nothing above. Tracked in INF-648.
