# A service calls another service

What a workload presents when it calls one of ours, what the called
service accepts, and how to build a service of your own that gets both
right. The rule underneath is [design/trust.md](../design/trust.md):
**two anchors, chosen by scope** — the cluster for a workload next door,
the issuer for everything further away.

## Decide which anchor, in one question

*Is the caller a workload in the same cluster as the service?*

| Yes | No |
|---|---|
| present the caller's **ServiceAccount token**, projected for the service's audience | obtain an **issuer token** first — by exchange for a workload or a CI job, by sign-in for a person — and present that |

That is the whole decision. Do not put an exchange in front of a
same-cluster call "for uniformity": the issuer would verify the same
ServiceAccount token and re-sign it, a round trip that adds no trust on
the hottest paths in the estate. Do not verify another cluster's keys
directly to avoid the issuer: that is a third anchor per cluster, and
the issuer exists so that decision is made once.

## Calling with a ServiceAccount token (same cluster)

The caller mounts a projected token **for the service's audience**. A
token for any other audience — the API server's default included — is
refused, which is what keeps every mounted token in the cluster from
being a credential for every service in it.

```yaml
volumes:
  - name: directory-roster-token
    projected:
      sources:
        - serviceAccountToken:
            audience: directory-roster      # the service's audience, from its values
            expirationSeconds: 3600
            path: token
```

Read the file on **every call**, not once: the kubelet rotates it under
the pod. Send it as `Authorization: Bearer …`. The directory's Go client
does this for you:

```go
src := tokens.ServiceAccountSource("/var/run/secrets/directory-roster/token")
dir := directory.New("http://directory-roster.directory-roster.svc:8080", src)
```

On the service side, the caller must be **named**. Reaching the port is
not being allowed to ask: the directory's `consumers[]` lists
`namespace/serviceAccount` pairs and an empty list admits nobody. A
NetworkPolicy admitting the caller's namespace is the second layer,
never the only one.

The issuer calling the hub, and github-roster calling the hub, are both
exactly this.

## Calling with an issuer token (anywhere else)

A **workload in another cluster** exchanges its own ServiceAccount token
at the issuer for a token whose audience is the service:

```
POST /token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the workload's ServiceAccount token>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
audience=<the service's client id>
```

The issuer verifies the subject token with *that* cluster's TokenReview
(the issuer trusts the clusters; the service trusts the issuer), resolves
the ServiceAccount through the policy's `service_account` matchers to
internal groups, checks the client's `requires`, and mints. The service
verifies the result against the issuer's JWKS and its own audience —
the same verifier a console uses for a forwarded bearer.

A **CI job** does the same with its platform token: see
[github-actions.md](github-actions.md). A **person** — a laptop over
the network, a script an engineer runs — signs in once with `accessctl
login` and exchanges from the cached login: `accessctl exchange
--audience <client id>`.

Every one of these needs the service declared as a **client** in the
policy, with `requires` naming the internal groups that may call it:

```yaml
groups:
  all:directory-roster:reader:
    matchers:
      - service_account: { namespace: team-sync, name: team-sync }   # a workload, this or any cluster the issuer trusts
clients:
  directory-roster:
    kind: public
    requires: [all:directory-roster:reader, all:access-roster:operator]
```

The group is named for what it is a role *on* — `<scope>:<thing>:<role>`,
here a reader of the directory across the installation — not for who is
in it ([naming](../design/trust.md#naming)).

## Building a service that accepts callers

Serve people and workloads on **two listeners**, one anchor each, and
never mount an operator RPC on the workload port. The directory hub is
the pattern:

| Listener | Behind | Verifier | Accepts |
|---|---|---|---|
| console, `:8081` | `access-proxy` | `Issuer` (issuer URL + this console's client id) | people |
| API, `:8080` | Service DNS | `Cluster` (TokenReview + audience + allow-list), and `Issuer` too when remote callers exist | workloads here; anything further away through the issuer |

In Go, both verifiers come from the module and a listener composes what
it needs:

```go
cluster, _ := identity.NewClusterVerifier(ctx, identity.ClusterConfig{
    Audience: "my-service",
    Allow:    []identity.ServiceAccountRef{{Namespace: "team-sync", Name: "team-sync"}},
})
issuer, _ := identity.NewIssuerVerifier(ctx, identity.IssuerConfig{
    Issuer:   "https://issuer.example.internal",
    Audience: "my-service",              // this service's client id at the issuer
})

api.Handle("/", connectmw.Interceptor(cluster, issuer).Wrap(handler))   // either anchor
console.Handle("/", httpmw.Require(issuer)(ui))                          // people only
```

Whichever anchor proved the caller, the handler sees one `Principal`
with `Groups []string`, and **the grant is keyed by the principal, not
by the anchor**: a consumer proven either way is the same consumer and
gets the same answer. If your service keeps a grant table of its own —
which callers may read what — key it by the principal too, so there is
one table behind both doors.

A service that serves **only workloads next door** needs only the
cluster verifier and no client at the issuer. A service that serves
**only people** needs only the issuer verifier, behind the proxy, and no
API listener at all. Add the second anchor when the second kind of
caller appears, not before.

## What never to do

- **A shared secret between two services.** There is always a
  ServiceAccount token or an issuer token to use instead.
- **An API key on the console listener**, or a browser session on the
  API listener. Two ports, two anchors.
- **Trusting a header** (`X-Forwarded-Email` and friends) outside a
  local run. It asks who can reach the port, not who signed anything.
- **Re-mapping group names** on the way in. The name in the policy is
  the name in the token is the name in your role check.

## Recovery is not one of these

Break-glass at the hub and the issuer is a person minting a
ServiceAccount token by hand. It is the cluster anchor used deliberately
as the floor for the day the issuer is unavailable, not a pattern for a
service to imitate: see [design/trust.md](../design/trust.md#recovery-is-the-root-not-a-back-door).
