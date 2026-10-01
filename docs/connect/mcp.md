# Connect an MCP server

**Anchor:** the issuer, on both sides of the call. A Model Context
Protocol server is a resource a token is minted *for*
([reference/policy.md#resources--what-a-token-is-for](../reference/policy.md#resources--what-a-token-is-for));
its client is usually software this installation never deployed and
cannot enumerate — somebody's editor, a hosted assistant — which is the
case [Clients that describe themselves](../reference/policy.md#clients-that-describe-themselves)
exists for. The two mechanisms below are independent and normally used
together: a client identifies itself with a URL, and separately asks for
a token scoped to one resource rather than to itself.

## The client: a Client ID Metadata Document (CIMD)

Every client declared in the policy is a reviewable row, and that stays
the right default. It does not fit an MCP client, because this
installation did not deploy it and cannot enumerate the population of
things that might connect. Such a client instead presents an **HTTPS
URL** as its `client_id`. That URL serves a small JSON document
describing the client — an OAuth Client ID Metadata Document, the
mechanism the Model Context Protocol's authorization spec points to now
that dynamic client registration (RFC 7591) is deprecated there.

Nothing is registered and nothing accumulates: the issuer fetches the
document, checks it, and treats the client as `public` for the length of
one cache entry. Turn it on with an allow-list of the hosts that may
serve one, and the group any of their clients' callers must hold:

```yaml
client_documents:
  origins:  [mcp-clients.example]        # hosts that may serve a document; empty = off
  requires: [all:observability:user]     # who may use ANY such client — mandatory
  ttl_cap:  10m                          # optional, worth setting for software you didn't deploy
```

`requires` is mandatory the moment `origins` is non-empty: turning the
mechanism on without saying who may use it would admit every person who
can sign in at all, which validation refuses
(`policy.ClientDocuments.validate`, [policy/clientdoc.go](../../policy/clientdoc.go)).
`ttl_cap` caps token lifetime for every such client, the same field a
declared client carries.

**Why this is proportionate.** Registration is not the authorization
decision here — reach is decided by the groups a caller holds, so a
client the issuer has never seen cannot widen anything. It can only ask a
person to consent to the reach that person already has. The threat is
therefore not escalation, it is **phishing**: a hostile client persuading
somebody to sign in to it and taking the token away. That is why the
guard is an allow-list of origins rather than a refusal of unknown
clients, and why `requires` here is mandatory rather than optional —
[policy/clientdoc.go](../../policy/clientdoc.go) states the argument in
full.

**The limits, checked in this order** (`internal/issuer/clientdoc.go`):

| Limit | Value | Why |
|---|---|---|
| origin allow-listed | checked first, before anything is dialled | the allow-list is also what stops the issuer being used to fetch an arbitrary URL — the origin decision is made before a request exists |
| response size | 64 KiB | the URL is caller-chosen, so the response is an untrusted stream |
| fetch timeout | 10 seconds per attempt, one retry of a transient failure | a sign-in is waiting on it; the last validated copy may be served for up to an hour past its expiry, only when the origin is unreachable or answers 5xx |
| cache | 10 minutes, then re-fetched | short enough that a client correcting its redirect URIs is not locked out for an afternoon |
| redirects | none — the fetch's `http.Client` refuses every one | the document is served *at* its own id; a redirect chain is how an allow-list on the first hop stops meaning anything |
| stale fallback | at most 1 hour past expiry, transport errors only | the copy was already validated and access is still decided by the person's groups; never served after a validation failure, a redirect or a 4xx |

**The SSRF note.** Resolving a document means the issuer makes a
server-side HTTP request to a URL the caller effectively chooses (by
presenting it as `client_id`). The allow-list check happens before a
request is built at all, an origin may name no scheme, path or wildcard
(`validateOrigin`), and there is no redirect-following to turn one
allow-listed host into a hop to somewhere else. That is the whole of what
stands between this mechanism and an issuer that would fetch anything a
caller named.

**The availability coupling.** Because there is no stale fallback, an
MCP client's continued ability to sign in is coupled to the availability
of whatever host serves its document: if that host is down, that
client's sign-ins fail, even though nothing about the issuer or the
resource it wants a token for has changed. Worth knowing before pointing
`origins` at somebody else's infrastructure.

A **declared client always wins** — the policy is consulted first, so a
document is never fetched for a client id that already has a row, and a
document can never displace one.

## The resource: RFC 8707

Until an MCP server exists, a client's id was always the token's
audience, because the client and the thing a person reached were one
object. An MCP client is somebody's editor; what it wants a token *for*
is a service elsewhere. So the MCP server is declared as a **resource**,
not a client:

```yaml
resources:
  https://observability-mcp.example/:
    requires: [all:observability:user]
    ttl_cap:  5m
    display_name: Observability MCP server
```

A resource id is an absolute URI with no fragment (RFC 8707;
`policy.validateResourceID`), matched **exactly** — a trailing slash or a
different scheme is a different resource. The MCP client sends it as the
`resource` parameter on the authorization and token requests; the
issuer's `aud` for the resulting token is that URI, not the client's id
(`internal/issuer/resource.go`).

**Both gates apply.** The client's `requires` says who may use that
client at all; the resource's `requires` says who may reach that
service; a caller must satisfy both, and the shorter of the two
`ttl_cap`s wins. Checking only the client would let anybody who may use
an editor reach every service that editor knows how to name.

A request naming a resource this installation has not declared, or more
than one resource, is refused with `invalid_target` at the moment of the
mistake — never silently narrowed or silently minted for the client
instead, which is what happened before this parameter was read at all.

## The MCP server's own side

The server is the resource's audience, so it verifies exactly what any
other backend does against this issuer
([connect/service-to-service.md](service-to-service.md)): the token's
signature against the issuer's JWKS, the issuer URL, and `aud` equal to
**its own resource URI** — not a client id. In Go, that is

```go
issuer := &identity.Issuer{URL: "https://access.example", Audience: "https://observability-mcp.example/"}
http.ListenAndServe(":8080", identity.Middleware(issuer)(mux))
```

the same `identity.Issuer` every console and API listener uses, with the
resource's own URI as `Audience`
([reference/go-module.md](../reference/go-module.md)); the TypeScript
package's `Issuer` takes the same shape
([reference/typescript.md](../reference/typescript.md)).

**Publish RFC 9728.** The Model Context Protocol expects a resource
server to serve its own OAuth 2.0 Protected Resource Metadata document —
conventionally at `/.well-known/oauth-protected-resource` next to the
MCP endpoint — naming this issuer's URL as an `authorization_server` and
its own resource URI as `resource`. That document is what lets a
compliant MCP client discover which issuer to authenticate against
without being told out of band. This is the MCP server's own
responsibility to serve: access-roster is the authorization server named
inside it, not the party that publishes it.

## Calling a backend: the server's own identity, not the caller's

The caller's token is for the MCP server and no one else: its `aud` is
the server's own resource URI, and the MCP authorization spec forbids a
server to pass through the token it received. So when a tool calls a
backend, the server does **not** forward the caller's bearer.

1. **Verify** the caller: signature, issuer, and `aud` equal to the
   server's own resource URI (above).
2. **Decide** with the caller's identity: its `groups` and subject are
   what the server authorizes the tool call against.
3. **Log** the caller in the server's own audit line, so a record says
   who asked.
4. **Call upstream as the server itself**: its workload identity, traded
   for a token for the backend's audience by RFC 8693 token exchange
   ([service-to-service](service-to-service.md)). The two identities
   answer different questions (who asked, and what this service may
   read), and the backend sees only the second.

[`resource-proxy`](#fronting-a-stock-mcp-server-with-resource-proxy)
does steps 1, 3 and 4 for a stock server (see its
[outbound section](#outbound-the-workloads-own-identity)); a Go server
does the same with `identity/resource` below.

**Acting on behalf of the user is not provided today.** If a backend must
act as the user rather than as the service, that needs a delegation (a
token exchange carrying an actor claim, naming the server as the actor
for that user) designed explicitly, with its own consent and audit
story. access-roster does not offer one yet; do not approximate it by
forwarding the caller's token.

This applies to HTTP transports (Streamable HTTP, HTTP+SSE), where the
bearer arrives as an `Authorization` header. Over **stdio** there is no
HTTP layer and so no bearer to verify at all.

## Permissions: nothing new is granted

An MCP tool that calls a backend is bound by the caller's `groups`: the
resource's `requires` decides who may reach the MCP server at all, and the
server decides what a tool may then do for that caller, bounded by what
its own workload identity may do on the backend. An MCP server is a new
way to call something, never a new grant. There is no separate "tool
permission" vocabulary to maintain in the policy.

## A Go server: `identity/resource`

`identity.Middleware` plus a hand-written 401 and a hand-written PRM
document is the same 120 lines in every MCP server. They live in one
package now:

```go
res, err := resource.New(resource.Config{
    IssuerURL:   "https://access.example",
    ResourceURL: "https://mcp.example.com/metrics",
    Scope:       "openid",
})
mux.Handle(res.Path(), res.Metadata())      // RFC 9728, unauthenticated
mux.Handle("/", res.Protect(mcpHandler))    // 401 + challenge, else the caller is in the context
who, _ := identity.FromContext(r.Context()) // inside mcpHandler
```

`Protect` reads the `Authorization` bearer only (never the gateway's
forwarded-token header: a public resource server does not get to promise
that nothing but a gateway reaches it). No token answers `401` with
`WWW-Authenticate: Bearer resource_metadata="<PRM URL>", scope="<scope>"`;
a token that was presented and did not verify adds `error="invalid_token"`
(RFC 6750 §3); an issuer that cannot be reached answers `503`, because
telling a legitimate caller to sign in again during an outage makes the
outage worse. `res.Ready(ctx)` is the readiness probe: nil once the
issuer's discovery document has been fetched. `resource.WellKnownPath`
is the RFC 9728 §3.1 location: the well-known prefix, then the resource's
own path (`/.well-known/oauth-protected-resource/metrics` for
`https://mcp.example.com/metrics`; a lone trailing slash is dropped, so a
root resource is the bare prefix).

`identity.Verified.ClientID` carries the token's `azp` (or `client_id`),
for a record of which client called. Never authorize on it.

## Fronting a stock MCP server with `resource-proxy`

Most MCP servers are somebody else's software and know nothing about
access-roster. `resource-proxy` is the sidecar that gives one its front
door without changing it: one container beside the stock server, from the
image `ghcr.io/truvity/access-roster/resource-proxy:<version>` (pin it by
digest; it is published with every release, multi-arch, distroless,
non-root, and needs no shell and no writable filesystem).

```
client ──▶ gateway ──▶ :8080 resource-proxy ──▶ 127.0.0.1:8081 stock MCP server
                        verifies the token                     │
                        serves the PRM                         ▼
                        writes the audit line       127.0.0.1:8429 resource-proxy (outbound)
                                                    adds the workload's OWN token ──▶ backend
```

### Inbound: who may call

Every request except the metadata document and the health endpoints needs
a token that verifies against `ISSUER_URL` with `aud` equal to
`RESOURCE_URL`. Who may *obtain* such a token is decided by
`resources.<RESOURCE_URL>.requires` in the policy, and nowhere else; the
proxy reads no group. The caller's `Authorization` header (and the
gateway's forwarded-token header) is removed before the request reaches
the stock server.

### Configuration

Every flag has an environment variable of the same name, upper case with
underscores; a flag given wins.

| Flag / environment | Default | Meaning |
|---|---|---|
| `--listen` / `LISTEN` | `:8080` | inbound listener |
| `--upstream` / `UPSTREAM` | required | the stock server, e.g. `http://127.0.0.1:8081/mcp`. Its path is where the resource's path maps to (below) |
| `--issuer-url` / `ISSUER_URL` | required | the issuer, exactly as in a token's `iss` |
| `--resource-url` / `RESOURCE_URL` | required | this resource's public URL: the token audience and the policy's `resources` key, byte for byte |
| `--scope` / `SCOPE` | `openid` | advertised in the PRM and the challenge, never checked; empty omits it |
| `--max-request-bytes` / `MAX_REQUEST_BYTES` | `4194304` | largest request body; more is `413` |
| `--body-read-timeout` / `BODY_READ_TIMEOUT` | `30s` | time to read one body |
| `--upstream-timeout` / `UPSTREAM_TIMEOUT` | `2m` | wait for the stock server's response headers (a stream is not bounded by it) |
| `--outbound-listen` / `OUTBOUND_LISTEN` | empty = off | loopback address of the outbound forwarder, e.g. `127.0.0.1:8429` |
| `--outbound-target` / `OUTBOUND_TARGET` | | where the outbound forwarder sends what it gets |
| `--outbound-token-endpoint` / `OUTBOUND_TOKEN_ENDPOINT` | | the issuer's token endpoint, ending in `/token` |
| `--outbound-client-id` / `OUTBOUND_CLIENT_ID` | | the exchange client this workload presents |
| `--outbound-audience` / `OUTBOUND_AUDIENCE` | | the audience to exchange for |
| `--outbound-sa-token-file` / `OUTBOUND_SA_TOKEN_FILE` | | the projected ServiceAccount token (audience: the issuer), re-read for every exchange |
| `--outbound-ca-file` / `OUTBOUND_CA_FILE` | empty = system roots only | PEM bundle of CA certificates, appended to the system roots, trusted only for the connection to `OUTBOUND_TARGET` (a target served by a private CA). The issuer and token-exchange connections never use it. Read once at start; unreadable or certificate-less is refused at start; restart to rotate |
| `--outbound-allow-non-loopback` / `OUTBOUND_ALLOW_NON_LOOPBACK` | `false` | see below |
| `--refresh-before` / `REFRESH_BEFORE` | `1m` | exchange again this long before expiry (never more than half a token's life) |

Setting any `OUTBOUND_*` value without `OUTBOUND_LISTEN`, or
`OUTBOUND_LISTEN` without the five it needs, is refused at start.

### The routing contract with the gateway

The proxy handles the path itself, so the gateway does **not** rewrite
anything. For `RESOURCE_URL=https://mcp.example.com/metrics` the gateway
routes to this pod:

| Request path | Handled as |
|---|---|
| `/metrics` and everything under `/metrics/` | authenticated, proxied. The prefix `/metrics` is replaced by the path of `UPSTREAM`: with `UPSTREAM=http://127.0.0.1:8081/mcp`, `/metrics` reaches the stock server as `/mcp` and `/metrics/x` as `/mcp/x`; with no path on `UPSTREAM`, `/metrics/x` is `/x`. The query string is kept |
| `/.well-known/oauth-protected-resource/metrics` | the PRM, unauthenticated |
| `/.well-known/oauth-protected-resource` | the same PRM, for a gateway that rewrites a path-suffixed request to the bare form. **Route this to one pod only**; with several resources on one host it names whichever pod got it |
| anything else under the authenticated catch-all | `404` after authentication |
| `/healthz`, `/readyz` | probes for the kubelet; do not route them through the gateway |

A client that speaks RFC 9728 asks for the path-suffixed document first,
so a host that serves several resources needs one route per resource for
its well-known path, to that resource's pod, beside the route for the
resource's own prefix. A resource at the root of its host
(`https://mcp.example.com/`) has no prefix to strip and its PRM is the
bare well-known path.

Streaming works through the proxy: responses are flushed as they are
written, nothing is buffered, so both Streamable HTTP and the older SSE
transport pass. Timeouts bound the request side only; a stream lives as
long as its client does.

### Outbound: the workload's own identity

The stock server points its backend URL at `OUTBOUND_LISTEN` and holds no
credential. The proxy adds `Authorization: Bearer <token>` to whatever
arrives there and forwards it to `OUTBOUND_TARGET`; the token is this
workload's **own**. The caller's token is never forwarded: the MCP
authorization spec forbids passing it through, and the two identities
answer different questions (who asked, and what this service may read).

The token is obtained the way any workload does
([service-to-service](service-to-service.md)): the pod's projected
ServiceAccount token, minted for the issuer as audience, is read from
`OUTBOUND_SA_TOKEN_FILE` **afresh for every exchange** (the kubelet
rotates it under the pod) and traded at `OUTBOUND_TOKEN_ENDPOINT` (RFC
8693, `tokens.Exchanger`) as `OUTBOUND_CLIENT_ID` for `OUTBOUND_AUDIENCE`. The result is cached and
exchanged again `REFRESH_BEFORE` ahead of expiry. If a refresh fails while
the previous token is still in date, that token is served and the next call
tries again; if none is, the call is `502`, never an unauthenticated
request. `/readyz` reports not ready until the first token was obtained.

The listener accepts any caller that can reach it and lends them this
workload's identity, so it must be loopback: anything else (`:8429`,
`0.0.0.0`, a pod IP) is refused at start unless
`OUTBOUND_ALLOW_NON_LOOPBACK=true` is set by name. Inside one pod
that is the stock server and nothing else.

### The audit line

One JSON line per request to the authenticated routes, on standard
output, written when the request finishes (a refused request is logged
too, with no caller):

```json
{"time":"…","level":"INFO","msg":"mcp_request","http_method":"POST","path":"/metrics",
 "status":200,"duration_ms":41.3,"sub":"ada@example.com","email":"ada@example.com",
 "name":"Ada L","client":"https://client.example/cimd.json",
 "method":"tools/call","tool":"query"}
```

`sub` (and `email` and `name` when the token has them), `client` (the
`azp` or `client_id` claim), the JSON-RPC `method` and, for `tools/call`,
the tool's `name`. A batch is `"method":"batch"` with a `calls` array of
`{method, tool}`. `duration_ms` of a stream is how long it stayed open.
Never in it: a token, a header, a query string, tool arguments, or any
response body. A body that is not JSON-RPC is logged with no method.

### Migrating a server that embedded its own copy

A server that carries its own 120-line copy of this (a `NewAuth` /
`Protect` / `Metadata` trio) has two ways out. As a Go server, replace
the copy with `resource.New` and `Protect`/`Metadata` above: the
behaviour is the same except that a root resource's metadata now lives at
the bare well-known path (RFC 9728 §3.1 drops the lone slash) and an
unreachable issuer is `503` rather than `401`. Or run it as the stock
server behind `resource-proxy` and delete the auth code. Either way the
policy's `resources` row and the clients do not change.
