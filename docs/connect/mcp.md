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
| fetch timeout | 5 seconds | a sign-in is waiting on it; a client whose metadata is slow to serve is a client somebody should fix |
| cache | 10 minutes, then re-fetched | short enough that a client correcting its redirect URIs is not locked out for an afternoon |
| redirects | none — the fetch's `http.Client` refuses every one | the document is served *at* its own id; a redirect chain is how an allow-list on the first hop stops meaning anything |
| stale fallback | none | a document that cannot be fetched right now is a client whose redirect URIs are not known right now; honouring yesterday's copy would honour URIs it may have retired |

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

## Forwarding the caller's identity onward

When the MCP server calls a backend on the user's behalf rather than with
an identity of its own, it forwards the caller's bearer token exactly as
it received it — the same "present what you were given" rule as any
other pass-through call, never re-minting or widening it.

**Not verified: this only works for an HTTP-based MCP transport**
(Streamable HTTP, or the older HTTP+SSE transport), where the bearer
travels as an `Authorization` header on each request. Over **stdio**
there is no HTTP layer between the client and the server to carry a
header at all, so header pass-through does not apply there by
construction; whether any *particular* MCP server actually forwards the
header correctly on an HTTP transport is a property of that server's own
code, not of the issuer, and is not verified here for any specific one.

## Permissions: nothing new is granted

An MCP tool that calls a backend is bound by the same `groups` claim that
backend's own RBAC already reads. The resource's `requires` decides who
may reach the MCP server at all; what a tool may then do through it is
whatever the caller's groups already let it do on the backend directly —
an MCP server is a new way to call something, never a new grant. There is
no separate "tool permission" vocabulary to maintain in the policy.
