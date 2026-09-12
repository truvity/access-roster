# The libraries — Go module and TypeScript package

**Status:** designed 2026-09-07; the Go `identity` core is built with the
hub, the rest with the issuer.

## Purpose

An application behind the proxy, or a service on the cluster network,
needs three things and should implement none of them: **who is calling**,
**may they do this**, and **how do I call the next service as myself**.
The Go module gives all three behind one `Identity` type; the TypeScript
package gives a UI the first without parsing a token.

## Go module `github.com/truvity/access-roster`

| Package | Gives |
|---|---|
| `identity` | `Identity{Subject, Email, Name, Groups, Roles, Source, Expiry}` and **exactly two verifiers**, one per anchor ([trust.md](trust.md)): `Issuer` (a bearer or forwarded token: JWKS, issuer URL, audience) and `Cluster` (a ServiceAccount token: TokenReview, audience, allow-list). A listener composes the one or two it needs; both yield the same `Identity`, so a handler never learns which anchor proved the caller. A header-trust source exists for a local run and nothing else; `FromContext` |
| `identity/httpmw`, `identity/fibermw`, `identity/grpcmw`, `identity/connectmw` | the same verification as middleware for net/http, fiber v3, gRPC unary and stream interceptors, and connect interceptors; every adapter also serves `GET /.access/whoami` for the UI |
| `authz` | `Require(role)` and `RequireAny(...)` per handler; role mapping from `groups` values or from the policy, so a two-role console needs no code of its own |
| `directory` | a typed `DirectoryService` client with the ServiceAccount token source built in and the authoritative rule enforced: `Live(email)` and `Members(group)` return a value and an `Authoritative` flag, and a helper `RemoveOnlyIf(authoritative)` for reconcilers |
| `tokens` | `Exchange(ctx, subject, audience)`, a refreshing `Source` for a projected ServiceAccount token, and the AWS `credential_process` and Kubernetes exec-credential encoders `accessctl` uses |
| `policy` | the policy engine and its schema — groups, claims, lifetimes, clients, github — one loader for the issuer and the console, so both act on the same policy |
| `connect` | the admin-consent flow and the backends behind storage interfaces, importable by a product that connects its customers' directories |

Design rules for the module: no framework leaks across packages, every
verifier is constructed from an anchor's coordinates (an issuer URL and
an audience; or an audience and an allow-list) and nothing else, no
global state, no third verifier and no group re-mapping anywhere, and
the `Identity` is the only thing handlers ever see. The module is where
the two-anchor rule stops being documentation and becomes the shape a
service is given: a service that serves people and workloads gets two
listeners because it constructs two verifiers, not because a page told
it to. The worked example is
[../connect/service-to-service.md](../connect/service-to-service.md).

## TypeScript package `access-roster`

Installed from the repository tag. `useIdentity()` fetches
`/.access/whoami` once and exposes `{email, name, roles, signOutUrl}`;
`<UserBadge/>` renders it with the sign-out link that ends both the proxy
and the issuer session. Generated Connect-Web clients for the hub's
console services ship under `/gen`. The package parses no token and
holds no secret; if `/.access/whoami` is not served, it renders as signed
out.

## The `/.access/whoami` contract

Every Go adapter serves it on the application's own origin, behind the
same verification as any handler:

```json
{"email":"alice@example.com","name":"Alice","roles":["operator"],"source":"forwarded","expiresAt":"2026-09-07T15:00:00Z","signOutUrl":"/oauth2/sign_out"}
```

One endpoint, one shape, so a console UI written in any framework can
show who is signed in without a dependency on the proxy's header names.
