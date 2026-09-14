# The libraries — Go module and TypeScript package

**Status:** built. The Go module ships `identity`, `tokens` and `policy`;
the TypeScript package ships a browser half, a React half and a Node
server half. The exact surface is in
[reference/go-module.md](../reference/go-module.md) and
[reference/typescript.md](../reference/typescript.md); this page is the
shape and the rules.

## Purpose

An application behind the proxy, or a service on the cluster network,
needs three things and should implement none of them: **who is calling**,
**may they do this**, and **how do I call the next service as myself**.
The Go module gives all three behind one `Verified` type; the TypeScript
package gives a UI the first without parsing a token, and a Node service
the same three the Go module gives.

## Go module `github.com/truvity/access-roster`

| Package | Gives |
|---|---|
| `identity` | `Verified{Subject, Email, Name, GivenName, FamilyName, Groups, ServiceAccount}` and **exactly two verifiers**, one per anchor ([trust.md](trust.md)): `Issuer` (a bearer or forwarded token: the key set, issuer URL, audience) and `Cluster` (a ServiceAccount token: a check you supply — a TokenReview, or the cluster's published key set — an audience, and the names it admits). A net/http `Middleware` puts the `Verified` in the context, `Require(groups...)` gates a handler, `WhoAmI` serves `GET /.access/whoami` for the UI, `FromContext` reads it back. Both verifiers yield the same `Verified`, so a handler never learns which anchor proved the caller |
| `tokens` | `Exchanger.Exchange(ctx, subject, kind, audience)` — `TypeJWT` for a proof from outside, `TypeAccessToken` for the CLI's own sign-in — and the encoders `accessctl` uses: the Kubernetes exec credential, `AssumeRoleWithWebIdentity` and the AWS `credential_process` |
| `policy` | the policy engine and its schema — groups, claims, lifetimes, clients, github — one loader for the issuer, the console and the controller, so all three act on the same policy; `Evaluate` takes a person, a CI job or a workload as one `Input` |

Not built, and additive when it is: `authz` (role helpers over
`Verified`), `directory` (a client for the endpoint that returns when
something needs it again), and adapters for fiber, gRPC and connect —
today another framework wraps the verifier itself.

Design rules for the module: no framework leaks across packages, every
verifier is constructed from an anchor's coordinates and nothing else,
no global state, no third verifier and no group re-mapping anywhere, and
the `Verified` is the only thing handlers ever see. The module is where
the two-anchor rule stops being documentation and becomes the shape a
service is given: a service that serves people and workloads constructs
two verifiers, and keeps them apart by route or by listener, not because
a page told it to. The worked example is
[../connect/service-to-service.md](../connect/service-to-service.md).

## TypeScript package `@truvity/access-roster`

Published to GitHub Packages at each release tag's version, with the
`@truvity` scope pointed at `https://npm.pkg.github.com`. Three entry
points. The root: `fetchIdentity()` and the `Identity` type. `/react`:
`useIdentity()`, which fetches `/.access/whoami` once and exposes the
four states — loading, signed in, signed out, unreachable — and
`<UserBadge/>`, which renders it with the sign-out link. `/server`:
`Issuer`, `middleware`, `requireGroups`, `whoami` and `whoamiPath`, so an
Express or Nest service verifies a bearer and serves the same endpoint
Go does. The package parses no token in a browser and holds no secret;
if `/.access/whoami` is not served, the UI renders as signed out.

## The `/.access/whoami` contract

Every Go and Node handler serves it on the application's own origin,
behind the same verification as any handler:

```json
{"status":"signed-in","email":"alice@example.com","name":"Alice Ant","givenName":"Alice","familyName":"Ant","groups":["all:myconsole:operator"],"version":"1.8.0"}
```

One endpoint, one shape, so a console UI written in any framework can
show who is signed in — and what it may do, from `groups` — without a
dependency on the proxy's header names. The console of this repository
answers with its roles and scopes beside these fields.
