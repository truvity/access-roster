# 0005 — ES384 is the signing algorithm

**Status:** Accepted
**Date:** 2026-09-25

## Context

What the issuer signs with follows from the key it is given:
`signingKey.certificate.algorithm`/`.size`/`.encoding` selects RSA or
ECDSA on P-256, P-384 or P-521, and the choice determines whether every
token is RS256, ES256, ES384 or ES512
([reference/access-issuer.md#what-the-chart-renders-and-what-it-expects](../reference/access-issuer.md#what-the-chart-renders-and-what-it-expects)). The
signing key is never minted by the service itself — cert-manager issues
it, or a deployment delivers it — so this decision is about the
**default** a fresh installation gets when it sets nothing.

An ECDSA key produces smaller tokens and cheaper verification per
operation than RSA at a comparable security level, and P-384 in
particular buys headroom over P-256 for a token that may carry a `groups`
claim of meaningful size. The cost is not the issuer's: it is every
relying party's verifier, and not every OIDC library treats "RS256" as
one algorithm among several rather than the only one it was written to
expect.

## Decision

**The chart's default signing key is ECDSA P-384, signing ES384.** A new
installation gets it without setting anything. Moving an *existing*
installation from RSA to ECDSA (or the reverse) is not a values edit to
make casually: it rotates the signing key, and every relying party that
has not first been checked against the new algorithm starts failing
verification the moment the new key is live — there is no overlap period
where both are accepted, because discovery advertises one algorithm at a
time.

**Every relying party must accept what discovery advertises.** A
verifier hard-pinned to RS256 is not this repository's default to design
around; installations with one relying party like that set
`signingKey.certificate: {algorithm: RSA, size: 2048, encoding: PKCS1}`
explicitly, which is a one-line, reviewable override
([reference/access-issuer.md](../reference/access-issuer.md),
[connect/kargo.md](../connect/kargo.md),
[connect/kubernetes-cluster.md](../connect/kubernetes-cluster.md)). The
chart's own Go and TypeScript verifiers accept whichever algorithm
discovery advertises, RS256, ES256, ES384 or ES512, by design
([reference/typescript.md](../reference/typescript.md)) — the constraint
is never on this repository's own side of a connection.

## Consequences

An installation adopting the default inherits a short, known list of
relying parties that need the RSA override instead: a `kube-apiserver`
left at its default `--oidc-signing-algs` (which is `RS256`, so the
cluster's own `AuthenticationConfiguration` or that flag must list
`ES384` explicitly to accept the default key —
[connect/kubernetes-cluster.md](../connect/kubernetes-cluster.md)), and
any relying party whose OIDC library hard-codes RS256 rather than reading
discovery (Kargo's is one such — [connect/kargo.md](../connect/kargo.md)).
Some ecosystems accept fewer algorithms still: opkssh verifies only
RS256, PS256, ES256 and EdDSA today, which is the blocker recorded in
[0004](0004-ssh-opkssh-and-the-secret-stores-ca.md) and is not solved by
anything in this record — it waits on that ecosystem, not on a key
rotation here.

Choosing RSA for one such relying party is a whole-installation decision,
not a per-consumer one: there is one signing key and one `iss`, so every
relying party sees whichever algorithm is chosen.

## Alternatives considered

**Default to RSA, the algorithm every OIDC verifier is guaranteed to
accept.** Rejected as the default: it optimizes for the least capable
verifier at the cost of every other relying party's token size and
verification cost, when the override for that one case is a single
declared value.

**Ship both an RSA and an ECDSA key simultaneously, so a relying party
could pick.** Rejected: `jwks_uri` can publish more than one key, but a token is minted
with one signing key at a time, so this would not let two relying parties
see different algorithms from the same sign-in — it would only complicate
key rotation for no verifier this repository has found that needs it.
