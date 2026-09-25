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
relying parties that need either the RSA override or their own
configuration to accept ES384 — worth naming rather than discovering one
integration at a time:

| Relying party | Default without configuration | What accepting ES384 needs |
|---|---|---|
| Kargo | its verifier is built from go-oidc's `oidc.NewVerifier` with no `SupportedSigningAlgs` set, which defaults to RS256 only | the RSA override on this issuer's key, since Kargo's own verifier does not read discovery to widen itself |
| `kube-apiserver` | the legacy `--oidc-signing-algs` flag defaults to `RS256` | that flag, or the cluster's `AuthenticationConfiguration`, must list `ES384` explicitly ([connect/kubernetes-cluster.md](../connect/kubernetes-cluster.md)) |
| OpenBAO or Vault, JWT auth on an **OIDC-type** role | `jwt_supported_algs` defaults to `[RS256]` for that role type (a **JWT-type** role has no such default and accepts every algorithm) | an OIDC-login recipe against this issuer must set `jwt_supported_algs` explicitly to admit ES384 |
| opkssh (OpenPubkey) | verifies RS256, PS256, ES256 and EdDSA only — ES384 is not in that list at all | nothing configures around this; it is the blocker recorded in [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md), and it waits on that project, not on a key rotation here |

Choosing RSA for one such relying party is a whole-installation decision,
not a per-consumer one: there is one signing key and one `iss`, so every
relying party sees whichever algorithm is chosen.

**A follow-up this decision exposes and does not itself solve: rotation
has no overlap window today.** The issuer publishes a single key in its
JWKS and reads its key file once, at start. Changing the key — a renewal,
and doubly an algorithm change such as moving from the ES384 default to
the RSA override or back — has no period where both the old and the new
key verify, and with more than one replica, each one picks up the new key
only at its own restart: until every replica has restarted, which replica
answers a token or a JWKS request is undefined, and a relying party can
see either key. A graceful-rotation mechanism — publishing both keys in
`jwks_uri` for an overlap window, or coordinating the read across
replicas — is required, and tracked as follow-up work, before any
installation is safe to move between signing algorithms; this record
does not resolve it, only names it as the sharp edge behind "moving an
existing installation... rotates the signing key" above.

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
