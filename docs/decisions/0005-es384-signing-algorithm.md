# 0005 — ES384 is the signing algorithm

**Status:** Accepted; partly superseded by [0009](0009-a-default-signing-algorithm-and-per-audience-exceptions.md)
**Date:** 2026-09-25

## Context

What the issuer signs with follows from the key it is given:
`signingKey.certificate.algorithm`/`.size`/`.encoding` selects RSA or
ECDSA on P-256, P-384 or P-521, and the choice determines whether every
token is RS256, ES256, ES384 or ES512
([reference/configuration.md#what-the-chart-includes-what-it-expects](../reference/configuration.md#what-the-chart-includes-what-it-expects)). The
signing key is never minted by the service itself — cert-manager issues
it, or a deployment delivers it — so this decision is about the
**default** a fresh installation gets when it sets nothing.

An ECDSA key gives a much smaller key and a much smaller signature than
an RSA key at a comparable security level, and signs faster. It does not
verify faster: RSA verification is typically cheaper than ECDSA
verification, because RSA's usual small public exponent makes that half
of the asymmetry run the other way — smaller and faster to *sign* with,
not to *verify* against. P-384 over the chart's other ECDSA option, P-256,
buys a materially larger security margin — a 192-bit security level
against P-256's 128-bit one — at the cost of a somewhat larger signature
and a somewhat slower sign and verify than P-256. None of this has
anything to do with the size of a `groups` claim or any other payload the
token carries: a token's size is a function of its claims, never of the
key that signs it. The cost that does follow from the *default* is every
relying party's verifier, and not every OIDC library treats "RS256" as
one algorithm among several rather than the only one it was written to
expect.

## Decision

**The chart's default signing key is ECDSA P-384, signing ES384.** A new
installation gets it without setting anything. Moving an *existing*
installation from RSA to ECDSA (or the reverse) is not a values edit to
make casually: it rotates the signing key, and, **as things stand
today**, every relying party that has not first been checked against the
new algorithm starts failing verification the moment the new key is
live — there is no overlap period where both are accepted, because
discovery advertises one algorithm at a time. That gap is today's state,
not a permanent one: a graceful-rotation design is in progress, described
under Consequences, and closes it.

**The fix for a relying party that refuses ES384 is to make it accept
ES384, not to move the issuer off it.** Where the relying party has a
signing-algorithm setting, set it — `kube-apiserver`'s flag or its
`AuthenticationConfiguration`, an OpenBAO or Vault role's
`jwt_supported_algs`. Where it hard-codes an algorithm instead of reading
the issuer's discovery document, the durable fix is upstream: teach it to
read `id_token_signing_alg_values_supported` and build its verifier from
that, the way a conformant OIDC relying party should, rather than
assuming RS256.

**The RSA override exists as a last resort, for an installation that
cannot wait on either of those**: `signingKey.certificate: {algorithm:
RSA, size: 2048, encoding: PKCS1}` is a one-line, reviewable value
([reference/configuration.md](../reference/configuration.md),
[connect/kargo.md](../connect/kargo.md),
[connect/kubernetes-cluster.md](../connect/kubernetes-cluster.md)), but
it is not the recommended answer: it moves the *whole* installation to a
smaller security margin and a larger token, for every relying party, to
accommodate the one that could not be configured or fixed. The chart's
own Go and TypeScript verifiers accept whichever algorithm discovery
advertises, RS256, ES256, ES384 or ES512, by design
([reference/typescript.md](../reference/typescript.md)) — the constraint
is never on this repository's own side of a connection.

## Consequences

An installation adopting the default inherits a short, known list of
relying parties that need configuring, fixing upstream, or — as a last
resort — the RSA override, to accept ES384. Worth naming rather than
discovering one integration at a time:

| Relying party | Default without configuration | What accepting ES384 needs |
|---|---|---|
| Kargo | its verifier is built from go-oidc's `oidc.NewVerifier` with no `SupportedSigningAlgs` set, which defaults to RS256 only, and it does not read discovery to widen itself | the durable fix is upstream: Kargo reading `id_token_signing_alg_values_supported` from discovery instead of hard-coding RS256; until then, the RSA override on this issuer's key is the last-resort interim |
| `kube-apiserver` | the legacy `--oidc-signing-algs` flag defaults to `RS256`, and **a managed control plane may not expose that flag at all** | list `ES384` on the flag where it is exposed, or in the structured `AuthenticationConfiguration`, which some managed control planes accept in the flag's place — verify which path, if either, the platform in question actually supports before relying on it ([connect/kubernetes-cluster.md](../connect/kubernetes-cluster.md)) |
| OpenBAO or Vault, JWT auth on an **OIDC-type** role | `jwt_supported_algs` defaults to `[RS256]` for that role type (a **JWT-type** role has no such default and accepts every algorithm) | an OIDC-login recipe against this issuer must set `jwt_supported_algs` explicitly to admit ES384 |
| opkssh (OpenPubkey) | verifies RS256, PS256, ES256 and EdDSA only — ES384 is not in that list at all | nothing configures around this; it is the blocker recorded in [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md), and it waits on that project, not on a key rotation here |

Choosing the RSA override for one such relying party is a
whole-installation decision, not a per-consumer one: there is one signing
key and one `iss`, so every relying party sees whichever algorithm is
chosen — which is exactly why it is the last resort in the table above
and not the first thing to reach for.

**A follow-up this decision exposes, in progress rather than solved
here: rotation has no overlap window today.** The issuer currently
publishes a single key in its JWKS and reads its key file once, at
start. Changing the key — a renewal, and doubly an algorithm change such
as moving from the ES384 default to the RSA override or back — has no
period where both the old and the new key verify, and with more than one
replica, each one picks up the new key only at its own restart: until
every replica has restarted, which replica answers a token or a JWKS
request is undefined, and a relying party can see either key.

A graceful-rotation design is in progress to close this: publish the old
and the new key together in `jwks_uri` for an overlap window, with
discovery's `id_token_signing_alg_values_supported` listing both
algorithms for that window, so a relying party that has not yet picked up
the new key or algorithm keeps verifying against the old one until it
does. Until that ships, treat any signing-key or signing-algorithm
change — including adopting this default on an existing RSA
installation — as requiring every relying party to be checked, and
migrated first where it is not ready.

## Alternatives considered

**Default to RSA, the algorithm every OIDC verifier is guaranteed to
accept.** Rejected as the default: RSA's key and signature are larger
than ECDSA's for a comparable security level, and signing at the issuer
is slower — verification is not the cost RSA carries; if anything RSA
verifies faster than ECDSA, which cuts the other way. Optimising the
default for the least capable verifier would tax every other relying
party's token size and every signing operation, when the fix for that one
verifier is a single declared value on its side, or on this issuer's, not
a property to give up installation-wide.

**Ship both an RSA and an ECDSA key simultaneously, as the steady state,
so a relying party could pick.** Rejected: `jwks_uri` can publish more
than one key, but a token is minted with one signing key at a time, so
this would not let two relying parties see different algorithms from the
same sign-in — it would only complicate key management permanently, for
no verifier this repository has found that needs a *standing* choice
rather than a one-time migration. This is a different question from
publishing both keys **transiently**, during a rotation's overlap window,
which is the graceful-rotation follow-up described under Consequences:
that closes a gap in *changing* the key, not a permanent second option
for verifying one.
