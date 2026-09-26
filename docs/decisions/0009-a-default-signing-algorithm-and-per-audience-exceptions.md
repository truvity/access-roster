# 0009 — A default signing algorithm, and per-audience exceptions

**Status:** Accepted
**Date:** 2026-09-26

## Context

[0005](0005-es384-signing-algorithm.md) settled the installation's
*default* signing algorithm (ECDSA P-384, ES384) and, under
Alternatives considered, rejected shipping more than one signing key at
once: "this would not let two relying parties see different algorithms
from the same sign-in — it would only complicate key management
permanently, for no verifier this repository has found that needs a
*standing* choice rather than a one-time migration."

A standing choice turned out to be exactly what several relying parties
need, at the same time, on the same installation:

- **OIDC Core §15.1** expects a provider to be *able* to sign with
  RS256. That is a statement about providers, not about every audience
  a provider serves equally — it does not say a provider may sign with
  only RS256, or that every token from it must be RS256.
- **EKS's associated OIDC identity provider** accepts RS256 only, by
  the platform owner's confirmation, for a Kubernetes cluster's own
  workload-identity trust — a fixed, unconfigurable constraint on one
  specific audience.
- **Kargo** verifies with go-oidc's `oidc.NewVerifier` and no
  `SupportedSigningAlgs`, which defaults to RS256 only and does not
  read discovery to widen itself — a library default, on one more
  audience, not this issuer's to fix.
- **opkssh** accepts RS256 and ES256, but not ES384 — a *third*
  boundary, narrower than either of the first two.

0005's answer to a relying party like this was: fix it upstream, or —
"as a last resort" — move the *whole installation* to RSA, accepting a
larger key and signature and a smaller security margin for every
audience, including the ones that never asked for it. That trade gets
worse, not better, as more relying parties turn up with different,
mutually incompatible constraints: EKS and Kargo both want RS256, but a
hypothetical future consumer wanting ES256-and-not-ES384 (as opkssh
already is, for a token this issuer does not currently mint for it)
cannot be satisfied by the same single algorithm at all. There is no
single installation-wide choice that satisfies "EKS and Kargo want
RS256" and "some other audience wants something else" at once.

## Decision

**The issuer signs with several algorithms at once, one key ring per
algorithm, and picks the key by the token's AUDIENCE.** A deployment
configures a key per algorithm it needs (`signingKey.certificate` for
the default, `signingKey.additional[]` for the rest — see
[reference/access-issuer.md](../reference/access-issuer.md)); a client
row or a resource row may pin `signing_alg: RS256 | ES256 | ES384`
(policy schema, not this issuer's arbitrary choice: the three values a
real relying party in this estate has actually asked for); a row naming
none gets the installation **default**, which stays ES384 and stays a
whole-installation choice exactly as 0005 decided.

The full mechanism — key rings, the selection rule per mint path, the
chart shape, validation — is
[reference/policy.md#signing-algorithm-per-audience](../reference/policy.md#signing-algorithm-per-audience).
What belongs here is the decision this reverses and why:

**This partly supersedes 0005.** 0005's *default* stands: ES384, chosen
for the reasons that decision gives, unchanged. What this reverses is
0005's rejection of "ship both an RSA and an ECDSA key simultaneously,
as the steady state" — that is now exactly what happens, deliberately,
scoped to the one or two audiences that need it rather than applied
installation-wide. 0005 was right that a single signing key cannot serve
two relying parties with different fixed constraints; the fix is not to
pick one relying party's constraint as everyone's default, but to stop
requiring one key to serve every relying party at all.

## Consequences

**A relying party gets exactly the algorithm it needs, with no cost to
any other.** EKS and Kargo's audiences pin `signing_alg: RS256`; every
other client and resource keeps signing ES384, at ES384's smaller key
and signature and larger security margin. Nobody's constraint is
imposed on anybody else's tokens.

**A pin is refused, loudly, if this installation has no key for it.**
At issuer start — the one place policy and keys are both in hand — never
silently on the first token that would have needed it. An operator who
writes `signing_alg: RS256` without adding an RS256 key to
`signingKey.additional` gets a refusal that names the row and the
missing algorithm, not a service that starts and quietly signs ES384
anyway.

**Key rotation is per algorithm, not installation-wide.** Each
algorithm's key lives in its own key ring with its own
publish-before-sign schedule ([0001](0001-sessions-and-an-absolute-limit.md)
is the closest prior art for a schedule shape, though it governs
sessions rather than keys); renewing the RS256 key never touches the
ES384 key's schedule or vice versa. This is a *narrowing* from the
single-key design 0005 describes as a "graceful-rotation…in progress":
a `KeyRing`, single-algorithm, is now the unit that rotates, and moving
one row's `signing_alg` from one algorithm to another is a policy edit,
not a key rotation at all — the key for the target algorithm already
exists or is refused at start.

**opkssh's ES384 gap is unaffected by this decision.** Nothing here
mints opkssh a token; the gap [0004](0004-ssh-opkssh-and-the-secret-stores-ca.md)
records is still that project's own blocker. This decision would let a
*future* opkssh-facing audience pin `ES256` without moving the rest of
the installation off ES384, which is the shape of an eventual fix but
is not one on its own.

**A relying party that reads `id_token_signing_alg_values_supported`
sees every algorithm currently published**, across every key ring, not
only the one its own audience happens to use — unchanged from how
discovery already behaved for a single key mid-rotation
([reference/access-issuer.md](../reference/access-issuer.md)). This is
strictly more permissive than before, never less: nothing that verified
against this issuer's discovery document stops working.

## Alternatives considered

**Leave 0005's answer as the only one, and tell EKS and Kargo to fix
themselves or accept the RSA override.** Rejected for the reason given
under Context: it does not scale past one relying party with one fixed
constraint, and this estate already has two with the *same* constraint
(RS256) and a third ([0004](0004-ssh-opkssh-and-the-secret-stores-ca.md))
with a narrower, different one. Moving the whole installation to RSA to
satisfy EKS and Kargo would also move every OTHER audience off ES384 for
no reason of its own.

**A signing algorithm chosen by the CLIENT presenting a request, rather
than the audience the token is FOR.** Rejected: the party that decides
what a token must look like to be accepted is whoever is going to
*verify* it — the audience — not whoever is asking for one on somebody's
behalf. A token exchange makes this concrete: the caller trading a proof
for a `kube-token` is not the party whose verifier decides `alg`: the
Kubernetes cluster's own OIDC provider is, and it is what the audience
denotes.

**A per-request `signing_alg` parameter, chosen by the caller.** Rejected
outright: it would let any caller ask this issuer to sign with whatever
it likes, which is a policy decision — who gets which algorithm — being
handed to the party with the least reason to be trusted with it. The
whole point of keying the choice on the declared audience is that an
operator, not a caller, decides it, exactly the way `requires` already
decides who may hold a client or a resource at all.
