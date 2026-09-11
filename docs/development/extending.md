# Extension points

Six places something new plugs in, each behind an interface that already
has one implementation. The rule for all of them: the new thing ships
with its fake and its acceptance scenario, or it is not done.

## 1. A directory backend (Entra, LDAP, …)

`backend/google` is the worked example, and `cmd/directory-roster`'s
registry is where a new one is announced: a build that lacks a declared
backend says exactly what it lacks rather than starting up empty.

`pkg/backend`: implement `Backend` — `Probe`, `Domains`, `Users`,
`Groups`, `Members` (atomic per group), plus `Consent` for the
admin-consent flow or `KeyCredential` for an uploaded key — and register
it under a name. The hub's record, routing, snapshots, freshness and
console need no change; Providers gains a button. Ship: the
backend's fake, a consent-runbook page, and the acceptance scenarios
connect / revoke / domain move against the fake.

## 2. A proof kind (another CI platform, a cloud's workload identity)

`internal/verify`: implement `issuer.Verifier` — `Verify(ctx, token,
tokenType) (issuer.Proof, error)` — and, if the proof carries attributes
no matcher reads yet, a matcher kind in `policy` for them. `Workload`
(TokenReview) and `GitHub` (the platform's JWKS, an owner allow-list, the
issuer's own URL as the required audience) are the two that exist; GitLab
or a cloud's instance identity are the same shape.

Two rules the existing ones keep and a new one must. **Recognition and
refusal are different answers**: a token this verifier does not own comes
back `issuer.ErrUnverified` so the next verifier may try it, and a token
it owns and rejects is final — never retried as something else. **The
trust boundary is configuration the verifier refuses to run without**
(an owner list, an audience), never a default: anybody can obtain a valid
token from a public platform for their own repository, so signature and
expiry alone prove that *a* job ran somewhere. A verifier adds a proof to
the issuer's estate anchor; it never adds a third anchor to a service
([../design/trust.md](../design/trust.md)). Ship: a fake issuer minting
real signatures in the test, the refusal cases (a stranger's owner, a
foreign audience, a forged signature, an empty allow-list), and a policy
test.

## 3. A matcher kind, or a table

`pkg/policy`: a matcher is a `Matcher` over a verified proof's claims; a
new proof kind brings its own. The five tables are the whole schema: a
need that cannot be met by a new group, a new client or a new matcher
kind is a need for a new dimension, and the answer to that is no — see
[reference/policy.md](../reference/policy.md) for why.

## 4. A middleware adapter

There are **no framework adapters yet** — `net/http` is what ships, and
the fiber, gRPC and connect adapters are designed and ticketed
(INF-648). Writing one means: read the token with `identity.TokenFrom`
or the framework's own accessor, ask each `identity.Verifier` in turn,
put the resulting `identity.Verified` into the framework's context with
`identity.WithVerified`, and serve `identity.WhoAmI` at
`identity.WhoAmIPath`.

Each is additive and changes nothing above it: they sit on the same
`Verified` that `identity.Middleware` already produces, which is the
reason the type is the seam.

## 5. A relying-party recipe

`docs/connect/<thing>.md`: what the relying party trusts (issuer, client,
audience or groups), the client it needs, the policy shape,
the person side and the job side. If it needs a new audience prefix,
name it in [reference/policy.md](../reference/policy.md).

## 6. A CLI subcommand

`cmd/accessctl`: subcommands share the login cache and the issuer client
in `internal/cli`; a new one that needs neither probably belongs in a
script. Keep the CI detection path working: every command must behave
with an ambient platform token and no cache.

## What is not an extension point

Authentication. There is no interface for "a way to prove who you are
that this repository checks itself". Passwords, MFA, consent screens and
user records are an identity provider's; the day one is needed, the
answer is to run one and connect it as a proof.
