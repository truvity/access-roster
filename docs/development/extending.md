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
console need no change; Directories gains a button. Ship: the
backend's fake, a consent-runbook page, and the acceptance scenarios
connect / revoke / domain move against the fake.

## 2. A proof kind (another CI platform, a cloud's workload identity)

`pkg/proof`: implement `Verifier` — given a token, return a verified
`Proof{Issuer, Subject, Claims}` or an error — and a subject kind in the
matcher kind that reads its claims. GitHub is the first; GitLab or a cloud's
instance identity are the same shape. Ship: fixtures of real tokens with
rotated keys, and a policy test.

## 3. A matcher kind, or a table

`pkg/policy`: a matcher is a `Matcher` over a verified proof's claims; a
new proof kind brings its own. The five tables are the whole schema: a
need that cannot be met by a new group, a new client or a new matcher
kind is a need for a new dimension, and the answer to that is no — see
[reference/policy.md](../reference/policy.md) for why.

## 4. A middleware adapter

`identity/<framework>mw`: wrap the framework's request into
`identity.Request{Header(name) string}`, call the shared `Authenticate`,
put the `Identity` in the context the framework uses, serve
`/.access/whoami`. The four existing adapters are each under a hundred
lines; a fifth should be too.

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
