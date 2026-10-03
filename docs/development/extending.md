# Extension points

Eight places something new plugs in, each behind an interface that already
has one implementation. The rule for all of them: the new thing ships
with its fake and its acceptance scenario, or it is not done.

## 1. A directory backend (Entra, LDAP, …)

`backend/google` is the worked example, and the registry in
`internal/app` (`backendOpeners`) is where a new one is announced: a
build that lacks a declared backend says exactly what it lacks rather
than starting up empty.

`backend/`: implement `Backend` — `Kind`, `Tenant`, `Probe`, `Accounts`,
`Groups`, `Account`, `GroupsOf` and `Revoke` — and the way it is opened:
from a consent the console runs, or from an uploaded key. Register it
under a name. The service's record, routing, snapshots, freshness and
console need no change; Directories gains a button. Ship: the
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

`policy/`: a matcher is a `Matcher` over a verified proof's claims; a
new proof kind brings its own. The seven tables are the whole schema: a
need that cannot be met by a new group, a new client or a new matcher
kind is a need for a new dimension, and the answer to that is no — see
[reference/policy.md](../reference/policy.md) for why.

## 4. A middleware adapter

There are **no framework adapters yet** — `net/http` is what ships, and
a fiber, gRPC or connect adapter would be additive. Writing one means: read the token with `identity.TokenFrom`
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

`cmd/accessctl`: subcommands share the login cache, the issuer client
and the ambient-token detection in that package; a new one that needs
none of them probably belongs in a script. Keep the CI path working:
every command must behave with an ambient platform token and no cache,
and it ships to a job through the release's Nix flake like the rest.

## 7. An audit action

What access-roster records is its catalogue,
[`internal/audit/catalogue/roster.yaml`](../../internal/audit/catalogue/roster.yaml),
held to the audit component's own toolchain. To record something new:
declare the action there — a fact, `roster.<thing>.<verb>` in the past
tense, with its operation, categories, profiles, target types, a data
schema beside it for anything it carries, and a sentence whose arguments
name the record's fields with underscores (`{targets_0_id}`,
`{data_org}`) — and add one constructor for it in
[`internal/audit/events.go`](../../internal/audit/events.go), the only
place its name is spelled. `just audit-catalogue` validates the document,
fails on an action emitted and not declared, and regenerates the console's
sentences; `TestTheConstructorsAreTheCatalogue` fails on one declared with
no constructor. **Any** change to the catalogue document, a new action as much
as a changed one, needs a new `version` in `roster.yaml` AND the released
document saved as `internal/audit/catalogue/testdata/released/roster-<version>.yaml`:
an audit installation refuses a different document under a version it already
holds, which stops the service at start (v1.41.0 and v1.42.0 did that, fixed in
v1.42.1), and `TestAReleasedCatalogueVersionIsNeverChanged` fails on it.
`just audit-catalogue` also regenerates `frontend/src/auditSentences.ts`;
commit it, or the recipe fails on the diff. Register the new data schema file
beside `roster.yaml` and add it to the action's `data_schema`. Never put an address, a name or a secret in data: an
identifier belongs in the actor, the subject or a target, where the
installation's profiles treat it.

## 8. A reconciler for another system (a SaaS, a forge)

GitHub organisations and Slack workspaces are reconcilers: a loop that, every
pass and for every target the policy binds, reads what the system holds, asks the
console who should hold it, decides, acts where the target is enabled, and
reports. `internal/rails` is what they share, with only the nouns different:
`Run` and `Pacing` (the pass loop and its backoff while a rollout leaves the
console on another policy), `Directory`, `Holders`, `Vouch` and `Removal` (the
console's two questions, each answer gated by `PolicyGuard`, and the rule that a
removal rests on a vouched answer or does not happen), `Ledger` (a held row is
recorded once, not again after a restart), `Journal` (the last good report per
target, so a failed pass keeps what was known), `CheckBreaker` and `Fingerprint`
(the circuit breaker: a pass that would remove more than half of a target waits
for an operator to confirm exactly that set) and `Switch` (the dry-run gate a
target is born behind). It is deliberately not a framework: there is no
`Reconciler` interface, and the decision, the change calls, the credentials, the
status document and the audit actions stay in the system's own package
(`internal/githubroster`, `internal/slackroster`); see
[ADR 0024](../decisions/0024-reconciler-rails-are-shared-pieces-not-a-framework.md).
A new one ships with: its fake of the system (`internal/slackapp/slackfake` is
the worked example), a pure `reconcile` package tested without I/O, a status
document the console shows, a chart value `…Roster.config.enabled…` (born disabled), its
audit actions, and a `docs/connect/<system>.md` page. Order the rollout so the
console, which the controller reads, goes first.

## What is not an extension point

Authentication. There is no interface for "a way to prove who you are
that this repository checks itself". Passwords, MFA, consent screens and
user records are an identity provider's; the day one is needed, the
answer is to run one and connect it as a proof.
