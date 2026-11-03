# 0020 — Grants come from a declared vocabulary, a token carries a fixed set of claims narrowed to its one audience, and token lifetimes have defaults and caps

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #999](https://github.com/truvity/sluis/issues/999).

## Context

[0017](/decisions/0017-identity-and-sign-in/#subjects) says a token carries only the grants of its own boundary, that grants are names declared per audience, and that lifetimes are set per issuer. It leaves open how the names are declared, which claims a token has, what a token carries for each audience, what happens to a name nobody declared, and what the lifetimes are.

v1 answered these in a policy document (v1 ADR 0010, on `master`): grants named `<scope>:<thing>:<role>`, an optional declared vocabulary with role ladders and sensitive scopes, a `groups` claim narrowed to the audience's needs, and token lifetimes with a default and a cap per client. Relying parties already depend on the shape: AWS roles, the Kubernetes API server and Argo CD read the `groups` claim, and some of them split a group name on `:`. The parity milestone keeps those relying parties working ([#787](https://github.com/truvity/sluis/issues/787), [#788](https://github.com/truvity/sluis/issues/788)); the first working version needs the rules they stand on.

Authority is declared only ([0004](/decisions/0004-the-data-model/#storage-classes)): a claim of a token is never taken from anything an operator or a vendor sends at run time.

## Decision

### Grant names and the vocabulary

- **A grant name is `<scope>:<thing>:<role>`,** read as the role on the thing in the scope. Each segment is a non-empty string of ASCII letters, digits, `-` and `_`. A scope is an environment, a company or `all`; a thing is a system, project or application; a role is a rung of that thing's ladder.
- **Every grant name is declared in a vocabulary,** a declared document loaded with the policy ([Install file](/reference/install-file/#policy)), whose shape is on [Vocabulary](/reference/vocabulary/). It lists the scopes, the things with their roles, and for each role what it implies. Unlike v1, where a vocabulary is optional, a v2 installation always has one.
- **A role ladder is explicit and does not inherit across scopes.** `admin: [operator]` means that holding `<scope>:<thing>:admin` holds `<scope>:<thing>:operator` too, transitively and on the same scope and thing. `all:x:admin` never implies `dev:x:admin`. A role may not cover more scopes than a role it implies; a role may be narrowed to some scopes.
- **A scope can be `sensitive`.** A wildcard never reaches a sensitive scope: a sensitive scope is named in full or not granted.
- **A wildcard `*` is allowed only in the scope or the thing position of a declared group binding.** It is refused in `requires`, in a token's claims, in lifetimes and in the role position, and a wildcard that expands to nothing fails the load.
- **An undeclared name is refused at load,** with an error that names the path and never the value ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). The grants of a person are therefore always names of the vocabulary, and the policy files, the client `requires` and the bindings are checked against it by `sluis config check`.

### The claims of a token

A token carries a fixed set of claims. A claim outside the set is not issued, and a declared key for one is refused at load.

| Claim | ID token | Access token | Value |
|---|---|---|---|
| `iss` | yes | yes | The issuer URL |
| `sub` | yes | yes | The person's subject ([0019](/decisions/0019-person-and-upstream-link/)); for a workload, its SPIFFE ID |
| `aud` | yes | yes | Exactly one registered client id ([0017](/decisions/0017-identity-and-sign-in/#audiences)) |
| `exp`, `iat` | yes | yes | Time of expiry and of issue |
| `jti` | no | yes | A random id |
| `client_id` | no | yes | The client that asked |
| `nonce` | when sent | no | The request's nonce |
| `auth_time` | when requested, and always in an access token of a session | yes | When the person last signed in at the upstream; unchanged by a refresh |
| `acr`, `amr` | yes | yes | As the upstream sent them; absent when it sent none |
| `sid` | yes | when a session backs the token | The session id the console lists |
| `groups` | yes | yes | The person's grants, narrowed to the audience (below) |
| `email`, `email_verified` | scope `email` | no | The upstream's claims |
| `name`, `preferred_username` | scope `profile` | no | The upstream's claims, and the directory's account name where there is a directory |
| `cnf` | no | when bound | `jkt` of the client's DPoP key, only for an audience that declares binding |

- **The header of an access token carries `typ` `at+jwt`, a `kid` and the algorithm of the audience** ([REQ-TOKEN-001](/requirements/token/#REQ-TOKEN-001), [REQ-TOKEN-017](/requirements/token/#REQ-TOKEN-017)).
- **Personal data is released only where the granted scopes ask for it,** and never in an access token for another resource ([REQ-TOKEN-006](/requirements/token/#REQ-TOKEN-006), [REQ-TOKEN-022](/requirements/token/#REQ-TOKEN-022)).
- **An absent `acr`, `amr` or `auth_time` stays absent.** sluis never fills in a value the upstream did not send, so a relying party reads absence as unknown.
- **`groups` is flat,** a JSON array of strings, one grant name each, with the ladder expanded. A token carries the grants of its own boundary only.
- **`groups` is narrowed to the audience.** A token carries each held grant whose `<scope>:<thing>` pair appears among the pairs of the audience's `requires`, in any role, so a relying party never reads a grant meant for another system. Narrowing never changes what `requires` admits: admission is checked against the full set. The audience is the client of the request, or for a token exchange the target the exchange was granted, never the client that presents the token.
- **Claims beyond this set, such as claim fragments merged from groups, a per-audience group delimiter, a group-wise lifetime and a signing algorithm other than ES384,** are the parity milestone's ([#786](https://github.com/truvity/sluis/issues/786), [#788](https://github.com/truvity/sluis/issues/788)). When they arrive they are declared and added to this set, and nothing outside the set can be issued before.

### Binding

- **Binding is declared per audience, and the default is a bearer token.** An audience that declares DPoP or mutual TLS gets a bound token with `cnf`; an audience that does not gets a bearer token without `cnf`. The parity relying parties (AWS web identity, the Kubernetes API server, Argo CD) accept bearer JWTs only ([0002](/decisions/0002-families-of-actors/#the-four-families)). The first working version issues bearer tokens and always binds authorization codes with PKCE; DPoP and mutual TLS follow in [#912](https://github.com/truvity/sluis/issues/912).

### Lifetimes

| Token | Default | Maximum |
|---|---|---|
| Access and ID token of a person | 1 hour | 1 hour |
| Access token of an agent session | 30 minutes ([0018](/decisions/0018-sessions/#agent-sessions)) | 1 hour |
| Access token of a machine client or a workload exchange | 1 hour | 1 hour |

- **A token's `exp` is the earliest of its default, the issuer's `token_ttl`, the client's `ttl_cap`, the end of the session that backs it and the end of the proof that was exchanged.** An exchange never yields a token that outlives the token it was made from ([REQ-EXCH-004](/requirements/exch/#REQ-EXCH-004)).
- **The default is set per issuer** with the `token_ttl` key of the front and of each environment boundary ([Install file](/reference/install-file/#front)); a client lowers it with `ttl_cap`. `sluis config check` refuses a value above the maximum, which is fixed in code.
- **The defaults and the maximum are v1's** (`lifetimes.token` is 1 hour, an agent's access token 30 minutes with a ceiling of 1 hour), so a relying party that tuned its refresh to them keeps working. An issuer and a client can only shorten; a longer token is a new record. Refresh tokens and sessions have their own limits ([0018](/decisions/0018-sessions/)).

## Consequences

- A relying party reads a token that holds only the grants it asked for, and a typo in a grant name stops the load, not the first sign-in of the person who needed it.
- The cost is a vocabulary to write and keep, which v1 let an installation skip; a new thing needs a line in it before any policy can name it.
- A relying party that reads a grant beyond its `requires` stops seeing it. Its `requires` must name that thing, and the parity override ([#788](https://github.com/truvity/sluis/issues/788)) covers the cases where one audience must read more.
- Short tokens mean more refreshes, and each is a signing operation on the token key. The load is small beside a card's rate ([Board capacity](/runtimes/bare-metal/#board-capacity)).
- A bearer token copied from a log is useful until it expires, at most one hour; an issuer or a client that wants less sets `token_ttl` or `ttl_cap`.
- Requirements: [REQ-TOKEN-033](/requirements/token/#REQ-TOKEN-033) to [REQ-TOKEN-039](/requirements/token/#REQ-TOKEN-039) and [REQ-POLICY-010](/requirements/policy/#REQ-POLICY-010) to [REQ-POLICY-013](/requirements/policy/#REQ-POLICY-013) are added.

## Roads not taken

- **An optional vocabulary, as in v1.** A name nobody declared would load, and a typo would grant nothing or the wrong thing until someone noticed.
- **Free-form claims merged from groups in the first working version.** Every merge is a way for configuration to widen a token; the fixed set lets the claims be tested as a whole.
- **Every held grant in every token.** A relying party would read grants meant for other systems, and tokens would grow with the person's rights.
- **A report mode before narrowing is enforced, as in v1.** v2 has no installation to migrate; the report mode only delays the rule.
- **Role inheritance across scopes.** `all:x:admin` reaching every environment is the surprise the explicit ladder avoids.
- **Wildcards in `requires`, in token claims or in the role position.** A wildcard there would admit or grant by pattern where the rule should name the thing.
- **A default shorter than v1's, such as 15 minutes.** A leaked bearer token would live a quarter as long, but every relying party tuned to v1's hour would refresh four times as often and each refresh is a signing operation; an issuer or a client can still choose it with `token_ttl` or `ttl_cap`.
- **A maximum above an hour.** A leaked bearer token would stay useful for longer, and v1 itself caps an agent's access token at an hour.
- **Sender-constrained tokens for every audience.** The parity relying parties cannot check a binding, so those tokens would be bearer anyway.

## Follow-ups

- Per-audience group override, delimiter and signing algorithm; claim fragments; lifetimes by group: [#786](https://github.com/truvity/sluis/issues/786), [#787](https://github.com/truvity/sluis/issues/787), [#788](https://github.com/truvity/sluis/issues/788).
- DPoP and mutual-TLS binding: [#912](https://github.com/truvity/sluis/issues/912).
