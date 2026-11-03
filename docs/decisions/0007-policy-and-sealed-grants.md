# 0007 — Policy is written in Cedar and evaluated by a Rust policy actor

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

Every credential sluis mints, and every sign-in it admits, rests on one question: may this subject do this? In v1 the answer comes from a YAML policy document with grant names of the form `scope:thing:role` (v1 ADR 0010, on `master`), evaluated inside the issuer next to the request parser and the signing keys.

v2 separates the decision from everything else. `policy` is its own actor with no state and no network ([0041](/decisions/0041-core-actors-with-one-responsibility-each/#the-actors)). It reads declared, reviewed policy, is given the facts of a request, and returns a decision as a sealed grant. Integrations return facts and never decide, and a minter acts only on a grant that `policy` made.

Forces: the actor decides whether a mint is allowed, so it must be small, memory-safe and fail closed; the language needs a published grammar and a conformance corpus; a policy that does not fit its schema must be refused before it takes effect; the policy is a file for reviewers; and operators want some changes, such as granting a standard set of rights or suspending someone, without a review and without a writable policy API.

## Decision

- **Cedar is the policy language.** Policies are Cedar policies, checked against a Cedar schema. Cedar is in the [standards register](/standards/) with its pinned version.
- **The `policy` actor is written in Rust and uses the `cedar-policy` crate**, the reference implementation, to parse, validate and evaluate ([0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)).
- **`policy` decides from declared policy and the request.** It has no state port and no network; facts reach it only in the request. Policy is declared configuration ([0004](/decisions/0004-the-data-model/#origins)), never operator-set, with the one exception of template links below.
- **The validator runs at load and at every reload.** A policy that does not fit the schema is refused with an error naming the offending path, and the actor does not start with it. Declared policy may live-reload as a whole versioned snapshot: validated, swapped atomically and audited with its digest; a snapshot that fails validation is refused while the policy in force stays.
- **Evaluation fails closed.** A request is denied unless a policy explicitly permits it, an explicit `forbid` wins over a `permit`, and an evaluation that cannot be completed is a denial.
- **The output is a grant sealed under the environment's sealing key, not signed** ([0006](/decisions/0006-keys-and-sealing/#grants-are-sealed-not-signed)). `policy` asks the keys port to seal it and holds no key.
- **Callers do not link Cedar.** Other actors reach `policy` through its ConnectRPC contract ([0002](/decisions/0002-families-of-actors/#contracts)); the language never appears in their code.
- **Grant names are declared in a vocabulary and narrowed per audience**, continuing v1 ADR 0010 ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)).

### Template links

- **Template-linked policies are the one exception to declared policy.** Policy logic stays declared: Cedar templates, and a declared delegation policy that says who may link which template to which principals and resources.
- **Within those bounds the console creates and removes template links.** A link adds no logic a reviewer has not seen in the template. Tighten-only actions, such as suspending a subject or revoking a grant, take effect at once.
- **Links reach `policy` in the request.** A link is an operator-set record ([0004](/decisions/0004-the-data-model/#origins)); the actor that asks for a decision sends the links that apply to the request's principal and resource with the facts, so `policy` keeps no state port.
- **The same pattern issues records.** Instances such as tenants, accounts and upstream connections are issued under declared templates and a declared delegation policy ([0047](/decisions/0047-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/#instances-are-issued-under-declared-templates)).
- The record kind of a link, its owning writer and the Cedar schema of requests, entities and actions are on the [Policy](/reference/policy/) page, which fixes them for the first working version.

## Consequences

- The decision is made by a small process that cannot read or exfiltrate anything. Its failure modes are a wrong decision and a refusal to decide, and both are visible in the audit trail.
- An operator can grant a standard set of rights, or suspend someone, from the console without a pull request, and the delegation policy bounds what a stolen operator session can link. The cost is a template and a delegation rule for each right granted this way.
- The policy is a file with a grammar, a validator and a conformance corpus; a test states a policy's behaviour as a request and an expected decision.
- Rust sits in the smallest and most sensitive actor. Its build, packaging and supply-chain review are shared with the other Rust executables of [0012](/decisions/0012-the-language-follows-the-executable/).
- Cedar moves. The language and the crate are pinned, and a change of version is a reviewed change that runs the conformance cases first.
- The v1 YAML policy does not carry over unchanged. Operators who migrate rewrite their grants in Cedar; the cutover tooling belongs to the parity milestone ([#1017](https://github.com/truvity/sluis/issues/1017)).

## Roads not taken

- **Keep a YAML policy document of our own.** Familiar from v1, but a grammar, validator and matching rules of our own with no published corpus to test against.
- **Cedar in Go, inside the core.** One language for the core, but the reference implementation and its validator are Rust, and a gap between a port and the reference is a gap in a decision engine.
- **Open Policy Agent with Rego.** Widely used, but a general query language that is hard to bound, without Cedar's schema check at load.
- **CEL with rules in our own format.** Safe to evaluate, but no policy sets, no defined `permit`/`forbid` combination and no schema validator for the whole set.
- **Rules written in the actor's code.** A policy change would be a release, and reviewers would read code, not policy.
- **Policies written from the console.** A writable policy API: a stolen operator session could widen any grant, and `policy` would need a state port.
- **A decision point with state or network access.** It could fetch facts itself, but becomes a target and its decisions can no longer be reviewed as a file.

## Follow-ups

- Cutover and migration from v1, including policy: [#1017](https://github.com/truvity/sluis/issues/1017).
