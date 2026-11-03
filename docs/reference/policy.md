---
title: Policy
description: "The Cedar schema of sluis policy: entity types, actions and context, how grants and template links reach the stateless policy actor, and a worked example."
status: target
sidebar:
  order: 7
---

`policy` decides every question of the form "does this person hold this grant", "may this person have a token for this client" and "may this workflow have the release key sign" ([ADR 0007](/decisions/0007-policy-and-sealed-grants/)). It has no state and no network, so everything it needs arrives in the request. This page fixes what the request holds, the Cedar schema the policy is written against, how the grants of a person are found, how an operator's template links reach `policy`, and one policy file with test vectors. Who calls `policy` is in the [actor registry](/reference/actors/#policy); the install-file keys that name the files are [`policy`](/reference/install-file/#policy).

## The schema is sluis's, the policy is the operator's

- **One schema, version 1, fixed by sluis and embedded in `policy`.** An operator writes policy against it and cannot add a type, an action or an attribute. This keeps every request checkable: `policy` validates each request against the schema and refuses one that does not fit, and every policy file against it at load and at every reload ([ADR 0007](/decisions/0007-policy-and-sealed-grants/#decision)).
- **No namespace.** The names below are the whole vocabulary; nothing an operator writes can collide with them.
- **Adding is compatible.** A type, an action, an optional attribute or a new optional context name may be added in a release; removing or changing one is a new schema version beside this one, as for the install file ([Install file](/reference/install-file/)).
- **The file is** [`policy-schema.cedarschema`](https://github.com/truvity/sluis/blob/main/docs/reference/policy-schema.cedarschema), in the Cedar schema syntax of Cedar 4.14.0 (language version 4.6, checked on 2026-11-01). This copy is checked against that file (`just check-examples`).

<!-- example: docs/reference/policy-schema.cedarschema -->
```text
// The Cedar schema of sluis policy, schema version 1 (the first working version).
// It is fixed by sluis and embedded in the `policy` actor; an operator writes policy against it
// and cannot add types, actions or attributes. Every request is validated against it.

// An upstream account, named by the upstream's declared name and the value of the upstream's
// subject claim: `<upstream>/<claim value>` (ADR 0019). An operator can name an account before
// its first sign-in, which the random subject of a person does not allow. `org` is the company
// that owns the upstream.
entity Account = {
  upstream: String,
  org: String,
};

// A grant of the vocabulary, written `<scope>:<thing>:<role>` (ADR 0020). `sensitive` is true
// when its scope is sensitive.
entity Grant = {
  scope: String,
  thing: String,
  role: String,
  sensitive: Bool,
};

// A person, known by the opaque `sub` of the issuer, and linked to the upstream account they
// signed in with. `org` is the company claim, and `state` is `live` or `held` (ADR 0019: an
// operator holds a person on the console). `grants` is not sent by the asking actor: `policy`
// finds it with the action "grant.hold" and adds it before it decides any other action.
entity Person in [Account] = {
  org: String,
  state: String,
  grants?: Set<Grant>,
};

// An environment boundary, such as `dev`.
entity Boundary;

// A client of an issuer. The token's `aud` is exactly one client id, so a client is also the
// resource of a token request. `requires` is the client's declared list of grants, and `kind`
// is `public`, `confidential` or `exchange`.
entity Client in [Boundary] = {
  kind: String,
  requires: Set<Grant>,
};

// A workload that proved its identity. For a GitHub Actions job the attributes are the claims of
// its verified token; a name the proof does not carry is absent.
entity Workload = {
  verifier: String,
  repository?: String,
  ref?: String,
  workflow?: String,
  environment?: String,
};

// A signing key of a boundary, named by its purpose, such as `release-signing`.
entity SigningKey in [Boundary];

// What the asking actor knows about how the person signed in. A name that the upstream did not
// send is absent, which a policy reads as unknown.
type Authentication = {
  acr?: String,
  amr?: Set<String>,
  // Seconds since the person last authenticated for this boundary, counted by the asking actor.
  auth_age?: Long,
};

// Whether a person holds a grant. The policy files bind groups to grants with this action.
action "grant.hold" appliesTo {
  principal: Person,
  resource: Grant,
  context: {},
};

// A person asks for a token for a client, at a code exchange or a refresh.
action "token.issue" appliesTo {
  principal: Person,
  resource: Client,
  context: Authentication,
};

// A person's token is exchanged for a token for a client of a boundary (RFC 8693).
action "token.exchange" appliesTo {
  principal: Person,
  resource: Client,
  context: Authentication,
};

// A workload asks for a signature by a signing key (ADR 0024). The context is the SHA-384 of the
// content in lower-case hex, and its length in bytes.
action "artifact.sign" appliesTo {
  principal: Workload,
  resource: SigningKey,
  context: {
    content_sha384: String,
    content_length: Long,
  },
};

// An operator asks to link a template in a boundary. The context names the template and the
// values of its slots, for the delegation policy to judge.
action "policy.link" appliesTo {
  principal: Person,
  resource: Boundary,
  context: {
    template: String,
    principal_account?: Account,
    resource_grant?: Grant,
  },
};
```

## Entity types

The types follow the [actor registry](/reference/actors/) and the [record kinds](/reference/storage/#record-kinds-of-the-first-working-version): a type exists when an actor of the first working version asks about it ([principle 8](/principles/#8-nothing-without-a-consumer)). The asking actor sends the facts as a slice of entities with the request; `policy` reads no store.

| Type | What it is | Facts sent by | Id |
|---|---|---|---|
| `Account` | An account of an upstream, named by the pair that links a person: the upstream's declared name and the value of its subject claim ([ADR 0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)) | `session` or `exchange`, from the `upstream-link` of the person | `<upstream>/<claim value>`, such as `workforce/u-1001`; never an e-mail address |
| `Person` | A person who signed in, `in` the `Account` they are linked by | The asker, from the session and the `person` record | The opaque subject ([ADR 0019](/decisions/0019-person-and-upstream-link/#the-records)) |
| `Grant` | A grant of the vocabulary, with its scope, thing, role and whether the scope is sensitive | `policy`, from the vocabulary | `<scope>:<thing>:<role>`, such as `dev:example-app:user` ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)) |
| `Client` | A client of an issuer, and the resource of a token request | The asker, from the install file's [`clients`](/reference/install-file/#clients) and `boundaries.<name>.clients` | `<boundary>/<client id>`, such as `dev/example-app`; the group issuer's clients are under `front` |
| `Boundary` | An environment boundary, and the place a link lives in | The asker, from [`boundaries`](/reference/install-file/#boundaries) | The boundary's name; `front` for the group issuer |
| `Workload` | A workload that proved its identity: in the first version a GitHub Actions job, checked by the `github-oidc` verifier | `exchange`, from the verified proof | `<verifier>/<proof subject>` |
| `SigningKey` | A signing key of a boundary | `exchange` | The key's purpose, `release-signing` ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#who-does-what)) |

- **A person is named by an account, because an operator cannot know a subject.** The subject is 128 random bits assigned at the first sign-in, so a binding or a link written before it names the account that will be linked. A binding never names an e-mail address, which does not identify ([ADR 0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)). `Account.org` is the `org` key of the account's upstream in the install file, the company that owns it ([Install file](/reference/install-file/#upstreams)), and `Person.org` is the `org` of the account the person is linked by, so it is the company claim of [ADR 0017](/decisions/0017-identity-and-sign-in/#issuers). The asker reads it from the install file and never from the upstream's answer, and no policy file sets it.
- **`state` is `live` or `held`.** An operator's `person-hold` is a tighten-only action that takes effect at once; `session` sends the state, and the first `forbid` of the example refuses a person who is not live. Lifting a hold gives back only what the policy grants.
- **A client's id carries its issuer.** Client ids are unique per issuer, not across issuers ([ADR 0017](/decisions/0017-identity-and-sign-in/#audiences)), and a Cedar entity id must be unique, so `dev/example-app` and `prod/example-app` are two entities. A `Client` is `in` its `Boundary`, so a policy can say "any client of `dev`". `Client.requires` is the install file's `requires`, a set of `Grant`.
- **`Workload` attributes are the verified claims of the proof.** For a GitHub Actions job they are the repository, the ref, the workflow and the environment ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#who-does-what)); a name the proof does not carry is absent, and a policy tests `has` before it reads.

### What comes with parity

Each of these is added by the record or pull request that first asks about it, and is compatible with version 1:

| Added | By | Because |
|---|---|---|
| `Group`, and a binding that names a directory group | Directory sync ([#805](https://github.com/truvity/sluis/issues/805)) | The first working version reads no directory; internal groups are accounts ([ADR 0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)) |
| `Host` and the action `cert.issue` | Host enrolment ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/)) | Their first asker is `exchange` with a host proof |
| `Resource` | Declared resources ([#979](https://github.com/truvity/sluis/issues/979)) | A resource is a declared URL with its own `requires`, which schema v1 of the install file does not have |
| Attributes for the claims of a token | The per-audience claim override ([#788](https://github.com/truvity/sluis/issues/788)) | The first version issues the fixed set of [ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token) |

## Actions

| Action | Principal | Resource | Asked by | Meaning |
|---|---|---|---|---|
| `grant.hold` | `Person` | `Grant` | `policy`, for itself | Whether this person holds this grant. The bindings of the policy files are written on this action |
| `token.issue` | `Person` | `Client` | `session` | Whether this person may have a token for this client, at a code exchange or a refresh |
| `token.exchange` | `Person` | `Client` | `exchange` | Whether this person's token may become a token for this client, as when `sluis login` exchanges the group issuer's token at a boundary |
| `artifact.sign` | `Workload` | `SigningKey` | `exchange` | Whether this workload may have this key sign this content ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/)) |
| `policy.link` | `Person` (the operator) | `Boundary` | `session`, for a write that `console` routed | Whether this operator may link this template, with these slot values, in this boundary |

There is no separate action for step-up. A request that needs a fresher or stronger authentication is denied by a policy that says so ([below](#step-up)), which keeps the one question "may this person have this token" in one place.

## Context

The context of `token.issue` and `token.exchange` is the same record, `Authentication`:

| Name | Type | Meaning |
|---|---|---|
| `acr` | `String` | The authentication class reference of the person's latest authentication, as the upstream or sluis states it |
| `amr` | `Set<String>` | The methods used, with the values of RFC 8176 (`pwd`, `mfa`, `hwk`) |
| `auth_age` | `Long` | Seconds since the person last authenticated for this boundary, counted by the asker from the session's `auth_time` |

- **An absent name is unknown.** An upstream such as Dex sends no `acr`, `amr` or `auth_time` ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)), and sluis never fills one in ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)). The asker leaves the names out, and a policy tests `context has amr` before it reads `context.amr` and treats absence as "not shown": a rule that requires multi-factor authentication is then not met.
- **`policy` has no clock.** The asker counts `auth_age`, so a request and its answer are the same on any day, which is what makes the vectors below repeatable ([principle 6](/principles/#6-generic-products-joined-by-a-contract)).
- **The values of `acr` are the installation's.** The example uses `urn:example:acr:mfa`.

`artifact.sign` carries `content_sha384`, the SHA-384 of the content in lower-case hex, and `content_length`. `grant.hold` has no context. `policy.link` carries `template`, the template's id, and the slot values that the template has: `principal_account` for a `?principal` slot and `resource_grant` for a `?resource` slot. It holds what the delegation policy needs to judge the link, and nothing else.

## How a person's grants are found

[ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary) has grants, not groups, as what a person holds, and `policy` is where facts become grants. `policy` decides a request about a person in two steps:

1. **Find the grants.** For every grant of the vocabulary, `policy` asks `grant.hold` for the person, with the bindings and links of the policy as they stand. It then adds every grant that a held role implies, by the ladder of the vocabulary, on the same scope and thing, and puts the full set into `Person.grants`.
2. **Decide the action** with the person's grants in the entity. The standard rule `principal has grants && resource.requires.containsAny(principal.grants)` is the Cedar form of "at least one required grant".

- **The answer carries the full set** of held grants, so that the asker narrows the `groups` claim to the audience's `<scope>:<thing>` pairs ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); admission was decided on the full set.
- **A sensitive grant is held only by a binding that names it in full.** A grant of a sensitive scope counts as held only when a determining policy has that grant as its resource, `resource == Grant::"prod:example-app:admin"`; `policy` reads the scope of the determining policies for this ([REQ-POLICY-011](/requirements/policy/#REQ-POLICY-011)). A wildcard written as a condition on `resource.scope` or `resource.role` can give any other grant, and Cedar alone would give it a sensitive one too.
- **The loader tries each binding.** It evaluates every static policy on `grant.hold` for a probe person of the account the policy names against every grant of the vocabulary, and refuses a policy that no grant satisfies ("a wildcard that expands to nothing", [REQ-POLICY-012](/requirements/policy/#REQ-POLICY-012)) and one that satisfies several roles of one scope and thing at once (a wildcard in the role position). A grant name that is not in the vocabulary, as a `Grant::"…"` in a policy file, is refused at load with the path ([REQ-POLICY-010](/requirements/policy/#REQ-POLICY-010)).
- **The vocabulary is a file beside the policy,** [`policy/vocabulary.yaml`](https://github.com/truvity/sluis/blob/main/tests/installations/local/policy/vocabulary.yaml) in the example, named by `policy.vocabulary`. Its shape is on [Vocabulary](/reference/vocabulary/). `policy` builds the `Grant` entities from it: one for every scope, thing and role the file declares, with `sensitive` taken from the scope.

## What a decision holds

`policy`'s contract is a ConnectRPC service like the others ([Contracts and errors](/reference/contracts/)). Its request and answer carry:

| In the request | |
|---|---|
| The question | The principal, action and resource as entity ids, and the context |
| The facts | The slice of entities the question needs: the person with the account, the client with its `requires`, the boundary, or the workload and the key |
| The links | The template links that apply, as [below](#template-links) |

| In the answer | |
|---|---|
| The decision | `allow` or `deny`. A policy that errors counts as no permit; a request that does not fit the schema is refused, not decided |
| The reasons | The ids of the determining policies, each with its annotations |
| The grants | For a person: the full set of held grants, after the ladder |
| The snapshot | The digest of the policy set, the vocabulary and the links, and the version of the schema, for the audit record |
| The sealed grant | On `allow` only: the mint grant, or for `artifact.sign` the signing grant, sealed under the environment's sealing key ([ADR 0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)) |

The `proto/` file is written with the first code. Every decision is audited with its reasons and the snapshot digest.

### Policy ids and annotations

- **Every policy and template carries an `@id`.** The id is stable and appears in the reasons, the audit record and the tests. A policy with no `@id`, or a repeated one, is refused at load.
- **The only annotation sluis reads is `@step_up`,** on a `forbid`. Other annotations are carried in the reasons and ignored.

## Step-up

[ADR 0017](/decisions/0017-identity-and-sign-in/#step-up) has `policy` decide which clients need multi-factor authentication and how fresh it must be, and the asker answer with RFC 9470. The two meet in an annotation:

- **A `forbid` that expresses a step-up rule carries `@step_up("acr_values=<values> max_age=<seconds>")`,** the values RFC 9470 puts in `insufficient_user_authentication`.
- **When the determining policies of a `deny` include one with `@step_up`,** `session` answers `insufficient_user_authentication` with those values and the person signs in again. When there is none, the answer is a plain refusal, and it looks the same for an unknown and a refused client ([Contracts and errors](/reference/contracts/#oauth-and-openid-connect-endpoints)).
- **A rule is written with `unless`:** the `forbid` applies unless the context shows what is asked for. Unknown context therefore forbids, and the person is asked to step up.

## Template links

A template is declared policy, in a policy file, with `?principal` and `?resource` slots. A **link** gives the slots values and so makes a policy. Links are the one operator-set part of policy ([ADR 0007](/decisions/0007-policy-and-sealed-grants/#template-links), [ADR 0004](/decisions/0004-the-data-model/#storage-classes)). In the first version the templates bind an account to a grant, or revoke a grant from an account.

### Making a link

1. An operator asks the console for a link: a template id and the slot values.
2. `console` routes the write to the actor that owns the record kind, which is `session`.
3. `session` asks `policy` the question `policy.link` with the operator as principal, the boundary as resource and the template and slot values as context. A `deny` ends it.
4. On `allow`, `session` writes the link into the record `policy-link-set` of the boundary by compare-and-set, and the audit record names the operator, the template, the slot values and the delegation policy that permitted it.

- **The delegation policy is Cedar too.** It is a set of ordinary policies in the policy files, on the action `policy.link`. A template with no delegation policy cannot be linked by anyone: the link set stays as it is.
- **One record, one owner.** The kind is `policy-link-set`, owned by `session`, a reader being `exchange` ([Storage](/reference/storage/#record-kinds-of-the-first-working-version)). The first working version's state port has no delete and no listing by prefix ([Storage](/reference/storage/#state)), so the whole set of a boundary is one record under the fixed id `links`, changed by compare-and-set, and removing a link writes the set without it. Parity may split the set when the port can list.
- **A link has** an id, the template id, the slot values as entity ids, who made it and when. A link made twice with the same template and slot values is one link.
- **Tighten-only.** A template whose effect is `forbid` can only narrow what is permitted; the console offers those for "revoke a grant". The delegation policy still says who may link it, and a link takes effect on the next decision, with no cache between the record and the request. Suspending a person is not a link: it is a `person-hold`, which `session` writes and sends as `state`.

### Sending links to `policy`

- **The asker reads the set before each decision** and sends, with the facts, the links whose slot values are the request's account, grant, client or boundary. `policy` keeps nothing between requests.
- **`policy` links them in memory,** validates each against the loaded templates, and evaluates. The links are part of the snapshot digest of the audit record.
- **A link that cannot be applied denies the request.** An unknown template, a slot of the wrong type or a grant the vocabulary no longer has means the policy files and the link set have drifted, and ignoring the link could drop a `forbid`. The denial is audited with the link id. `sluis config check --live` reports such a link as a `fail`, so that an edit to the policy files that orphans a link is found before it is deployed ([Commands](/reference/cli/#sluis-config-check-and-explain)).

### The grants of one tenant

A company is a tenant: its accounts and its grants carry its `org`, and its administrators may bind accounts of their own `org` to grants in their own scope, with no review of the operator's and no change to the policy files. The delegation policy of the example below does this in one policy; the vectors show what it allows and what it refuses. In the example a company's scope has the company's name, which is the convention the delegation policy states ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary): a scope is an environment, a company or `all`).

## A worked example

The local installation's [example install file](/reference/install-file/#the-example-file-for-local) names `policy/local.cedar` and `policy/vocabulary.yaml`. It declares one client, `example-app` in the boundary `dev`, which requires one of two grants: `dev:example-app:user`, or the same role in the scope of the company `acme`. The vocabulary has one thing, `example-app`, with a ladder of three roles, and three scopes, one of them sensitive.

<!-- example: tests/installations/local/policy/vocabulary.yaml -->
```yaml
# The grant vocabulary of the local installation (ADR 0020). Schema v1:
# https://sluis.id/reference/vocabulary/
#
# A grant is <scope>:<thing>:<role>. Every scope has every thing, and every role of a thing exists
# in every scope unless the role names its `scopes`. A role implies the roles listed under it, on
# the same scope and thing.
$schema: https://sluis.id/schema/vocabulary/v1/vocabulary.schema.json

scopes:
  dev: {}                   # an environment
  acme: {}                  # a company
  prod: { sensitive: true } # named in full or not granted; a wildcard never reaches it

things:
  example-app:
    roles:
      user: []
      operator: [user]
      admin: [operator]
```

The policy has the held-person rule, four bindings, the standard rule, one step-up rule, the signing rule, two templates and two delegation policies.

<!-- example: tests/installations/local/policy/local.cedar -->
```text
// The policy of the local installation (tests/installations/local), written against the Cedar
// schema of sluis policy, version 1, and the vocabulary beside it. The ids are stable: audit
// records and tests name them.

// ---- A held person gets nothing --------------------------------------------------------

// An operator's hold takes effect at once and outlasts every binding (ADR 0019).
@id("person-not-live")
forbid (principal is Person, action, resource)
when { principal.state != "live" };

// ---- Which accounts hold which grants (the bindings) -----------------------------------

// A binding names accounts, by the upstream's declared name and the value of its subject claim,
// never by e-mail address. These two hold the user role of the example app.
@id("bind-example-users")
permit (
  principal is Person,
  action == Action::"grant.hold",
  resource == Grant::"dev:example-app:user"
)
when { principal in [Account::"workforce/u-1001", Account::"workforce/u-1002"] };

// A wildcard in the thing position: this account holds the admin role of every thing in the
// scope `dev`.
@id("bind-dev-admins")
permit (principal in Account::"workforce/u-2001", action == Action::"grant.hold", resource)
when { resource.scope == "dev" && resource.role == "admin" };

// A sensitive scope is named in full.
@id("bind-prod-admins")
permit (
  principal in Account::"workforce/u-3001",
  action == Action::"grant.hold",
  resource == Grant::"prod:example-app:admin"
);

// A wildcard that reaches a sensitive scope. Cedar permits it, and `policy` does not count the
// grants it reaches in `prod`, because only a policy that names a sensitive grant in full may
// give it (REQ-POLICY-011).
@id("bind-all-admins")
permit (principal in Account::"workforce/u-4001", action == Action::"grant.hold", resource)
when { resource.role == "admin" };

// ---- What a person may get a token for -------------------------------------------------

// A person who holds one of a client's required grants may have a token for it.
@id("token-requires")
permit (
  principal is Person,
  action in [Action::"token.issue", Action::"token.exchange"],
  resource is Client
)
when { principal has grants && resource.requires.containsAny(principal.grants) };

// ---- Step-up ---------------------------------------------------------------------------

// `example-app` of the `dev` boundary wants multi-factor authentication no older than 15
// minutes. When a request carries no `amr` or no `auth_age`, as with an upstream that sends
// none, the answer is "not shown", so the person is asked to step up. The annotation tells
// `session` what to ask for (RFC 9470): the values of `acr_values` and `max_age` that it puts
// in `insufficient_user_authentication`.
@id("example-app-fresh-mfa")
@step_up("acr_values=urn:example:acr:mfa max_age=900")
forbid (
  principal is Person,
  action in [Action::"token.issue", Action::"token.exchange"],
  resource == Client::"dev/example-app"
)
unless {
  context has amr && context.amr.contains("mfa") &&
  context has auth_age && context.auth_age <= 900
};

// ---- Signing a release ------------------------------------------------------------------

// The release workflow of one repository, on a version tag, in the `release` environment, may
// have the release key sign.
@id("release-signing-from-tag")
permit (
  principal is Workload,
  action == Action::"artifact.sign",
  resource == SigningKey::"release-signing"
)
when {
  principal.verifier == "github-oidc" &&
  principal has repository && principal.repository == "acme/app" &&
  principal has ref && principal.ref like "refs/tags/v*" &&
  principal has workflow && principal.workflow == ".github/workflows/release.yaml" &&
  principal has environment && principal.environment == "release"
};

// ---- Templates, for bindings that operators link at run time ---------------------------

// An account holds a grant. Linked per tenant.
@id("bind-account-to-grant")
permit (
  principal in ?principal,
  action == Action::"grant.hold",
  resource == ?resource
);

// An account does not hold a grant, whatever else gives it. A forbid can only narrow, so
// it is what the console offers for "revoke".
@id("revoke-grant-from-account")
forbid (
  principal in ?principal,
  action == Action::"grant.hold",
  resource == ?resource
);

// ---- Who may link which template (the delegation policy) -------------------------------

// The administrators of a company, named by account, may bind accounts of their own company to
// grants in their own company's scope.
@id("delegate-company-bindings")
permit (
  principal is Person,
  action == Action::"policy.link",
  resource == Boundary::"dev"
)
when {
  principal in [Account::"acme/a-01", Account::"globex/a-01"] &&
  context.template == "bind-account-to-grant" &&
  context has principal_account && context.principal_account.org == principal.org &&
  context has resource_grant && context.resource_grant.scope == principal.org &&
  !context.resource_grant.sensitive
};

// The security account may revoke any grant from any account.
@id("delegate-revocation")
permit (
  principal in Account::"workforce/u-9001",
  action == Action::"policy.link",
  resource == Boundary::"dev"
)
when { context.template == "revoke-grant-from-account" };
```

Two links are in force in the vectors: an account of the company `acme` is bound to the company's grant, and one account loses the user role. This is the file the asker would send them from.

<!-- example: tests/installations/local/policy/links.json -->
```json
[
{"template_id": "bind-account-to-grant", "link_id": "bind-acme-s-01-acme-example-app-user", "args": {"?principal": "Account::\"acme/s-01\"", "?resource": "Grant::\"acme:example-app:user\""}},
{"template_id": "revoke-grant-from-account", "link_id": "revoke-u-1002-dev-example-app-user", "args": {"?principal": "Account::\"workforce/u-1002\"", "?resource": "Grant::\"dev:example-app:user\""}}
]
```

### Test vectors

The vectors are in [`tests/installations/local/policy/`](https://github.com/truvity/sluis/tree/main/tests/installations/local/policy): `vectors.json` runs with the two links above, and `vectors-unlinked.json` runs the same questions with no link. Each vector is a request, the entities it needs, the decision and the ids of the determining policies, in the format of `cedar run-tests`. The people are stand-ins for opaque subjects, and `p-analyst` is linked by the account `workforce/u-1001`. Run with Cedar 4.14.0 (language version 4.6) on 2026-11-01, all 31 pass:

```sh
cedar run-tests --policies local.cedar --schema policy-schema.cedarschema \
  --template-linked links.json --tests vectors.json
```

| Vector | Decision | Determined by |
|---|---|---|
| 1. An account bound to a grant holds it | allow | `bind-example-users` |
| 2. The same binding does not give the admin role | deny | no policy permits |
| 3. A wildcard over the things of one scope | allow | `bind-dev-admins` |
| 4. The same wildcard stops at its scope | deny | no policy permits |
| 5. A sensitive scope named in full | allow | `bind-prod-admins` |
| 6. A wildcard reaches a sensitive scope: Cedar allows, and policy does not count it | allow | `bind-all-admins` |
| 7. A link binds the company's staff account to a grant | allow | `bind-acme-s-01-acme-example-app-user` |
| 8. The link says nothing about another scope | deny | no policy permits |
| 9. A revocation link beats the binding | deny | `revoke-u-1002-dev-example-app-user` |
| 10. A person who holds a required grant, fresh multi-factor | allow | `token-requires` |
| 11. The same person exchanges a token | allow | `token-requires` |
| 12. A company's grant also admits | allow | `token-requires` |
| 13. A ladder: the admin role admits where operator is required | allow | `token-requires` |
| 14. The user role does not reach operator | deny | no policy permits |
| 15. Password only: deny, and step up | deny, step up | `example-app-fresh-mfa` |
| 16. Multi-factor, but 20 minutes old: deny, and step up | deny, step up | `example-app-fresh-mfa` |
| 17. An upstream that sends no amr and no auth_age: deny, and step up | deny, step up | `example-app-fresh-mfa` |
| 18. A person an operator holds gets nothing | deny | `person-not-live` |
| 19. A person who holds none of the required grants | deny | no policy permits |
| 20. The release workflow on a version tag signs | allow | `release-signing-from-tag` |
| 21. The same workflow on a branch | deny | no policy permits |
| 22. Another repository | deny | no policy permits |
| 23. A proof with no environment | deny | no policy permits |
| 24. A company administrator binds their company's account to a grant of their company's scope | allow | `delegate-company-bindings` |
| 25. The same administrator tries another company's account | deny | no policy permits |
| 26. The same administrator tries a grant of another scope | deny | no policy permits |
| 27. The same administrator tries to revoke a grant | deny | no policy permits |
| 28. The security account links a revocation | allow | `delegate-revocation` |
| 29. A person who is no delegate links nothing | deny | no policy permits |
| unlinked 1. No binding link: the staff account does not hold the company's grant | deny | no policy permits |
| unlinked 2. No revocation link: the binding holds | allow | `bind-example-users` |

The vectors cover what Cedar decides. Two rules that belong to the `policy` actor are not in them and get vectors in its conformance test: the sensitive-grant rule (row 6 is a `deny` there) and the ladder (the entities above carry the grants after it). A request that does not fit the schema, such as an `auth_age` that is a string, is refused and not decided. The same vectors run against any other engine that is offered as a replacement ([principle 6](/principles/#6-generic-products-joined-by-a-contract)).

## What `sluis config check` checks

Offline, on the policy files, the vocabulary and the install file ([Install file](/reference/install-file/#what-sluis-config-check-checks)):

- every policy file parses, and the set validates against the schema;
- every policy and template has a unique `@id`, and every `@step_up` is on a `forbid` and holds well-formed `acr_values` and `max_age`;
- every `Grant::"…"` in a policy file and every grant in a client's `requires` is a name the vocabulary declares, and each binding passes the probe of [How a person's grants are found](#how-a-persons-grants-are-found);
- every `Client` the policy names is one the install file declares, every `Boundary` a declared boundary, and every `Account` names an upstream that the install file declares;
- every client's `requires` is not empty.

With `--live`, the operator-set records are read as well, and a link whose template the files no longer have is a `fail`.

## Roads not taken

- **Entities loaded from the install file by `policy`.** It would give `policy` a view of the clients, but `policy` would then read configuration that only `session`, `exchange` and `signer` read ([Install file](/reference/install-file/#top-level-keys)), and a request could not be judged from itself. The asker sends the slice.
- **A schema the operator extends.** A type or an attribute of an operator's own would let a policy depend on facts no actor sends, and a reload could change what a request means. A new attribute is a release.
- **A Cedar namespace for sluis's names.** It makes every policy longer to write and protects against a collision that no operator can cause.
- **Grants as group names.** A group is a directory's word and the first version has no directory; a grant is a name of the vocabulary that a binding gives to an account, and the token carries it ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/)).
- **A person named by subject or e-mail address in a binding.** The subject does not exist before the first sign-in, and an address is reused and renamed ([ADR 0019](/decisions/0019-person-and-upstream-link/#roads-not-taken)).
- **Wildcards as a pattern language of their own, outside Cedar.** It would be a second grammar to validate beside Cedar's. A wildcard is a condition on the `Grant` attributes, and the loader's probe holds it to the rules of [REQ-POLICY-011](/requirements/policy/#REQ-POLICY-011) and [REQ-POLICY-012](/requirements/policy/#REQ-POLICY-012).
- **An action `session.step_up`.** It would split "may this person have this token" from "is the authentication enough for it" into two questions with two sets of policies that can disagree. One `forbid` with `unless` keeps them in one.
- **Dates and durations in Cedar's `datetime` extension for freshness.** It would put a clock into `policy`, which has none, and a request would no longer answer the same on another day. Seconds counted by the asker keep the vectors fixed.
- **A link kind per asking actor.** Two writers cannot share a kind, and a binding applies to both `token.issue` and `token.exchange`, which are decided after the grants are found. One kind owned by `session`, read by `exchange`, keeps one link in one place.
- **`policy`, `console` or `exchange` as the owner of the links.** `policy` has no state port ([ADR 0007](/decisions/0007-policy-and-sealed-grants/)); `console` never writes a record ([ADR 0004](/decisions/0004-the-data-model/#one-writer-per-kind)); `exchange` is the second reader, and one writer for a kind is enough.
- **Ignoring a link that does not apply.** The request would go through without a `forbid` that an operator meant to have in force.
