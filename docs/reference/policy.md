---
title: Policy
description: "The Cedar schema of sluis policy, its entities, actions and context, how grants and links reach the policy actor, the grant vocabulary, and a worked example."
status: target
sidebar:
  order: 7
---

`policy` decides every question of the form "does this person hold this grant name", "may this person have a token for this client" and "may this workflow have the release key sign" ([0007](/decisions/0007-policy-and-sealed-grants/)). It holds no key and no data of its own, and every fact it needs arrives in the request. It reads the reviewed policy through the store. This page fixes what the request holds, the Cedar schema the policy is written against, how the grant names of a person are found, how template links reach `policy`, the vocabulary of grant names, and one policy file with test vectors. Who calls `policy` is in the [actor registry](/reference/actors/#policy). The policy documents are the config kinds `Policy` and `RegulatedPartyPolicy`, and the vocabulary is the config kind `GrantVocabulary` ([Kinds](/reference/kinds/)).

A **grant name** is an entry of the vocabulary, `<scope>:<thing>:<role>`. A **sealed grant** is one decision of `policy`, sealed by key@ ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)). The two are different things. The Cedar entity `Grant` below stands for a grant name, and this page says "grant" alone only for the sealed grant.

## The schema is sluis's, the policy is the operator's

- **One schema, version 1, fixed by sluis and embedded in `policy`.** An operator writes policy against it and cannot add a type, an action or an attribute. This keeps every request checkable: `policy` validates each request against the schema and refuses one that does not fit, and every policy document against it at load and at every reload ([0007](/decisions/0007-policy-and-sealed-grants/#cedar-in-a-rust-actor)).
- **No namespace.** The names below are the whole vocabulary; nothing an operator writes can collide with them.
- **Adding is compatible.** A type, an action, an optional attribute or a new optional context name may be added in a release; removing or changing one is a new schema version beside this one, as for every schema ([0013](/decisions/0013-release-train-packaging-and-distribution/#compatibility-between-releases)).
- **The file is** [`policy-schema.cedarschema`](https://github.com/truvity/sluis/blob/main/docs/reference/policy-schema.cedarschema), in the Cedar schema syntax of Cedar 4.14.0 (language version 4.6, checked on 2026-11-01). This copy is checked against that file (`just check-examples`).

<!-- example: docs/reference/policy-schema.cedarschema -->
```text
// The Cedar schema of sluis policy, schema version 1 (the first working version).
// It is fixed by sluis and embedded in the `policy` actor; an operator writes policy against it
// and cannot add types, actions or attributes. Every request is validated against it.

// An upstream account, named by the upstream's declared name and the value of the upstream's
// subject claim: `<upstream>/<claim value>` (ADR 0019). An operator can name an account before
// its first sign-in, which the random subject of a person does not allow. `org` is the tenant
// (the company) of the account's sign-in: the tenant whose connection signed it in (ADR 0019).
entity Account = {
  upstream: String,
  org: String,
};

// A grant name of the vocabulary, written `<scope>:<thing>:<role>` (ADR 0020). The entity is
// called Grant; it stands for a grant name and never for the sealed grant of ADR 0007.
// `sensitive` is true when its scope is sensitive.
entity Grant = {
  scope: String,
  thing: String,
  role: String,
  sensitive: Bool,
};

// A person, known by the opaque `sub` of the issuer, and linked to the upstream account they
// signed in with. `org` is the tenant (the company) the person belongs to, and `state` is `live`
// or `held` (ADR 0019: an operator holds a person on the console). `grants` is the set of grant
// names the person holds. The asking actor does not send it: `policy` finds it with the action
// "grant.hold" and adds it before it decides any other action.
entity Person in [Account] = {
  org: String,
  state: String,
  grants?: Set<Grant>,
};

// A boundary, such as `dev`.
entity Boundary;

// A client of an issuer. The token's `aud` is exactly one client id, so a client is also the
// resource of a token request. `requires` is the client's declared list of grant names, and `kind`
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

// Whether a person holds a grant. The policy files bind accounts to grant names with this action.
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

The types follow the [actor registry](/reference/actors/) and the [kinds](/reference/kinds/): a type exists when an actor of the first working version asks about it ([principle 8](/principles/#8-nothing-without-a-consumer)). The asking actor sends the facts as a slice of entities with the request; `policy` reads no item for them.

| Type | What it is | Facts sent by | Id |
|---|---|---|---|
| `Account` | An account of an upstream, named by the pair that links a person: the upstream's declared name and the value of its subject claim ([0019](/decisions/0019-person-and-upstream-link/#linking-an-upstream-account)) | `session` or `exchange`, from the `UpstreamLink` of the person | `<upstream>/<claim value>`, such as `workforce/u-1001`; never an e-mail address |
| `Person` | A person who signed in, `in` the `Account` they are linked by | The asker, from the session and the `Person` item | The opaque subject ([0019](/decisions/0019-person-and-upstream-link/#the-records)) |
| `Grant` | A grant name of the vocabulary, with its scope, thing, role and whether the scope is sensitive | `policy`, from the vocabulary | `<scope>:<thing>:<role>`, such as `dev:example-app:user` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)) |
| `Client` | A client of an issuer, and the resource of a token request | The asker, from the `InstallationClient` or `TenantClient` it read ([0021](/decisions/0021-clients/#the-client-declaration)) | `<boundary>/<client id>`, such as `dev/example-app` |
| `Boundary` | A boundary, and the place a link is made in | The asker, from the `Boundary` config kind | The boundary's name |
| `Workload` | A workload that proved its identity: in the first version a GitHub Actions job, checked by the `github-oidc` verifier | `exchange`, from the verified proof | `<verifier>/<proof subject>` |
| `SigningKey` | A signing key of a boundary | `exchange` | The key's purpose, `release-signing` ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api)) |

- **A person is named by an account, because an operator cannot know a subject.** The subject is 128 random bits assigned at the first sign-in, so a binding or a link written before it names the account that will be linked. A binding never names an e-mail address, which does not identify ([0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)).
- **`org` is the tenant the person belongs to,** the tenant of the client the person signs in to ([0033](/decisions/0033-customer-connections/#which-tenant-a-person-belongs-to), [0019](/decisions/0019-person-and-upstream-link/#the-records)). The broker's organisation id is not copied into `org`: the asker reads `org` from the person's item, and no policy document sets it. `Account.org` is, in the same way, the tenant of the sign-in that linked the account; a config `Upstream` names no tenant.
- **`state` is `live` or `held` in the first version.** An operator's `PersonHold` is a tightening that takes effect at once; `session` computes the state and sends it, and the first `forbid` of the example refuses a person who is not live. Lifting a hold gives back only what the policy grants. The states `suspended` and `left` join with the directory at parity ([0019](/decisions/0019-person-and-upstream-link/#states)).
- **A client's id carries its boundary.** Client ids are unique per issuer, not across issuers ([0017](/decisions/0017-identity-and-sign-in/#audiences)), and a Cedar entity id must be unique, so `dev/example-app` and `prod/example-app` are two entities. A `Client` is `in` its `Boundary`, so a policy can say "any client of `dev`". `Client.requires` is the client's declared `requires`, a set of `Grant`.
- **`Workload` attributes are the verified claims of the proof.** For a GitHub Actions job they are the repository, the ref, the workflow and the environment ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api)); a name the proof does not carry is absent, and a policy tests `has` before it reads.

### What comes with parity

Each of these is added by the record or pull request that first asks about it, and is compatible with version 1:

| Added | By | Because |
|---|---|---|
| `Group`, and a binding that names a directory group | Directory sync ([#805](https://github.com/truvity/sluis/issues/805)) | The first working version reads no directory; internal groups are accounts ([0019](/decisions/0019-person-and-upstream-link/#what-policy-sees)) |
| `Target`, and the batch membership method | Reconcilers ([#1220](https://github.com/truvity/sluis/issues/1220)) | A directory adapter asks which people a connection's groups put in a target ([0026](/decisions/0026-reconcilers/#the-desired-state)) |
| `Host` and the action `cert.issue` | Host enrolment ([0022](/decisions/0022-workload-identity-and-host-enrolment/)) | Their first asker is `exchange` with a host proof |
| `Resource` | Declared resources ([#979](https://github.com/truvity/sluis/issues/979)) | A resource is a declared URL with its own `requires` ([0021](/decisions/0021-clients/#resources)) |
| Attributes for the claims of a token | The per-audience claim override ([#788](https://github.com/truvity/sluis/issues/788)) | The first version issues the fixed set of [0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token) |

## Actions

| Action | Principal | Resource | Asked by | Meaning |
|---|---|---|---|---|
| `grant.hold` | `Person` | `Grant` | `policy`, for itself | Whether this person holds this grant name. The bindings of the policy documents are written on this action |
| `token.issue` | `Person` | `Client` | `session` | Whether this person may have a token for this client, at a code exchange or a refresh |
| `token.exchange` | `Person` | `Client` | `exchange` | Whether this person's token may become a token for this client, as when `sluis login` exchanges the token of the front issuer at a boundary |
| `artifact.sign` | `Workload` | `SigningKey` | `exchange` | Whether this workload may have this key sign this content ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api)) |
| `policy.link` | `Person` (the one who asks) | `Boundary` | `exchange`, for a write that `console` routed | Whether this person may link this template, with these slot values, in this boundary |

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

[0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary) has grant names, not groups, as what a person holds, and `policy` is where facts become grant names. `policy` decides a request about a person in two steps:

1. **Find the grant names.** For every grant name of the vocabulary, `policy` asks `grant.hold` for the person, with the bindings and links of the effective policy set as they stand. It then adds every grant name that a held role implies, by the ladder of the vocabulary, on the same scope and thing, and puts the full set into `Person.grants`.
2. **Decide the action** with the person's grant names in the entity. The standard rule `principal has grants && resource.requires.containsAny(principal.grants)` is the Cedar form of "at least one required grant name".

- **The answer carries the full set** of held grant names, so that the asker narrows the `groups` claim to the audience's `<scope>:<thing>` pairs ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)); admission was decided on the full set.
- **A sensitive grant name is held only by a binding that names it in full.** A grant name of a sensitive scope counts as held only when a determining policy has that grant name as its resource, `resource == Grant::"prod:example-app:admin"`; `policy` reads the scope of the determining policies for this ([REQ-POLICY-011](/requirements/policy/#REQ-POLICY-011)). A wildcard written as a condition on `resource.scope` or `resource.role` can give any other grant name, and Cedar alone would give it a sensitive one too.
- **The loader tries each binding.** It evaluates every static policy on `grant.hold` for a probe person of the account the policy names against every grant name of the vocabulary, and refuses a policy that no grant name satisfies ("a wildcard that expands to nothing", [REQ-POLICY-012](/requirements/policy/#REQ-POLICY-012)) and one that satisfies several roles of one scope and thing at once (a wildcard in the role position). A grant name that is not in the vocabulary, as a `Grant::"…"` in a policy document, is refused when the snapshot loads, with the path ([REQ-POLICY-010](/requirements/policy/#REQ-POLICY-010)).
- **The vocabulary is a config document of the boundary,** the kind `GrantVocabulary`; its shape is [below](#the-grant-vocabulary). `policy` builds the `Grant` entities from it: one for every scope, thing and role the document declares, with `sensitive` taken from the scope.

## What a decision holds

`policy`'s contract is a ConnectRPC service like the others ([Contracts and errors](/reference/contracts/)). It has two methods: the decision, whose request and answer are below, and a [batch membership method](#the-batch-membership-method) for directory adapters. The request and answer of a decision carry:

| In the request | |
|---|---|
| The question | The principal, action and resource as entity ids, the tenant the question is about, and the context |
| The facts | The slice of entities the question needs: the person with the account, the client with its `requires`, the boundary, or the workload and the key |

| In the answer | |
|---|---|
| The decision | `allow` or `deny`. A policy that errors counts as no permit; a request that does not fit the schema is refused, not decided |
| The reasons | The ids of the determining policies, each with its annotations and the layer it came from |
| The grant names | For a person: the full set of held grant names, after the ladder |
| The digest | The digest of the effective policy set, the vocabulary and the schema version, for the audit record |
| The sealed grant | On `allow` only: the sealed grant, sealed by key@ under the boundary's `grant` data key ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)) |

The `proto/` file is written with the first code. Every decision is audited with its reasons and the digest.

### The batch membership method

A directory adapter asks for the members of the targets its directory feeds, once per connection after each refresh ([0026](/decisions/0026-reconcilers/#the-desired-state)). It is the one place where `policy` answers about many subjects at once.

| In the request | |
|---|---|
| The connection | The directory connection and its tenant; policy reads the targets' ReconcileTarget itself |
| The facts | The directory groups and memberships of the connection that the adapter read, each with its age, as a slice of entities. The adapter counts the age; `policy` has no clock |

| In the answer | |
|---|---|
| The members | For each target, named with the tenant that owns its container, the vendor identifiers of the people the connection's groups are to put in it, as opaque references |
| The missing declarations | For each target that is owned by another company, whether the connection's company allows its group to be provisioned there; a target without the allowance is listed and gets no member |
| The reasons and the digest | As for a decision |
| The sealed grant | For each owner's tenant of a target both sides declared, the grant for writing its part, an empty part included |

- **The answer is the decision, and the adapter only writes it.** The adapter adds, removes and reorders no member ([0025](/decisions/0025-integrations/#the-rule)).
- **A fact that has passed its `max_age` is stale,** and a target whose answer rests on it is listed as such, so that the adapter writes no part for it.


### Policy ids and annotations

- **Every policy and template carries an `@id`.** The id is stable and appears in the reasons, the audit record and the tests. A policy with no `@id`, or a repeated one, is refused at load.
- **The only annotation sluis reads is `@step_up`,** on a `forbid`. Other annotations are carried in the reasons and ignored.

## Step-up

[ADR 0017](/decisions/0017-identity-and-sign-in/#step-up) has `policy` decide which clients need multi-factor authentication and how fresh it must be, and the asker answer with RFC 9470. The two meet in an annotation:

- **A `forbid` that expresses a step-up rule carries `@step_up("acr_values=<values> max_age=<seconds>")`,** the values RFC 9470 puts in `insufficient_user_authentication`.
- **When the determining policies of a `deny` include one with `@step_up`,** `session` answers `insufficient_user_authentication` with those values and the person signs in again. When there is none, the answer is a plain refusal, and it looks the same for an unknown and a refused client ([Contracts and errors](/reference/contracts/#oauth-and-openid-connect-endpoints)).
- **A rule is written with `unless`:** the `forbid` applies unless the context shows what is asked for. Unknown context therefore forbids, and the person is asked to step up.


## Template links

A template is policy declared in a `Policy` document, with `?principal` and `?resource` slots. A **link** gives the slots values and so makes a policy. Links are how a tenant, an operator and a product change policy at run time without a review of new logic: the logic is in the template, which a reviewer has seen ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). In the first version the templates bind an account to a grant name, or revoke a grant name from an account.

### Which layer a link is in

| Link | Kind | Class | Lasts | Written by |
|---|---|---|---|---|
| A template linked inside the tenant | `PolicyLink` | Durable, tenant layer | Until it is removed | `exchange` |
| A predefined policy that only forbids | `PredefinedPolicyLink` | Durable, operator layer | Until it is removed | `exchange` |
| A predefined policy that grants beyond config, such as break-glass | `PredefinedPolicyLinkTemporary` | Temp, operator layer | 1 hour by default, 24 hours at most | `exchange` |

- **A link inside a template is not a loosening.** The template is config's grant to the tenant layer, so a link within it is within the bound of the layer below and is durable, with no expiry ([0004](/decisions/0004-the-data-model/#what-a-loosening-is)).
- **The kind decides which write is a loosening.** The durable `PredefinedPolicyLink` accepts only a predefined policy that tightens, and only the temp kind accepts one that loosens ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). The store checks the kind and the policy named, and that the template exists in config.
- **A tightening takes effect on the next decision and lasts.** A template whose effect is `forbid` can only narrow what is permitted; the console offers those for "revoke a grant". Suspending a person is not a link: it is a `PersonHold`, which `session` writes and sends as `state`.

### Making a link

1. A tenant admin or an operator asks the console for a link: a template id and the slot values. A product acting for its tenant makes the same request through its API.
2. `console` routes the write to the actor that owns the kind, which is `exchange` ([0027](/decisions/0027-the-console/#writes)).
3. `exchange` asks `policy` the question `policy.link`, with the person as principal, the boundary as resource and the template and slot values as context. A `deny` ends it.
4. On `allow`, `exchange` writes the link under a grant sealed for the tenant, and the audit record names who asked, the template, the slot values and the delegation policy that permitted it.

- **The delegation policy is Cedar too.** It is a set of ordinary policies in the `Policy` document, on the action `policy.link`. A template with no delegation policy cannot be linked by anyone, and a stolen session is bounded by it.
- **A link has** an id, the template id, the slot values as entity ids, who made it and when. A link made twice with the same template and slot values is one link.

### How links reach `policy`

- **`policy` reads the effective policy set,** `EffectivePolicySet(boundary, tenant)`, through the store: the four layers composed by union with Cedar forbid-wins, each part with the version it came from ([0004](/decisions/0004-the-data-model/#layered-and-linked-kinds)). The links are part of it. `policy` recompiles when the set changes, by watch, or by a re-read with an ETag on Lambda ([0005](/decisions/0005-the-store/#watch-and-the-resume-point)).
- **The request names the tenant,** and the asker sends only facts. `policy` links the templates in memory, validates the result, and evaluates. The digest of the set is in the audit record.
- **A link that cannot be applied denies the request.** An unknown template, a slot of the wrong type or a grant name the vocabulary no longer has means the layers have drifted, and ignoring the link could drop a `forbid`. The store refuses the write of such a link, and it refuses a config snapshot that removes a template a link names ([0005](/decisions/0005-the-store/#the-snapshot)), so the denial is the last line. It is audited with the link id.

### The grants of one tenant

A company is a tenant: its accounts and its grant names carry its `org`, and its administrators may bind accounts of their own `org` to grant names in their own scope, with no review of the operator's and no change to the policy documents. The delegation policy of the example below does this in one policy; the vectors show what it allows and what it refuses. In the example a company's scope has the company's name, which is the convention the delegation policy states ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary): a scope is an environment, a company or `all`).

## The grant vocabulary

A grant name is `<scope>:<thing>:<role>`, and every grant name a policy, a client or a token can name is declared in one document, the **vocabulary** ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)). It is the config kind `GrantVocabulary`: Fixed, written by the publishing pipeline, and read by `policy`, `exchange`, `session`, `signer` and the console. This section fixes its shape for the first working version, schema v1. How grant names are found, bound and checked at run time is above.

Schema v1 has only the keys that code of the first working version reads ([principle 8](/principles/#8-nothing-without-a-consumer)). Adding a key or a value is compatible; removing or changing one is a new schema version beside v1.

### Format

- **The document is YAML read by the same strict profile as every config document:** one document, plain JSON data, no anchors, aliases, merge keys, tags or duplicate keys ([Bootstrap file](/reference/bootstrap-file/#format)). It is signed like the others ([Signed config](/reference/signed-config/)).
- **The schema is the JSON Schema generated from the Protobuf message,** with the `$id` `https://sluis.id/schema/vocabulary/v1/vocabulary.schema.json`, embedded in `policy` and in the `sluis` command ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). `unevaluatedProperties: false` is on every object, so an unknown key is an error that names its path. An error never shows a value. `$schema` may name the `$id`, for editors; a document that names another `$id` is refused.
- **Names.** A scope, a thing and a role are each 1 to 64 characters of ASCII letters, digits, `-` and `_`, as in a grant name. The colon and `*` are not in the set, so a name cannot be split wrongly and a wildcard cannot be a name.

### Keys

| Key | Required | Meaning |
|---|---|---|
| `$schema` | no | The schema `$id`, for editors |
| `scopes` | yes | A mapping from a scope's name to its declaration. At least one |
| `things` | yes | A mapping from a thing's name to its declaration. At least one |

#### `scopes`

A scope is an environment, a company or `all` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)). The document does not say which; a scope named like a boundary or a tenant means that boundary or tenant by convention, which is how the delegation policy of [The grants of one tenant](#the-grants-of-one-tenant) reads a company's scope. `all` is an ordinary name with no meaning of its own: `all:x:admin` is a grant name like any other, and never implies `dev:x:admin`.

| Field | Required | Meaning |
|---|---|---|
| `sensitive` | no | `true` for a sensitive scope. Default `false`. A wildcard never reaches a sensitive scope: a grant name of it counts as held only when a policy names that grant name in full ([How a person's grants are found](#how-a-persons-grants-are-found)) |

A scope with no field is written `{}`.

#### `things`

A thing is a system, a project or an application.

| Field | Required | Meaning |
|---|---|---|
| `roles` | yes | A mapping from a role's name to its declaration. At least one. The ladder of the thing |

#### A role

A role is written in one of two forms.

- **The short form is a list of role names,** the roles it implies: `admin: [operator]` means that holding `admin` holds `operator` too, transitively, on the same scope and the same thing. An empty list, `user: []`, implies nothing.
- **The long form is a mapping** when the role exists in some scopes only:

  | Field | Required | Meaning |
  |---|---|---|
  | `implies` | no | The same list as the short form. Default empty |
  | `scopes` | no | The scopes the role exists in. At least one, each declared in `scopes`. Default: every declared scope |

The two forms mean the same when the long form leaves `scopes` out, and the document may mix them.

### What the document declares

The grant names of an installation are the combinations the document lists: for every thing, every role of it, and every scope the role exists in, the grant name `<scope>:<thing>:<role>`. `policy` builds one `Grant` entity for each, with its `scope`, `thing`, `role` and `sensitive` ([Entity types](#entity-types)), and finds the held grant names of a person by that set. A name that is not among them is not a grant name: a policy document, a client's `requires`, a binding or a link that names one is refused when the snapshot loads.

A role ladder is explicit. It never inherits across scopes: the roles a role implies are the ones of the same scope and thing. Implication is transitive, and the held set a token is narrowed from has the whole ladder expanded ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).

A role that exists in some scopes only is written in the long form:

```yaml
# Example: a role only some scopes have
scopes:
  dev: {}
  prod: { sensitive: true }
things:
  deploy:
    roles:
      viewer: []
      releaser: { implies: [viewer], scopes: [dev, prod] }
      debugger: { implies: [viewer], scopes: [dev] }   # no debugger in prod
```

### What the vocabulary checks

Beyond the schema, which cannot state these rules:

- every role a role `implies` is a role of the same thing, and not the role itself;
- the ladder of a thing has no cycle;
- every scope a role names in `scopes` is declared, and none is repeated;
- a role exists in no scope its implied roles do not exist in: the scopes of a role are within the scopes of every role it implies, because holding the role holds those too;
- every grant name that a policy document, a client's `requires`, a binding or a link uses is a grant name the document declares ([What `sluis config check` checks](#what-sluis-config-check-checks)).

An error names the path in the document and never the value. The repository check `just check-installations` runs all of this on every example installation under `tests/installations/`: the document's shape, the rules above, and every grant name in the Cedar policy files and links beside it.

### The example vocabulary

The local installation's vocabulary is [`tests/installations/local/policy/vocabulary.yaml`](https://github.com/truvity/sluis/blob/main/tests/installations/local/policy/vocabulary.yaml). It declares one thing, `example-app`, with a ladder of three roles in three scopes, one of them sensitive; the test vectors below run against it. This copy is checked against that file (`just check-examples`).

<!-- example: tests/installations/local/policy/vocabulary.yaml -->
```yaml
# The grant vocabulary of the local installation (ADR 0020). Schema v1:
# https://sluis.id/reference/policy/#the-grant-vocabulary
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

## A worked example

The local installation's boundary `dev` has a `Policy` document, [`policy/local.cedar`](https://github.com/truvity/sluis/blob/main/tests/installations/local/policy/local.cedar), and the vocabulary above. It also has one client, `example-app` in the boundary `dev`, which requires one of two grant names: `dev:example-app:user`, or the same role in the scope of the company `acme`. The vocabulary has one thing, `example-app`, with a ladder of three roles, and three scopes, one of them sensitive.

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

// A person who holds one of a client's required grant names may have a token for it.
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

// ---- Reading the audit log -------------------------------------------------------------

// The reader of the local installation may ask for a grant to open any tenant's evidence (ADR 0028
// "Access", ADR 0007 "Four layers": `audit.read` comes from the bindings of the configuration, not from
// the built-in layer). The local audit front has no sign-in yet, so the reader asks for itself; a
// boundary that signs people in binds the people and not the actor. `policy` cannot tell tenants
// apart in Cedar (a tenant is not an entity), so this permit is for every tenant of the boundary, and
// the tenant a grant names is the one the reader asked for, which key@ checks again.
@id("bind-reader-audit-read")
permit (principal == Actor::"reader", action == Action::"audit.read", resource is Boundary);

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

Two links are in force in the vectors: an account of the company `acme` is bound to the company's grant name, and one account loses the user role. This is the file the effective policy set would carry them in.

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

Offline, on the config documents of a boundary ([Commands](/reference/cli/#sluis-config-check-and-explain)); the snapshot validation of [Signed config](/reference/signed-config/#the-snapshot) makes the same checks when store@ loads:

- every policy document parses, and the set validates against the schema;
- every policy and template has a unique `@id`, and every `@step_up` is on a `forbid` and holds well-formed `acr_values` and `max_age`;
- every `Grant::"…"` in a policy document and every grant name in a client's `requires` is a name the vocabulary declares, and each binding passes the probe of [How a person's grants are found](#how-a-persons-grants-are-found);
- every `Client` the policy names is one the config declares, every `Boundary` a declared boundary, and every `Account` whose upstream part names an `Upstream` of the config is checked against that upstream. Any other account names an upstream that no `Upstream` declares, and the check refuses it;
- every client's `requires` is not empty;
- every link names a template that a `Policy` document has.

## Roads not taken

- **Entities read from the store by `policy`.** It would give `policy` a view of the clients, but a request could not be judged from itself, and `policy` would read items that only `session`, `exchange` and `signer` read. The asker sends the slice.
- **A schema the operator extends.** A type or an attribute of an operator's own would let a policy depend on facts no actor sends, and a reload could change what a request means. A new attribute is a release.
- **A Cedar namespace for sluis's names.** It makes every policy longer to write and protects against a collision that no operator can cause.
- **Grants as group names.** A group is a directory's word and the first version has no directory; a grant name is an entry of the vocabulary that a binding gives to an account, and the token carries it ([0020](/decisions/0020-grant-vocabulary-and-token-claims/)).
- **A person named by subject or e-mail address in a binding.** The subject does not exist before the first sign-in, and an address is reused and renamed ([0019](/decisions/0019-person-and-upstream-link/#roads-not-taken)).
- **Wildcards as a pattern language of their own, outside Cedar.** It would be a second grammar to validate beside Cedar's. A wildcard is a condition on the `Grant` attributes, and the loader's probe holds it to the rules of [REQ-POLICY-011](/requirements/policy/#REQ-POLICY-011) and [REQ-POLICY-012](/requirements/policy/#REQ-POLICY-012).
- **An action `session.step_up`.** It would split "may this person have this token" from "is the authentication enough for it" into two questions with two sets of policies that can disagree. One `forbid` with `unless` keeps them in one.
- **Dates and durations in Cedar's `datetime` extension for freshness.** It would put a clock into `policy`, which has none, and a request would no longer answer the same on another day. Seconds counted by the asker keep the vectors fixed.
- **`policy` or `console` as the owner of the links.** `policy` writes no kind ([0007](/decisions/0007-policy-and-sealed-grants/#cedar-in-a-rust-actor)); the console writes only `Switch` and `LogLevelOverride` itself ([0004](/decisions/0004-the-data-model/#one-writer-per-kind)). `exchange` owns the links and `policy` reads them.
- **Ignoring a link that does not apply.** The request would go through without a `forbid` that a tenant admin or an operator meant to have in force.
