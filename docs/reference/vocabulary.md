---
title: Vocabulary
description: "The grant vocabulary file, schema v1: its keys, the role ladder, sensitive scopes, the checks on it and the example file for local."
status: target
sidebar:
  order: 8
---

A grant is a name, `<scope>:<thing>:<role>`, and every grant a policy, a client or a token can name is declared in one file, the **vocabulary** ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)). The install file names it with [`policy.vocabulary`](/reference/install-file/#policy). This page fixes the file's shape for the first working version, schema v1. How grants are found, bound and checked at run time is on [Policy](/reference/policy/).

Schema v1 has only the keys that code of the first working version reads ([principle 8](/principles/#8-nothing-without-a-consumer)). Adding a key or a value is compatible; removing or changing one is a new schema version beside v1, as for the install file.

## Format

- **The same strict YAML profile as the install file:** one document, plain JSON data, no anchors, aliases, merge keys, tags or duplicate keys ([Install file](/reference/install-file/#format)).
- **The schema is JSON Schema draft 2020-12** with the `$id` `https://sluis.id/schema/vocabulary/v1/vocabulary.schema.json`, generated from the Pkl sources in `schema/` and embedded in `policy` and in the `sluis` command. `unevaluatedProperties: false` on every object, so an unknown key is an error that names its path. An error never shows a value. `$schema` may name the `$id`, for editors; a file that names another `$id` is refused.
- **The path** is the value of `policy.vocabulary`, relative to the directory of the install file.
- **Names.** A scope, a thing and a role are each 1 to 64 characters of ASCII letters, digits, `-` and `_`, as in a grant name. The colon and `*` are not in the set, so a name cannot be split wrongly and a wildcard cannot be a name.

## Keys

| Key | Required | Meaning |
|---|---|---|
| `$schema` | no | The schema `$id`, for editors |
| `scopes` | yes | A mapping from a scope's name to its declaration. At least one |
| `things` | yes | A mapping from a thing's name to its declaration. At least one |

### `scopes`

A scope is an environment, a company or `all` ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#grant-names-and-the-vocabulary)). The file does not say which; a scope named like an environment boundary or a company boundary of the install file means that boundary by convention, which is how the delegation policy of [Policy](/reference/policy/#the-grants-of-one-tenant) reads a company's scope. `all` is an ordinary name with no meaning of its own: `all:x:admin` is a grant like any other, and never implies `dev:x:admin`.

| Field | Required | Meaning |
|---|---|---|
| `sensitive` | no | `true` for a sensitive scope. Default `false`. A wildcard never reaches a sensitive scope: a grant of it counts as held only when a policy names that grant in full ([Policy](/reference/policy/#how-a-persons-grants-are-found)) |

A scope with no field is written `{}`.

### `things`

A thing is a system, a project or an application.

| Field | Required | Meaning |
|---|---|---|
| `roles` | yes | A mapping from a role's name to its declaration. At least one. The ladder of the thing |

### A role

A role is written in one of two forms.

- **The short form is a list of role names,** the roles it implies: `admin: [operator]` means that holding `admin` holds `operator` too, transitively, on the same scope and the same thing. An empty list, `user: []`, implies nothing.
- **The long form is a mapping** when the role exists in some scopes only:

  | Field | Required | Meaning |
  |---|---|---|
  | `implies` | no | The same list as the short form. Default empty |
  | `scopes` | no | The scopes the role exists in. At least one, each declared in `scopes`. Default: every declared scope |

The two forms mean the same when the long form leaves `scopes` out, and the file may mix them.

## What the file declares

The grants of an installation are the combinations the file lists: for every thing, every role of it, and every scope the role exists in, the grant `<scope>:<thing>:<role>`. `policy` builds one `Grant` entity for each, with its `scope`, `thing`, `role` and `sensitive` ([Policy](/reference/policy/#entity-types)), and finds the held grants of a person by that set. A name that is not among them is not a grant: a policy file, a client's `requires`, a binding or a link that names one is refused at load.

A role ladder is explicit. It never inherits across scopes: the roles a role implies are the ones of the same scope and thing. Implication is transitive, and the held set a token is narrowed from has the whole ladder expanded ([ADR 0020](/decisions/0020-grant-vocabulary-and-token-claims/#the-claims-of-a-token)).

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

## What `sluis config check` checks

Beyond the schema, which cannot state these rules:

- every role a role `implies` is a role of the same thing, and not the role itself;
- the ladder of a thing has no cycle;
- every scope a role names in `scopes` is declared, and none is repeated;
- a role exists in no scope its implied roles do not exist in: the scopes of a role are within the scopes of every role it implies, because holding the role holds those too;
- every grant name that a policy file, a client's `requires`, a binding or a link uses is a grant the file declares ([Install file](/reference/install-file/#what-sluis-config-check-checks)).

An error names the path in the file and never the value. The repository check `just check-installations` runs all of this on every example installation under `tests/installations/`: the file's shape, the rules above, and every grant name in the install file's `requires` and in the Cedar policy files and links beside it.

## The example file for local

The local installation's vocabulary is [`tests/installations/local/policy/vocabulary.yaml`](https://github.com/truvity/sluis/blob/main/tests/installations/local/policy/vocabulary.yaml). It declares one thing, `example-app`, with a ladder of three roles in three scopes, one of them sensitive; the test vectors of [Policy](/reference/policy/#a-worked-example) run against it. This copy is checked against that file (`just check-examples`).

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
