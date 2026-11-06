# Policy: validation at load

What the loader refuses and what it only warns about, for [the policy](policy.md). Test a file before it ships: [test the policy](../../guides/sluis/test-the-policy.md).

## Refused at load

Conflicts across files are refused when the layers merge. The merged policy is validated once.

| Area | Refused |
|---|---|
| Keys | unknown keys, `memberships` among them |
| Groups | a `claims` or `lifetimes` key or a `requires` entry that names no declared group |
| Members | an address without a domain |
| Claims | a scalar conflict across two `claims` fragments |
| Matchers | no field; `service_account` without `namespace` and `name`; `aws` without a twelve-digit `account` or with a pattern that does not compile; `github` `visibility` other than `public`, `private`, `internal` |
| Clients | `display_name` or `description` that is not one bounded line; `sign_in_exchange` on a non-`public` client; a confidential client without `secret`; an empty `requires` |
| PKCE | `pkce` other than `required` or `optional`; `pkce: optional` on a `public` client; `pkce` on an `exchange` client |
| Harness | `harness` on an `exchange` client |
| Session | `session` on an `exchange` client; `session: agent` with `sign_in_exchange: true` |
| Resources | an id that is not an absolute URI without a fragment; a `requires` naming no declared group |
| `client_documents` | an origin with a scheme, path or wildcard; `origins` without `requires`; `requires` or `ttl_cap` without `origins` |
| Version | `version` other than 1; `apiVersion` other than `sluis.truvity.github.io/policy/v2` |

| Other checks | Page |
|---|---|
| vocabulary | [policy-vocabulary.md](policy-vocabulary.md) |
| `groups_delimiter`, `signing_alg` | [policy-clients.md](policy-clients.md) |
| GitHub, people and Slack bindings | [policy-bindings.md](policy-bindings.md) |
| a company's own rows against its ceiling | [policy-fragment.md](policy-fragment.md) |

`session: agent` alone loads. With `signed_out` or `backchannel_logout_uri` it only warns ([agent-class sessions](policy-clients.md#agent-class-sessions)).

## Groups nothing consumes

At start the service warns about a group declared in `groups` that none of these references. It also warns about a group name that is neither a grant (`<scope>:<thing>:<role>`) nor an identity (`rung:<name>`, `emp:<slug>`). A warning is never an error.

| Counts as a reference |
|---|
| a client's, a resource's or `client_documents` `requires` |
| a GitHub organisation `members` binding |
| a GitHub team `members` or `maintainers` binding |
| a Slack channel's `from` binding |
| a `groups:` override on a client, a resource or `client_documents` ([ADR 0006](../../decisions/0006-groups-claim-scoped-per-audience.md)) |
| a GitHub App catalogue grant's group |
| the service's own roles `<scope>:sluis:operator` and `<scope>:sluis:viewer` |

A group referenced only by `claims` or `lifetimes` does not count. `rung:` and `emp:` groups are never reported.
