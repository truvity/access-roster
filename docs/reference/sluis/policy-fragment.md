# Policy: a company's access fragment

A company's own rows and the ceiling an installation holds them to, part of [the policy](policy.md). Why: [ADR 0078](../../decisions/0078-a-company-access-fragment-is-owned-rows-checked-against-a-ceiling-and-by-effect.md). Go package: `policy/tenant`.

A fragment has no key for the matrix, the vocabulary, the lifetimes, the claims or the clients, and a rung takes no session length. An unknown key is an error.

## Fragment

Schema: `schemas/policy/tenant/fragment.schema.json`.

| Key | Holds |
|---|---|
| `rungs` | people added to a named rung: `groups`, `users` |
| `projects` | business projects: `scopes`, `secret_scopes`, `viewer_scopes`, `deployers`, `approvers`, `viewers`, `viewer_users` |
| `applications` | a `<scope>:<thing>:<role>` group granted to `groups` and `users` |
| `github` | an organisation's `members`, `teams` and `ignore` |
| `slack` | a workspace's `channels` |
| `jobs` | CI jobs, keyed by the group each becomes |
| `workloads` | programs, keyed by the group each becomes: a ServiceAccount or `aws` roles |

## Ceiling

Schema: `schemas/policy/tenant/ceiling.schema.json`. The empty ceiling allows nothing.

| Key | Holds |
|---|---|
| `directories` | email domains of every address and directory group |
| `groups` | patterns `scope:thing:role`; `*` is one whole segment and never the scope `all` |
| `rungs` | rungs the owner may add people to |
| `github_orgs`, `slack_workspaces` | organisations and workspaces the owner holds |
| `clusters`, `aws_accounts` | where the owner's workloads may run |

## Violations

Each has the owner, a code, a path and a sentence.

| Code | Refused |
|---|---|
| `owner-directory` | an address or directory group outside the directories, including another company's |
| `owner-name` | a group the rows mint or are granted that matches no pattern, or an owner with no name |
| `owner-rung` | a rung outside the ceiling |
| `owner-github`, `owner-slack` | an organisation, a CI job's repository owner or a workspace the owner does not hold |
| `owner-place` | a cluster or AWS account the owner may not run in |
| `owner-collision` | a key the installation or another owner already declares; two owners minting one group |
| `owner-effect` | what the fragment does to the installation's roster reaches outside the ceiling |
| `owner-empty-ceiling` | the empty ceiling and a fragment that declares something |

## Checks

| Check | Reads | Runs |
|---|---|---|
| `sluisctl policy fragment check` | the rows, with no installation model: partial | in the company's repository |
| `tenant.CheckEffect`, `tenant.MergeAll` | the roster before and after the merge | where the installation merges |

The second decides: joining a rung brings the rung's cells, and only the derived roster shows them. An owner with any violation is left out whole; the others merge unchanged, in any order.

The command takes no `--base` yet: that waits for a file format for the installation model.

## The command

```sh
sluisctl policy fragment check --ceiling <file> [--owner <name>] <fragment>
```

It reads two YAML or JSON files, needs no session or network and writes nothing.

| Flag | Meaning |
|---|---|
| `--ceiling <file>` | The owner's ceiling. Required |
| `--owner <name>` | The company's name in each line of the answer. Default `company` |

| Result | Exit |
|---|---|
| Inside the ceiling: `ok`, then a `partial` line | `0` |
| Refused: a line per violation, then the `partial` line | `1` |
| An unreadable or invalid file, or an unknown key; the error names the file | `1` |
| A bad command line | `2` |
