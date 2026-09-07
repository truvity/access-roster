# The policy

One schema, loaded by both services. It answers four questions and no
others: who is in which internal group, what a group adds to a token, how
long a token lives, and which client may be issued one. Everything that
shapes a token is derivable from this file by reading it.

Decided 2026-09-07; supersedes the earlier flat rules list, which
survives only as the matchers inside machine groups.

## The tables

```yaml
version: 1

groups:                        # internal groups — the vocabulary
  sre:
    members: [role-sre@a.example, role-sre@b.example]   # directory groups, any workspace
  dpo:
    members: [role-security@a.example]
  ci-gitops:
    matchers:                                             # machine groups: matched, not listed
      - github: { repository: example-org/gitops, ref: refs/heads/master }
  hub-operators:
    members: [directory-admins@a.example]

claims:                        # what a group adds to a token — sparse
  sre: { groups: [cluster-kernel:admin, cluster-prod:admin] }
  dpo: { groups: [cluster-kernel:auditor], tailnet: { tiers: [vpc] } }

lifetimes:                     # how long — default plus exceptions
  default: 12h
  sre: 8h
  ci-gitops: 1h

clients:                       # who may be issued a token for what; the id is the audience
  k8s:kernel:        { kind: public,       requires: [sre, dpo, it] }
  aws:1111:power:    { kind: exchange,     requires: [sre] }
  aws:1111:deployer: { kind: exchange,     requires: [ci-gitops] }
  argocd:            { kind: confidential, secret: argocd-oidc-client, redirects: [https://argocd.example/auth/callback], requires: [sre, dpo, engineer], ttl_cap: 12h }
  local-dev:         { kind: public,       redirects: [http://localhost:8000/callback], requires: [engineer] }

memberships:                   # the one table a console may extend — the same shape as groups.*.members
  hub-operators: [platform-admins@b.example]
```

| Table | Key | Holds | Who writes it |
|---|---|---|---|
| `groups` | internal group name | directory `members`, or `matchers` for machines | declared |
| `claims` | internal group name | a claim fragment merged into the token | declared |
| `lifetimes` | internal group name, or `default` | a duration | declared |
| `clients` | client id | kind, secret ref, redirects, `requires`, `ttl_cap` | declared, plus self-registration |
| `memberships` | internal group name | extra directory groups | declared baseline, console additions |

The hub loads `groups`, `claims`, `lifetimes` and `memberships`. The issuer
loads all five. Same parser, same validation, same layers.

## Proof → groups

Every caller arrives with a proof the service verifies but did not
produce, and every proof resolves to a set of internal groups. After that
point a person and a job are the same thing.

| Proof | Becomes the groups… |
|---|---|
| a corporate sign-in | whose `members` (or `memberships`) contain a directory group the hub confirms the account is in, **authoritatively** |
| a CI identity token | whose `matchers` the token's claims satisfy |
| a Kubernetes ServiceAccount token | whose `matchers` name that namespace and ServiceAccount |

Attributes exist only in matchers, at the front door. There is no policy
engine behind it: relying parties are role-based systems, and a cluster
role binding cannot read an attribute.

A token describes **one account**, never a person. Someone with accounts
in two Workspaces has two identities with two subjects. Linking accounts
is a consumer's concern (github-roster's), never the issuer's.

## Groups → token, by deep merge

The token's claims are the fixed identity claims — `sub` (stable per
account: workspace id plus the backend's user id), `email`, `name`,
`groups` with the internal group names — plus the deep merge of the
`claims` fragments of every group the caller is in.

| Kind | Merge rule |
|---|---|
| lists | union, de-duplicated, sorted |
| maps | merged recursively |
| scalars | may not conflict: two groups setting one key to different values is a **load-time error**, never a runtime choice |
| lifetime | the shortest across the caller's groups, then the client's `ttl_cap`, then `lifetimes.default` |

Lifetime is a property of the privilege, never of the identity provider:
nothing in this file may be a function of a pair such as group and
workspace, group and client, or group and person. When an exception is
needed, the answer is a new internal group, one reviewed line.

## Clients → audience and gate

A client's id is the `aud`. `requires` lists the internal groups any one of
which admits a caller; a caller in none is refused before a token exists.

| Kind | Used by | Has a secret |
|---|---|---|
| `public` | kubelogin per cluster, accessctl, Kargo's CLI, `local-dev` | no |
| `confidential` | ArgoCD, Kargo, a self-registered access-proxy | yes: a Secret in the issuer's namespace |
| `exchange` | AWS roles reached by token exchange | no |

Clients are declared or **self-registered** by an in-cluster workload
presenting its ServiceAccount token, within the host pattern allowed for
its namespace. Clients are never created in a console. Local development
uses the one declared `local-dev` client.

## Layers

Two sources, one schema, merged additively:

1. the **declared layer**: the deployment's ConfigMap(s), rendered from
   the installation's own access model; several may exist and merge;
2. the **console layer**: what the console wrote, `memberships` only for
   the hub.

A key present in both is shown once, marked declared, and the console's
copy is ignored rather than merged over it. The console layer exports as
the same YAML, so an installation that starts standalone moves its
edits into git by pasting.

## Validation at load

Unknown keys refused. Every key in `claims`, `lifetimes` and
`memberships` names a declared group. Every `requires` entry names one.
Every member address has a domain. No scalar conflict across any two
fragments. A matcher has at least one field. A typo fails the rollout,
not a login.

## What the console may change

| Area | Console | Declared only |
|---|---|---|
| memberships | attach a snapshotted directory group to a declared internal group; detach what the console attached | the baseline |
| groups, claims, lifetimes, clients, matchers | nothing | all |
| self-registered clients | revoke one | — |

## Testing the file

`accessctl policy test policy.yaml` evaluates fixtures — an account with
directory groups, a CI token's claims, a client id — and prints the token
that would result, so the file is reviewed like code.
