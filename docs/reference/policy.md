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
    matchers:                                             # matched, not listed
      - github: { repository: example-org/gitops, ref: refs/heads/master }
  hub-viewers:
    matchers: [{ email_domain: a.example }]                # the escape hatch, see below
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
  argocd:            { kind: confidential, secret: argocd-oidc-client, redirects: [https://argocd.example/auth/callback], signed_out: [https://argocd.example/], requires: [sre, dpo, engineer], ttl_cap: 12h }
  local-dev:         { kind: public,       redirects: [http://localhost:8000/callback], requires: [engineer] }

memberships:                   # the one table a console may extend — the same shape as groups.*.members
  hub-operators: [platform-admins@b.example]
```

| Table | Key | Holds | Who writes it |
|---|---|---|---|
| `groups` | internal group name | directory `members`, or `matchers`; a group with neither is one nobody is in yet, which is where a fresh installation starts | declared |
| `claims` | internal group name | a claim fragment merged into the token | declared |
| `lifetimes` | internal group name, or `default` | a duration | declared |
| `clients` | client id | kind, secret ref, `redirects`, `signed_out`, `requires`, `ttl_cap` | declared, plus self-registration |
| `memberships` | internal group name | extra directory groups | declared baseline, console additions |

The hub loads `groups`, `claims`, `lifetimes` and `memberships`. The issuer
loads all five. Same parser, same validation, same layers.

## The hub's own two groups, and scoping them

`hub-operators` and `hub-viewers` are the only names the hub reads out of
the policy for itself. It holds no role vocabulary of its own: an identity
is an operator because the policy puts it in the operators group, exactly
as any other relying party's roles work.

Suffix either with `@<workspace id>` and the role is held over **that one
tenant**:

```yaml
groups:
  hub-operators:                                  # the whole installation
    members: [platform-admins@a.example]
  hub-operators@C0northern:                       # one directory only
    members: [it-admins@north.example]
  hub-viewers@C0northern:
    matchers: [{ email_domain: north.example }]
```

A scope is a naming convention over the ordinary table rather than a
column in it, because the table is already where an installation says who
is in what, and the hub already reads two names out of it by convention.
A scope is a third: nothing in the schema, the merge or the validation has
to know. Only those two names carry one, so `team@north.example` is an
ordinary group and grants nothing over a workspace called
`north.example`.

What a scope means, exactly:

| | Installation-wide role | Scoped role |
|---|---|---|
| connect a new directory, upload a key | yes | **no** — the workspace does not exist yet, so there is nothing to be scoped to |
| edit the policy, the memberships, the OAuth client | yes | **no** |
| reconnect, probe, refresh, choose domains or groups, disconnect | every workspace | the named one |
| list directories, groups and people | every workspace | only the named ones |

A scope never widens the installation-wide role and never narrows it: an
identity holding one may act everywhere and carries no scopes at all.

**Recovery is not scoped**, by construction. It exists for the day the
directory or the policy is what is broken, and a recovery scoped to one
workspace could not repair the workspace whose absence caused it.

## Proof → groups

Every caller arrives with a proof the service verifies but did not
produce, and every proof resolves to a set of internal groups. After that
point a person and a job are the same thing.

| Proof | Becomes the groups… |
|---|---|
| a corporate sign-in | whose `members` (or `memberships`) contain a directory group the hub confirms the account is in, **authoritatively** |
| a CI identity token | whose `matchers` the token's claims satisfy |
| a Kubernetes ServiceAccount token | whose `matchers` name that namespace and ServiceAccount |

`matchers` are conditions on a verified proof, so they also cover a
signed-in address (`email`) or its domain (`email_domain`). Those are the
escape hatch for the day before any directory group exists, and for a
population no group describes; `members` is the normal way, because it is
the one the directory can confirm and therefore the one liveness gates.

Attributes exist only in matchers, at the front door. There is no policy
engine behind it: relying parties are role-based systems, and a cluster
role binding cannot read an attribute.

A token describes **one account**, never a person. Someone with accounts
in two Workspaces has two identities with two subjects. Linking accounts
is a consumer's concern (github-roster's), never the issuer's.

## Groups → token, by deep merge

The token's claims are the fixed identity claims — `sub`, `email`,
`name`, and `groups` with the internal group names — plus the deep merge
of the `claims` fragments of every group the caller is in.

**`groups` is the whole of the authorization a token carries** (decided
2026-09-09, [../design/trust.md](../design/trust.md)): flat, one string
per internal group, never a structured roles claim beside it. Every
relying party binds those strings as they are — a `ClusterRoleBinding`
subject, an ArgoCD `g,` line, a `requires` here — and nothing re-maps
them. A group's name is therefore the whole of what it usually adds; the
`claims` table is for the rare relying party that reads something that
is not a group. Where provenance must travel — which company's
directory vouched for this — it goes into the string
(`hub-viewers@<workspace id>`), where every consumer keeps working.

> **`sub` is an open decision.** This page said *workspace id plus the
> backend's user id*; the issuer mints **the address**. Both are
> defensible — the address is readable in every audit log and needs no
> second lookup; an opaque id survives a rename. Decided before 1.0
> (INF-681); until then the code is the truth.

| Kind | Merge rule |
|---|---|
| lists | union, de-duplicated, sorted |
| maps | merged recursively |
| scalars | may not conflict: two groups setting one key to different values is a **load-time error**, never a runtime choice |
| lifetime | the shortest across the caller's groups, then the client's `ttl_cap`, then `lifetimes.default` |

Conflicts are refused when the policy loads rather than when someone in
both groups signs in, so a bad edit fails a rollout and never produces a
token whose shape depends on who is looking.

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

`redirects` are where a code is delivered — a path that *starts* a
sign-in. `signed_out` are the pages a person may land on after an
RP-initiated logout — the application's front page. They are two lists
because putting somebody on a redirect URI after signing out begins the
login they just ended; one address in both fails the load, and an
`exchange` client, which nobody signs into, may declare no `signed_out`
at all.

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

## Not in this file

The **hold window** — how long a signed-in identity keeps its last granted
role while the directory cannot be vouched for — is a property of the hub,
not of the policy: it belongs to the service that has to stay usable while
its own directory is uncertain. It is a chart value.

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

Two ways, and both answer the same question.

`accessctl policy test policy.yaml` evaluates fixtures — an account with
directory groups, a CI token's claims, a client id — and prints the token
that would result, so the file is reviewed like code.

The console does it live against the policy in force. Search for a
person and their page shows the internal groups, what put them in each,
the merged claims, the lifetime, and every client with whether they reach
it; Matchers lists every rule and answers the same for a CI job or a workload. From the other
end, a group's page and a client's page list the people who hold them
right now, which is the question an access review asks and the one this
file cannot answer alone: the file says which directory groups count, and
only the directory knows who is in them. A policy that reads correctly
and behaves differently is the failure worth catching, and those pages
are where it shows.
