# The policy

One schema, loaded by both services. It answers four questions and no
others: who is in which internal group, what a group adds to a token, how
long a token lives, and which client may be issued one. Everything that
shapes a token is derivable from this file by reading it. It supersedes
an earlier flat rules list, which survives only as the matchers inside
machine groups.

## The tables

```yaml
version: 1

groups:                        # internal groups — the vocabulary, named <scope>:<thing>:<role>
  prod:k8s:admin:
    members: [role-sre@a.example, role-sre@b.example]   # directory groups, any workspace
  prod:k8s:auditor:
    members: [role-security@a.example]
  prod:shop:deployer:
    members: [team-shop@a.example]
  rung:sre:                                             # two segments: a lifetime carrier, not a grant
    members: [role-sre@a.example, role-sre@b.example]
  ci:platform:deployer:
    matchers:                                           # matched, not listed
      - github: { repository: acme/platform, ref: refs/heads/master }
  all:access-roster:viewer:
    matchers: [{ email_domain: a.example }]              # the escape hatch, see below
  all:access-roster:operator:
    members: [directory-admins@a.example]

claims:                        # what a group adds beyond its own name — sparse, usually empty
  prod:k8s:auditor: { tailnet: { tiers: [vpc] } }

lifetimes:                     # how long — default plus the rungs
  default: 4h
  rung:sre: 8h
  ci:platform:deployer: 1h

clients:                       # who may be issued a token for what; the id is the audience,
                               # unless the request names a resource below
  k8s:prod:        { kind: public,       requires: [prod:k8s:admin, prod:k8s:auditor] }
  aws:1111:power:    { kind: exchange,     requires: [prod:k8s:admin] }
  aws:1111:deployer: { kind: exchange,     requires: [ci:platform:deployer] }
  argocd:            { kind: confidential, secret: argocd-oidc-client, redirects: [https://argocd.example/auth/callback], signed_out: [https://argocd.example/], requires: [prod:k8s:admin, prod:k8s:auditor], ttl_cap: 12h, display_name: Argo CD, description: Continuous delivery for the mgmt cluster. }
  local-dev:         { kind: public,       redirects: [http://localhost:8000/callback], requires: [prod:shop:deployer] }
  accessctl:         { kind: public,       redirects: [http://127.0.0.1/callback], requires: [prod:k8s:admin, prod:k8s:auditor], sign_in_exchange: true, display_name: accessctl }

resources:                     # what a token may be minted FOR, when that is not the client asking
  https://mcp.example/:        { requires: [prod:k8s:admin], ttl_cap: 5m, display_name: Telemetry }

client_documents:              # clients that describe themselves; empty means the mechanism is off
  origins:  [clients.example]
  requires: [prod:shop:deployer]
  ttl_cap:  5m
```

| Table | Key | Holds | Who writes it |
|---|---|---|---|
| `groups` | internal group name | directory `members`, or `matchers`; a group with neither is one nobody is in yet, which is where a fresh installation starts | declared |
| `claims` | internal group name | a claim fragment merged into the token | declared |
| `lifetimes` | internal group name, or `default` | a duration | declared |
| `clients` | client id | kind, secret ref, `redirects`, `signed_out`, `requires`, `ttl_cap`, `sign_in_exchange`, `display_name`, `description`, `backchannel_logout_uri` | declared |
| `github` | organisation login | the organisation's own `members`, and `teams` keyed by slug, each with `members` and `maintainers` | declared |
| `resources` | resource indicator (an absolute URI) | `requires`, `ttl_cap`, `display_name`, `description` — the gate on a service a token may be minted *for* | declared |
| `client_documents` | — | `origins`, `requires`, `ttl_cap`: which hosts may serve a client's own description, and who may use such a client | declared |

Seven tables, one writer. There is no `memberships` table and no
console-written layer: the console writes nothing into the policy, and
the key is refused like any other unknown one rather than ignored. A
directory group that should feed an internal group is named in that
group's `members`, here, in git.

The policy may be one file or a directory of them, which is how the chart
mounts it. In a directory, every `*.yaml` file says `version: 1`. The
keyed tables (`groups`, `claims`, `lifetimes`, `clients`, `resources`,
and each organisation's `teams` under `github`) merge by key, and a key
declared in two files is refused. `vocabulary` and `client_documents` are
installation-wide: one file declares each, and a second is refused.
Under `github`, one organisation's own `members` come from one file, and
its `ignore` entries add up across files.

The last two arrived together and for one reason: a client and the thing
it wants a token for stopped being the same object. `resources` is what a
token may be *for*; `client_documents` is how a client this installation
does not deploy may still ask. Both are off unless written — an
installation that names neither behaves exactly as it did.

## Naming

Every grant is named **`<scope>:<thing>:<role>`** — *role, on thing, in
scope* — and the reasoning is in [design/trust.md](../design/trust.md#naming).
`scope` is an environment, a tenant id, or `all`; `thing` is what the role
is on (a subsystem such as `k8s`, a project such as `shop`, an application
such as `access-roster`); `role` is from that thing's own ladder. The two
exceptions are not grants and are two segments on purpose: `rung:<name>`
carries a session lifetime, `emp:<slug>` is a person. The loader warns on
a name in neither shape. In force since v0.9.3.

The grammar, `all`, sensitive scopes and the naming anti-patterns are
[docs/taxonomy.md](../taxonomy.md); what a *name* is checked against, once
an installation opts in, is the next section.

## Vocabulary

An OPTIONAL top-level table, in force since v1.32.0, that declares which
scopes and things exist, each thing's role ladder, and which role implies
which other one:

```yaml
vocabulary:
  scopes:
    kernel: { sensitive: true }
    prod:   { sensitive: true }
    devel: {}
    stage: {}
    all:   {}          # only for a thing that exists once per installation
  things:
    k8s:
      scopes: [kernel, devel, stage, prod]
      roles: { viewer: [], operator: [viewer], admin: [operator] }
    argocd:
      scopes: [kernel, devel, stage, prod]
      roles: { viewer: [], deployer: [viewer], operator: [viewer], admin: [deployer, operator] }
    grafana:
      scopes: [all]
      roles: { viewer: [], editor: [viewer], admin: [editor] }
    ssh:
      scopes: [kernel, devel, stage, prod]
      roles:
        admin: []                    # list form: valid on every scope ssh declares
        user: { scopes: [devel] }    # object form: valid on devel alone
```

| Table | Key | Holds |
|---|---|---|
| `vocabulary.scopes` | scope name | `sensitive` (optional, default false) |
| `vocabulary.things` | thing name | `scopes` (the declared scopes this thing exists in) and `roles` (role name to `policy.RoleSpec` — see [Per-role scopes](#per-role-scopes)) |

**Opt-in, and strict once opted into.** No `vocabulary` table means
nothing here applies — today's behaviour, unchanged, and every existing
policy keeps loading and evaluating exactly as it did. Declare one, and
the policy **refuses to load** when any concrete grant name anywhere in
the file fails to fit it, naming the offending name and the reason:

- the scope isn't declared under `vocabulary.scopes`;
- the thing isn't declared under `vocabulary.things`;
- the scope isn't one of the thing's declared `scopes`;
- the role isn't one of the thing's declared `roles`.

"Anywhere" means every `groups` key, every `claims` key, every
`lifetimes` key except `default`, every client's, resource's and
`client_documents`'s `requires`, and every GitHub binding. `rung:` and
`emp:` names are exempt everywhere, as they always were: the vocabulary
governs grants, and those are not grants.

**Roles imply explicitly, and the graph may not cycle.** `admin: [operator]`
means holding admin also holds operator directly; what operator itself
implies is operator's own entry — `admin: [deployer, operator]` above
means admin implies BOTH, branching rather than chaining. `implies` may
only name another declared role of the **same** thing, and validation
refuses a graph with a cycle, naming the role it closes at. See
[taxonomy.md#inheritance](../taxonomy.md#inheritance) for how the implied
roles are actually granted — that happens once, in evaluation, not here:
this table is only the declaration.

### Per-role scopes

A role's own value in `things.<t>.roles` is EITHER the plain list of
implied roles shown above, OR an object naming `implies` and/or `scopes`
explicitly — `ssh.user` above, restricted to `devel` alone even though
`ssh` itself declares `kernel`, `devel`, `stage` and `prod`. Both keys are
optional; `policy.RoleSpec` accepts either shape and every policy written
before this existed used the list form, which still parses exactly as it
always did (no role restricted to anything). This is for a role that
only ever makes sense on some of its thing's scopes — `ssh.user` for a
break-glass login meant only for `devel`, never `kernel` — where the
plain thing-wide `scopes` was too coarse to say so.

A role's own `scopes`, when declared, must be a non-empty subset of its
thing's own — refused at load otherwise, naming which of the three it is:
a scope the role names that is not declared under `vocabulary.scopes` at
all, a scope the role names that its thing does not itself have, or an
explicit empty list (pointless to declare — a role valid nowhere is
almost certainly a stray empty list, not an intentional one).

**A concrete grant is refused when the role does not cover its scope**,
distinctly from a scope the *thing* does not have: `kernel:ssh:user` is
refused — `ssh` does declare `kernel`, but `user` restricts itself to
`devel` — with a message naming the role's own scopes, `role "user" of
thing "ssh" is valid only on scopes [devel]`. A [mapping
wildcard](#mapping-wildcards) skips rather than refuses: `*:ssh:user`
expands to `devel:ssh:user` alone, silently leaving out `kernel`, `stage`
and `prod` the same way it already skips a thing that lacks the role
entirely — see the next section for when that empties a wildcard
completely.

**Inheritance must not lose scope coverage.** An `implies` edge is
refused at load when its target role does not cover every scope its
source does: `admin: [user]` where `admin` is valid everywhere (the
default) and `user` restricts itself to `devel` alone would let holding
`kernel:ssh:admin` imply a `user` role that was never meant to reach
`kernel` — refused rather than silently dropping `kernel` from what
`admin` implies, because a mismatch here is a policy mistake, not a shape
evaluation should quietly work around. See
[docs/decisions/0012-per-role-scopes-in-the-vocabulary.md](../decisions/0012-per-role-scopes-in-the-vocabulary.md).

**Mapping wildcards** — `*` in the scope and/or thing position of a
`groups` key, such as `*:k8s:admin` or `devel:*:viewer` — need a declared
vocabulary and are refused without one. A role wildcard (`S:T:*`) is
always refused, and so is `*:*:*`. See
[taxonomy.md#mapping-wildcards](../taxonomy.md#mapping-wildcards) for the
grammar and [Groups → token, by deep merge](#groups--token-by-deep-merge)
for how a wildcard key is expanded and unioned with a caller's concrete
groups.

**A wildcard that expands to no group is refused, not silently accepted.**
A key nobody is ever in is exactly the "grant that never took effect"
this table exists to catch, whether the key is a plain typo or a wildcard
whose sensitive exclusion happens to empty it:

- if the wildcard's own scope segment is concrete and marked `sensitive`
  — `prod:*:viewer` with `prod` sensitive — the refusal says so by name:
  *`"prod:*:viewer": scope "prod" is sensitive and is never reached by a
  wildcard; name the concrete groups (e.g. "prod:k8s:viewer") instead`*;
- for any other reason the expansion is empty — no declared thing has
  the role at all (`devel:*:admins` when nothing declares `admins`), no
  thing with that role declares the named scope, no thing with that role
  and that scope allows the role itself on it (`kernel:*:user` when every
  thing's `user` role restricts itself to scopes that do not include
  `kernel` — see [Per-role scopes](#per-role-scopes)), or every scope a
  swept-in thing declares turns out sensitive (`*:k8s:viewer` when every
  scope `k8s` has is `sensitive`) — the refusal says *`"<key>" expands to
  no group: <why>`*.

**Explainability.** `policy.Result`'s `Held` carries, per held group:
`Key` — the `groups` key that matched directly, equal to the group's own
name for an ordinary key and different for a wildcard's — and `Implies` —
the concrete group whose role, one hop at a time, implied this one, empty
when the group was held directly. A caller may hold one group for more
than one reason, so `Held` carries one entry per reason rather than
picking a winner. This is data for a console page a later change will
build; nothing here renders it.

## The service's own two groups, and scoping them

`all:access-roster:operator` and `all:access-roster:viewer` are the only
names the service reads out of the policy for itself. It holds no role
vocabulary of its own: an identity is an operator because the policy puts
it in the operators group, exactly as any other relying party's roles
work.

Put a **workspace id** in the scope position and the role is held over
**that one tenant**:

```yaml
groups:
  all:access-roster:operator:                     # the whole installation
    members: [platform-admins@a.example]
  C0northern:access-roster:operator:              # one directory only
    members: [it-admins@north.example]
  C0northern:access-roster:viewer:
    matchers: [{ email_domain: north.example }]
```

A scope is a naming convention over the ordinary table rather than a
column in it, because the table is already where an installation says who
is in what, and the service already reads two names out of it by convention.
A scope is a third: nothing in the schema, the merge or the validation has
to know. Only the service's two roles read a workspace out of the scope
position; `north.example:k8s:admin` would be an ordinary group and grants
nothing over a workspace.

What a scope means, exactly:

| | Installation-wide role | Scoped role |
|---|---|---|
| connect a new directory, upload a key | yes | **no** — the workspace does not exist yet, so there is nothing to be scoped to |
| edit the policy or the OAuth client | **nobody**: the policy is a file in git and the client is a Secret |  |
| reconnect, probe, refresh, choose domains or groups, disconnect | every workspace | the named one |
| list directories, groups and people | every workspace | only the named ones |

A scope never widens the installation-wide role and never narrows it: an
identity holding one may act everywhere and carries no scopes at all.

### Who owns a GitHub organisation

The same two groups can operate one company's GitHub organisations and not
another's. Which directory owns an organisation is **not in the policy**: it
is recorded in the organisation's own connection when it is connected, because
access-roster already knows which directories are connected, and a second copy
in a file would only drift from the first. The policy names an organisation by
its login and binds its teams; it carries no `owner`.

**Who may connect an organisation nobody has connected yet, and who then owns
it** (one rule, the same for a Slack workspace):

| The caller | Owner of what it connects |
|---|---|
| the installation-wide operator (`all:access-roster:operator`) | **chosen** on the connect form: any connected directory, or none |
| an operator of exactly one connected directory (`<id>:access-roster:operator`) | that directory, without being asked |
| an operator of several connected directories | **chosen** among them, and must |
| an operator of a directory that is not connected, a viewer, anyone else | refused |

The owner is recorded with the connection and with its audit record
(`roster.github_org.connected` carries `owner`). It is a directory workspace
id; the console shows the directory by its primary domain, the domain of the
account the hub connected it as. A directory that is not connected cannot be
named, and none ever is by a caller who does not operate it.

**Changing it** is the installation-wide operator's alone, to any connected
directory or to none (`ChangeGitHubOrganisationOwner`, or the *Change owner*
button on the organisation's page). It is recorded as a configuration change
(`roster.github_org.owner_changed`, with the previous and the new owner). The
owner of an organisation cannot hand it to another directory, or take one.

| An organisation… | may be operated by |
|---|---|
| connected with an owner | the `<owner>:access-roster:operator` of that workspace, **or** the `all:access-roster:operator` |
| connected with none, or connected before owners were recorded | the `all:access-roster:operator` alone (how it always was) |
| not connected yet | connecting it: the installation-wide operator, or an operator of a directory, as above |

"Operated" is every action on it: connect, reconnect, disconnect, confirm its
removals, its runner Apps, the Apps the catalogue declares for it and their
recent tokens, and finishing a connect when GitHub sends the browser back (the
role is checked again there, for whoever is signed in then; the owner a flow
will record travels in the signed state, so it cannot be changed on the way).
Adopting links (`ImportGitHubLinks`) is people's rather than an organisation's,
so it is open to an operator of any directory but adopts an account only on the
evidence of an organisation that caller may operate.

What is *seen* follows the recorded owner: a viewer scoped to a workspace sees
the organisations that workspace owns, their Apps and reports, and nothing of
another company's. An organisation nobody has connected shows its bindings
alone, and only to whoever could connect it. The link App and the links are
every organisation's, so they are the installation-wide viewer's alone. A
scoped role over a workspace that owns no organisation, and could connect none,
is refused the GitHub pages rather than shown an empty one.

A policy that still carries `github.<org>.owner` (a key v1.41.0 briefly
accepted) is **refused at load**, with a message saying the owner is now
chosen on the console when the organisation is connected. Delete the key; the
organisation keeps working as an installation-wide one until it is connected
again with an owner, or its owner is changed by the installation-wide operator.
[Slack workspaces follow the same rule](#who-owns-a-slack-workspace).

**Recovery is not scoped**, by construction. It exists for the day the
directory or the policy is what is broken, and a recovery scoped to one
workspace could not repair the workspace whose absence caused it.

## Proof → groups

Every caller arrives with a proof the service verifies but did not
produce, and every proof resolves to a set of internal groups. After that
point a person and a job are the same thing.

| Proof | Becomes the groups… |
|---|---|
| a corporate sign-in | whose `members` contain a directory group the service confirms the account is in, **authoritatively** |
| a CI identity token | whose `matchers` the token's claims satisfy: `repository`, `owner`, `ref`, `workflow`, `environment`, `workflow_ref`, `job_workflow_ref`, `sha`, `event_name` and `ref_type` as globs, and `visibility` (`public`, `private` or `internal`) exactly |
| a Kubernetes ServiceAccount token | whose `matchers` name that namespace and ServiceAccount |

Globs are Go's `path.Match`, where `*` does not cross a `/`. Every field
left out matches anything, so a matcher written before a field existed
keeps meaning what it meant. `job_workflow_ref` —
`example-org/app/.github/workflows/release.yml@refs/heads/main` — is the
workflow file the job is defined in (the called file, for a reusable
workflow), and `workflow_ref` the file the run started from: together
with `ref` and `event_name` they pin a group to one reviewed workflow on
one branch, run the way it is meant to run, rather than to every job a
repository can run. That is the shape a group behind a write grant of a
[catalogue App](../connect/github-apps-catalogue.md#pinning-a-grant-to-one-workflow)
should have.

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

| Claim | What it says |
| -- | -- |
| `sub` | the account. A person is their **email**; a ServiceAccount (a workload, or a recovery sign-in) is **`<cluster>:k8s:<namespace>:<name>`** — the cluster included so the same namespace and name on two clusters are two subjects |
| `email`, `email_verified`, `preferred_username` | the address again, so that no consumer needs a fallback |
| `name`, `given_name`, `family_name` | who they are, when the directory says. Absent for a workload |
| `groups` | **the whole of the authorization** |
| `auth_time` | when the person signed in. Not when the token was minted: a refresh an hour later carries the same `auth_time` and a fresh `iat`, which is what a re-authenticate rule reads |
| `sid` | the session this token belongs to — the same id the console lists and revokes. Absent on a token no session backs, such as a workload's |

The ID token carries all of them, because a relying party that reads the
ID token (ArgoCD and Kargo both do) must not have to make a second call
to learn who signed in. The userinfo endpoint answers the same set.

**`groups` is the whole of the authorization a token carries**, as
[../design/trust.md](../design/trust.md) sets out: flat, one string
per internal group, never a structured roles claim beside it. Every
relying party binds those strings as they are — a `ClusterRoleBinding`
subject, an ArgoCD `g,` line, a `requires` here — and nothing re-maps
them. A group's name is therefore the whole of what it usually adds; the
`claims` table is for the rare relying party that reads something that
is not a group. Where provenance must travel — which company's
directory vouched for this — it goes into the string
(`<workspace id>:access-roster:viewer`), where every consumer keeps
working.

> **`sub`.** A person is their **email**
> address — readable in every audit log, no second lookup, and what the
> service already keys by; a rename becomes a new `sub` whose old sessions
> end, which for a controlled directory is acceptable, arguably correct.
> A ServiceAccount is **`<cluster>:k8s:<namespace>:<name>`**, from the
> issuer's `cluster` value; an installation that names no cluster keeps
> the unqualified `k8s:<namespace>:<name>`. The earlier *workspace id plus
> the backend's user id* is retired. A `service_account` matcher may name
> a `cluster` to narrow to one; naming none matches any, so every rule
> written before clusters were named still means what it meant.

> **Which clusters.** The clusters whose
> ServiceAccount tokens count are **not** in this file. They are chart
> values — `exchange.clusters`, one row of `{name, issuer, jwksUri}` per
> cluster — because they are not a statement about who may do what, which
> is what this file is for. They are where a signature is checked, which
> is deployment configuration and carries no secret. A `cluster` named in
> a matcher is the `name` of one of those rows, and renaming a row
> silently changes what every rule about it matches.</br></br>
> The check itself is the key set that cluster publishes, never a call to
> the cluster: EKS exposes one per cluster (it is what IRSA rests on),
> Talos serves it at the API server's `/openid/v1/jwks`. So one issuer
> serves many clusters while holding access to none, including its own.
> TokenReview remains for recovery alone.

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

A client's id is the `aud`, unless the request named a resource — see
[Resources](#resources--what-a-token-is-for). `requires` lists the internal
groups any one of which admits a caller; a caller in none is refused
before a token exists.

| Kind | Used by | Has a secret |
|---|---|---|
| `public` | kubelogin per cluster, accessctl, Kargo's web UI and CLI, `local-dev` | no |
| `confidential` | ArgoCD, every access-proxy | yes: a Secret in the issuer's namespace |
| `exchange` | AWS roles reached by token exchange | no |

`redirects` are where a code is delivered — a path that *starts* a
sign-in. `signed_out` are the pages a person may land on after an
RP-initiated logout — the application's front page. They are two lists
because putting somebody on a redirect URI after signing out begins the
login they just ended; one address in both fails the load, and an
`exchange` client, which nobody signs into, may declare no `signed_out`
at all.

A token **exchange** trades a proof for a token whose `aud` is any
declared client, and the target's `requires` decides. The proofs are the
ones in the table above, each checked against its own issuer's keys, plus
one of this issuer's own: a person's sign-in to a client that declares
`sign_in_exchange: true` -- `accessctl`, whose tokens never leave the
laptop -- presented by that client, as its `access_token`, while the
session behind it is live. It is what lets one kubeconfig and one aws.ini
serve a laptop and a CI job alike. No other token this issuer signs is a
proof: an ID token or a relying party's access token is for that party.
Only a `public` client may declare it.

### What the sign-in page calls a client

`display_name` and `description` are what the issuer's sign-in page shows
a person: *Sign in to continue to **Argo CD***, the description on the
line under it, and the host the sign-in returns to. Both are optional.

| The row declares | The page says |
|---|---|
| `display_name` | that name |
| no name, and the id is `k8s:<cluster>` | *Kubernetes — `<cluster>`* |
| no name | the client id, as it is |

The host is taken from the redirect URI of the request being answered,
which the issuer has already matched against `redirects`, and it is
shown as text, never as a link. When that redirect is on this computer
(`localhost` or a loopback address, which is where kubelogin and
accessctl listen) the page says instead that *a program on this computer*
is asking, names the client, and shows no port. Nothing on the page comes
from its own query string, and nothing on it says which groups would
admit anybody. The refusal a signed-in person sees for a client they
hold no group of names the application the same way.

**Both fields are public.** Anyone who starts a sign-in for a client
reads them, before proving who they are, so neither is a place for
anything a stranger should not know: say what the application is for,
not what it holds or who administers it. Validation refuses a name over
80 characters, a description over 200, a blank value, and any control
or formatting character — a line break, a tab, a bidirectional override
— because each would make the page say something other than what the
file appears to. Everything is HTML-escaped when written.

An issuer older than the release that introduced them refuses both keys
as unknown, like any other: deploy the issuer before declaring them.

**`backchannel_logout_uri`** opts a client into OIDC Back-Channel
Logout: when a sign-in ends, the issuer POSTs a signed `logout+jwt`
naming the session (`sid`) to every such client that signed the person
in. It is for a client running its own session — a console behind
`access-proxy` cannot take one, because oauth2-proxy keeps each session
under a key only the browser's cookie holds, and so lives with the
proxy's refresh interval instead.

Clients are **declared**: one row each in the deployment's values, with
`requires` mandatory — an empty list means nobody, not everyone, and the
issuer refuses to start on one. Never created in a console and never
registered by a workload, so the set of them is answerable by reading the
repository. Local development uses the one declared `local-dev` client.

There is one exception, off unless an installation asks for it, and it
keeps that property in a weaker form: a client that this installation does
not deploy may identify itself by a URL serving a document about itself,
admitted only from an allow-listed origin. What is then answerable by
reading the repository is the set of **origins**. See
[Clients that describe themselves](#clients-that-describe-themselves).

## Resources — what a token is for

A client's id was always the audience, because until recently the client
and the thing a person reached were one object: somebody signs in to Argo
CD, and the token is for Argo CD.

That stops holding as soon as they are not one object. A Model Context
Protocol client is somebody's editor; what it wants a token for is a
service elsewhere. Minting `aud` as the client's id there states something
untrue and useless — a service pinning `aud` to decide whether a token was
meant for it would have to pin the name of every editor that might call.

So a resource is declared, a client names it with the `resource` parameter
(RFC 8707), and `aud` is the resource:

```yaml
resources:
  https://mcp.example/:
    requires: [prod:k8s:admin]
    ttl_cap: 5m
    display_name: Telemetry
```

**The two gates compose.** A client's `requires` says who may use that
client; a resource's says who may reach that service; a caller must
satisfy both. Checking only the client would let anybody who may use an
editor reach every service that editor can name.

**Both caps apply, and the shorter wins.** Each was written by somebody
saying *not longer than this*, and honouring the longer would answer
neither.

### What a client asking for a resource gets, and what it does not

| It asks | It gets |
|---|---|
| nothing | a token for the client itself — unchanged, and what every client did before this table existed |
| a declared resource it is entitled to | a token whose `aud` is the resource, capped by both, and the same `aud` on every refresh of that session |
| a resource this installation does not declare | `invalid_target`, at the moment of the mistake |
| a resource it is not entitled to | refused at sign-in, naming the resource and the group it would need |
| more than one resource | refused: a token for several audiences means nothing anybody should rely on, so it is refused rather than quietly narrowed to the first |
| a relative URI, or one with a fragment | refused: RFC 8707 says a resource indicator is an absolute URI with no fragment, and a fragment is a way for two parties to spell the same resource differently while believing they agree |

**A resource indicator is matched exactly.** A trailing slash or a
different scheme is a different resource, which the refusal says, because
the alternative is somebody comparing two URLs by eye.

**The refusal is the point.** The parameter was previously *ignored* — the
library's decoder drops what it does not model — so a client asking for a
token scoped to one service was handed one scoped to itself, and told
nothing. A token that fails somewhere else later, for a reason nobody
connects to this request, is the expensive version of this mistake.

**The session remembers.** A refresh an hour later carries a token and
nothing else, so the resource is recorded with the session: without it the
renewed token would be minted for the *client* while the original named a
resource, silently changing what the token is for halfway through a
session — and the resource's own gate would go unchecked for the rest of
that session's life. It is re-checked on every refresh, which is where a
withdrawn grant actually bites.

## Groups in a token (scoping)

**Today every token's `groups` claim carries every internal group the
caller holds**, whatever the audience. `groups` is still the whole of the
authorization, and this does not change what `requires` admits — see
[0006](../decisions/0006-groups-claim-scoped-per-audience.md) for why a
token that carries an installation's whole naming structure into one
narrow client's cookie is a cost worth ending, and
[0010](../decisions/0010-a-declared-vocabulary.md) for how the rule below
was sharpened once a declared [vocabulary](#vocabulary) existed to name a
thing precisely.

**The decided rule.** A token carries every group the caller holds
(after [inheritance](#vocabulary)'s expansion, which [Proof → groups](#proof--groups)
already closes before this runs) whose `<scope>:<thing>` pair appears
among the `<scope>:<thing>` pairs of its audience's `requires` — in ANY
role. The audience is the client, or the [resource](#resources--what-a-token-is-for)
a request named; for a token exchange, the target the exchange was
GRANTED, never the client presenting it.

```yaml
clients:
  grafana: { kind: confidential, secret: grafana-oidc, requires: [devel:grafana:viewer] }
```

Grafana requires `devel:grafana:viewer`. A caller holding
`devel:grafana:editor`, `devel:grafana:viewer`, `devel:k8s:admin` and
`prod:shop:deployer` gets a Grafana token carrying
`[devel:grafana:editor, devel:grafana:viewer]`: both share Grafana's own
pair, `devel:grafana`, so BOTH survive even though only `viewer` is
named — the pair is what is checked, never the role. The other two are
dropped: `devel:k8s:admin` is a different thing entirely, and
`prod:shop:deployer` is a different scope of a thing this audience never
named.

**The override.** A client row, a resource row, or the
[client_documents](#clients-that-describe-themselves) block itself may
set `groups: all` (carry everything, exactly as every token does today)
or `groups: [thing, thing, …]` (additionally carry every held group of
one of those things, in ANY scope, on top of whatever pair matching
already keeps):

```yaml
clients:
  console:
    kind: confidential
    secret: console-oidc
    requires: [devel:grafana:viewer]
    groups: [shop]   # console also reads a shop group to pick an app-level role
```

`all` or a list of names is all validation checks without a declared
vocabulary; with one, each name in the list must be a thing
[vocabulary.things](#vocabulary) declares — a typo in an override is
exactly the mistake a declared vocabulary exists to catch everywhere
else, and this is one more place it names a grant.

**A self-described client IS gated, and scoped.** A client admitted
through [client_documents](#clients-that-describe-themselves) has no row
of its own in `clients` — its id is whatever URL it serves its own
document at — but every one this installation admits shares ONE gate,
`client_documents.requires`, and its pairs are read from there; a
`client_documents.groups` override widens it for every document client at
once, the same way a client's own `groups` widens one row.

**An audience that matches no gate at all** — not a declared client, not
a declared resource, and not a URL `client_documents.origins` permits
(including every audience, when this installation admits no document
client) — keeps nothing by pair matching, because "the audience's
requires" names a gate that does not exist for it. That is the plain
reading of the rule, and it is also the useful one for report mode: every
such audience's tokens log "would drop everything" until it is given a
row, an allow-listed origin, or an override, to read.

**`rung:` and `emp:` names** are not grants ([taxonomy.md](../taxonomy.md))
and have no `<scope>:<thing>` pair, so pair matching never keeps them.
An override keeps one of them either of two ways: naming the FULL
two-segment name outright (`groups: [rung:sre]`), for one specific name;
or naming its FAMILY — `rung` or `emp`, the part before the separator —
to keep every held name of it at once, the same way a thing entry keeps
every role of it. This is the one an installation with more than a
handful of people actually reaches for: a Kubernetes cluster's audience
binds each person's own namespace to their `emp:<slug>`, and no single
outright entry could name every person's slug in advance.

```yaml
clients:
  k8s:devel:
    kind: public
    requires: [devel:k8s:viewer]
    groups: [emp]   # every emp:<slug> held, for the cluster's own binding
```

A declared vocabulary constrains a bare-word entry to a declared thing OR
one of the two known families (there is no `vocabulary.families` table —
`rung` and `emp` are the only two, and validation knows them by name); an
entry containing a separator (an exact two-segment name) is neither a
thing nor a family, so a vocabulary has nothing to say about it and it
validates either way. Nothing about how `rung:` and `emp:` names are
USED changes: a `rung:` group's lifetime is read off the full held list
at the issuer, before scoping ever runs (see [Groups → token, by deep merge](#groups--token-by-deep-merge)),
so a `rung:` group missing from a token's `groups` claim under `enforce`
still shortens that token's life exactly as it does today — scoping
narrows what a token SAYS, never what the issuer computes from what a
caller holds.

**`off`, `report`, `enforce`.** `groupsScoping` (a chart value,
`GROUPS_SCOPING` in the environment — see
[configuration.md](configuration.md)) is one of the three. `off` computes
and logs nothing. `report`, the default since 1.32.0, computes the rule
above for every minted token and logs one line when it would have dropped
something — audience, client, subject and the dropped names, at INFO —
without changing the token: `groups` mints exactly as it always has
either way. `enforce` actually narrows the claim to what the rule above
keeps, and logs the SAME finding at DEBUG instead of INFO, because a
dropped group is the steady state once enforce is on rather than news on
every token.

Turning enforce on is opt-in and per installation: the chart's default
stays `report`, and an installation is expected to run report first, read
what it logs, and add a `groups:` override to any client or resource the
log names, before ever setting `groupsScoping: enforce` — see
[docs/operations/runbook.md#reading-the-groups-scoping-report](../operations/runbook.md#reading-the-groups-scoping-report)
and
[docs/operations/runbook.md#turning-enforce-on](../operations/runbook.md#turning-enforce-on).

**What enforce narrows, and what it does not.** Every place a token or
`/userinfo` writes `groups` narrows to `kept`: the ID token, the access
token (an authorization code, a refresh, a token exchange alike), a token
this installation's own console mints for itself
(`Storage.MintFor`), and `/userinfo`'s answer — see the next paragraph.
Nothing else changes. `requires` still gates entry against the FULL
evaluated set, never the narrowed one; a `rung:` group's lifetime is still
read off that same full set, before scoping ever runs — see
"`rung:` and `emp:` names", above, on the same point. Scoping narrows
what a token SAYS, never what the issuer computes from what a caller
holds.

**`/userinfo` is scoped too.** The `userinfo` endpoint
(`SetUserinfoFromToken`) answers with the SAME `groups` a token's owner
already holds, keyed by the presented access token rather than by a fresh
policy evaluation. Narrowing only the token's own claim and leaving
`userinfo` unscoped would not enforce anything: a relying party that
wanted the fuller list could still just call `userinfo` and read it
there, which is exactly the leak this whole design exists to close. So
enforce narrows both, by the SAME audience — the presented access token's
own audience or resource, read off its stored record — or scoping would
be bypassed by one call.

**Finding a role that went missing.** A relying party that used to read a
group beyond what its own `requires` names, and stops seeing it once
enforce is on, needs a `groups:` override — the fix is never in code.
Turn the issuer's log level to DEBUG, reproduce the failure, and read the
line naming that audience and subject: `dropped` names exactly the groups
the token stopped carrying. Add whichever of them the relying party
actually reads to a `groups:` override on that audience's row (a client's,
a resource's, or `client_documents.groups` for a self-described one) and
reload the policy — see
[docs/operations/runbook.md#turning-enforce-on](../operations/runbook.md#turning-enforce-on)
for the full walk-through.

## Groups delimiter (per audience, opkssh interop)

A client row or a resource row may pin `groups_delimiter`, which rewrites
every `:` in each name under that audience's `groups` claim to a different
string, AFTER the rule above has already decided which groups survive:

```yaml
clients:
  ssh-fleet:
    kind: public
    requires: [devel:ssh:user]
    signing_alg: RS256      # opkssh cannot verify this installation's default
    groups_delimiter: "."   # devel:ssh:user -> devel.ssh.user
```

**Why this exists at all.** It is a temporary interop shim for exactly one
relying party: opkssh's own server-side policy line,
`oidc:groups:<value>`, splits its ARGUMENT on every `:` and compares only
the LAST segment against a held group — so it can never match a name
shaped `<scope>:<thing>:<role>`, this schema's own separator, however the
value is quoted (the quotes are not stripped from what opkssh compares
against). `groups_delimiter: "."` mints `devel.ssh.user` instead of
`devel:ssh:user` for that one audience, which opkssh's own splitting
reads as a single, whole segment — a name its policy line can actually
match. See
[ADR 0015](../decisions/0015-a-per-audience-groups-delimiter-for-opkssh.md)
and [0004](../decisions/0004-ssh-opkssh-and-the-secret-stores-ca.md) /
[0011](../decisions/0011-ssh-people-opkssh-machines-and-hosts-openbao.md)
for opkssh's adoption in full. Upstream fixing its own parser removes the
need for this on any audience that no longer has the bug to work around.

**Rows without it are unaffected.** Empty (the default) leaves `groups`
exactly as every other audience already sees it — the grant's own `:` —
on the ID token, the access token, `/userinfo`, a token exchange and the
console's own internal mint (`MintFor`) alike: everywhere [Groups in a
token (scoping)](#groups-in-a-token-scoping) already narrows.

**Which row wins follows [signing_alg](#signing-algorithm-per-audience)
exactly**: an ID token reads the CLIENT's own `groups_delimiter`, because
an ID token never names a resource as its audience; an access token
reads the RESOURCE's, when a request named one, else the client's own.

**It changes how a group's name is spelled, never which groups a caller
carries.** `requires` still gates on the full, un-rewritten names; a
`groups:` override still names the un-rewritten group; the [Groups in a
token (scoping)](#groups-in-a-token-scoping) rule above still runs FIRST,
against the real names, and this only rewrites what survives it.

**Refused at load, unconditionally:**

- **Empty, or the separator itself, `:`.** Nothing to rewrite to, or a
  rewrite that changes nothing.
- **Whitespace, a quote (`"`) or a comma.** A value this schema
  round-trips through YAML and, eventually, a comma-joined display list
  must never need escaping to carry.
- **An ASCII letter, digit or `-`** — exactly `[A-Za-z0-9-]`, what every
  scope, thing and role this codebase's own vocabulary examples are built
  from ([taxonomy.md](../taxonomy.md)). A delimiter drawn from the same
  alphabet a name is written in is exactly the separator-collision mistake
  this restricts against.

`.` is the documented example precisely because it sits outside that
alphabet — no scope, thing or role this schema's own tests, fixtures or
reference docs declare uses one, and taxonomy.md's own grammar never
does either. **This is not a proof that `.` (or any other character) can
never appear in a group name** — a Groups-table key is not required to
fit `<scope>:<thing>:<role>` at all, so nothing in this schema can rule
every character out for every installation's every group, forever. That
is why the load-time check does not stop at the delimiter's own alphabet:

**Also refused at load: a delimiter that would collide two of THIS
policy's own declared groups.** Every concrete group this policy could
ever put in a token — every ordinary and non-grant Groups-table key,
and every mapping wildcard's expansion — is rewritten with the candidate
delimiter and checked against every other; two names that would become
the same string refuse the load, naming both. This is the actual
guarantee behind `groups_delimiter`: not that a character can never
collide in principle, but that IT DOES NOT, for the groups this
installation has actually declared, checked the moment a row asks for
it.

**Never point this at an audience whose own tokens this installation
reads back.** The hub's own two roles
([The service's own two groups, and scoping them](#the-services-own-two-groups-and-scoping-them))
are parsed by splitting on `:` — a `groups_delimiter` on this hub's own
client would make its own operator and viewer groups unreadable to
itself. This option is for an external relying party's parser bug, never
for a client this installation's own code consumes.

## Signing algorithm per audience

The issuer signs with several algorithms at once — RS256, ES256 and
ES384, whichever ones the deployment configured a key for — and picks the
one to use, per token, from the audience it is minting for. A client row
and a resource row may each pin one with `signing_alg`:

```yaml
clients:
  eks-cluster:
    kind: exchange
    requires: [prod:k8s:admin]
    signing_alg: RS256
resources:
  https://legacy.example/:
    requires: [prod:k8s:admin]
    signing_alg: RS256
```

**Why a pin exists at all.** OIDC Core §15.1 expects a provider to be
*able* to sign with RS256, and not every relying party keeps up: EKS's
associated OIDC identity provider and Kargo's verifier accept RS256 and
nothing else. Rather than pin the whole installation to the slowest
relying party forever — which is what changing `signingKey.certificate`
in the chart does — this is the one row that asks for it, and every
other audience keeps the installation default (ES384 in the chart).
[ADR 0009](../decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md)
is the decision in full, including why it partly supersedes
[ADR 0005](../decisions/0005-es384-signing-algorithm.md).

**Rows without it get the installation default** — today's one key's own
algorithm, ES384 in the chart — unchanged from before this existed.

**The audience decides, not the client asking.** For an ID token it is
always the client, because an ID token never names a resource as its
audience. For an access token it is the resource a caller named
(`resource`, above) or the client itself. For a token exchange
(`accessctl kube-token`, a CI job's exchange) it is the audience the
exchange was *granted* — the target — never the client presenting the
exchange: a caller authenticating as `local-dev` to exchange for
`eks-cluster` gets `eks-cluster`'s algorithm, not `local-dev`'s. For a
Back-Channel Logout token it is the client receiving it. For the
console's own short-lived mint (`MintFor`) it is that call's own target.

**A pin naming an algorithm this installation has no key for is refused
at issuer start**, not on the first token that would have needed it — see
`signingKey.additional` in [access-issuer.md](access-issuer.md). Fail
loudly, at start, or an operator's `signing_alg: RS256` on a row nobody
minted an RS256 key for would silently keep signing ES384 forever.

**An unknown value is refused at load**: `signing_alg` accepts exactly
`RS256`, `ES256` or `ES384` — the three this schema knows a real relying
party has asked for, not every algorithm a key in this estate could ever
produce.

## Clients that describe themselves

Every client above is minted as code, and that is the right default: a row
is reviewable, and its `requires` is where *who may obtain a token* is
decided. It does not fit software this installation does not deploy and
cannot enumerate — somebody's editor, a hosted assistant — which is how
clients of the Model Context Protocol arrive.

Such a client presents an **HTTPS URL** as its `client_id`, and that URL
serves a JSON document describing it (an OAuth Client ID Metadata
Document). The issuer fetches it, validates it, and treats the client as
`public`. Nothing is registered and nothing accumulates.

```yaml
client_documents:
  # The hosts that may serve a document. Empty -- the default -- turns the
  # whole mechanism off.
  origins: [clients.example]
  # Who may use ANY such client. Mandatory: origins without requires would
  # admit every person who can sign in at all.
  requires: [rung:engineering]
  # Optional, and worth setting: these tokens go to software this
  # installation did not deploy.
  ttl_cap: 5m
```

### Why this is proportionate, and what it does not weaken

Registration is not the authorization decision here. Reach is decided by
the groups a caller holds, so **a client this issuer has never seen cannot
widen anything** — it can only ask a person to consent to the reach that
person already has. A document may ask for a different `kind`, a longer
`ttl_cap` or a wider `requires`; none of those fields is read.

So the threat is not escalation. It is **phishing**: a hostile client
persuading somebody to sign in to it and taking the token away. That is
why the guard is an allow-list of origins rather than a refusal of unknown
clients, and why `requires` is mandatory here rather than optional.

A **declared client always wins**: the policy is consulted first, so
nothing is fetched for a client that is already in this file, and a
document cannot displace one.

### What it refuses

| Shape | Refused because |
|---|---|
| a document whose `client_id` is not the URL it was served from | otherwise a document at any allow-listed host could claim to be any client, and the id a person sees, the id the audit records and the id the token is minted for would all be a name its holder chose |
| an origin that is not allow-listed | decided before anything is dialled, so the allow-list is also what stops the issuer being used to fetch arbitrary URLs |
| a response larger than 64 KiB, or slower than 10 seconds per attempt | the URL is caller-chosen, so the response is an untrusted stream and a sign-in is waiting on it |
| a redirect to anywhere else | the document is served *at* its own id; a redirect chain is how an allow-list on the first hop stops meaning anything |
| a document with no `redirect_uris` | there would be nowhere to deliver a code |
| an `origins` entry with a scheme, a path or a `*` | an origin is a host; a wildcard also admits every subdomain somebody forgot about |
| `requires` or `ttl_cap` with no `origins` | written by somebody who expected it to apply |

A fetched document is honoured for ten minutes and then fetched again. A
transient failure of the fetch (a timeout, a reset connection, a 5xx answer)
is retried once after a short pause, within the sign-in's own deadline.

**Stale-while-error is bounded and transport-only.** If the refresh of a
document that was already validated still fails that way, the last good copy
is served for at most one hour past its normal expiry, and the issuer logs a
warning with the origin and the error each time. It is never served when the
origin *answered* and the answer is refused: a document that changed and no
longer validates, a redirect, a 4xx, an oversized body. This is safe because
the copy passed every check when it was fetched, access is still decided by
the person's groups and not by the document, and the window is short. Past
the window, a document that cannot be fetched is a client whose redirect URIs
are not known right now, and the flow fails.

The display name comes from the document, so it is text chosen by whoever
served it, shown on a page **before anybody has authenticated**. It is
bounded and stripped of anything that moves the cursor; with no name, the
host is shown, because the host is the part a person can recognise and the
part that was allow-listed. The audit trail records the **URL**, which is
the identity — the name is decoration its holder chose.

`client_id_metadata_document_supported` appears in the discovery document
only while an origin is named, because a client reads that field to decide
whether to present a URL at all.

## GitHub teams

```yaml
github:
  globex:                                   # the organisation's login
    members: [all:globex:employee]          # in the organisation, with or without a team
    teams:
      team-platform:                        # the team's SLUG, not its display name
        members: [all:platform:engineer]
        maintainers: [all:platform:lead]
      team-security:
        members: [all:security:analyst]
  acme:
    teams:
      team-platform:
        members: [all:platform:engineer]
    ignore:                                 # left alone here, whatever the bindings say
      - admin@partner.example               # an address in a bound group nobody can take out
      - temp-owner                          # a GitHub login: a temporary owner, a break-glass seat
```

**A team is a consumer of an internal group, exactly as a client's
`requires` is.** Read it that way: the holders of these groups are the
people that team should contain. Nothing about a provider appears here —
which accounts hold a group is a question only the directory answers,
and it is answered once, in `groups`.

That is the whole reason this table names internal groups rather than
provider addresses: everything the policy already does applies
to a team for free. Holders from two workspaces, a matcher for the day
before a group exists, the naming convention, the console's holders
view — a team gets all of it by being an ordinary consumer.

GitHub has **two team roles** and both are declared per team. A holder of
a maintainer group is a maintainer even when a member group also names
them: the wider role is the one they were given.

An organisation's own `members` is for the people who belong in it
**without** a team. Being in a bound team implies organisation
membership, so this is not a list of everybody — it is what keeps
somebody no team accounts for from being removed as unaccounted for.

**`ignore` is for what nobody here controls.** An ignored address is never
wanted in that organisation, whatever group it sits in: it is not invited,
and it is not reported as waiting to link. An ignored login is never added,
removed or changed, linked or not, owner or not. An account whose every
linked address is ignored is left alone with them. Each entry is an address
or a GitHub login; two files ignoring accounts in one organisation ignore
both. Deleting the line brings the account back under the bindings, and
`git log` says when.

**Nothing here grants anything, and none of it appears in a token.** A
controller reads this table and makes each organisation match; this
service only holds it and shows it. The reason it lives in this file
rather than the controller's own is the one that decides every question
like it — *a reader of the access model sees every GitHub team's source
without opening another file* — and `git log` is the history of who was
in what.

What is refused, and why each would otherwise be silent:

| Refused | Because |
|---|---|
| a group nothing declares | the binding would name something with no meaning, and read as though it worked |
| a team with neither `members` nor `maintainers` | *remove everyone from platform* is not something to express by leaving a list out |
| an organisation binding no group and no team | *stop managing this organisation* is expressed by removing it, not by emptying it |
| the same team declared twice across two merged files | the second would silently replace the first |
| the same organisation's `members` declared twice | the same reason |

The same team name in two **organisations** is fine: `team-platform` on
two orgs is two different teams.

The console's Rules page lists these beside every other rule. A binding's
rule is the internal group, so it links to that group's page, and *depends
on* is whatever the group depends on — the provider for a membership, the
proof alone for a matcher. It feeds a team rather than an internal group,
so it opens no client.

## People

```yaml
people:
  jdoe: [j.doe@acme.example, john@globex.example]   # one person, two companies' addresses
```

`people` says which addresses are **the same person** — someone with an
address in two companies' domains. The key is a name you choose. It is
generic, not Slack's: any reconciler that looks a person up by their
address in one domain needs it.

It **only links addresses.** It never says who holds a group; the
directory alone answers that. A person listed here gains nothing until the
directory puts one of their addresses in a group, and is not removed from
anything by being left out.

Refused: a person with no address, an address that is not one, the same
address under two people (or twice under one), a key that is not a plain
name (lowercase letters, digits, `.`, `_`, `-`). Addresses are compared
lowercased. The same person declared in two merged files is a clash.

### Who owns a Slack workspace

A Slack workspace is known to the policy by its **key** and the channels bound
in it. Three things the policy used to be asked for are not in it any more,
because access-roster already knows each at run time:

| Fact | Where it comes from |
|---|---|
| the workspace's **owner**, the directory it belongs to | chosen when the workspace is connected, by the [one rule](#who-owns-a-github-organisation) (the installation-wide operator chooses a connected directory or none; an operator of one directory owns what it connects; an operator of several chooses among theirs), and recorded in the workspace's connection |
| the Slack **team** | recorded from `oauth.v2.access` at the **first install**; every later install or reconnect must belong to the same team (anything else is revoked and refused), and the controller acts with a bot token only while `auth.test` agrees |
| the **domains** a person is looked up by | the domains the **owning directory serves**, read from the console every pass; never copied |

Changing the owner is the installation-wide operator's alone
(`ChangeSlackWorkspaceOwner`, the *Change owner* button on the workspace), and
is recorded as `roster.slack_workspace.owner_changed`. A workspace with **no
owner** has no domains to look anyone up by, so every person in it is **held**
with *no owning directory: set the owner on the console*, and nothing is
invited. If the owning directory cannot be read, or is no longer connected, the
workspace's pass fails and changes nothing, rather than reading as "nobody is
here".

| A Slack workspace… | may be operated by |
|---|---|
| connected with an owner | the `<owner>:access-roster:operator` of that directory workspace, **or** the `all:access-roster:operator` |
| connected with none | the `all:access-roster:operator` alone |
| not connected yet | connecting it: the installation-wide operator, or an operator of a directory |

"Operated" is every action on the workspace and on its [catalogue
Apps](../connect/slack-apps-catalogue.md): connecting, creating, installing and
reinstalling, and finishing an install when Slack sends the browser back (the
role is checked again there, for whoever is signed in then). A catalogue App is
created in a workspace that is **already connected**: the page refuses with
*connect the workspace first* until the workspace has recorded its team. What
is *seen* follows the recorded owner: a viewer scoped to a directory workspace
sees the Slack workspaces and Apps it owns and nothing of another company's; a
scoped role over a directory that owns no Slack workspace and could connect
none is refused the page rather than shown an empty one.

A policy that still carries `slack.workspaces.<key>.team_id`, `.domains` or
`.owner` (keys v1.41.0 briefly accepted) is **refused at load**, with a message
saying where the value now comes from. Delete the keys and connect from the
console.

## Slack channels

> **A controller that reads this is being built. Until it ships, nothing
> reads these keys**: they are validated at load, merged, digested and
> shown, and nothing more. The decision logic it will run is in
> [the Slack reconciler](../design/access-roster.md#the-slack-reconciler).

```yaml
slack:
  workspaces:
    acme:                                   # a key WE choose
      channels:                             # by channel NAME, as Slack spells it
        eng-private: {private: true, mode: strict, ignore: [boss@acme.example, U0123ABCD], from: [acme:eng:member]}
        ops: {from: [acme:sre:member], adopt: C0123ABCD}   # take over an existing channel
    globex: {}                              # declared; its channels are bound elsewhere
```

Channels in the policy are fed by **internal groups** (`from`), for channels
the infrastructure owns, such as alert channels. Channels managed
interactively on the console are not here: they are records fed by **directory
groups**, and a record for a channel this section already binds (the same name,
or the same `adopt` id) is refused as *defined in git*, unless it is a
console takeover of exactly that channel (`supersedes_policy`), after which
the policy entry is reported *superseded* and not reconciled. See
[console channels](../connect/slack-workspace.md#console-channels-ordinary-channels-managed-on-the-console).

Each workspace is connected by **its own app** and bot token; the token is
never in this file. The workspace key is ours; the Slack team, the owning
directory and the domains are not declared here (see
[who owns a Slack workspace](#who-owns-a-slack-workspace)). A person is found
in a workspace by their address in one of the **owning directory's served
domains** (and `people` links their other addresses).

Channels are bound to **internal groups directly**, exactly as a GitHub
team is: the holders of `from` are who the channel should contain. (Slack
user groups are out of scope.) A channel is **created if missing, otherwise
taken over by name**: a visible channel with the declared name is adopted (a
public one is joined, a private one the bot is in is managed) and recorded once
as `roster.slack_channel.adopted`, so declaring a channel that already exists
is safe and a second declaration of it changes nothing. `adopt: <id>` is
**optional disambiguation**, never a requirement: for a renamed channel, or
when two channels are candidates, naming the id says which; by ID, because a
name can be changed or reused and an ID cannot. What is never done, each held
with its reason: converting a channel's visibility (a channel that is public in
Slack and declared `private`, or the other way round), unarchiving an archived
channel of that name (*archived: unarchive it in Slack or rename it*), and
creating a second channel under another name when the name is taken by a
private channel the bot cannot see (*a private channel with this name exists;
invite the bot to it*). A `strict` adopted channel removes only after the usual
vouching by the directory, and the first pass after adopting it is subject to
the breaker like any other.

**What the controller will do.** Each channel has a `mode`:

- `extend` (the default): **only add**. The controller invites the people
  the bindings name and removes nobody, so whoever else is in the channel
  stays;
- `strict`: **add and remove**. The channel is made to match the bindings.
  Strict is allowed on **private channels only**, because Slack lets only
  an administrator remove somebody from a public channel and the bot would
  be refused at every pass; `mode: strict` with `private` unset is refused
  at load. `ignore` (addresses, or Slack user ids such as `U0123ABCD` for
  somebody with no address here) names people a strict channel never
  removes; it is refused without `mode: strict`.

A strict channel never removes bots or apps, the controller's own bot,
deactivated users, guests (reported, never touched) or anybody on
`ignore`. And in every channel:

- people are **removed only after the directory vouches** for the answer,
  so a directory outage never empties a channel;
- a **breaker** stops a run that would remove more than half of a
  channel's members, or more than half of the workspace's managed members,
  unless an operator confirms exactly that set;
- a person with no Slack account yet, or with no address in the
  workspace's domains, is **held** with that reason, never an error.

**Shared (Slack Connect) channels are not in the policy.** They span
workspaces, and they are created and edited interactively on the console,
which keeps them as records of its own. The policy declares only what is
fixed at deploy time: the workspaces by key, and the channels bound inside each.

What is refused, and why each would otherwise be silent:

| Refused | Because |
|---|---|
| a workspace key that is not a plain slug | it appears in messages, audit records and credential names |
| `team_id`, `domains` or `owner` on a workspace, or `owner` on a GitHub organisation | removed in favour of what access-roster records and reads at run time; the message says where each comes from, so a stale policy fails the rollout rather than being half-read |
| a channel name that is not lowercase letters, digits, `-`, `_` (at most 80) | Slack would refuse it at create time, not at load |
| `mode` other than `extend` or `strict`; `mode: strict` on a channel that is not `private` | Slack would refuse every removal from a public channel, at every pass |
| `ignore` without `mode: strict`, or an entry that is neither an address nor a Slack user id, or one listed twice | an extend channel removes nobody, so the list would mean nothing |
| a channel with no `from` | *empty this channel* is not something to express by leaving a list out |
| a group nothing declares | the binding would name something with no meaning |
| `adopt` not `^[CG][A-Z0-9]{8,}$`, or one ID adopted twice in a workspace | two bindings would fight over one channel (`adopt` itself is optional: a channel is taken over by name without it) |

Across merged files a workspace merges field by field, as a GitHub
organisation does: one file may declare it and another bind channels in it.
A channel comes from one file, and a repeat is a clash. Bound
groups count as consumed, so they are not reported by the unused-group
lint. Validation runs on the merged policy, so a reference across files
is checked once, after the merge.

## One source

The deployment's ConfigMap(s), rendered from the installation's own
access model. Several may exist and merge additively; a key present
twice is refused.

Nothing is merged under the declared one at runtime. Who is in which
internal group is this file and nothing else, so `git log` is the
complete history of access.

## Not in this file

The **hold window** — how long a signed-in identity keeps its last granted
role while the directory cannot be vouched for — is a property of the service,
not of the policy: it belongs to the service that has to stay usable while
its own directory is uncertain. It is a chart value.

## Validation at load

Unknown keys refused, `memberships` among them. Every key in `claims`
and `lifetimes` names a declared group. Every `requires` entry names one.
Every member address has a domain. No scalar conflict across any two
fragments. A matcher has at least one field; a `service_account` matcher
names `namespace` and `name`, with `cluster` optional; a `github`
matcher's `visibility` is `public`, `private` or `internal`. A client's
`display_name` and `description` are one bounded line each;
`sign_in_exchange` is allowed on a `public` client only; a confidential
client names its secret. A resource's id is an absolute URI with no
fragment and its `requires` names a declared group; `client_documents`
refuses an origin carrying a scheme, a path or a wildcard, and refuses
`origins` without `requires` — as well as `requires` or `ttl_cap` with no
`origins`, which is a block somebody expected to apply. A typo fails the
rollout, not a login.

### Groups nothing consumes

At every load — issuer start, issuer policy reload, github-roster start —
the issuer and github-roster warn if an internal group is declared in the
`groups` table but referenced by none of:

- any client's `requires`
- any resource's `requires`
- `client_documents` `requires`
- any GitHub organisation `members` binding
- any GitHub team `members` or `maintainers` binding
- this hub's own roles — groups whose third segment is `operator` or
  `viewer` and whose second segment is `access-roster`, which the hub reads
  directly from the token

A group referenced only by a `claims` or `lifetimes` key does not count;
claims and lifetimes decorate a group and do not consume it — they add to a
token or its lifetime only when the caller holds the group for some other
reason.

The groups with the `rung:` or `emp:` prefix are not grants and never
reported: they are identities and sessions, not roles on things.

KNOWN LIMITATION: a relying party may read groups from the token beyond what
its `requires` names, for its own role mapping (for example, a console's
viewer vs editor role). Such groups are consumed outside the policy's view,
so this warning may name them. The gap closes when a client can declare the
groups it maps — per `docs/decisions/0006-groups-claim-scoped-per-audience.md`
— and the lint will then count those declarations.

The warning is always a warning, not an error. An installation may
legitimately declare a group ahead of the client or resource that will use
it — fresh infrastructure, or a group prepared before its consumer arrives —
and a rollout should not wait. But a group that will never be used is usually
a typo or a leftover, and the warning reaches an operator at the moment they
would see it: at load, where they read their logs.

## What the console may change

Nothing in this file. The console reads the policy and shows it — every
group, every rule, every client — and its only writes are removals of
sessions (revoke, *sign out everywhere*). It cannot attach a directory
group to an internal one: that is an edit to this file, in git.

## Testing the file

Three ways, at three moments.

**Before it ships:** the file is parsed by the issuer's own loader, the
same code that refuses it at startup. Run it as a test on every render
of the policy (for example a `TestTheRenderedIssuerPolicyLoads` of your
own), so an
unknown key, a client with no `requires` or a redirect that is also a
landing page fails the pull request rather than the rollout — and a
rollout the issuer refuses is the worst case, because the previous pods
keep serving the previous policy while everything reads Synced.

**In a test:** the `policy` package is the engine itself.
`policy.Parse`, then `policy.NewSet`, then `Evaluate` with an `Input` —
an account with its directory groups, a CI token's claims, a client id —
returns the groups, claims and lifetime a token would carry, so a change
to the file can be pinned by a fixture the way the issuer's own tests
pin it. There is no `accessctl` subcommand for this; the Go package is
the interface.

**Live:** the console does it against the policy in force. Search for a
person and their page shows the internal groups, what put them in each,
the merged claims, the lifetime, and every client with whether they reach
it; Rules lists every rule that grants a group — a directory group by
membership, a sign-in, a CI job or a workload by pattern — and answers
the same for the two that have no name to search for. From the other
end, a group's page and a client's page list the people who hold them
right now, which is the question an access review asks and the one this
file cannot answer alone: the file says which directory groups count, and
only the directory knows who is in them. A policy that reads correctly
and behaves differently is the failure worth catching, and those pages
are where it shows.
