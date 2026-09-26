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
| a response larger than 64 KiB, or slower than 5 seconds | the URL is caller-chosen, so the response is an untrusted stream and a sign-in is waiting on it |
| a redirect to anywhere else | the document is served *at* its own id; a redirect chain is how an allow-list on the first hop stops meaning anything |
| a document with no `redirect_uris` | there would be nowhere to deliver a code |
| an `origins` entry with a scheme, a path or a `*` | an origin is a host; a wildcard also admits every subdomain somebody forgot about |
| `requires` or `ttl_cap` with no `origins` | written by somebody who expected it to apply |

A fetched document is honoured for ten minutes and then fetched again.
**There is no stale fallback**: a document that cannot be fetched is a
client whose redirect URIs are not known right now, and honouring
yesterday's copy is honouring URIs it may have retired.

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
