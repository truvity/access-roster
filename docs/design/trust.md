# Trust — two anchors, one vocabulary

**Status:** decided 2026-09-09, after the first live token comparison. It
is the rule under every other design document: which credential a caller
presents, which credential a service accepts, and what a token says once
it is issued. When a design and this page disagree, this page wins and
the design gets a dated correction.

## The rule

An installation has **exactly two trust anchors**, and a service accepts
**exactly the two** — never a third.

| Anchor | Root of trust | Scope | Proves |
|---|---|---|---|
| **the cluster** | the API server: a ServiceAccount token checked with a TokenReview, bound to an audience | this cluster | **recovery alone**: *somebody who can mint a token for the recovery account here*. A workload's token is now verified against the key set its own cluster publishes, so it is the issuer anchor and not this one — which is what lets one issuer serve many clusters while holding access to none |
| **the issuer** | access-issuer's signing key, published as JWKS | the estate: every cluster, every cloud account, CI, people | *an identity this installation's policy has resolved to internal groups* |

They are not two authorities that could disagree. **The issuer is built
on the cluster**: its workload verifier turns a ServiceAccount token into
an issuer token, so an issuer token for a workload is the same fact seen
from estate height. Accepting both is one layering seen from two places,
not "dual trust".

The choice is made by **scope**, and never by preference:

| A caller is… | It presents | Because |
|---|---|---|
| a workload in the **same cluster** as the service | its ServiceAccount token | the issuer would verify the same token and re-sign it: a hop that adds no trust, on the hottest path there is |
| a workload in **another cluster** | an issuer token | ServiceAccount tokens do not cross clusters, and a service that verified N clusters' key sets directly would be the N×M problem the issuer exists to collapse |
| a **person** | an issuer token, obtained by a sign-in the issuer ran against a corporate directory | people hold no ServiceAccount |
| a **CI job** | an issuer token, obtained by exchanging the platform's identity token | the organisation allow-list and the matchers — repository, ref, visibility — live in the issuer, once |
| a **laptop over the network** | an issuer token, obtained by `accessctl` trading its own sign-in for the audience | same as a person: that is what it is. Of the issuer's own tokens, only the access token of a sign-in at a public client declaring `sign_in_exchange`, presented by that client, is a proof — never an ID token, which every relying party is handed |
| the **break-glass** operator | a ServiceAccount token, minted by hand with cluster RBAC | see *Recovery* below — this is the root showing through, not a third anchor |

A service that serves only local workloads needs only the cluster
anchor. A service that serves only people needs only the issuer. A
service that serves both — access-roster's own console API is the
reference — keeps them apart by **verifier**: two listeners, or one on
which every route says which proof it takes, and an operator RPC never
admitted on a workload's proof alone.

## Why not the issuer for everything

Three reasons, and the first one decides it alone.

1. **Bootstrap.** The way in on the day the directory is broken cannot
   depend on the issuer, which depends on the directory: no token
   without a directory, no repair without a token. The cluster anchor is
   what the issuer itself stands on, so it has to be accepted beneath it.
2. **A same-cluster call gains nothing from an exchange.** The issuer
   would verify the caller's ServiceAccount token and re-sign it: a
   round trip that adds no trust, on paths that can be the hottest a
   service has.
3. **Cluster RBAC is already the authority for local workloads.** Who may
   mount which ServiceAccount is decided, audited and revoked in the
   cluster. Re-deriving that at the issuer duplicates a decision the
   cluster has already made and can already prove.

## Why not the cluster for everything

Because it cannot reach past itself. A ServiceAccount token is meaningful
to one API server. People, CI platforms, other clusters and cloud accounts
share no API server with anything, and the only thing they can all trust
is a signing key published at a URL. That is the issuer, and it exists so
that estate-wide trust decisions — which GitHub organisations, which
other clusters, which corporate directories — are made **once** instead
of in every service that might be called from outside.

## The vocabulary: internal groups, and only those

Whichever anchor proved a caller, the answer a service acts on is the
same thing: **a list of internal group names.** It is the waist of the
whole design.

- The issuer puts it in the token's `groups` claim, flat, a string each.
- The cluster anchor yields a ServiceAccount, and a `service_account`
  matcher in the policy puts that account in internal groups — the same
  names.
- Every relying party binds on those names: a `ClusterRoleBinding`
  subject, an ArgoCD `g,` line, a client's `requires`, a console's role
  check. **No relying party re-maps them**, and no library translates
  them.

**The claim shape is `groups` only.** Decided 2026-09-09 after decoding a
live token from the identity provider being replaced beside one from
this issuer. That provider carried the same facts three times — a flat
`groups` list, and two nested maps of role → organisation → domain — and
**nothing in the estate read the nested ones**: Kubernetes can only
consume a flat string array, ArgoCD reads `groups`, AWS trust policies
read `aud`. A second representation of one fact is two things that can
disagree and two things a consumer can accidentally depend on.

When a fact about *where* a grant came from has to travel — which
company's directory vouched for this role — it goes **into the string**,
where every consumer keeps working: `<workspace id>:access-roster:viewer`
is that convention — a role over one directory with the scope in the
first position, like every other grant (see *Naming*). The `claims`
fragment table stays for the rare relying party that needs a claim that
is not a group (cloud session tags, say); the default is that a group's
name is the whole of what it adds.

### Naming

Decided 2026-09-09 (evening); in force since v0.9.3.

Every grant is **`<scope>:<thing>:<role>`** — three segments, `:`
between, lowercase. *Role, on thing, in scope.*

| Segment | Is | Examples |
|---|---|---|
| `scope` | an environment, a tenant id, or `all` | `dev`, `prod`, `C0north`, `all` |
| `thing` | what the role is **on**: a subsystem, a project, an application | `k8s`, `shop`, `github-roster`, `access-roster` |
| `role` | from that thing's own ladder | `admin`, `viewer`, `auditor`, `deployer`, `approver`, `operator` |

So: `prod:k8s:admin`, `prod:shop:deployer`, `all:access-roster:operator`,
`C0north:access-roster:viewer` — the last being a role held over one
directory rather than the installation, with the scope where every other
name has it and the **workspace id** as the scope, never a domain.

Two rules that follow from the shape:

- **Two-segment names are not grants, deliberately.** `rung:<name>`
  carries a session lifetime; `emp:<slug>` is a person, which per-scope
  bindings attach to. Neither is *a role on a thing*. A reader who sees
  two segments knows it is not a grant; there are no other two-segment
  families.
- **A cluster-scoped consumer binds `<env>:k8s:<role>` by default.**
  Being admin of the cluster is the qualification for being admin of the
  ArgoCD that manages it, and the installation's matrix decides rung ×
  scope → a generic role that each system translates in its own RBAC. A
  consumer owns a `thing` of its own only when its ladder genuinely
  diverges. That is an escape hatch; the default keeps a token at a few
  dozen groups rather than a few dozen per subsystem.

Why the shape and not the one before it: `cluster-prod:cluster:admin`
said "cluster" twice because the two occurrences meant different things.
The prefix was the identity provider's project name leaking through the
mapper that flattened it — residue of the thing being decommissioned —
and the tier meant *Kubernetes*, which `k8s` says. The old shape also
put an application role (`cluster-prod:roster:operator`) under a
cluster scope it had nothing to do with, so nothing could tell an app
role from a project role from a tier role by looking. The new one is
parseable in three positions, sorts scope-first, and carries none of the
old provider's vocabulary.

The rename is safe because RBAC binds any number of names to one role:
during the migration the bindings carry both spellings, the issuer
mints only the new, the old provider only the old, and the old bindings
go when it does.

Identity claims travel beside `groups` and are not authorization:
`sub`, `email`, `name`, `given_name`, `family_name`,
`preferred_username`, `sid`, `auth_time`. A relying party's UI shows
them; its policy never reads them. A person's `sub` is their email; a
ServiceAccount's is `<cluster>:k8s:<namespace>:<name>` — the cluster
first, like every scope, so the same account on two clusters is two
subjects, not one. One function renders it and one reads it, because the
estate has minted three spellings and a reader that knew only its own
would refuse a token from a release either side.

## Recovery is the root, not a back door

Break-glass at the service and at the issuer is a ServiceAccount token,
minted by a person with `kubectl create token`, for an account the chart
creates bound to nobody. Under the rule above it is the **cluster
anchor, used deliberately as the floor**: in the scenario it exists for,
the directory is what is broken, the issuer depends on the directory, so
the estate anchor is unavailable *by construction* and the only thing
still trusted is the cluster. Authorization is cluster RBAC — who may
mint that account's token — which is the right authority, because it is
the only one left standing.

It is not a third anchor, it is not "dual trust", and it must stay the
**only** human path that bypasses the issuer.

## The proxy under the rule

A console is for people, so it lives on the issuer anchor **only**.
`access-proxy` holds the browser session and forwards the issuer's token;
the console verifies it against issuer and audience. It never accepts a
ServiceAccount token, and there is no reason it should: nothing in a
cluster opens a web page.

Two gates decide who gets in, and they are not duplicates. The **issuer's
`requires`** on the client is primary: a caller in none of its groups is
refused before a token exists, so the proxy never sees a session. The
**proxy's `groups` posture** is defence in depth and route-level
narrowing — *this path needs a stricter group than the client as a
whole*. Keep both; know which is which.

## A service that has both a console and an API

The plain shape, and the one to copy when nothing argues otherwise:

```
console listener   → behind gateway-native OIDC, access-proxy, or its own code flow → issuer anchor
API listener       → reached by Service DNS                    → cluster anchor (+ issuer, for remote callers)
```

Two anchors, and an operator RPC is never mounted where a workload's
proof alone admits. The network policy admits the gateway to one and the
consumers to the other, as the second layer — never the only one,
because reaching a port proves nothing.

access-roster itself serves both on one listener: the console's routes
take the browser's own session, and its API takes an issuer token or a
workload's ServiceAccount token — verified against the cluster's
published key set, so the service holds access to no cluster — with the
policy's `service_account` matchers deciding what that workload is in.
The GitHub controller is that caller. One listener is fine when every
route says which proof it takes; two is fine when it does not have to.

The console may share the issuer's hostname under a path — the family's
own console does, at `/console/`, and since the two are one process its
session pages are same-origin with the session service. An API listener
never appears on any hostname: it is reached by Service DNS or not at
all.

When an API admits remote callers too, it accepts both anchors, and
**the grant is keyed by the principal, not by the anchor**: a consumer
proven either way is the same consumer and gets the same answer. One
grant table, two doors.

### Admission is not authorization

*The directory API these grants governed is not served today: its one
consumer, the issuer, is the same process. The shape stays written down
for the day it returns.*

Being a consumer and being a consumer of *everything* were one decision,
and that was the gap. A caller admitted at all could enumerate every
group of every company the service reads. One consumer — the issuer — needs
exactly that; the next one needs one directory and one question.

So a consumer is declared with a grant along three axes: **which
directory** (workspaces, or the domains they serve), **which groups**,
and **which questions** (`resolve`, `groups`, `describe`, `probe`). No
grant is full read, so nothing that predates them changes meaning.

Two properties follow, and both are deliberate:

- **Outside the grant answers as unserved does.** Not found, not in
  domain, no groups — identical to an address in a domain this service never
  serves. A refusal would confirm the domain exists, which is what the
  grant withholds; and consumers already read the unserved answer
  fail-safe, so nothing has to learn a new failure mode.
- **Discovery is itself scoped.** `Describe` lists only granted domains.
  A grant on the questions alone would still hand every admitted caller
  the shape of every company the service serves.

The API listener stays read-only whatever a grant says: there is no read
class that can be spelled to reach a write.

## The libraries are where the rule becomes shape

The Go module offers **two verifiers and nothing else**: `Issuer`
(bearer or forwarded token, issuer URL + audience) and `Cluster` (a
ServiceAccount token: a check you supply, an audience, the names it
admits). A service composes them per route. Both yield one `Verified`
with `Groups []string`, so a handler never learns which anchor proved
the caller and cannot come to depend on it. The TypeScript package,
`@truvity/access-roster`, reads that from `/.access/whoami` and
translates nothing.

There is no third verifier and no "trust this header" mode that outlives
a local run. See [libraries.md](libraries.md).

## What this rules out

- **A service verifying another cluster's key set directly.** That is a
  third anchor per cluster; go through the issuer.
- **A shared secret between two services**, API key or otherwise. There
  is always a ServiceAccount token or an issuer token to use instead.
- **A structured roles claim** beside `groups`. It would be a second
  waist.
- **Any library that re-maps group names** on the way in. The name in
  the policy is the name in the token is the name in the binding.
- **A console accepting ServiceAccount tokens**, or an API listener
  gating on a browser session.

## Related

- [access-roster.md](access-roster.md) — the whole service: what the
  estate anchor verifies and mints, the directory model behind it, and
  recovery.
- [access-proxy.md](access-proxy.md) — the console exposure.
- [libraries.md](libraries.md) — the two verifiers.
- [../connect/service-to-service.md](../connect/service-to-service.md) —
  the how-to for a service calling another.
- [../reference/policy.md](../reference/policy.md) — internal groups, the
  claim tables, and what a token is minted *for*: a client, a declared
  **resource** (RFC 8707), or a client that describes itself by an
  allow-listed URL (a Client ID Metadata Document).
