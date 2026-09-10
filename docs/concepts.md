# Concepts

The words this repository uses precisely.

## The directory

| Term | Means |
|---|---|
| **workspace** | one directory tenant the hub holds a credential for — a Google customer, later an Entra tenant. Identified by the backend's tenant id, never by a domain |
| **domain** | discovered from the workspace, re-read on every probe, never typed. Addresses route to workspaces by domain |
| **served** | which of a workspace's discovered domains this hub answers for. Chosen when the workspace is connected: the consenting administrator's own domain is pre-selected, the tenant's other domains are listed and off, and *all of them, including ones added later* is an explicit choice. Changeable afterwards on the directory's page; for a declared workspace it is in the values. An unserved domain routes nothing and its accounts are never read. The list is intersected with discovery, so it can never claim a domain the tenant does not own |
| **synced** | which of a workspace's groups this hub keeps. All of them unless it is narrowed (values, or the console). It narrows what is KEPT, not what is read: the hub still lists the tenant's groups, because that list is what an operator chooses from. A group left out is not cached, not answered and not offered — and the choice is bounded by the last read, so nothing can be named that the directory does not hold |
| **snapshot** | the hub's copy of one workspace: accounts with liveness, groups with flat members, domains, taken every refresh interval. Every read answers from it and says which one (`snapshot_at`) |
| **authoritative** | a domain's answers may be acted on: its workspace's last probe succeeded, its snapshot is inside the freshness window, and no other workspace serves the domain too. Anything else is *provisional* or *contested* |
| **provisional** | a served domain whose answers may not be acted on for removals, **and why**: *first snapshot pending*, *snapshot stale*, or *probe failed*. Consumers add but never remove on it. The wire contract is the `authoritative` boolean and nothing else; this is the console's word for its `false`. It replaced *hold* on 2026-09-09: *hold* named what a consumer does, not what the domain is, and on a tenant connected ten seconds earlier it read as an alarm beside a green health chip. An unserved domain is neither — it is simply not read |
| **contested** | a domain two workspaces both serve. Authoritative for neither until one of them stops serving it: a move in progress, or a misconfiguration |
| **`max_age`** | a caller's freshness demand: omitted serves the snapshot, a value makes it fresher first, zero fetches now. Point lookups satisfy it with one live read, never a full refresh |

## Trust

| Term | Means |
|---|---|
| **anchor** | a root of trust a service verifies a caller against. There are exactly two: the **cluster** (a ServiceAccount token checked by the API server, bound to an audience — proves a workload *here*) and the **issuer** (access-issuer's signing key — proves an identity the policy has resolved, from anywhere). A service accepts one or both, by the scope of who calls it, and never a third. [design/trust.md](design/trust.md) |
| **proof** | something a service can verify without authenticating anyone: a corporate sign-in's ID token, a CI platform's identity token, a Kubernetes ServiceAccount token. Every proof resolves to internal groups; after that a person and a job are the same thing |
| **the waist** | the internal group name: the one currency of authorization, whichever anchor proved the caller. In a token it is the flat `groups` claim and nothing else; in a binding, a `requires`, a role check, it is the same string, never re-mapped |
| **federated issuer** | an OpenID issuer whose tokens access-roster accepts as a proof for token exchange, trusted by its public key set and nothing else: GitHub Actions, and every cluster's own ServiceAccount-token issuer. A new cluster is one row naming its key set. The issuer holds no credential for any of them |

## The policy

| Term | Means |
|---|---|
| **internal group** | the vocabulary of access. A caller is in one by directory **membership** or by a **matcher**; everything downstream speaks these names and never a directory address |
| **membership** | one directory group inside an internal group, declared in the policy. Who is *in* the directory group changes without a commit, because the directory owns that; which directory groups feed which internal group does not |
| **matcher** | a condition on a verified proof: a CI repository and ref, a ServiceAccount, a signed-in address or its domain. Where attributes live, and the only place they do |
| **claim fragment** | what an internal group adds to a token. Every held group's fragment is deep-merged: lists union, maps recurse, and two groups setting one scalar differently is refused when the policy loads |
| **lifetime** | how long a token lives: the shortest across the caller's groups, then the client's cap. A property of the privilege, never of where the person signed in |
| **client** | a relying party. Its id is the token's audience, its `requires` is who may be issued one, and it is **declared** by the deployment — never created by a console and never registered by a workload, so the set of clients is answerable by reading the repository |
| **scope** | a role held over one workspace rather than the installation, written `<workspace id>:access-roster:operator` in the groups table — the first segment of every grant's `<scope>:<thing>:<role>` name ([design/trust.md](design/trust.md#naming)). It gates every action done TO that workspace and filters what its holder lists; it never widens or narrows the installation-wide role, and recovery is never scoped |

## The console

The console **reads**. It shows every person, every provider group, every
internal group, every rule that grants one, and every open session — the
whole chain from a directory to a client, and why each link exists. It
changes exactly two things, and both are removals or bootstrap rather
than policy: it **revokes** a session, and it **connects a provider** by
admin consent, which genuinely needs a browser because there is no
infrastructure-as-code way to obtain that credential.

It cannot change who is in a group. That is the policy, rendered from the
installation's own access model and reviewed in git (INF-694), so `git
log` is the complete history of access and there is nothing for a console
and a repository to disagree about.

| Term | Means |
|---|---|
| **exposure** | a console placed behind `access-proxy`: a hostname, a backend, a posture. The proxy runs the login against the issuer, keeps the session, forwards the bearer |
| **posture** | what an exposure enforces: `authenticated` — any identity the issuer would mint for this client passes, and the client's `requires` at the issuer is the gate; `groups` — the gateway itself checks the claim, which suits a caller that already carries a token and cannot serve a browser that does not yet have one |
| **session** | what the issuer holds for one identity and one client: a refresh token and how it was obtained. Listed on a person's page and a client's page, revocable by an operator, and by the person for their own — "sign out everywhere". A proxy's browser session is one of them, seen from the proxy's side |
| **bootstrap surface** | the paths a console publishes on a route the proxy does *not* cover: its sign-in page, recovery, and the consent callback — so that a redirect from a directory is never swallowed by a login prompt. A request there carries **no gateway identity, by design**; the consent callback takes its operator from the state the hub signed when an operator started the flow |
| **recovery** | the way in for the day no directory can vouch for anybody: a Kubernetes ServiceAccount token, checked by the API server against a mandatory audience. Nothing is stored, and it grants nothing by itself — at the issuer it completes as the ServiceAccount *subject*, and only a `service_account` matcher in the policy puts that subject in a group. It is the **cluster anchor used as the floor** — the issuer depends on the directory, and the directory is what is broken — not a third anchor and not a back door |
