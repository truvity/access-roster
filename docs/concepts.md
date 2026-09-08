# Concepts

The words this repository uses precisely.

## The directory

| Term | Means |
|---|---|
| **workspace** | one directory tenant the hub holds a credential for — a Google customer, later an Entra tenant. Identified by the backend's tenant id, never by a domain |
| **domain** | discovered from the workspace, re-read on every probe, never typed. Addresses route to workspaces by domain |
| **served** | which of a workspace's discovered domains this hub answers for. Chosen when the workspace is connected *(0.8)*: the consenting administrator's own domain is pre-selected, the tenant's other domains are listed and off, and *all of them, including ones added later* is an explicit choice. Changeable afterwards on the directory's page; for a declared workspace it is in the values. An unserved domain routes nothing and its accounts are never read. The list is intersected with discovery, so it can never claim a domain the tenant does not own |
| **synced** | which of a workspace's groups this hub keeps. All of them unless it is narrowed (values, or the console). It narrows what is KEPT, not what is read: the hub still lists the tenant's groups, because that list is what an operator chooses from. A group left out is not cached, not answered and not offered — and the choice is bounded by the last read, so nothing can be named that the directory does not hold |
| **snapshot** | the hub's copy of one workspace: accounts with liveness, groups with flat members, domains, taken every refresh interval. Every read answers from it and says which one (`snapshot_at`) |
| **authoritative** | a domain's answers may be acted on: its workspace's last probe succeeded, its snapshot is inside the freshness window, and no other workspace serves the domain too. Anything else is *provisional* or *contested* |
| **provisional** | a served domain whose answers may not be acted on for removals, **and why**: *first snapshot pending*, *snapshot stale*, or *probe failed*. Consumers add but never remove on it. The wire contract is the `authoritative` boolean and nothing else; this is the console's word for its `false`. It replaced *hold* on 2026-09-09: *hold* named what a consumer does, not what the domain is, and on a tenant connected ten seconds earlier it read as an alarm beside a green health chip. An unserved domain is neither — it is simply not read |
| **contested** | a domain two workspaces both serve. Authoritative for neither until one of them stops serving it: a move in progress, or a misconfiguration |
| **`max_age`** | a caller's freshness demand: omitted serves the snapshot, a value makes it fresher first, zero fetches now. Point lookups satisfy it with one live read, never a full refresh |

## The policy

| Term | Means |
|---|---|
| **proof** | something a service can verify without authenticating anyone: a corporate sign-in's ID token, a CI platform's identity token, a Kubernetes ServiceAccount token |
| **internal group** | the vocabulary of access. A caller is in one by directory **membership** or by a **matcher**; everything downstream speaks these names and never a directory address |
| **membership** | one directory group inside an internal group. The one table a console may extend, and the reason a group's population changes without a commit |
| **matcher** | a condition on a verified proof: a CI repository and ref, a ServiceAccount, a signed-in address or its domain. Where attributes live, and the only place they do |
| **claim fragment** | what an internal group adds to a token. Every held group's fragment is deep-merged: lists union, maps recurse, and two groups setting one scalar differently is refused when the policy loads |
| **lifetime** | how long a token lives: the shortest across the caller's groups, then the client's cap. A property of the privilege, never of where the person signed in |
| **client** | a relying party. Its id is the token's audience, its `requires` is who may be issued one, and it is declared or self-registered — never created in a console |
| **layer** | where a fact came from: `declared` by the deployment, or `console`. They merge additively and declared wins, so a console can add a membership and never widen one it did not add |

## The console

| Term | Means |
|---|---|
| **exposure** | a console placed behind `access-proxy`: a hostname, a backend, a posture. The proxy runs the login against the issuer, keeps the session, forwards the bearer |
| **posture** | what an exposure enforces: `groups` — only listed claim values pass; `authenticated` — any signed-in employee passes and the application authorizes itself |
| **session** | what the issuer holds for one identity and one client: a refresh token and how it was obtained. Listed on a person's page and a client's page, revocable by an operator, and by the person for their own — "sign out everywhere". A proxy's browser session is one of them, seen from the proxy's side |
| **bootstrap surface** | the paths a console publishes on a route the proxy does *not* cover: its sign-in page, recovery, and the consent callback — so that a redirect from a directory is never swallowed by a login prompt. A request there carries **no gateway identity, by design**; the consent callback takes its operator from the state the hub signed when an operator started the flow |
| **recovery** | the way in for the day no directory can vouch for anybody: a Kubernetes ServiceAccount token, checked by the API server against a mandatory audience. Nothing is stored, and it grants nothing by itself — at the issuer it completes as the ServiceAccount *subject*, and only a `service_account` matcher in the policy puts that subject in a group |
