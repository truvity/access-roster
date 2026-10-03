# Concepts

The words this repository uses precisely.

## The directory

| Term | Means |
|---|---|
| **workspace** | one directory tenant the service holds a credential for — a Google customer, later an Entra tenant. Identified by the backend's tenant id, never by a domain |
| **domain** | discovered from the workspace, re-read on every probe, never typed. Addresses route to workspaces by domain |
| **served** | which of a workspace's discovered domains this service answers for. Chosen when the workspace is connected: the consenting administrator's own domain is pre-selected, the tenant's other domains are listed and off, and *all of them, including ones added later* is an explicit choice. Changeable afterwards on the directory's page; for a declared workspace it is in the values. An unserved domain routes nothing and its accounts are never read. The list is intersected with discovery, so it can never claim a domain the tenant does not own |
| **synced** | which of a workspace's groups this service keeps. All of them unless it is narrowed (values, or the console). It narrows what is KEPT, not what is read: the service still lists the tenant's groups, because that list is what an operator chooses from. A group left out is not cached, not answered and not offered — and the choice is bounded by the last read, so nothing can be named that the directory does not hold |
| **snapshot** | the service's copy of one workspace: accounts with liveness, groups with flat members, domains, taken every refresh interval. Every read answers from it and says which one (`snapshot_at`) |
| **authoritative** | a domain's answers may be acted on: its workspace's last probe succeeded, its snapshot is inside the freshness window, and no other workspace serves the domain too. Anything else is *provisional* or *contested* |
| **provisional** | a served domain whose answers may not be acted on for removals, **and why**: *first snapshot pending*, *snapshot stale*, or *probe failed*. Consumers add but never remove on it. The wire contract is the `authoritative` boolean and nothing else; this is the console's word for its `false`. It replaced *hold* on 2026-09-09: *hold* named what a consumer does, not what the domain is, and on a tenant connected ten seconds earlier it read as an alarm beside a green health chip. An unserved domain is neither — it is simply not read |
| **contested** | a domain two workspaces both serve. Authoritative for neither until one of them stops serving it: a move in progress, or a misconfiguration |
| **`max_age`** | a caller's freshness demand: omitted serves the snapshot, a value makes it fresher first, zero fetches now. Point lookups satisfy it with one live read, never a full refresh |

**A Slack workspace is not a workspace in this table.** Here, *workspace* is a
directory tenant. A Slack workspace is a Slack team the Slack controller
manages; it is always written *Slack workspace*, is named by a key in the
policy's `slack.workspaces` table, and is owned by one directory workspace (its
*owning directory*), recorded when it is connected.

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
| **client** | a relying party: the software *asking* for a token. Its `requires` is who may be issued one, and it is **declared** by the deployment — never created by a console and never registered by a workload. One exception, off unless configured: a client may identify itself by an HTTPS URL serving a document about itself, admitted only from an allow-listed origin, so what stays answerable by reading the repository is the set of *origins* rather than the set of clients. [reference/policy.md](reference/policy.md#clients-that-describe-themselves) |
| **resource** | what a token is *for*, when that is not the client asking. A client names one with `resource` (RFC 8707) and it becomes the token's audience; with none, the client's own id is. Declared, with its own `requires` — so the client says who may ask and the resource says what may be asked for, and both apply. [reference/policy.md](reference/policy.md#resources--what-a-token-is-for) |
| **scope** | a role held over one workspace rather than the installation, written `<workspace id>:access-roster:operator` in the groups table — the first segment of every grant's `<scope>:<thing>:<role>` name ([design/trust.md](design/trust.md#naming)). It gates every action done TO that workspace (a directory workspace, or a GitHub organisation or Slack workspace it owns) and filters what its holder lists; it never widens or narrows the installation-wide role, and recovery is never scoped |

## The console

The console **reads**. It shows every person, every provider group, every
internal group, every rule that grants one, every open session, and
every GitHub organisation and Slack workspace with what its controller would
change — the whole chain from a directory to a client, a team or a channel, and
why each link exists. What it changes is bootstrap, removal and confirmation
rather than policy: it **connects** a directory by admin consent and a GitHub
organisation, the link App or a runner App by an owner creating the App, and a
Slack workspace (a configuration token pasted once, then OAuth install) and a
catalogue Slack App the same way, each of which genuinely needs a browser
because there is no infrastructure-as-code way to obtain that credential; it
**revokes** a session and **disconnects** what it connected; it **keeps**
console channel and Slack Connect records; it **archives** a channel in Slack
only when asked to, as an opt-in when forgetting an ordinary console channel;
it **asks for a pass now** (Refresh); and it **confirms** a set of removals a
controller held, Slack's the same way as GitHub's, or **imports** GitHub links
approved elsewhere.

It cannot change who is in an internal group. That is the policy, rendered from
the installation's own access model and reviewed in git. There is one
deliberate exception in kind, not in rule: **console channels and Slack Connect
channels** are records the console writes, because the people who own a Slack
channel are not the people who own the infrastructure. They are fed by directory
groups and individual addresses, never by internal groups, are audited action by
action (`roster.slack_console_channel.*`, `roster.slack_shared_channel.*`),
backed up, and shown beside the policy's channels with their kind. Git remains
the complete history of access to infrastructure; the trail is the history of
these records.

| Term | Means |
|---|---|
| **exposure** | a console placed behind a gateway (gateway-native OIDC on Envoy Gateway, upstream oauth2-proxy on other gateways, or your own flow): a hostname, a backend, and (for proxied shapes) a posture. The gateway or proxy runs the login against the issuer, keeps the session, forwards the bearer |
| **posture** | what an exposure enforces: `authenticated` — any identity the issuer would mint for this client passes, and the client's `requires` at the issuer is the gate; `groups` — the gateway itself checks the claim, which suits a caller that already carries a token and cannot serve a browser that does not yet have one |
| **session** | what the issuer holds for one identity and one client: a refresh token and how it was obtained. Listed on a person's page and a client's page, revocable by an operator, and by the person for their own — "sign out everywhere". A proxy's browser session is one of them, seen from the proxy's side |
| **bootstrap surface** | the paths a console publishes on a route the proxy does *not* cover: its sign-in page, recovery, and the consent callback — so that a redirect from a directory is never swallowed by a login prompt. A request there carries **no gateway identity, by design**; the consent callback takes its operator from the state the service signed when an operator started the flow |
| **recovery** | the way in for the day no directory can vouch for anybody: a Kubernetes ServiceAccount token, checked by the API server against a mandatory audience. Nothing is stored, and it grants nothing by itself — at the issuer it completes as the ServiceAccount *subject*, and only a `service_account` matcher in the policy puts that subject in a group. It is the **cluster anchor used as the floor** — the issuer depends on the directory, and the directory is what is broken — not a third anchor and not a back door |
| **secret store** | an OpenBAO (or Vault) that trusts this issuer as an ordinary relying party and mints credentials for it — SSH certificates, database client certificates, or shared development values. There is no second authorization model: the issuer holds no grant in the store, and the store's policy decides who may ask. Accessed through `accessctl` or a workload's identity |

## Reconcilers: GitHub and Slack

| Term | Means |
|---|---|
| **binding** | a row of the policy's `github` table: an organisation's own `members`, and each team's `members` and `maintainers`, every entry an internal group. The controller makes the team equal to who holds those groups |
| **link** | the tie between a GitHub account and a person, by the work addresses GitHub verified on it. Made by the **person** authorizing the link App, **matched** from a public profile that shows a work address the directory has, or **imported** from a pairing approved elsewhere. A self-link is checked every pass; the other two hold no token and are not. A link is `linked`, `lost` (the address left GitHub) or `unverifiable` (the link App is gone) |
| **dry run** | what every organisation or Slack workspace is until the chart lists it in `githubRoster.config.enabledOrgs` / `slackRoster.config.enabledWorkspaces`: derived every pass, shown on its page with what would change, and left alone |
| **held** | a change the controller decided not to make because a person is needed: no free GitHub seat, an owner it would demote, a removal set over the breaker, a private Slack channel the bot cannot see, a channel whose visibility differs from the declared one, an archived channel of that name, a channel defined in both git and the console. Shown with its reason, as *needs you* |
| **waiting** | Slack only: nobody here needs to act. A person has no Slack account yet (*waiting for them*), or a Slack Connect side waits for the other workspace to accept |
| **reported** | a fact the controller notes and never acts on: an owner's team or link, an outside collaborator, a Slack guest, a leaver in a channel that is not strict |
| **retrying** | a change that failed for a transient reason (the directory unable to vouch just now, a change the system refused) and is tried again next pass rather than held |
| **breaker** | the rule that a pass whose removals concern more than half of a unit removes nobody until an operator confirms exactly that set. The unit is an organisation's members on GitHub; on Slack, a channel's members, and separately the workspace's managed members. A confirmation names the set by a fingerprint, lapses after 24 hours, and one confirmation covers every gate that fingerprint fits |
| **runner App** | the GitHub App a self-hosted runner scale set registers with: one per organisation per **tier**, created from the console, kept in a Secret for the deployment to hand to its runners. Nothing in the service acts with it |
| **catalogue App** | a GitHub App the deployment declares as data (`githubApps.catalogue`): created and installed from the console, its key kept in a Secret by its catalogue id, its permissions compared with what GitHub holds. Its **grants** name the groups that may ask for its installation tokens |

## Slack

| Term | Means |
|---|---|
| **policy channel** | a channel bound in git, in `slack.workspaces.<key>.channels`: private or public, fed by internal groups, `mode: extend` (the default, add only) or `strict` (private only; adds and removes), with an `ignore` list and an optional `adopt` id used only to disambiguate. For channels the infrastructure owns, such as alert channels |
| **console channel** | an ordinary channel managed on the console, kept as a record `_channel.<workspace>.<name>.json`: fed by **directory** groups of the workspace's owning directory and by **individual addresses** (`members`), never by internal groups. Audited and backed up with the other Slack records |
| **Slack Connect channel** | a channel shared between your own Slack workspaces, kept as a console record `_shared.<name>.json`: a host (immutable), the workspaces it is shared `with`, privacy per side, and members from directory groups and addresses of any connected directory. Always `extend`. Never in git |
| **no mixing** | a channel is one kind. Directory groups never feed a policy channel and internal groups never feed a console channel. A channel defined both in git and as a console record is held on both sides until one definition is removed |
| **owning directory** | the connected directory that owns a Slack workspace (or a GitHub organisation). Recorded when the connection is made, never in the policy. Its served domains are how a person is found in the workspace, and its scoped operator may operate the workspace |
| **connect** | pasting a throwaway Slack app configuration token (12 hours, used once, never stored or logged); the service creates the roster's own Slack App from a manifest and sends a workspace owner to Slack to install it. The bot token lands in `<release>-slack-credentials` only when the team matches the one recorded at first install |
| **catalogue App** (Slack) | a Slack App the deployment declares as data in `slackApps`: created and installed from the console, bot token kept in `<release>-slack-catalogue-apps`, optionally copied by a `push` to a secret store. Not used by the reconciler |
| **Discovered** | every channel the bots can see that no policy binding or record manages, with **Manage** to bring one under management |
| **guest-side probe** | for a managed Slack Connect channel, a `conversations.info` by id to the workspaces its record names as sides, to learn a side the bot did not list. Expected "not visible" answers are logged at debug |

## The audit trail

| Term | Means |
|---|---|
| **audit installation** | an installation of [truvity/audit](https://github.com/truvity/audit) that keeps the trail. It belongs to this application and runs in its namespace: one address takes both the catalogue this service registers at start-up and every record it sends |
| **action** | one thing that can happen, declared in the catalogue (`internal/audit/catalogue/roster.yaml`): `roster.person.signed_in`, `roster.github_member.invited`, `roster.slack_member.invited`, `roster.slack_action.held`, `roster.slack_removals.confirmed`, … Each has one constructor in `internal/audit/events.go` |
| **record** | one action that happened, or was refused: who acted, who it concerns, what it was about, how it ended. Every record is also one log line, sharing its id |
| **block** | the one delivery that waits: a recovery sign-in is kept by the installation before it succeeds, and refused when it cannot be |
| **async** | every other delivery: the record goes on a bounded queue in the process and is retried with backoff until the writer takes it. A restart loses what the queue held, and past its bound the oldest are dropped and counted -- which is the trade a trail that must not block the request makes, deliberately |
