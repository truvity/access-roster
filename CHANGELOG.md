# Changelog

One line per release; full detail lives in the release notes and the
git history.

## Unreleased

The first release has not been cut. This section describes what is in the
repository, not the order it arrived in.

- **directory-roster**, the directory hub: workspaces whose domains are
  discovered, snapshots with the freshness policy (`max_age`, the
  cheapest path, an in-domain miss that always checks live once), routing
  by email domain with conflict detection, and the authority rule that
  makes everything degrade to a hold rather than to "gone".
- **Served domains**: a workspace may be narrowed to a subset of the
  domains its tenant owns — `workspaces[].serve` in the values, or
  *Choose which to serve* on a connected directory's page. What is left
  out is discovered and shown but routes nothing and is not cached, only
  two workspaces that both serve a domain contest it, and the list is
  intersected with discovery so a domain moving between tenants hands
  over without an edit.
- **DirectoryService** over ConnectRPC for consumers, authenticated by
  Kubernetes ServiceAccount tokens; the operator services, the login
  routes, the consent callback and `/.access/whoami` on a second
  listener.
- **Connecting a real Google Workspace**, both ways in: admin consent
  (offline access, a forced consent screen so a reconnect really returns a
  refresh token, and the consenting account read from the id token) and an
  uploaded service-account key. Disconnecting hands the refresh token back
  to Google.
- **Nothing is lost on restart.** What a console changed — connected
  workspaces, their credentials, the memberships, the OAuth client, the
  session key and the break-glass password — is kept as plain ConfigMaps
  and Secrets in the hub's own namespace, written and read by the hub
  itself. `STORE=memory` keeps nothing and says so at WARN; the chart
  always sets `kubernetes`. At start, a declaration removed from the
  values takes its record with it, and a credential that cannot be read
  leaves one workspace unhealthy rather than stopping the hub.
- **Snapshots shared across replicas**, in Valkey: one copy of each
  directory, gzipped, with the reverse index rebuilt on read rather than
  stored. The refresh lease is held for the whole interval rather than for
  the work, so replicas that tick at different moments still read a
  directory once per interval — a quota is per tenant, not per reader —
  while a failed pass hands its lease straight back. No address configured
  keeps snapshots in memory, which the hub says at start.
- **The policy** (`docs/reference/policy.md`): five tables — groups,
  claims, lifetimes, clients, memberships — one schema for both services,
  deep merge with a load-time scalar-conflict check, shortest lifetime,
  layered loading, memberships the only console-writable table, clients
  declared or self-registered and never created in a console. The hub is
  a relying party of it: `hub-operators` and `hub-viewers`.
- **The issuer design, completed on sessions and standards**: sessions
  are first-class issuer state, listable per identity and client and
  revocable, which gives the console its second write — Revoke, and
  "sign out everywhere" for oneself — and the operator a lever between
  the proxy's sign-out and the next refused refresh. The standards table
  names what is in (Core code+PKCE, Discovery, RP-Initiated Logout as the
  conformance target; device, token exchange, JWT profile, client
  credentials, revocation, dynamic registration, JWT access tokens) and
  what is deliberately out (introspection, implicit and hybrid, back-
  channel logout for 1.0, the session iframe, PAR, DPoP, mTLS, CIBA), on
  `zitadel/oidc/v3`, with the OpenID conformance suite as the spike's
  seventh item.
- **The console** on the fleet stack, organised as the graph the content
  actually is rather than as a set of tables: search on every page, an
  overview that answers whether anything is broken, and a page per
  tenant, group, client and person, each carrying its edges in both
  directions. Every name is a link, every page opens with a
  plain-language summary, and actions live on the object they change.
  The navigation is two clusters, identity and access, with one adjective
  each — directory groups and internal groups — and a page at every level
  of both: a directory group's page mirrors an internal group's, and the
  membership that joins them is editable from either end. A person's page
  is the chain, one row per internal group held. Matchers lists every
  declared rule — the identity side's second way in, by shape rather than
  by membership — and keeps the proof simulator for a CI job or a
  workload, because a run exists only while it runs. A client's page
  lists the machines that reach it beside the people. People filters by
  directory and by whether an account is live. **Add a directory** offers both ways in and only
  the ways the deployment can take. The visual layer follows Material's
  guidance for a console: a navigation rail with the two sides as groups
  and a header kept for search and identity, a denser lowercase theme,
  and one meaning per form — names are links, chips are states, facts are
  a label over a value, and two-column data is a list. The account sits at
  the foot of the rail with your name linking to your own page, which
  also says how you signed in; detail pages split into a main column and
  an aside on wide windows, so a person's chain fits a screen. The
  contract was tightened for it: `Explain` names the directory that
  served the address, `SearchPeople` reports the total before the limit,
  and `GetPolicy` carries matchers only in structured form.
- **The Google backend**, which is the first real directory the hub can
  read: the Admin SDK over a service-account key with domain-wide
  delegation, discovering the customer id and every verified domain,
  listing accounts and groups with their flat membership, and answering
  one address at a time. Archived counts as not live beside suspended.
  Unverified domains are not served, because a domain anyone may claim in
  a console is not evidence of anything. The credential type is pinned to
  a service-account key, since a credentials file may also name an
  external account that fetches its token from a URL the file itself
  carries. The console's setup guidance now reads its scope list from the
  backend rather than repeating it.
- **Declared workspaces are read at start**, which the chart had shipped
  the configuration for and no code had read. The tenant id became
  optional — the credential opens one tenant and it knows its own id — and
  supplying it turns adoption into a check that refuses a credential
  opening a different tenant. A declared workspace that cannot be adopted
  stops the process rather than leaving a hub that silently serves less
  than it was configured to. The chart renders the Gateway, HTTPRoute and
  Certificate for the console host it had always claimed to.
- **Day one leads itself.** Overview carries what a fresh installation
  still has to do, with that installation's own redirect URI and scopes to
  copy rather than a document's placeholders, and each step disappears as
  it completes. The break-glass account's default is computed rather than
  fixed: it stays off when the values already declare a workspace and a
  non-empty `hub-operators`, because such a deployment signs in through
  the directory from its first boot and a password nobody needs is a
  standing credential. `GetSettings` reports the setup values.
- **A demonstration mode** (`DEMO=1`): two tenants in memory and a
  consent connector, so every use-case is walkable before a credential
  exists.
- **The documentation set**: why it exists, the concepts, the fifteen
  integration points, the architecture, a design per battery, the
  reference pages, one connect guide per kind of relying party, the
  operations runbooks and the extension points.

Designed but not built: access-issuer, access-proxy, the libraries as a
public module, accessctl and the GitHub Action.
