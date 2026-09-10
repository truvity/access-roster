# Changelog

One line per release; full detail lives in the release notes and the
git history.

## v0.9.15

- **The session service is mounted whether or not a cross-origin console
  was configured.** It was gated on `console.origin` — a value that
  answers a different question, *may some other origin call this* — so on
  one origin, where there is no CORS to configure and nobody sets it, the
  service was never mounted. Every sessions section in the console
  answered 404 while `/account`, server-rendered beside them off the same
  store, worked perfectly: the half a person is most likely to try
  working, and the half a console shows not. The value now decides only
  whether the CORS wrapper goes on. (INF-682)

## v0.9.14

- **The console asked the wrong host who it was.** `/.access/whoami` was
  fetched as an absolute path, so mounted under `/console/` it resolved
  against the **origin** — the issuer — which serves no such endpoint.
  The console concluded nobody was signed in: it offered *Sign in* to
  somebody already authenticated and disabled every operator control,
  while the Connect calls beside it worked, because those had been
  fixed for the mount point and this had not. Every path the console asks
  for now goes through one `mounted()` helper, so there is one place to
  get it right rather than one per call site.
- **A snapshot already past its freshness window is refreshed at start.**
  A ticker's first tick is a whole interval away, so a restart served the
  previous process's snapshot for fifteen minutes — and a deployment
  rolling more often than that never reached a tick at all. The snapshot
  aged past the window and every domain read *provisional*, which is a
  release cadence showing up to an operator as a loss of authority. Only
  what is already stale is re-read, and the existing lease still means
  replicas starting together read once between them.

## v0.9.13

- **The console's assets are referenced relatively, so one bundle serves
  at any mount point.** Mounted under a path they were requested from the
  origin root — where the issuer answers — so every asset 404'd and the
  console did not load. A build-time base path could not fix it either:
  the bundle is committed and embedded, so baking one deployment's prefix
  into it would ship that prefix to all of them. `./assets/…` resolves
  against the page instead. It requires the trailing slash, so the bare
  prefix now redirects to itself with one, and the Connect transport
  resolves its base from the page rather than a literal. (INF-687)
- **A bare GET of the issuer's host can land somewhere useful.**
  `route.rootRedirect` on the issuer — the issuer serves nothing at `/`,
  every endpoint it answers being a named one, so a person who types the
  domain got a 404. Empty keeps that 404, which is honest for an issuer
  deployed alone.
- **`/register` is dropped, and every client is declared.** Only our own
  proxy could ever have called it; an endpoint that mints clients is the
  one surface an issuer least wants; and declaring them keeps *who can
  obtain tokens for which audience* answerable by reading a repository
  rather than by querying the running service. `registration.enabled`
  leaves the access-proxy chart, `/register` leaves the issuer's surface,
  and the console's Clients page is read-only by construction rather than
  by policy. The drift it would have prevented is closed by generating a
  console's client from one row instead. (INF-664, INF-688)

## v0.9.12

- **The sign-out chain moves with the console.** Mounted under a path,
  the console's sign-out link still pointed at `/oauth2/sign_out` at the
  root — which belongs to the issuer, not the proxy — and its
  `post_logout_redirect_uri` was the host root rather than the console's
  own page, so it matched no `signed_out` entry and the issuer landed the
  person on its own page. Both halves fail quietly: one is a button that
  404s, the other is a sign-out that worked and reads as though it did
  not. The proxy prefix now derives from `route.pathPrefix` when unset,
  so the two cannot drift, and three guards hold the chain. No prefix
  renders exactly what it always did. (INF-687)

## v0.9.11

- **One Gateway can be shared between the hub and its issuer.** Both
  charts rendered their own for `route.host`, so pointing them at one
  hostname produced two Gateways each declaring a listener for it — and
  Envoy Gateway merges every Gateway of a class into one deployment, so
  they collide on that listener rather than coexisting. Exactly one may
  own it now: the hub's `route.gateway.{name,namespace,sectionName}`
  attaches to an existing one instead of rendering a Gateway and a
  Certificate, and the issuer's `route.sharedWith[]` admits routes from
  the namespaces named (its own always included — a selector, unlike
  `from: Same`, does not imply it). Both default to today's shape.
  Whether a Gateway accepts a route from another namespace is decided
  there and not by a ReferenceGrant, which governs `backendRefs` and has
  nothing to say about `parentRefs`. (INF-687)

## v0.9.10

- **The console's sessions sections need the issuer to share the origin,
  not merely to exist.** They were gated on an issuer being configured at
  all. But the session service is called **same-origin**, with the
  browser's issuer cookie and no bearer — that is the whole point of
  putting the console under its issuer's host — so wherever the two are
  still separate hosts the sections rendered and then called the
  console's own origin, which serves no such service. A 404 per section,
  on every deployment that has not done the cutover. Supersedes v0.9.9,
  which carried the bug.

## v0.9.9

- **Docs: one domain, and where session management lives.** Decided with
  Oleg 2026-09-10: the issuer, the directory's console and the shared UI
  live on one hostname. The issuer sits at the **root** — its URL is the
  `iss` claim and discovery lives at the origin root, so it cannot take a
  path — and the console is mounted under **`/console/`**, the gateway
  rewriting the prefix away. On one origin the console's session pages
  call the issuer with the browser's own session cookie, so the
  cross-origin bearer question stops existing. The global sessions
  listing **exists**: operator-only, capped, audited. The issuer's plain
  `/account` page stays as the fallback for an installation with no
  console. `docs/design/access-issuer.md` *One origin*, `docs/design/hub.md`,
  `docs/architecture.md`, the references. (INF-687, INF-682)

## Unreleased

- **The console can be mounted under a path of its host, so it can share
  its issuer's origin.** `route.pathPrefix` on the hub's chart: the
  console's own route matches the prefix and the gateway rewrites it
  away, so the hub's own routes never learn it exists. The **bootstrap
  surface stays at the host root** — `/login` and `/connect` are
  registered OAuth redirect URIs, and a provider returns to the literal
  address on file, so a prefixed one would be a callback nothing points
  at. Two chart guards hold both halves. Empty is exactly today's shape.
  (INF-687)
- **The global session listing exists, for an operator.** A request
  naming neither an identity nor a client used to be refused outright;
  it now answers for an operator and is refused for everyone else. It is
  the incident case: the one where you do not know *whose* session to
  look for. Paged by a cursor that is the last session seen rather than
  an offset, because an offset is invalidated by every session that opens
  or closes between two calls and this index is precisely the thing that
  changes constantly. Capped, and a session now reports the browser
  session that parented it. (INF-682)
- **Sessions in the console.** *Active sessions* with Revoke on a
  person's page and *Sign out everywhere* on your own; *Open sessions* on
  a client's page; and a new operator-only **Sessions** page listing the
  installation, filterable by person and client. Rows opened from one
  browser group together. They call the issuer's session service
  same-origin with the browser's own session cookie — no bearer, no CORS
  — and render only when the console knows of an issuer. Removal only,
  never a grant. (INF-682)

## v0.9.8

- **A ServiceAccount's subject names its cluster.** `sub` was
  `k8s:<namespace>:<name>`, and the same namespace and name exist on every
  cluster in an estate — so two different machines were one subject, which
  is the collision `sub` exists to prevent. It is now
  `<cluster>:k8s:<namespace>:<name>`, from the issuer's new `cluster`
  value; scope first, like every group name. An installation that names no
  cluster keeps the unqualified form, so nothing changes until it is set.
  A `service_account` matcher may name a `cluster` to narrow to one, and
  naming none matches any — every rule written so far still means what it
  meant. (INF-681)
- **One spelling for a ServiceAccount, and one reader for all three.**
  A recovery sign-in completed as the API server's
  `system:serviceaccount:<ns>:<name>` while a token exchange minted
  `k8s:<ns>:<name>`, so the same machine had two subjects and a
  `service_account` matcher could admit one and not the other. Recovery
  now completes as the issuer's own spelling. Every spelling the estate
  has minted is still **read** — by one function, in `policy` — because a
  reader that knew only its own would refuse a token from a release either
  side of it, and for recovery that is exactly the day it is the only way
  in. (INF-681)

## v0.9.7

- **The issuer holds a session with the browser, so a second console
  costs no login.** It held only a login-round-trip cookie: every console
  bounced the person back through the corporate directory, and *global
  sign-out* had almost nothing to end. Now an authorization request
  completes against that session — silently — and `auth_time` comes from
  where the person actually authenticated rather than from the moment a
  token was minted. `prompt=login` and `max_age` are honoured, including
  `max_age=0`, which is a request for a fresh authentication and not, as
  a zero duration would otherwise read, no requirement at all. The
  directory still decides: a silent sign-in re-asks the hub, so a
  suspended account stops being admitted instead of coasting on a browser
  session. `end_session` ends the sign-in, not only one application's
  tokens — the half-sign-out that looks exactly like a whole one.
  (INF-685)
- **An account page, served by the issuer at its own host.** `/account`
  lists what you have open and ends all of it. Being same-origin with the
  session service is the point: the browser already holds this issuer's
  session there, so the page needs no bearer, no CORS and no console, and
  its buttons are form posts rather than JavaScript. *Sign out
  everywhere* ends both halves — the sessions already running and the
  sign-in that would silently open more. Per-client sessions now record
  the browser session that parented them and the time it authenticated.
  (INF-685)
- **Docs: the SSO session and where session management lives.** The
  design now says plainly that the issuer holds a first-class **SSO
  session** (to build, INF-685) and that session management is served at
  the **issuer's own host** — an account page, same-origin with the
  session service — rather than through a cross-origin bearer from each
  console. The v0.9.4 `console.origin` CORS path becomes the optional way
  to weave the operator view into the directory console. `docs/design/access-issuer.md`.
- **Docs: `sub` is decided.** A person is their email; a ServiceAccount is
  `<cluster>:k8s:<namespace>:<name>` (the cluster qualifier is the one part
  still to land in code, INF-681). `docs/reference/policy.md`,
  `docs/design/trust.md`.

## v0.9.6

- **One question to the directory per token, not four.** Every claim a
  token carries comes from one answer, and the code was asking for it up
  to four times over one exchange — the hub call behind it being the
  issuer's hottest. Asking twice is not only two round trips where the
  design counted on one; it is two answers that can disagree, with the
  grants from before a change and the name from after.

## v0.9.5

- **An ID token names who signed in.** It carried no `sub` at all, which
  makes it invalid, and no `email`, `name` or `groups` either. Every
  client asserts userinfo claims in its ID token, so the library
  assembles one from this storage and assigns the result **wholesale** —
  and the hook it assembles from was empty here, deprecated in favour of
  the one the userinfo *endpoint* uses. Supplying nothing did not leave
  the ID token's own claims alone; it overwrote them. A relying party
  that reads the ID token rather than calling userinfo — ArgoCD and Kargo
  both do — saw nobody. (INF-681)
- **A token says which session it belongs to, and when the person signed
  in.** `sid` is the session id the console lists and revokes, so a
  relying party can say WHICH of a person's sessions it holds rather than
  only that it holds one; a token no session backs, such as a workload's,
  carries none rather than an empty one. `auth_time` is the sign-in, not
  the minting: a refresh an hour later carries the same `auth_time` and a
  fresh `iat`, and that difference is the whole of what a
  "re-authenticate for this action" rule reads. Both are identity;
  `groups` still decides. (INF-681)
- **A session remembers the scopes it was granted.** It did not, and a
  refresh arrives carrying a token and nothing else — so the answer to
  "what may this session ask for" was *nothing*. Two consequences, both
  live: a refresh naming any scope at all was refused as though it had
  asked for more than it held, and one naming none minted an ID token
  the library assembled from an empty scope set. A session recorded
  before this release has no scopes and behaves exactly as they all did.

## v0.9.4

- **The issuer answers what sessions it is holding, and ends them.**
  `SessionService` (`ListSessions`, `RevokeSessions`) over the shared
  index, served only when `console.origin` names the one browser origin
  allowed to call it. It can only ever **remove**: no call here grants
  anything, which is what makes it safe to point a console at. Your own
  sessions are yours to list and end; somebody else's need an operator;
  listing a client names everybody on it, so that is an operator's too.
  A request that narrows to neither an identity nor a client is refused —
  "everything" names every person signed in. A session id alone is never
  enough to end somebody else's, and a mismatch answers exactly as an
  absent session does, so an id cannot be probed. (INF-682)
- **A token names the person, not only the address.** `ResolveUser`
  carries the account's given and family names (additive fields 7 and 8),
  the issuer puts them in `userinfo` and the ID token as `name`,
  `given_name`, `family_name` and `preferred_username`, and a relying
  party's UI shows somebody rather than an address — which is what ArgoCD
  and Kargo render after a cutover. Identity, never authorization:
  `groups` decides, as before, and every one of these is absent for a
  workload or a recovery sign-in, which have no names to give. A **held**
  answer carries the last known grants and no names: the hold window
  exists for authorization, and a name recovered from memory would be a
  claim the issuer cannot currently vouch for. (INF-681)

## v0.9.3

- **Every grant is named `<scope>:<thing>:<role>`.** The hub's own two
  roles are `all:access-roster:operator` and `…:viewer`; a role over one
  directory is `<workspace id>:access-roster:<role>`, the scope in the
  first position like every other name, where it used to be an `@`
  suffix. `policy.ScopedGroup` and `SplitScopedGroup` follow, and the
  loader **warns** at start on a name that is neither a grant nor one of
  the two families that deliberately are not grants (`rung:<name>`,
  `emp:<slug>`) — a convention is worth saying out loud where an operator
  sees it, and worth not refusing, since an installation mid-rename holds
  both shapes at once. The demonstration policy is written in the shape
  it documents. **This must be pinned in the same window as the
  installation's own policy rename**, or the console stops recognising
  its operators. (INF-684)
- **Docs: the naming rule.** Every grant is `<scope>:<thing>:<role>` —
  `kernel:k8s:admin`, `prod:eudi:deployer`, `all:access-roster:operator`
  — with `rung:` and `emp:` the only two-segment families and neither a
  grant. The reasoning is in `docs/design/trust.md`.

## v0.9.2

- **A GitHub Actions workflow can prove what it is.** `verify.GitHub`
  turns a workflow identity token into a proof carrying repository, owner,
  ref, workflow and environment — the five things a `github:` matcher pins
  a job to — so CI can trade its token for one of this issuer's. Two
  settings are the trust boundary, not tuning: `github.owners` (anybody
  may run a workflow in their own repository and get a valid token, so the
  owner allow-list is the whole of what makes one of them ours — empty
  verifies nothing) and the audience, which is this issuer's URL and is
  not configurable, so a token minted for a cloud provider cannot be
  replayed here. A token from another issuer comes back *unrecognised* so
  the next verifier may try it; one this verifier owns and refuses is
  final. (INF-646)
- **The session index is shared, not per-process.** It answered from
  whatever one replica happened to record: a listing was arbitrary rather
  than wrong, and a revocation reported success while the session went on
  working at the pod next door — the worst failure available to a control
  whose whole job is to end access. It now lives in the same store as the
  logins in progress. Sets make it findable, the record's TTL is the whole
  of expiry, and a listing repairs the sets it walks. A refresh token is
  hashed into its key rather than written into the keyspace: an index that
  can be read must not be an index that can be replayed. (INF-646)
- **The rule under everything is written down.** `docs/design/trust.md`:
  a service trusts exactly two anchors — the cluster for a workload next
  door, the issuer for everything further away — chosen by scope, never
  a third; `groups` is the one vocabulary; recovery is the cluster anchor
  used as the floor; a service with a console and an API has two
  listeners. `docs/connect/service-to-service.md` is the how-to. Every
  connect guide names its anchor; the policy examples use the built
  syntax (`clients:` with `signed_out`, `github.owners`) instead of the
  design-era one.

## v0.9.0

- **Sign out ends the sign-in, not just the cookie.** Clearing the
  proxy's session cookie ends the session with one application; the
  issuer still holds the person's sign-in, so the next click — that
  console or any other behind the same issuer — admits them again with no
  password. The screen said signed out and they were not, which is the
  one failure a person cannot see. `access.signOutThroughIssuer` now
  renders both halves (proxy sign-out → the issuer's RP-initiated logout
  → back to the console's front page), and refuses to render half a chain.
  A client's landing pages are a new `signed_out` list in the policy,
  separate from `redirects`: a redirect URI *starts* a sign-in, so landing
  there after signing out begins the login just ended — and listing one
  address as both now fails the load. (INF-676)

## v0.8.6

- **A policy change is a rollout, not a reload.** The declared layer is
  read once at start, and the hub's Deployment carried no checksum of it:
  the ConfigMap changed, kubelet wrote the file a minute later, and every
  replica went on answering from the policy it booted with — a grant
  visible in git, in the ConfigMap and in ArgoCD's *Synced*, and nowhere
  in the running service. Seen live rolling out the derived policy
  (INF-662). The issuer has carried `checksum/policy` since its first
  release; the hub reads the same file the same way and now does too, and
  `just chart-lint` fails either chart that loses it.
- The console's account block is three lines — name, address, roles —
  with the roles held over a single directory named beside the
  installation-wide one.

## v0.8.5

- **A person's page reads down the column.** The 300px rail was carrying
  the two longest things on the page — every directory group the person
  is in, and the JSON a token would carry — so on a real directory they
  had to be read sideways while the main column ended halfway down. Both
  now sit in the main column, in the order the page already reads; the
  rail keeps the seven short facts, which is what a rail is for.

## v0.8.4

- **A probe retries what it could not ask, and not what was refused.**
  One transient `503` from Google's `domains.list` — seen live, during a
  rollout — flipped a directory whose credential is fine to *failing*,
  and with 0.8.0's reasons attached it told the operator its domains were
  *provisional — probe failed*. A directory that answers 503 has said
  nothing about the credential; one that answers 403 has. Backends now
  mark the first kind `ErrUnavailable`, the hub retries only that, and a
  revoked credential still surfaces on the first attempt.

## v0.8.3

- **React 19**, and the console bundle rebuilt on it. The major itself was
  a deliberate, human-merged update; what a bot cannot do is rebuild what
  `package.json` produces, so the repository declared 19 and carried a
  bundle built against 18. `frontend/dist` is embedded in the binary and
  `ts/dist` is what a git-tag install gets, so a stale one ships a console
  nobody's manifest describes. CI now runs `console` and both bundle
  recipes fail when a fresh build differs from what is committed.
- An empty **Directories** page offers the action it names, instead of
  saying "Add one to start serving its domains" with the only control in
  the page header.
- The connect runbook says what an unpublished consent screen actually
  does: in Testing it admits only listed test users, so the first tenant
  connects and the next company's administrator is refused before the
  request reaches the hub — with the seven-day refresh-token expiry as
  the half that bites later.

## v0.8.2

- **Sign-out ends the session that actually signed you in.** Behind a
  proxy the console's sign-out cleared this hub's own cookie — which
  nothing was using, because the proxy holds the session and forwards a
  bearer. So sign-out did nothing, and it landed on a sign-in page with
  no way in, this hub's own sign-in being off by design. `access.signOutURL`
  names the proxy's own sign-out, the console navigates to it rather than
  POSTing (a redirect a fetch would swallow), and the login page now says
  where the door is instead of showing an empty card.
- **A page waiting for a first snapshot fills in when it lands.** The
  first snapshot runs detached, so a directory's page opens on a
  workspace with nothing in it and used to stay that way — a photograph
  of the first two hundred milliseconds, while the read it was waiting
  for finished five seconds later behind it. The directory and Overview
  pages now say the first snapshot is running and refresh themselves
  until it is not.

## v0.8.1

- **A probe cancelled by the hub's own shutdown is no longer written down
  as a probe that failed.** Seen on the 0.8.0 rollout: the pod stopped
  mid-probe, the token request returned `context canceled`, and that
  became the workspace's health — so a directory whose credential is
  fine showed as failing, and its domains as *provisional — probe
  failed*, until the next pass. A probe that did not happen is not a
  probe that failed.

## v0.8.0

Everything the first live connect exposed, and the two choices it showed
the console was making for the operator.

- **A request never waits on the directory.** The first snapshot ran
  inside the consent callback and met the gateway's fifteen-second route
  timeout: a 502 for a workspace that had already been stored. A console
  listing with no snapshot read the directory under the request's own
  context. Narrowing refreshed before returning. All three now run
  detached; a read that did not ask for freshness never fetches; and
  narrowing excludes from what is already in memory, so it does not
  depend on a read succeeding.
- **The store is the truth and the reader map is a cache of it.** With
  two replicas, a workspace connected on one was "not found" on the other
  until it restarted. A miss now opens the workspace from the credential
  stored beside the record.
- **Group members are read with bounded concurrency** — eight in flight,
  atomic, in the directory's order — and every pass logs how long it took.
- **`hold` is now `provisional`, and says why**: first snapshot, stale,
  probe failed, contested. The Overview also counted *unserved* domains
  as held, which is how one record read "0/7 served, 7 on hold" on one
  page and "six not served, one hold" on another.
- **A connect asks which domains to serve**, with the consenting
  administrator's own domain pre-selected, instead of quietly serving all
  seven a tenant happened to own. "All of them, including ones added
  later" is still the empty list — now chosen rather than defaulted into.
  And a **reconnect keeps the answer**: it brings a new credential, not a
  new configuration.
- **An operator chooses which groups to sync.** `Workspace.SyncGroups`
  existed and was wired to nothing — not the refresh, not either store,
  not the contract, not the console, and `clone` did not even copy it.
- **The setup panel names the redirect URIs where each flow lands.** With
  one shared OAuth client the sign-in returns to the *issuer*, not here,
  so an operator was registering a URI nothing returns to. And the client
  is checked before an administrator is sent to spend a real consent on
  one the provider will refuse.
- **A role may be held over one workspace** (`hub-operators@C0example`),
  so connecting a second company's directory does not hand its
  administrator the first one. Recovery stays installation-wide by
  construction.

## v0.7.2

- **A consent that fails says so on a page.** The callback answered 502
  and the CDN in front of the console replaced it with its own "Bad
  gateway" — six kilobytes of Cloudflare HTML in place of the line naming
  the exact Google project and the exact API to enable. The diagnosis
  survived only in the log, which is the one place the person who could
  act on it was not looking. Every browser-facing outcome of the consent
  callback now renders a page in the console's own style, carrying what
  the directory said verbatim and the usual causes in order of
  likelihood, and none of them answers 5xx. A test asserts that.

## v0.7.1

- **The customer id is read from the admin's own user record.** `Tenant`
  called `Customers.Get`, which needs a *fifth* scope,
  `admin.directory.customer.readonly`, that is not among the four the hub
  asks for. Google granted the consent and the first read then failed with
  `Request had insufficient authentication scopes` — naming no scope, and
  arriving as a 502 on the callback. A `User` carries `customerId` and is
  covered by the user scope already granted, so the id is free and no
  administrator has to consent again.

## v0.7.0

- **The consent callback takes its operator from the signed state.** It is
  a redirect from Google and it lands on the bootstrap route — the one
  that exists precisely so a callback is not swallowed by a login prompt,
  which means the gateway adds no identity to it. Insisting on an identity
  in that request refused the one flow the route exists to finish: a live
  403, `this needs the operator role`, on the first workspace anyone tried
  to connect. The authorisation still happens where it always did, when an
  operator asks for the consent; the state now carries the answer, signed
  by the hub and pinned to the browser by the cookie the callback already
  checked. `docs/reference/configuration.md` had described this shape all
  along.
- `Identity.Who()` — the address where there is one, the subject where
  there is not. A recovery sign-in completes as a ServiceAccount and has
  no address, so `ConnectedBy` recorded a blank for exactly the sign-in
  whose actions most need a name against them.
- Dependencies: typescript 7, vite 8 with @vitejs/plugin-react 6, MUI 9.4,
  vitest 5. React stays on 18.

## v0.6.4

- **access-proxy writes `weight` out on every `backendRefs` entry.** The
  API server defaults it, ArgoCD normalises core-API defaults but not
  CRDs, and the child Application was therefore permanently OutOfSync —
  the third field in this family after the route's `matches` and
  `certificateRefs.group`, and the only chart of the three that had not
  learnt it. The lint now counts one `weight` per backend.

## v0.6.3

- **The gateway now sends the proxy the session cookie.** An HTTP
  ext_authz service is sent only `Host`, `Method`, `Path`,
  `Content-Length` and `Authorization` unless the `SecurityPolicy` says
  otherwise, so the proxy answered every check without ever seeing the
  cookie it had just written: sign-in completed, the callback returned
  its 302, and the next request began a fresh login — forever. The chart
  names `cookie` itself and will not let a value take it away; the lint
  asserts every rendered policy carries it.

## v0.6.2

- A recovered sign-in has no email address. It completes as a
  ServiceAccount **subject** and is carried as one end to end, instead of
  failing where an address was assumed.

## v0.6.1

- The issuer reads a confidential client's secret. It was constructed
  with no resolver at all, so every confidential client got
  `invalid_client`.

## v0.6.0

- **Recovery sign-in**, so a first installation can be bootstrapped:
  a ServiceAccount token checked by the API server against a mandatory
  audience. It stores no credential and grants nothing by itself — the
  policy's `service_account` matchers decide what it is in.

## v0.5.0

- A bootstrap surface on the hub the gateway does not cover, so the
  console that connects the first directory is reachable before any
  directory exists.

## v0.4.3

- `certificateRefs.group` written out — the last Gateway API field the
  API server defaulted and ArgoCD would not normalise, which left the
  child Application permanently OutOfSync and gated every later wave.

## v0.4.2

- The HTTPRoute path match written out, for the same reason.

## v0.4.1

- Several protected routes on one host, each with its own posture — the
  shape a surface needs where a demo path is open to any employee and the
  application behind it is not.

## v0.4.0

- **The access-proxy chart is published.** oauth2-proxy, a Valkey session
  store and the Gateway API resources that put them in front of one
  console, for applications that cannot run the code flow themselves.

## v0.3.0

- The hub verifies the gateway's forwarded token against the issuer's
  keys instead of trusting a header.

## v0.2.0

- **The TypeScript package exists.** `@truvity/access-roster`, installed
  from git at a tag with `ts/dist` committed so it needs no toolchain and
  no registry: `fetchIdentity`, `useIdentity()` and `<UserBadge>`, with
  react and MUI as optional peers. It parses no token — the browser asks
  the application it is already talking to. Its reference page described
  three states and the endpoint's real shape had different fields; both
  now match what is served, and there is a **fourth state**, `unknown`,
  for when the question could not be asked. A console that showed a
  sign-in button because one request failed would send a signed-in person
  to authenticate again for nothing.
- **Revocation always reaches the shared state.** It took a hit in the
  per-process session index as proof that revocation was done and
  returned — so a token revoked on the replica that happened to hold the
  session stayed valid at every replica, including that one. Both now
  happen, always, in that order.

## v0.1.0

The first release: enough to stand the hub up on a cluster, connect the
companies it serves, and let people in. The issuer is here and runnable
but has not carried a relying party yet.

**Not in it**, though the reference documents describe them: the
TypeScript package (`docs/reference/typescript.md`) and most of the Go
module for consoles (`docs/reference/go-module.md` — `identity`,
`authz`, `directory`, `tokens`). What a `go get` at this tag gets is the
policy engine and the backend interface. Both libraries belong to the
work that replaces gateway-auth, and nothing in the hub's rollout needs
them.

This section describes what is in the release, not the order it arrived
in.

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
- **Nothing untrusted reaches a log line unsanitised.** Addresses,
  request paths and the errors built from them now pass through
  `internal/logsafe`, which removes what a reader or a parser would take
  for the end of a record. Structured handlers escaped these already —
  none of it was forgeable in practice — but it is now true by
  construction rather than by the handler's choice, and named where it can
  be seen. The address stays in the line: an audit record that does not
  say who was refused is not one.
- **A login in progress is shared across replicas.** The authorization
  request, the code, the tokens and the device flow were four maps in one
  process — so a browser that started at `/authorize` on one replica and
  came back from the provider at another found nothing, and a terminal
  polling the device endpoint reached whichever pod answered. All four now
  live in Valkey when one is configured, each carrying its own expiry so
  nothing sweeps, with the user code claimed by a single atomic write
  because two replicas minting the same short code must not both believe
  they own it. Memory remains the default and says so at start.
- **The release publishes both services.** `.goreleaser.yaml` was missing
  entirely — the workflow would have failed at its GoReleaser step on the
  first tag ever cut. It now builds the hub, the issuer and the acceptance
  binary for linux and darwin on both architectures, publishes two images
  under `ghcr.io/truvity/access-roster/`, and stamps the git tag into each
  binary's version. `just release-check` validates it without cutting one.
- **access-issuer has a chart**, so the release has both to publish: the
  Deployment, the TokenReview permission the exchange needs, the policy
  ConfigMap, the route, and the cert-manager `Certificate` that produces
  the signing key with `rotationPolicy: Always` — a renewal has to be a
  new key, because a renewed certificate over the same key rotates
  nothing. `issuerURL` and `hub.address` fail the *render* when unset,
  rather than the pod.
- **People can sign in to the issuer.** `/login` is the chooser the
  library sends a browser to, `/login/<provider>/start` and `/callback`
  are the round trip, and `/signed-out` is where a logout lands. One
  button per provider kind, never one per company; with one provider it
  redirects rather than asking a question with one answer. The address is
  all that is taken from the provider — the hub decides whether it is
  anybody here, and refuses on that page, naming the address, because
  everywhere downstream the person would just be admitted nowhere. The
  half-finished request travels in signed state, so a callback cannot
  finish somebody else's login, and that state's key is derived from the
  signing key rather than being a second Secret to provision.
- **The issuer's signing key is provisioned, not minted.** It reads a PEM
  a Secret carries — cert-manager issuing one, external-secrets delivering
  one — mounted as a file, and holds no permission to read Secrets at all.
  A service that creates its own credential is an exception to how every
  other credential here is provisioned. The key id is now the key's own
  RFC 7638 thumbprint rather than a name travelling beside it, which is
  what lets the key arrive from anywhere and makes rotation a matter of a
  new key having a new id.
- **access-issuer is a service.** `cmd/access-issuer` and
  `internal/issuerapp` assemble it from the environment — policy, the door
  to the hub, the signing key, the verifiers — and serve discovery, the
  JWKS, the code flow, exchange, revocation and the device flow, with
  health beside them. It refuses to start without an issuer URL, because
  that string is baked into every token and every relying party's trust
  and a default would be a value nobody chose spread across an estate.
- **Discovery stopped advertising the implicit grant.** `response_types`
  was already corrected; `grant_types_supported` was not, and a relying
  party reads that one and picks — offered implicit, a library uses it,
  and the refusal arrives in a browser redirect where nobody sees why.
- **The chart has been installed and run**, in kind, with the real
  Kubernetes store and token recovery: two replicas, recovery by a minted
  token straight into the console, the API listener admitting the declared
  consumer and refusing every other identity, and no standing credential
  anywhere in the namespace. The first attempt would not start at all —
  the rendered policy carried no `version`, so the loader refused it. The
  version belongs to the chart now, not to the values.
- **An acceptance suite against a real API server** (`just acceptance`, a
  throwaway kind cluster). It covers the three things a fake clientset is
  silent about and the hub leans on: name validation, a create that raced
  another — now handled rather than failed — and TokenReview, which is
  what recovery and the API listener's guard are made of. Running it
  showed that the audience is enforced by *asking* for it: a token minted
  for another audience comes back not authenticated at all.
- **The wiring is testable.** Everything `main()` decided moved to
  `internal/app`, with an acceptance suite that boots a whole hub from the
  environment and walks the use cases over the real handlers, and a test
  that compares every variable the binary reads against every one the
  chart sets — reading both from the source, because the five settings
  that were read and never set were exactly the kind of thing a restated
  list gets wrong.
- **The hub's own sign-in is a switch** (`access.login.directory`), and
  turning it off closes the routes rather than hiding the buttons —
  connecting a directory is unaffected, because an operator granting this
  hub access is not a way in. The external-OIDC login the values gestured
  at is **removed** rather than built: an installation that has an issuer
  has access-proxy in front of it, and the proxy's forwarded identity is
  that path.
- **Four chart values that did nothing now do something.** `PUBLIC_URL`
  was never set, so a deployed hub built both OAuth redirect URIs — and
  the values its setup steps tell an operator to paste — from
  `http://localhost:8081`; it now comes from `route.host`, and the session
  cookie is marked Secure with it. The forwarded-identity path a console
  behind the fleet's gateway has been documented as using was never
  rendered either; it now is, with the header name as a value. Session
  lifetime and log level joined them.
- **The API listener authenticates its callers.** It was open: anything
  that could reach the port got every account and group of every company
  the hub serves. Callers now present a projected ServiceAccount token
  with the hub's audience, verified by TokenReview against the declared
  `consumers`. A deployment declaring none admits nobody; outside a
  cluster there is nothing to verify against, so it stays open and the
  process says so at start.
- **Signing in with a directory works.** `GET /login/<backend>/start` →
  `/callback` asks the provider for `openid email profile` and nothing
  else: the address is all that is taken from it, and whether the account
  is live, which company it belongs to and what it may do are answered by
  the directory this hub already reads. An address in no served domain is
  refused at the door rather than given a session with no role, while a
  person of a served company who is in no group signs in fine — their own
  page explains what they have. One button per directory *kind* on the
  sign-in page, never one per company, which would publish the tenant list
  to anyone who loads it. The OAuth client now needs **two** redirect
  URIs, and the setup step shows both.
- **Recovery replaces the break-glass account.** In a cluster the hub
  stores no credential at all: recovery is a ServiceAccount token minted
  for one audience and a few minutes, checked with a TokenReview, so the
  authority is the cluster's own RBAC — revocable by removing a binding,
  recorded in the cluster's audit log, and naming who recovered rather
  than "admin". Whoever could read a stored break-glass Secret already had
  cluster access, so the secret was only ever converting that access into
  a session; this does it directly. Outside a cluster a password is
  generated and printed once, kept as an Argon2id digest with a random
  salt, serialised, and silent for a minute after ten failures — the
  correct one included, so the limit says nothing about which guess was
  close. Only that shape is a standing credential, so only it gets a
  warning and a "turn it off" setup step. `POST /admin/login` becomes
  `POST /login/recovery`.
- The forwarded identity header is now required to be an address before it
  is taken as a principal; the consent cookie is cleared with the same
  attributes it was set with.
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
