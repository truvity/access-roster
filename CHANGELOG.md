## v0.14.7

**The git history was rewritten at this version, and every tag before it
was deleted.** Nothing in the code changed by the rewrite — the tree at
this commit is byte-identical to what v0.14.6 shipped — but every commit
before it has a new hash, and the old tags are gone. A clone from before
this point cannot be fast-forwarded; re-clone instead.

- **Generated bundles are no longer in git.** `frontend/dist` cost 29.2 MB
  of history, about seventy per cent of the repository, because a
  minified bundle is a new blob on every dependency bump. It also bought
  a silent failure: a committed artifact goes stale while everything
  still compiles, which is how v0.14.0 shipped a console reading a
  protobuf field the server no longer sent. Absent, the embed is a
  compile error. Loud beats stale.

  `ts/dist` goes for the same reason, with a `prepare` script so a git
  install still needs no toolchain of its own. `gen/` STAYS: it is Go
  source, small and diffable, and it is what makes the module
  `go get`-able without buf.

- **`directory-roster` leaves the release.** One service, one image, one
  chart. The hub was a second binary until INF-691 folded it into the
  issuer, which runs it in process — `internal/app` is still here and
  still does the directory work. What goes is the separate deployment,
  which had gone on being built and pushed for a service deployed
  nowhere.

- **react 19.3.0**, which is what Renovate's two open pull requests were
  for. Neither could land: a bot can edit a lockfile and cannot rebuild
  what it changes. There is nothing to rebuild now.

- **The chart/binary environment check now points at the issuer's chart**
  and reads both environment consumers. It immediately named eight
  settings the merged service supplies to nobody, `SIGN_OUT_URL` among
  them — which is the defect behind *"sign out does not work"*, reported
  twice. Nothing failed at the time, because an empty string is valid
  everywhere it lands. The list is in the test now, with what replaced
  each one.

## v0.14.6

Both of these were found by LOOKING at the screenshots the conformance
suite had already collected. The suite cannot see what is in them — it
asks a person — so a module sitting in REVIEW with a picture of the
wrong thing passes silently. Two did.

- **The signed-out page was telling people the opposite of what had
  happened.** It said applications they already had open *"keep their OWN
  sessions until those expire"* and that ending a sign-in here *"cannot
  reach into them"*. True when it was written, and false since v0.14.2:
  signing out revokes every session the browser opened. So the page
  claimed a person's other consoles were still open at the moment it
  closed them.

  It now says what happens, and keeps the one piece of honesty that is
  still due: a proxy already holding a valid access token finds out at
  its next refresh, so a console can serve for a few minutes more. That
  delay is bounded by the client's `ttl_cap`.

- **`/authorize` refused with the library's bare text.** Unstyled black
  on white, with nothing on it saying which service had been reached.
  It is reached exactly when there is nowhere safe to redirect somebody
  — an unregistered `redirect_uri`, an unknown client — so the person is
  left looking at it with no way onward. It renders as a page now, in
  the same voice as the rest, keeping the library's sentence because it
  already says what is wrong.

## v0.14.5

- **A client's `ttl_cap` now reaches the tokens a browser gets.** It was
  applied on token exchange and nowhere else, so declaring it on a
  console did nothing at all — the code flow used the deployment-wide
  lifetime whatever the client said.

  That number is the lever over how long a REVOKED session keeps working.
  A client only learns a session ended when it next has to refresh, so
  the access token's remaining life is exactly the window in which a
  sign-out has not taken effect yet. Reported twice from live use, as a
  console that went on serving after signing out; the sessions are now
  revoked at sign-out (v0.14.2, v0.14.4) and this is what makes the
  revocation prompt rather than eventual.

  Back-channel logout would close the window entirely by telling each
  client at the moment of sign-out. It is still not served, because
  oauth2-proxy does not consume it, so a short cap is the lever we have.

## v0.14.4

**Security.** An unauthenticated `GET /end_session` ended every session
in the installation — every person and every workload, from anyone on the
internet, at an address the discovery document publishes.

The library hands the storage whatever the end-session request named, and
a bare request names nothing: no `id_token_hint` and no `client_id` left
both arguments empty. `TerminateSession` passed that straight into
`Revoke(Query{})`, and an empty query selects everything.

The same path had a second, quieter weakness. An `id_token_hint` is a
*hint* in the specification rather than a credential, and the library
accepts an **expired** one by design. Honouring it as authority to revoke
meant anybody who found an old ID token — in a log, in browser history,
in a referrer header — could sign that person out of a console.

`TerminateSession` now ends nothing. What a logout request can actually
prove is the cookie it carries, so the browser's own sign-in is the only
authority for what gets revoked. The hint keeps its real job, which is
choosing the client's signed-out page. Ending one identity's sessions at
one client is still available through `RevokeSessions`, which authorizes
the caller first.

- **Both sign-out doors now do the same thing**, and the one that had the
  weaker half was the one a PROXY uses. `/logout` revoked every session
  the browser had opened; `/end_session` — what oauth2-proxy chains to —
  only ended the sign-in. So a console behind a proxy went on refreshing
  and serving pages after a sign-out that reported success, which is how
  it was reported from hubble. Both call one `SignOut` now.

## v0.14.3

- **Signing out lands on the page that says so.** `/end_session` had no
  default landing page, so a request naming nowhere to go redirected to
  the issuer root, which redirects to the console, which starts a new
  authorization — and the last thing a person saw after signing out was a
  login prompt. That reads as the sign-out having failed. It now lands on
  the signed-out page, which says what did and did not end.

- **A refused sign-out no longer signs anyone out.** The browser session
  was ended on the way IN to `/end_session`, before the library had
  looked at the request. A request it then rejected — a bad
  `id_token_hint`, an unregistered `post_logout_redirect_uri` — produced
  an error page for a sign-out that had already happened. The response is
  now held until its status is known, and the sign-in ends only if the
  request was good.

- **`/end_session` answers a browser with a page.** Every failure there
  was an OAuth JSON body, which is right for `/token` and wrong for an
  endpoint a person's browser is redirected to. Anything that does not
  ask for HTML still gets the JSON, with its `error` code intact.

- **A `post_logout_redirect_uri` with no `id_token_hint` and no
  `client_id` is refused** rather than quietly dropped. There is no
  client named, so there is nothing to have registered it, and "not
  registered" is the only answer available. Nothing was being sent
  anywhere unregistered before this — the URI was ignored and the person
  signed out regardless — but silence in answer to a request is its own
  defect.

- **The conformance driver answers the suite's manual steps.** Eight of
  the eleven RP-Initiated Logout modules end at a page the suite cannot
  see and ask a human for a screenshot of it. Unanswered, each sat in
  WAITING until the next module interrupted it — a row of greyed-out
  results that looked like a server fault and was a step nobody had
  performed. The driver uploads the screenshot from the browser it is
  already driving.

## v0.14.2

- **Signing out ends what the browser opened**, not only the sign-in
  itself. The design leaned on those sessions dying *"at their next
  refresh"* — they do, because a revoked session's refresh is refused —
  but nothing was revoking them. So every console the person had opened
  kept its own session until it happened to refresh, and a sign-out that
  reported success left access in place.

  The sessions go first and the sign-in second: if the first half fails
  the sign-in is still there and the person can try again, where the
  other order would leave sessions running with nothing listing them.

## v0.14.1

- **The console bundle shipped in v0.14.0 was stale**, so the Sessions
  page's new sign-ins table would have shown nothing: a protobuf field
  was renamed `signins` → `sign_ins`, the TypeScript was regenerated, and
  `frontend/dist` was never rebuilt — so the bundle read a field the
  server no longer sends.

  `just check` did not catch it because `ts` and `console` were not in
  it: CI runs each recipe as its own parallel job, so the local check and
  the pre-push hook skipped the two that build. They are in it now. The
  check is slower and it is the check that runs before a push.

## v0.14.0

- **Reusing an authorization code ends the session it opened.** RFC 6749
  4.1.2 says a code used twice must be denied and SHOULD revoke the
  tokens already issued from it. We denied the reuse — the first
  redemption deletes the request — but left the first redemption's tokens
  working, which conformance saw as a resource endpoint answering 200
  where it wanted a 4xx.

  Denying alone is the worse half: a code presented twice is a code
  somebody else has, and the tokens from its first use are the ones now
  in doubt. PKCE with S256 is required here and already defeats most code
  interception, so this is defence in depth rather than an open door —
  and it is the cheap half, because the code arriving twice is the whole
  signal.

  A reuse is logged at WARN, since it is either a broken client or a
  stolen code and both are worth seeing.


- **A token says how the person was proved.** `acr` was empty, so a
  client asking with `acr_values` got none back — which conformance
  flags, and which matters more than the flag: a recovery sign-in
  bypasses the directory **by design**, and a relying party that wants to
  refuse one had no way to see it in a token. Two classes, and discovery
  now advertises both, because a client cannot ask for a value it has no
  way to learn about.

  `amr` said `pwd` for everything, which is untrue of every sign-in this
  issuer serves: recovery presents a ServiceAccount token, and a
  directory sign-in presents whatever the provider asked for — which we
  are not told, so claiming a password was an invention. It is empty
  where we were not told.


- **A response carrying a credential is never cached.** RFC 6749 5.1
  requires `Cache-Control` on the token endpoint and the library does not
  set it, so conformance failed `oidcc-refresh-token` with *"token
  endpoint response does not contain 'cache-control' header"*. The rule
  exists for a reason worth stating: a token response sitting in a
  proxy's cache, or a browser's, is a credential anybody who can reach
  that cache now holds.

  `no-store` and `Pragma: no-cache` go on `/token`, `/revoke`,
  `/userinfo` and `/introspect` — and deliberately **not** on discovery
  or the key set, which are public documents that should be cached.
  Telling the world not to cache a key set would put a fetch of it in
  front of every verification anybody does.


- **`prompt=none` with nobody signed in now answers the CLIENT.** OpenID
  Connect Core 3.1.2.6 requires `login_required` at the redirect URI; the
  issuer rendered an HTML page saying so instead, and the code comment
  had predicted the failure without fixing it.

  Worse than it sounds: the caller of `prompt=none` is usually a hidden
  iframe doing a silent renewal. It cannot read an HTML page, has nobody
  to show it to, and waits until it times out — so a relying party doing
  silent refresh would hang rather than re-authenticate. Conformance
  called it *"expected an error but did not get one"*, which is the same
  fact from the other side.

  Found by the Basic OP profile, which is the first thing that run has
  paid for.


- **The conformance driver runs in headless Chrome, because it has to.**
  The first one used `curl` on the reasoning that the flow is redirects
  and one form POST. It is not: the suite's callback is an HTML page that
  posts the result back **with JavaScript**, so `curl` reached it, never
  ran it, and every module sat in WAITING while the authorization it was
  waiting for had already succeeded. From outside that is indistinguishable
  from a hang.

  `hack/conformance_drive.py` drives Chrome over the DevTools protocol and
  submits the recovery form in the page, so the browser follows the
  redirects itself and runs the callback's script.

- **What a recovery sign-in cannot prove**, now written down. A recovery
  subject is a ServiceAccount: no address, no name, so `userinfo` returns
  no `email`, `name` or `preferred_username`. Every module checking the
  claims a scope implies warns for a reason that does not exist when a
  person signs in. The unattended run is evidence for the protocol
  modules and not for the claim-bearing ones.

- **Run one plan at a time.** The suite serves every plan's callback under
  its alias and the clients register one callback, so a second plan with
  a different alias is refused a redirect it never registered, and one
  with the same alias interrupts the running test — which it reports only
  in its own log, so from outside it looks like a hang. This is what
  stopped the first attempt.


- **The Sessions page lists the SIGN-INS**, above the sessions they
  opened. This is what made revoking look like a no-op: the page showed
  every per-client session and no sign-in, so emptying the list changed
  nothing about who could walk back in. Worse, the console's own sign-in
  appeared nowhere at all — it never redeems the code it gets back, so it
  opens no session — while being the very thing keeping the reader signed
  in.

  Each row ends that browser's sign-in and everything under it.
  `ListSessionsResponse` gains `sign_ins`, the sign-in store gains a
  global index beside its per-identity one, and both are returned under
  the same permission rule as the sessions.


- **Signing out leads back to signing in.** The signed-out page said what
  had happened and left you there; sign-out now lands on the console,
  which is where a sign-in can actually start. Not `/login` itself: its
  buttons carry the id of a pending authorization request, so visiting it
  without one is a page that looks like a sign-in and cannot finish. The
  console's front page sends an unauthenticated browser through
  `/authorize`, which makes that request. A deployment with no console
  still gets the signed-out page, which is the honest ending for one.

- **"Sign out everywhere" on your own page follows through.**
  *Everywhere* includes here: naming no client ends the sign-in as well
  as the sessions, so the page was left acting signed in until its next
  call failed with a sentence about tokens — reported as an error on
  revoke, and it was the trace of the sign-out that had already worked.

- **A refused call says the session ended**, rather than repeating the
  issuer's sentence about tokens, which is true and is not what happened
  to the person reading it.

## v0.13.3

- **Sign-out still did not work, and for a second reason.** The route
  existed but answered **GET only**, and the console sends **POST** — its
  own sign-out was a POST on the reasoning that a link which logs you out
  is a link anyone can put in a page. So the button got a 404 from a
  route that was there.

  It was verified the first time with `curl`, which sent GET, so the
  proof missed exactly the path the button takes. The network tab showed
  it in one line: `logout POST 404`.

  `/logout` now answers both. And the console is told the issuer's
  sign-out **absolutely**, because it treats a bare `/logout` as its own
  and fetches it — right where it serves that route, wrong here, where
  the route answers with a redirect a fetch would swallow and leave
  somebody reading "signed out" with the session still open.


- **The account block went back to the foot of the rail.** Moved up and
  moved back on looking at it: near the brand it competed with the
  navigation for the first thing the eye lands on, and a console is
  opened to go somewhere rather than to check whose account it is. What
  it needed was not height. It was a sign-out that says *Sign out*
  instead of an icon to guess at, and that stays — as does Settings in
  the list of places to go rather than alone in the foot.

## v0.13.2

- **The Config profile runs in CI**, daily and on demand
  (`.github/workflows/conformance.yaml`), and the three profiles are
  named in the README with which of them can run unattended and why.

  Config is the one that can: it reads the discovery document and the key
  set, so it needs no client, no secret and nobody at a browser. It also
  guards the surface most likely to break by accident — change a provider
  option and discovery changes with it, silently, for every relying party
  that reads it.

  **On a schedule rather than on a tag**, deliberately. A tag is a build,
  not a deployment: at the moment `v1.2.3` is pushed the cluster still
  runs what it ran before, so a run then would certify the OLD issuer and
  file the result under the NEW version. Certifying the tag itself means
  standing its image up inside the job with a policy, a signing key and a
  certificate the suite accepts — worth doing, and a different job.

  The other two sign somebody in, and the signing-in needs a credential
  from the cluster. CI has no business holding that, so they stay a
  person's job — `hack/conformance-drive.sh` makes thirty sign-ins one
  command.


- **The rail puts who you are at the top, and says "Sign out".** The
  account block sat at the foot of a scrolling column, which is the last
  place somebody looks for the first question a console like this raises:
  *which account am I looking at this with*. Settings sat down there too,
  alone behind two dividers, rather than in the list of places to go.

  Sign-out is a labelled button now instead of a bare icon. An icon alone
  is a guess, and this is the one control nobody should have to guess at
  — it was reported as not working when it was both hard to find and, as
  above, a 404.


- **Two directories read `provisional · stale` on a service that was
  working.** The refresh lease was held for the whole refresh interval,
  so the lease and the ticker were the same length and beat against each
  other: a tick arriving a second before its predecessor's lease expired
  was refused, and the next chance came a whole interval later. The
  effective period doubled to thirty minutes — **exactly the freshness
  window** — so the snapshot aged out and every domain in it lost
  authority.

  The evidence was in the ages: two directories at 32 minutes, and a
  third that happened to miss the collision at 17. The lease now runs
  three quarters of the interval, which still refuses a replica whose
  turn comes a few minutes later and never refuses one ticking on
  schedule.

  **The start-up catch-up now refreshes what is DUE rather than what is
  already stale.** A fourteen-minute-old snapshot on a pod that has just
  replaced another used to wait a whole interval more, reaching
  twenty-nine minutes — one rollout short of provisional. A restart
  should not extend the schedule, and an afternoon of releases should
  not look like a directory going bad.

## v0.13.1

- **Sign-out did nothing, because nothing served `/logout`.** The
  console's button pointed there, the issuer answered 404, and the
  sign-in survived — reported as *"even sign-out button does not work"*,
  which it did not. The issuer serves `/logout` now: it ends the browser's
  sign-in, clears the cookie and lands on the signed-out page.

  `/logout` rather than pointing the console at `/end_session`, on Oleg's
  call and it is the right one: this is the address a person expects and
  types, `end_session` is a name from a specification, and the console
  could not supply the `id_token_hint` that endpoint wants anyway — it
  never redeems the code it gets back, so it holds no ID token. Both end
  the same thing.

- **The signed-out page stopped linking to a page that was deleted.** It
  sent people to `/account`, which went with INF-695. It now says what
  ending a sign-in does and does not reach, and points at the console's
  Sessions page for the rest.

- **`hack/conformance-drive.sh`** completes the browser half of a run
  without a browser. Nothing in that flow is JavaScript — a chain of
  redirects and one form POST — so it follows them with `curl` and signs
  in through recovery, which is a ServiceAccount token rather than a
  person at a Google prompt. It signs in fresh each time, because that is
  what the logout modules exist to check.

  It also treats `INTERRUPTED` as terminal. `conformance-run.sh` did not,
  which is why an alias conflict looked like a hang: **run one plan at a
  time**, because the suite serves every plan's callback under its alias
  and starting a test in a plan that shares one interrupts the running
  test.

## v0.13.0

- **Revoking every session left the sign-in standing.** Reported from the
  live console: *"I revoked all sessions, but still has access
  everywhere."* Every Revoke button sent a session id, and that path ends
  one session and nothing else — so a browser whose rows were all revoked
  kept its SSO session, the list emptied, and the next `/authorize`
  completed silently with no password. The half sign-out this design
  names twice, shipped in the console that was supposed to prevent it.

  The Sessions page now offers **signing the browser out** beside the
  rows, which ends the sign-in and every session under it. The rows keep
  their narrow meaning, because ending one session that is not the one
  you are using is a real thing to want.

  `RevokeSessionsRequest` gains `sso`, and it is checked against the
  identity before anything is ended — the permission check is against the
  identity the caller names, so without that an id alone would end
  somebody else's sign-in. Both properties have tests, and the first was
  verified to fail without the fix.

  **What this does not reach** is a relying party's own session. A console
  that ran its own flow holds its own cookie; `end_session` is
  front-channel and back-channel logout is not built, so Kargo answers
  until its own session expires however thoroughly you revoke here. Said
  plainly in `docs/design/access-roster.md` rather than left to be
  discovered twice.

- **`hack/conformance-run.sh` runs a whole plan.** The suite's page has no
  *run all* and Basic OP has thirty modules. It starts them in order,
  waits for each, prints the result, and names the URL to open for the
  ones that genuinely need a person at a sign-in. `--from` resumes after
  a failure rather than re-running what passed.

## v0.12.8

- **Filter rows stopped stepping sideways when they wrap.** MUI's
  `spacing` sets margins on children and `gap` does not, so a row that
  declared both wrapped with a stray indent on every line after the
  first — visible on the Sessions filters on a phone, and latent in three
  more rows. The rows that wrap now use `gap` alone.

## v0.12.7

- **Every filter on every page wraps now.** Provider groups was still
  scrolling 73px sideways on a phone after the first pass, because it had
  its own copy of the control. Rules and its proof simulator are on the
  shared one too, so there is one filter in the console rather than five
  spellings of one.

## v0.12.6

Found by signing in to the live console with a headless browser and
looking at every page at 1440px and at 390px.

- **The Overview stopped shouting.** "Needs attention" rendered one row
  per internal group that opens no client — **73 of them**, because the
  clusters and cloud accounts that will require those groups are Phase 2.
  A healthy installation read as a broken one, the page was 4832px tall,
  and the working state was pushed off the screen. Runs of the same
  finding now collapse into one row with a count once there are more than
  three: below that the names are the information, above it the count is.

- **The filters fitted on a phone.** A `ToggleButtonGroup` is a flex row
  that does not wrap, so twelve domains ran off the side of the screen
  and took the page's width with them — the People page scrolled 182px
  sideways and Provider groups 73px, with the filter itself unreachable.
  One shared `Facet` now wraps, and three pages that had hand-rolled the
  same control with slightly different spacing use it.

- **The account block stopped linking to a page that cannot exist.** A
  recovery sign-in has no address — it is a ServiceAccount the cluster
  vouched for — so the link went to an empty person page. It still says
  who is signed in, and shows the full subject on hover rather than its
  first twenty characters.

## v0.12.5

- **The conformance runbook was followed, and it was wrong twice**
  (INF-683). It told you to leave `requires` off the two temporary
  clients — the policy refuses a client that requires no group, so the
  render would have failed before a single test ran — and it gave their
  hostname without the port, which the render also refuses, because a row
  names one host and the redirects are on `:8443`. Both are fixed, and
  the page now records what the last run actually reported.

  **Config profile: PASSED against the merged service**, 34 checks, no
  failures and no warnings. The two attended profiles need a person at a
  browser and are the remaining gate.


- **The documentation describes what ships** (INF-698). The sweep found
  seven Go symbols the guides promised and the module does not export —
  `identity.NewIssuerVerifier`, `identity.ClusterConfig`,
  `identity.ServiceAccountRef`, a `directory` package, an `authz`
  package — every one written down as though it shipped. A stranger
  following `docs/connect/console-app.md` or `service-to-service.md`
  could not have compiled what they were told to write.

  `just check` now asks the compiler: `hack/check-docs-symbols.py` runs
  `go doc` for every `identity.`/`tokens.`/`policy.` name the docs use,
  and fails on one that does not exist. Nothing compiles a code block in
  a Markdown file, which is why this drifted in silence.

- **`docs/integrations.md` stopped carrying a banner saying it was
  wrong.** Cases ④, ④b and ⑤ described the two-service shape; ④ is now a
  workload proven against its own cluster's published key set, ⑤ is a
  function call, and ④b is gone with the listener it described. The
  two-anchor summary was rewritten too: recovery alone stands on the
  cluster now.

- **`docs/connect/console-app.md` covers both console shapes** — a proxy
  in front, or its own flow — and says which is which, with the real
  `identity.Middleware`/`identity.Require` rather than a package that was
  never built. It also warns against registering a sign-out landing page
  as a redirect, which is the trap the cutover hit.

- The install line for the TypeScript package named a tag from eight
  releases ago.

## v0.12.4

- **The console says `access-roster`.** It said `directory-roster`, which
  was the name of a service that no longer exists, and the wording around
  it still called this "the hub" — a word that meant something only while
  there were two services. The provider pages, the setup steps and the
  settings hints say `access-roster` now.

- **The Sessions page is a table.** Four facts per session were stacked
  into one caption line, so a page that can hold a hundred rows used a
  third of its width and lined up none of its columns: a reader scanning
  for *whose session expires soonest* had to read every line. It is now
  Person, Client, Way in, Browser, Opened, Last used, Expires, with a
  facet for the way in that offers only the ways actually present.

  **The browser grouping became a column** rather than a run of
  subheadings. Two rows carrying the same mark came from one browser, and
  a blank is a session with no browser behind it at all — which is what a
  token exchange is. A column can be compared down the page, which is the
  one thing a subheading cannot.

  The grouped list stays for a person's page and a client's page, where
  it sits in a narrow column, holds three rows, and the grouping is the
  point.

## v0.12.3

- **The Sessions page came back.** It vanished at the cutover, silently:
  the console learned where its issuer was from the FORWARDED bearer's
  issuer, which the proxy in front configured, and on one origin there is
  no proxy. An empty issuer reads as *there is no issuer to talk to*, so
  the console hid the Sessions page and the sessions section of a
  person's page — on exactly the deployment where they work best, since
  the call is now same-origin and carries the browser's own SSO cookie.

  The merged process now tells the console its own issuer URL, the same
  way it already hands over the session reader and the sign-in entry.
  Nothing failed and nothing was logged, so the test asserts `whoami`
  reports an issuer and fails without the wiring.

- **The Providers page filters by provider and by state.** The state
  facet offers only the states actually present, so it never shows a
  button that returns nothing — and one function decides a domain's state
  for both the chip and the filter, because two would drift.

- **The People page's domain filter lists only served domains.** A
  provider discovers every domain its tenant owns, most of them parked;
  offering eleven when three can hold an account made the filter mostly
  buttons that return nothing, and hid the ones that work among them.


- **`hack/cutover-cleanup.sh`**, for the two messes the INF-691 cutover
  leaves that will not resolve on their own.

  A **stuck ValkeyCluster**: the retired store was pruned with foreground
  propagation, so it waits for its dependents while the Valkey operator
  keeps recreating them. The tell is that its pod, StatefulSet and
  Service are a few seconds old however long you watch.

  And **orphans**: the two retired Applications were pruned without a
  cascade, so everything they owned still runs with a tracking-id naming
  an Application that no longer exists. Nothing owns them, so nothing
  will ever prune them — and an orphaned HTTPRoute still competes for its
  hostname.

  It refuses to run unless hubble's session store and the workspace
  records are both present, because those are what must survive, and it
  names every object rather than selecting by label: a selector here
  would also match what the service itself wrote.

  **In the event neither was needed.** ArgoCD finished the cascade on its
  own a few minutes later and the operator let the store go. The script
  stays because the state it describes is real, was live for about twenty
  minutes, and is not something to diagnose a second time from scratch —
  and because next time it may not resolve itself.

## v0.12.2

- **`console.mount` accepts `/console/` as well as `/console`.** The
  chart matched the trailing-slash spelling exactly and then redirected
  it to `/console//`, a path the console does not serve — from a value
  nothing rejects, because both are legal strings. Our own configuration
  writes it both ways: a declared client carries `prefix: /console` and
  `mount: /console/`. The Go side already trimmed it; now the chart does
  too, and `just check` renders both spellings and diffs them.

  Found while pointing the live gitops values at the merged chart, which
  is exactly where it would have bitten.

# Changelog

One line per release; full detail lives in the release notes and the
git history.

## v0.12.1

- **The v0.12.0 release published nothing**, and the reason is the one
  this repository's own release config warns about: release machinery is
  exercised only by a tag. `accessctl` is the single binary built for
  Windows, so in one shared archive the Windows download held one binary
  where every other held four, and goreleaser refuses that — four minutes
  into the tagged run, after every cross-compile had already succeeded.

  `accessctl` now has its own archive, zipped on Windows as that platform
  expects, which is also the better shape: it is the one thing here that
  runs on somebody's own laptop.

  And `just check` now proves every archive is uniform across its
  platforms by reading the same file goreleaser reads. Neither
  `goreleaser check` nor `build --single-target` reaches the archives
  stage, which is why nothing caught this.


- **A session cookie is marked `Secure` by default**, decided by the
  scheme of the service's own public URL rather than by a flag that
  defaults to off. It used to default to off, so an installation that
  simply did not set `SECURE_COOKIES` served its session cookie without
  the flag and a proxy could carry it over a plain-http hop. The chart
  always set it, which is why nothing was wrong in our own deployments
  and why the alert CodeQL raised was about the default rather than
  about any line it pointed at.

  `SECURE_COOKIES` still overrides in both directions, for a TLS
  terminator the URL does not mention.


- **The Action's own comment was an expression.** GitHub evaluates
  `${{ ... }}` anywhere inside a `run:` block, including in a shell
  comment, because the block is a string value before it is a script.
  A comment added in v0.12.0 to explain which inputs are untrusted named
  an event expression literally, so every run of the action would have
  expanded it. Found by CodeQL, which was right to call it code
  injection. **v0.12.0's action is broken; use this.**

- **What reaches `GITHUB_ENV` is now the profile name this run wrote**,
  not the input that selected it. The check against the written list was
  already there, but passing the input through meant the value's shape
  still came from the workflow. A name built here is `role@account` from
  an audience whose whitespace was stripped, so it cannot carry the
  newline that would declare extra environment variables.

## v0.12.0

- **The GitHub Action's `default-profile` is checked against the profiles
  the run actually wrote.** It reached `GITHUB_ENV`, so a newline in it
  declared arbitrary environment variables for every later step of the
  job — the input is trusted only as far as whoever wrote the workflow,
  and an expression like `${{ github.event.* }}` is not trusted at all.
  Found by CodeQL. Checking it against what was written closes that and
  also catches a name that is simply a typo, which would otherwise
  surface as an AWS error three steps later about a profile that does
  not exist.

- **The GitHub Action** (INF-649, the other half). One action at the
  repository root, `curl` and `jq` and two files: nothing of ours is
  downloaded into a job, and there is no version of ours to bump when
  Amazon's tooling moves. One exchange per audience, a profile per
  `aws:<account>:<role>` with `web_identity_token_file`, a kubeconfig
  context per `k8s:<cluster>`, and every token masked before it is
  written anywhere.

  Exercised end to end against a stand-in for GitHub's id-token service
  and the issuer, which found the bug that would have hurt: `printf '%s'`
  leaves the last line unterminated and `read` drops it, so **the final
  audience of every job was silently discarded** — surfacing as a missing
  profile rather than an error.

- **`accessctl`** (INF-649, the CLI half). `login` runs the browser flow
  once — authorization code with PKCE on a loopback port, the only
  browser flow left since the device flow was withdrawn — and caches the
  refresh token in a 0600 file. Everything else shares that cache:
  `whoami`, `kubeconfig`, `aws-config`, `setup`, `exchange`, and the two
  credential helpers `kube-token` and `aws` that kubectl and the AWS SDKs
  run themselves.

  It writes into two files that belong to somebody else, so it is careful
  about both. The kubeconfig goes through `kubectl config` rather than
  being rewritten, because a person's other contexts are none of this
  tool's business. The AWS config is rewritten only between two markers,
  so a profile for a role somebody no longer holds does not survive as an
  entry that fails when used, and nothing outside the block is touched.

  Exit codes are a contract: 2 usage, 3 not signed in, 4 audience not
  granted, 5 issuer unreachable — so a wrapper can tell *sign in again*
  from *the issuer is down*, and knows not to retry a refusal.

- **A public `tokens` package**: the RFC 8693 exchange, and the two
  envelopes a credential helper has to speak. It is what `accessctl`
  will run on and what a workload can use directly.

  The exchange presents its client in HTTP Basic, because the library on
  the other side reads it from Basic alone and a posted `client_id` is
  refused with an error naming the client rather than the mistake. A
  refusal carries the issuer's own sentence — which audience, and which
  groups the proof holds — since that is the whole value of the error in
  a build log.

  `WriteExecCredential` answers whichever apiVersion kubectl asked for,
  and carries the expiry so kubectl caches instead of running the plugin
  on every API call. `WriteCredentialProcess` writes real STS
  credentials with `Version` as the **number** 1, and
  `AssumeRoleWithWebIdentity` obtains them — unsigned, which is why the
  AWS path needs no stored key: the token is the proof and the account's
  trust policy decides what it opens.

- **A public `identity` package, and access-roster uses it** (INF-648, the
  Go half). Two verifiers, one per anchor: `Issuer` for a token this
  installation signed, `Cluster` for a ServiceAccount token from the pod
  next door. Both yield one `Verified`, so a handler never learns which
  anchor proved the caller and cannot come to depend on it — the right
  anchor is decided by how far away the caller is, and that can change
  without the handler. No group re-mapping anywhere: the name in the
  policy is the name in the token is the name in the role check.

  With a `net/http` adapter: `Middleware` establishes the caller and
  passes the request on, because a listener serves pages that run before
  anybody is established; `Require` is what refuses, and never names the
  group that would have worked. `WhoAmI` answers rather than refuses when
  nobody is signed in, because that is something a console has to render.

  `Cluster` takes a review function rather than building one, so a
  consumer that only needs the issuer does not inherit Kubernetes client
  libraries.

  **The service consumes it.** `internal/server/forwarded.go` is now a
  thin adapter over `identity.Issuer` instead of a copy of the same
  verification. Doing that caught a narrowing: the lifted reader matched
  `Bearer ` exactly, and RFC 6750 makes the scheme case-insensitive —
  real clients send both spellings, and a caller that had done nothing
  wrong would have been refused.

- **GitHub team bindings are a table in the policy** (INF-696, the
  access-roster half). `github: <org>: <team>: [provider groups]`, read
  exactly like a group's `members`: the people the directory puts in
  those groups are the people that team should contain. It grants
  nothing here and appears in no token — a controller reads it and makes
  the organisation match — and it lives in this file for one reason, that
  a reader of the access model sees every team's source without opening
  another file.

  The console's Rules page lists them beside the rest with the same
  *depends on* column. They feed a team rather than an internal group, so
  they open no client and the page says so. A team fed by an empty list
  is refused, because "remove everyone from platform" is not something to
  express by leaving a list out; the same team declared in two merged
  files is refused too, because the second would silently replace the
  first.

  The controller, the read-only GitHub page and the directory endpoint it
  authenticates against are the other three parts of INF-696 and wait for
  github-roster.

- **The console signs people in as a client of the issuer** (INF-701),
  which is what makes one binary mean one door. Somebody with no session
  is sent to `/authorize` with the console's declared client, signs in at
  the issuer's page, and comes back with the issuer's session set. No
  proxy in front of the console running an OpenID flow against a service
  in the same process, and no login of the console's own.

  The code that comes back is never redeemed: what the console needed was
  the session, not a token, and it reads the directory and the policy in
  this same process. It is stripped from the URL so it reaches no
  bookmark and no referrer. Set `console.client` to a declared client
  whose redirects name this origin plus the mount; empty keeps the
  console's own page.

- **The console gets its own HTTPRoute**, and that is not tidiness. A
  gateway policy attaches to a *route*, so anything put in front of the
  console on a shared route would also sit in front of `/token`, `/keys`
  and discovery — every relying party in the estate asked to sign in to
  fetch a key set. It renders whether or not anything attaches to it,
  because discovering at cutover that there is nothing to attach to
  leaves only that bad option. The prefix is deliberately not rewritten
  away: the service strips it itself, so a gateway that stripped it too
  would hand the console a path it never serves.

- **The console admits whoever the issuer signed in.** One origin and one
  process, so the browser's issuer session is read directly rather than
  being relayed. Before this, a console on the issuer's own host was
  authenticated either by a proxy — which ran an OpenID flow against a
  service in the same process, a network round trip and a second session
  store to learn something already known — or by a login of its own,
  which is the second door an installation with a gateway deliberately
  turns off.

  It does **not** remove the need for a way to *start* a sign-in. A
  person arriving with no session anywhere still needs one, and the
  console's own login or a proxy in front of it is still what provides
  that. What this removes is the second session for a person who already
  signed in somewhere behind this issuer.

- **An installation that signs nobody in yet still serves its sessions.**
  The handler returned early on "no sign-in providers" and took the
  session service and the signed-out page with it. The posture where that
  bites is day one: recovery is available with no OAuth client configured
  — that is the whole point of it, the way in before any directory is
  connected — and a recovery sign-in opens a session like any other. An
  operator who had just recovered could not then list or revoke anything.
  The same mistake, in a new shape, as gating the session service on
  `console.origin` once did.

- **The endpoint reference no longer promises two endpoints that do not
  exist.** `/.access/grants` and `/.access/simulate` were listed as
  served. Neither is implemented; both belong to `accessctl` (INF-649),
  and the table now says so and names what answers the same question
  today.

- **A workload's cluster survives the exchange.** The verified proof
  travels through the OpenID library as a map of claims and is rebuilt on
  the other side, and the cluster was not among them — so it was dropped
  in silence. Two halves of that loss: the subject stopped naming the
  cluster, and the same namespace and name exist on every cluster, so two
  different machines became one `sub` — exactly the collision the
  qualifier exists to prevent. And a `service_account` matcher narrowed
  to one cluster was compared against an empty string, so it matched
  nothing at all and an operator would see a rule granting nothing with
  no reason visible.

  It predates the federation work — the qualifier never reached a token
  through exchange — but federation is what makes it reachable, because
  until now there was one cluster.

- **Both halves of the merged service act on one policy**, loaded once
  and handed to the issuer rather than loaded twice. They read the same
  file in a real deployment, so the disagreement stayed hidden — but
  their fallbacks differ, and two halves that *can* disagree about the
  policy is exactly the class of failure the merge existed to end. Found
  by booting the merged binary: with `DEMO=1` the directory half built a
  demonstration policy and the issuer half refused to start on an empty
  `POLICY_DIR`.

- **One design document.** `docs/design/hub.md` and
  `docs/design/access-issuer.md` fold into
  `docs/design/access-roster.md` — the directory model, freshness, the
  policy, the three proofs, the six grants, sessions and one origin, the
  console, the store, recovery, failure semantics — and end with an
  appendix naming everything that was removed and why, so nobody adds one
  back without a reason. `architecture.md` loses its two-services banner
  and draws one container. The README no longer promises a merge that has
  happened.

  `integrations.md` carries a note on the three cases that describe the
  old shape; it is rewritten with the rest of the documentation at 1.0.

- **The console reads.** It no longer writes who is in which internal
  group (INF-694). A console that could add a membership was a second
  source of truth beside git and a merge layer to reconcile them; who is
  in a group is now the policy, rendered from the installation's own
  access model, and `git log` is the complete history of access. Gone:
  the `memberships` table (refused now, not ignored), the console layer
  of the policy, the `layer` field on every member, and `SetOAuthClient`
  — the OAuth client is a Secret, delivered the way every other
  credential in the estate is.

  Kept, and each for a stated reason: **connect a provider** by admin
  consent, because Google's consent genuinely needs a browser and there
  is no infrastructure-as-code way to obtain that credential; and
  **revoke a session**, which is a removal and the lever between
  sign-out and expiry.

  Nothing was lost in the change: no installation had ever attached a
  membership through the console. Still to come under the same ticket:
  a provider's `serve` and `synced` are chosen in the console today, and
  become values once the values can name a consent-connected provider.

- **The issuer's UI is the login page.** `/account` — a person's own
  sessions and *sign out everywhere* — was server-rendered by the issuer
  because it had to be same-origin with the session service (INF-695).
  The console is same-origin and, since the merge, the same process, and
  its page for a person already shows both. Two pages showing one thing
  is two things to keep true of each other, so the issuer's is deleted
  and the address redirects into the console. The two POSTs behind it go
  with it: an endpoint that answers after the page using it is deleted is
  surface nobody is keeping honest.

  What the issuer still renders is `/login` and `/signed-out`, and both
  stay for the same reason: each runs before there is anyone to
  authorize, so neither can be a console page.

- **One issuer, many clusters, access to none of them.** A workload's
  ServiceAccount token is verified against the key set its own cluster
  publishes, never by asking the cluster (INF-692). Asking meant a
  TokenReview, and a TokenReview against a cluster elsewhere meant holding
  a kubeconfig for it — inside the service whose whole design is to hold
  almost no credential. A key set is public: EKS publishes one per cluster
  (it is what IRSA rests on) and Talos serves the same keys at the API
  server's `/openid/v1/jwks`. So a remote cluster's workload proves itself
  exactly the way a GitHub job does, and connecting one is a row of
  `exchange.clusters` naming a URL.

  This service's own cluster is a row like any other. There is no special
  case for it, because a special case is a second code path that only one
  installation exercises. The TokenReview verifier is deleted, and the
  cluster-scoped permission the chart creates now belongs to recovery
  alone — on the day everything else is broken it should depend on
  nothing but the API server.

  What this gives up, plainly: a TokenReview notices a deleted
  ServiceAccount and a key set does not, so a token stays usable until it
  expires. Bound tokens are short-lived, so the window is minutes.

- **Six grants, and the four that were served are gone.** The issuer
  serves the code flow with PKCE, refresh, userinfo, `end_session`,
  revocation and token exchange, and nothing else (INF-693). The device
  flow is for a machine with no browser, and both headless cases here — a
  CI job and a workload — are token exchange. Client credentials is a
  machine with a stored secret, which is the thing this design exists not
  to have. JWT bearer is token exchange with a different spelling.
  Introspection never applied: these are JWTs, verified offline against
  the key set.

  Withdrawn from discovery *and* from the storage, which is the part that
  matters. The device flow stops working because nothing implements the
  library's device interface any more, so there is no device state kept
  and no way for a code to be stored by something that changed its mind.
  A test asserts each withdrawn grant is refused at `/token`, because an
  endpoint that answers after its metadata stops mentioning it is the
  failure that hides.

  `grant_types_supported` prints three, not six: three of the six are
  grants and three are endpoints, which discovery advertises in fields of
  their own. Listing an endpoint as a grant type would be the metadata
  lying in a new way.

- **One service.** The directory hub and the issuer are one process
  (INF-691). The issuer asks the directory by calling a function instead
  of dialling a service, so a login now makes no network call except to
  the corporate directory: gone from every single sign-in are a
  ConnectRPC round trip, a TokenReview, a NetworkPolicy hop, and the
  class of failure where the two halves disagree about the same person.
  The console is served on the issuer's own origin under `/console/`,
  which is what lets its session pages use the browser's cookie with no
  bearer in JavaScript, and one `/readyz` answers for both stores. The
  split was built so that several things could ask the directory; the
  issuer became its only consumer, and the endpoint comes back on the
  merged service when the GitHub controller needs it.

  The console is now told where it sits, because a prefix that used to be
  stripped by the gateway also has to appear in every link the console
  hands a browser: `/login` resolves against the origin, where the
  issuer's page is.

  The `access-issuer` chart renders the whole of it: `directory.*` for the
  workspaces and their freshness, `console.mount` for where the console
  sits, a namespaced Role for the store, and no projected token for a hub
  nobody dials. `hub.address` is gone. The `directory-roster` chart and
  binary still ship unchanged, so an installation moves when it chooses
  and can move back; they go once nothing points at them.

  **Moving an installation is not only a chart switch.** What an operator
  connected — the workspace records and their credentials — lives as
  ConfigMaps and Secrets in the namespace the hub ran in. Copy them into
  the issuer's namespace before the cutover, or the new pod starts with no
  directories connected.

- **The console says *provider*, and the tables split domain out.** What
  the code calls a workspace the console now calls a **provider**, and
  the groups it holds **provider groups**; both sides of the rail then
  say simply *Groups*, and the heading above each — *Where people come
  from*, *Internal* — tells them apart, so the reader no longer carries
  a qualifier down every page. Providers list one row per *(provider,
  domain)* pair rather than stacking domains inside a cell, because the
  row is the unit a reader compares. Groups gain filters by provider and
  by domain; People gains a **Domain** column and a domain filter, and
  that one is applied by the hub (`SearchPeopleRequest.domain`) rather
  than over the page the console received — this list is capped at 200,
  and narrowing it in the browser would answer *nobody* while the
  snapshot holds hundreds. URLs and the API keep the old words, so
  nothing bookmarked or scripted moves.

- **A moved Valkey no longer needs a human.** On 2026-09-10 a Valkey pod
  was rescheduled onto a new address; the issuer and hubble's proxy went
  on dialling the old one for half an hour, reported **Ready**
  throughout, and had to be restarted by hand. Three things were wrong
  and all three are fixed. **Cluster mode is off by default**: with one
  shard it makes the client learn node addresses from `CLUSTER SLOTS`
  and talk to those, bypassing the Kubernetes Service — the one
  mechanism whose whole job is to survive a pod moving. **Readiness now
  follows the shared store** and liveness deliberately does not, so a
  replica that cannot reach it leaves the gateway's rotation and answers
  fast instead of hanging, while one blip cannot restart the fleet; the
  refusal names the dependency and the reason. And **a test proves the
  recovery** rather than assuming it: stop the server, start it again,
  and the client must work without being reconstructed. It recovers in
  about two seconds.

## v0.11.0

- **The documentation is rewritten around what the product is.** The
  README opens with the idea in three sentences and the niche in one
  table: dex is the right shape and stops one step short of knowing
  anyone's groups; the heavy providers can do all of it at the cost of
  running an identity product to use a fifth of one. `architecture.md`
  is a third of its length, draws the live two-service shape honestly
  and names the merge that follows; `why.md` carries the seven problems
  and seven principles and nothing the README already says. Seven
  decisions taken 2026-09-10 are recorded where they land — one
  service (INF-691), machines by a federated key set with token exchange
  as the one machine grant (INF-692), six grants (INF-693), a read-only
  console (INF-694), the login page as the issuer's only UI (INF-695) —
  and the two design documents carry a banner saying which of their
  sections are current and which are history. No code changes.

## v0.10.0

- **A runbook for the conformance run.** `docs/operations/conformance.md`:
  the suite from published images so there is no Java build, the Config
  profile as a script that needs no client and no browser, and the two
  attended profiles as a checklist — including the two temporary clients
  they need and the step to remove them afterwards, which is the one
  that gets forgotten.

- **A refused bearer at `/userinfo` now carries a challenge.** RFC 6750
  requires a `WWW-Authenticate` header on a 401 from a bearer-protected
  endpoint; the library answers an unusable access token with a bare
  error and no challenge, which is the one shape a conforming client
  cannot act on — it is told it is unauthenticated and not told what
  would fix it, so a client library reports a transport failure or
  retries the same token for ever. Found by the conformance work
  (INF-683), fixed in a wrapper because the header has to be set before
  the status is.

- **The API listener's consumers hold a grant.** Admission and
  authorization were one decision: a consumer admitted at all could
  enumerate every group of every company the hub reads. One consumer —
  the issuer — needs exactly that; a team-sync or a cross-cluster hook
  needs one directory and one question. A consumer is now declared with
  a grant along three axes — which directory (`workspaces` or `domains`),
  which `groups`, which `reads` (`resolve`, `groups`, `describe`,
  `probe`). No grant is full read, so nothing declared before this
  changes meaning. Outside the grant answers exactly as an unserved
  domain does, because a refusal would confirm what the grant withholds;
  `Describe` lists only granted domains, so discovery is scoped too; and
  the listener stays read-only whatever a grant says. **Breaking for a
  hub configured by environment alone:** `API_CONSUMERS` is gone and
  consumers are declared in a mounted file, because a grant does not fit
  in a comma-separated list in any spelling an operator could read. The
  chart renders and mounts it from the same `consumers[]` values.

- **The console's Matchers page becomes Rules.** It listed only
  rules that admit a proof by its *shape* and silently omitted those that
  admit by directory membership — 30 of 73 groups on the first real
  installation — so filtering it by a cluster role returned nothing and
  read as missing data rather than as the wrong page. How a rule is
  evaluated is a property to show in a column, not a reason to split the
  answer: a membership rule needs the directory to vouch and degrades to
  the hold window when it cannot; a matcher needs only the proof, which
  is why recovery is one. The page now shows every rule that puts an
  identity into an internal group, adds a **directory group** tab and a
  **depends on** column, and its group filter answers for all 73 groups
  rather than 30. `#/matchers` still resolves, so a bookmark does not
  land on the overview. The policy's `matchers:` field is unchanged, and
  People, Directory groups and Internal groups are untouched: they answer
  the same graph identity-first, source-first and target-first, and Rules
  is the fourth direction rather than a replacement for any of them.

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
