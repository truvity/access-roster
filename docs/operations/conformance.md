# The conformance run

access-issuer claims four OpenID Foundation profiles, and the claim is
worth exactly what the suite says about it. This is how to run it.

> The exit criterion for `v1.0.0` is a green run of all four
> (INF-683). One of them runs unattended; three need a person at a
> browser, because the whole point of them is that a person signs in.

| profile | plan | attended |
| -- | -- | -- |
| Config | `oidcc-config-certification-test-plan` | no |
| Basic OP | `oidcc-basic-certification-test-plan` | yes |
| RP-Initiated Logout | `oidcc-rp-initiated-logout-certification-test-plan` | yes |
| Back-Channel Logout | `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | yes |

**Why the fourth exists.** The Foundation does not certify RP-Initiated
Logout on its own: a logout certification is RP-Initiated **plus at
least one** of Session Management, Front-Channel or Back-Channel. We
serve Back-Channel and only Back-Channel, for reasons that are about
what a browser will actually do rather than about effort — see
[the design note](../design/access-roster.md#telling-the-relying-party-back-channel-logout). So this pair is the
smallest set that can be submitted, and neither half counts alone.


## When to run it

**At every major and minor release**, by a person, as a whole: all three
profiles, including the steps the suite hands to a human. Not on a
schedule, and not in CI.

It used to run the Config profile daily and nothing else. That is worse
than no check, because one profile passing daily reads as "conformance
passes" while the two that actually sign somebody in have not been run
for weeks — and those two are where every defect has been. The Config
workflow is still there for a single click
([.github/workflows/conformance.yaml](../../.github/workflows/conformance.yaml)),
because it needs no credential and guards the discovery document, which
changes silently when a provider option changes.

A patch release does not need a run. A patch that touches the issuing
path is not a patch.

The run is not done until every module is **PASSED, REVIEW, WARNING or
SKIPPED** — the Foundation's rule is that only FAILED and INTERRUPTED
disqualify a profile — and until somebody has *looked at* the evidence
attached to each REVIEW, which is a screenshot of a page. A REVIEW whose
screenshot shows the wrong page is a failure that the suite cannot see.

## The suite

**It runs in the cluster**, from the Foundation's published image, and
it exists exactly while the conformance client rows are declared: the
two rows in gitops' `cfg/access.yaml` render the suite with them
(`stacks/identity`, namespace `conformance`), and removing the rows
removes the suite. One thing to add for a run, one thing to take out.

Why in the cluster and not on a laptop, where it used to run at
`localhost.emobix.co.uk`. Three of the four plans are driven by a
browser and work against an issuer anywhere. The fourth, Back-Channel
Logout, is the one place the **issuer has to reach the suite**: a logout
token is a server-to-server POST, and a name that resolves to
`127.0.0.1` is, from the pod, the pod's own loopback. Pods cannot reach
the tailnet either. So the suite has a kernel hostname like every other
console, and the issuer reaches it through the same edge with a
certificate it already verifies.

Only the relying-party half is published at that name — `/test/` (the
callback, the post-logout landing page, the back-channel endpoint) and
the two static paths the callback page loads. The **control plane** —
the UI, the API that creates plans and reads results, the stored client
secrets — is on the ClusterIP only, because the suite's developer
profile has no login of its own. Reach it over the tailnet:

```bash
S=http://$(kubectl -n conformance get svc conformance-suite -o jsonpath='{.spec.clusterIP}'):8080
H='X-Forwarded-Proto: https'
curl -s -H "$H" "$S/api/runner/available"   # 200 once it is up; the first start takes a minute
```

**Every call carries that header.** The suite refuses a request that
does not claim to have arrived over HTTPS — its own nginx normally says
so — and at the ClusterIP there is no nginx. The drivers add it
themselves; a hand-typed `curl` has to.

Everything below drives it over that API, so a run is a script and not a
sequence of clicks. The drivers take the address as `SUITE=$S`. The
suite's own pages (`plan-detail.html`, `log-detail.html`) are at the
same address; the public hostname answers them with nothing, and that
is the point.

## Config — unattended

Needs no client and no browser: it reads the discovery document and the
key set, and checks them against the specification.

```bash
S=http://$(kubectl -n conformance get svc conformance-suite -o jsonpath='{.spec.clusterIP}'):8080; H='X-Forwarded-Proto: https'
cat > config.json <<'JSON'
{
  "alias": "access-issuer-config",
  "description": "access-issuer — Config profile",
  "server": { "discoveryUrl": "https://access.truvity.xyz/.well-known/openid-configuration" },
  "client": { "client_id": "conformance", "client_secret": "unused-here" }
}
JSON

PLAN=$(curl -s -H "$H" -X POST "$S/api/plan?planName=oidcc-config-certification-test-plan" \
  -H 'Content-Type: application/json' --data-binary @config.json | jq -r .id)
TEST=$(curl -s -H "$H" -X POST "$S/api/runner?test=oidcc-discovery-endpoint-verification&plan=$PLAN" | jq -r .id)
curl -s -H "$H" "$S/api/info/$TEST" | jq '{status, result}'
```

Change the discovery URL to point at whichever installation is under
test. Nothing about this run touches the installation's configuration.

**Last run: 2026-09-12 against `access.truvity.xyz` at 0.17.0 —
FINISHED / PASSED.** Discovery now also advertises
`backchannel_logout_supported` and `backchannel_logout_session_supported`,
both `true`, which the Back-Channel plan's own discovery module checks. Worth repeating after anything that changes discovery, since
that is the whole of what it reads.

## Basic OP and RP-Initiated Logout — attended

These sign somebody in, so they need clients at the issuer and a person
to complete the flow at the provider.

### 1. Declare the clients

The plans want **three** client slots and they map onto **two** clients:

| slot | what it is |
| -- | -- |
| `client` | the primary client, authenticating with `client_secret_basic` |
| `client_secret_post` | the same client again — the library takes the credential from the Basic header *or* the form, so one confidential client serves both |
| `client2` | a second client, for the tests that check a code issued to one cannot be redeemed by another |

They are ordinary declared rows (INF-688) in the estate's access matrix,
under `roster.clients`, and they are **temporary**: add them for the run
and take them out afterwards. A standing client whose only purpose was a
certification is surface with no consumer.

```yaml
  - name: conformance
    # The suite's own hostname. Every path below is host-relative, so
    # this one name is the redirect the issuer accepts, the landing
    # page, the back-channel URL and the BASE_URL the suite starts with.
    hostname: conformance.kernel.truvity.xyz
    redirects:  [/test/a/access-issuer/callback]
    signed_out: [/test/a/access-issuer/post_logout_redirect]
    # Only the Back-Channel plan reads this, and without it every module
    # of that plan waits for a logout token that is never sent.
    backchannel_logout: /test/a/access-issuer/backchannel_logout
    requires: [all:access-roster:viewer]
  - name: conformance-2
    hostname: conformance.kernel.truvity.xyz
    redirects:  [/test/a/access-issuer/callback]
    signed_out: [/test/a/access-issuer/post_logout_redirect]
    backchannel_logout: /test/a/access-issuer/backchannel_logout
    requires: [all:access-roster:viewer]
```

The alias in those paths (`access-issuer`) has to match the `alias` in
the test configuration below — the suite serves each test plan's
callback under its own alias, and a mismatch reads as the issuer
refusing the redirect. The hostname is also what the suite is started
with, so a run needs no hand-kept agreement between three places: the
`hostname` here is read by the chart that renders the suite.

**`requires` is mandatory** and these are no exception: the policy
refuses to load a client that requires no group, with *"client
%q requires no group, so nobody may use it"*. An earlier version of this
page said to leave it off, which would have failed the render before a
single test ran.

Name a group the person running the suite already holds.
`all:access-roster:viewer` is the bootstrap matcher that admits the
`truvity.com` domain, so it is the smallest thing that works here — the
tests sign in as a real person, and that person has to be admitted like
any other.

### 2. Read the secrets

They are generated in the cluster and never leave it, which is the
point. Read them at the moment you need them, and do not put them in a
file that outlives the run:

```bash
kubectl -n access-issuer get secret conformance-client \
  -o jsonpath='{.data.client-secret}' | base64 -d
```

### 3. Configure and run

```bash
S=http://$(kubectl -n conformance get svc conformance-suite -o jsonpath='{.spec.clusterIP}'):8080; H='X-Forwarded-Proto: https'
cat > basic.json <<JSON
{
  "alias": "access-issuer",
  "description": "access-issuer — Basic OP",
  "server": { "discoveryUrl": "https://access.truvity.xyz/.well-known/openid-configuration" },
  "client":  { "client_id": "conformance",   "client_secret": "$FIRST_SECRET" },
  "client2": { "client_id": "conformance-2", "client_secret": "$SECOND_SECRET" },
  "client_secret_post": { "client_id": "conformance", "client_secret": "$FIRST_SECRET" }
}
JSON

curl -s -H "$H" -X POST "$S/api/plan?planName=oidcc-basic-certification-test-plan&variant=%7B%22server_metadata%22%3A%22discovery%22%2C%22client_registration%22%3A%22static_client%22%7D" \
  -H 'Content-Type: application/json' --data-binary @basic.json | jq -r .id
```

Then run every module of the plan in order:

```bash
hack/conformance_drive.py <plan-id>
```

**In headless Chrome, and it has to be a browser**, with `SUITE=$S` so
the driver's API calls go to the ClusterIP while the browser follows the
suite's public callbacks. The suite's callback
is an HTML page that posts the result back with JavaScript: `curl`
follows every redirect, reaches that page, never runs it, and the module
sits in WAITING while the authorization it was waiting for has already
succeeded. That reads as a hang, and it is why a plan can show a row of
grey boxes with nothing obviously wrong.

Signing in is RECOVERY rather than a person at a Google prompt, which is
what makes thirty modules unattended — and which **changes what some of
them prove**, see below.

The suite's own page has no *run all* — each module is a separate click,
and Basic OP has thirty of them. The script starts them in order, waits
for each, and prints the result, so the clicking that is left is only the
part that needs a person. A module waiting for a sign-in says so with the
URL to open; `--from <module>` resumes after a failure instead of
re-running what already passed.

**Screenshots are answered too.** Eight of the eleven RP-Initiated Logout
modules end at a page the suite cannot see: the issuer must REFUSE, so
there is no redirect back and no callback. The suite asks a human to
upload a screenshot of that page and waits. Unanswered, the module sits
in WAITING until the next one interrupts it — which is what a row of
eight greyed-out logout results was, and it was a step nobody had
performed rather than a server fault. The driver takes the screenshot
from the browser it is already driving and uploads it, then marks the URL
visited so the suite stops waiting for a callback that is not coming.

A FRESH BROWSER is started for each module, because several of them say
so in as many words: *"please remove any cookies you may have received
from the OpenID Provider before proceeding"*. Without it the driver
carries one sign-in through the whole plan, and
`oidcc-prompt-none-not-logged-in` fails — the issuer is asked whether
anybody is signed in, a live session says yes, and it completes silently,
which is correct behaviour being recorded as a defect.

*When* it takes that shot is the whole of it. The suite logs the review
step BEFORE it hands the browser the end_session URL, so a driver that
uploads the moment the placeholder appears photographs the suite's own
"processing response" page — eight identical screenshots of the wrong
thing, uploaded successfully. Every one of these steps ends on a page the
ISSUER served, so that is the test the driver applies before shooting.

And *which page* is the other half. Two shapes of step, and they want
opposite things. The logout steps end ON the page in question and the
browser stays there. The re-authentication steps — `oidcc-prompt-login`
and `oidcc-max-age-1` — want the login prompt shown during the **second**
authorization, which is a page the driver fills in and leaves; by the
time the placeholder is logged the browser is back on the suite's
callback. So every issuer page passed through is photographed on the way,
and the latest one answers.

These finish as **REVIEW**, which is not a failure: it is the suite saying
a human must look at the evidence. The evidence is attached, and signing
it off is a person's job at certification time.

**`KUBECTL`** overrides how the driver runs kubectl, for the case where
reaching the cluster needs more than the binary — a context that
authenticates through OIDC needs the `kubectl-oidc_login` credential
plugin on PATH, and kubectl only says so once its cached token expires,
which is a plan that runs for ten minutes and then dies in the middle.

Or open the suite's own pages at `$S` over the tailnet, find the plan,
and run its modules by hand.

### What a recovery sign-in cannot prove

A recovery subject is a ServiceAccount, not a person: it has no address
and no name, so `userinfo` returns no `email`, no `name` and no
`preferred_username`. Every module that checks the claims a scope
implies — `oidcc-scope-email`, `oidcc-scope-profile`,
`oidcc-alternate-happy-flow` — therefore warns for a reason that does not
exist when a person signs in.

So the unattended run is evidence for the PROTOCOL modules and not for
the claim-bearing ones. Those, and the two that require a screenshot
(`oidcc-prompt-login`, and the missing-response-type error page), are a
person's pass with a real Google sign-in.

### Run one plan at a time

The suite serves every plan's callback under its `alias`, and the
declared clients register exactly one callback — so a second plan with a
different alias is refused a redirect it never registered, and a second
plan with the SAME alias interrupts the running one. The interrupted test
says so only in its own log ("Stopping test due to alias conflict"),
which from outside looks exactly like a hang. Each one that reaches a sign-in stops and
waits for you: a browser window opens on the issuer's chooser, you sign
in with Google as usual, and the test continues on its own.

The logout plan is **not** the same call. It takes a different set of
variants — `client_registration` and `response_type`, with no
`server_metadata` — and posting the Basic OP variant to it returns an
error with no plan id rather than a plan:

```bash
variant='%7B%22client_registration%22%3A%22static_client%22%2C%22response_type%22%3A%22code%22%7D'
curl -s -H "$H" -X POST "$S/api/plan?planName=oidcc-rp-initiated-logout-certification-test-plan&variant=$variant" \
  -H 'Content-Type: application/json' --data-binary @basic.json | jq -r .id
```

`response_type=code` because this issuer serves only `code` — which is
the whole reason the other response types are absent from discovery. Ask
the suite rather than guess; `GET /api/plan/available` lists each plan's
variant keys and their permitted values.

The Back-Channel plan takes the **same** variants as that one, and is
started the same way:

```bash
curl -s -H "$H" -X POST "$S/api/plan?planName=oidcc-backchannel-rp-initiated-logout-certification-test-plan&variant=$variant" \
  -H 'Content-Type: application/json' --data-binary @basic.json | jq -r .id
```

What it needs that the others do not is **a client declaring where to
send the logout token**. Back-Channel Logout is opt-in per client, so a
row that declares none is never contacted and every module of this plan
waits for a token that is not coming:

```yaml
    backchannel_logout: /test/a/access-issuer/backchannel_logout
```

The alias in that path is the same alias as the callback, for the same
reason: the suite serves every endpoint of a plan under it.

Both conformance rows carry it, because the tests that check one
client's logout does not end another's need the second client to be
listening too.

**And the issuer must be able to reach the suite.** This is the one
module where it has to: a logout token is a server-to-server POST, and
a suite on a laptop at a name that resolves to `127.0.0.1` is, from the
pod, the pod's own loopback. The module then sits in WAITING after
*"Received front channel redirect; waiting for back channel request"*
while the issuer logs `connection refused` against the registered URL.
That log line is the proof the mechanism ran; the module needs the suite
on a host the cluster can reach, with a certificate the issuer trusts
— or the Foundation's hosted suite.

### 4. Afterwards

- Export each plan's results from the suite and attach them to the
  ticket. A green run nobody kept is a green run nobody can check.
- **Remove the two client rows.** This is the step that gets forgotten,
  and it is the only one that leaves anything behind.

## What the run has already found

Pointing the suite at the live issuer is not a formality. It found that
a refused bearer at `/userinfo` carried no `WWW-Authenticate` header,
which RFC 6750 requires — a 401 a conforming client cannot act on,
written inside a dependency and invisible from our side of it. Fixed in
v0.10.0.

## What is deliberately not in the target

Token exchange is served and is **not** part of any profile claimed
here. It is now the only one: the device flow, JWT bearer and client
credentials were served through 0.11 and are gone (INF-693).

The reverse also has to hold, and since 0.11 it is the half worth
running: nothing this family's design names as *out* may be found
served. A grant withdrawn from discovery that goes on ANSWERING is the
failure that hides, because the metadata looks right. See
[../reference/access-issuer.md](../reference/access-issuer.md#endpoints).
