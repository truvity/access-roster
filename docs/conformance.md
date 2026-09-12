# OpenID Foundation conformance


access-roster targets four OpenID Foundation profiles. A profile is
claimed only once the suite says so, which is why this page carries
the last run rather than an intention. The procedure for producing a
run is [operations/conformance.md](operations/conformance.md); this page
is what the last one said and what each of its columns means.

**Last run 2026-09-12 against the deployed issuer at v1.0.0**, from the
suite running in the cluster (plans `xywkLCaSn66Wo`, `QQw1OfSOykbnC`,
`Ps1nixuqZlBQp`, `6hKMyvxwF8baj`).

| Profile | Passed | Review | Skipped | Warning | **Failed** |
|---|--:|--:|--:|--:|--:|
| [Config OP](https://openid.net/certification/connect_op_testing/) | 1 | 0 | 0 | 0 | **0** |
| [Basic OP](https://openid.net/certification/connect_op_testing/) | 21 | 4 | 4 | 6 | **0** |
| [RP-Initiated Logout OP](https://openid.net/certification/connect_op_logout_testing/) | 3 | 8 | 0 | 0 | **0** |
| [Back-Channel Logout OP](https://openid.net/certification/connect_op_logout_testing/) | 2 | 0 | 0 | 0 | **0** |

The Foundation's rule is that **PASSED, REVIEW, WARNING and SKIPPED all
count, and only FAILED or INTERRUPTED disqualify** a profile. On that
rule all four are certifiable, and the logout pair the Foundation requires
for a submission — RP-Initiated plus one of the other three — is green
for the first time. The columns are here rather than a word
like *green* because the four states mean different things and two of
them need explaining.

## REVIEW is a screenshot handed to a person

Twelve modules end at a page the suite cannot see — it must refuse, so
there is no redirect back — and each asks a human to confirm what was
shown. All twelve were reviewed on 2026-09-12 and every screenshot shows
the page its step demanded:

| What the step demands | Modules | What the screenshot shows |
|---|--:|---|
| an error page, the `redirect_uri` is not registered | 2 | *That sign-in request was not valid* |
| an error page, the `id_token_hint` is not valid | 2 | *That sign-out request was not valid — id_token_hint invalid* |
| an error page, the `post_logout_redirect_uri` is not registered | 3 | *That sign-out request was not valid — post_logout_redirect_uri invalid* |
| the successful logout page | 3 | *Signed out* |
| the login prompt during a second authorization | 2 | the sign-in chooser |

**This review is not a formality.** It has caught a defect both times it
has been done: once two pages that were wrong (a signed-out page claiming
other consoles were still running, and an unstyled library error), and
once ten screenshots that were byte-identical pictures of the wrong page
because of a fault in the driver. A REVIEW whose evidence is wrong passes
silently.

## SKIPPED means the discovery document was believed

Three modules skip because `scopes_supported` says we do not offer
`address` or `phone`, and one because we answer `request_not_supported`.
Those are optional features we decline: `address` and `phone` are
standard scopes for a postal address and a telephone number, and a
directory reader for infrastructure has no source for either and no
business holding them. The suite read discovery, believed it, and
skipped — which is evidence the discovery document is truthful rather
than a gap.

## WARNING is mostly personal data we decline to hold

Four warnings say userinfo does not carry every claim the `profile` and
`email` scopes permit. **Verified with a real Google sign-in**, not the
automated recovery path: `sub`, `name`, `given_name`, `family_name`,
`preferred_username`, `email`, `email_verified` and `groups` are all
returned. What is missing is `birthdate`, `gender`, `zoneinfo`,
`locale`, `picture`, `website`, `profile`, `nickname`, `middle_name` and
`updated_at` — data this issuer has no source for and no reason to
carry. A warning for declining to hold somebody's birthdate is a warning
worth keeping.

The other two come from one module noting the ID token carries claims
the client did not request by scope. One is `groups`, which is the
entire point of this issuer and what Kargo and ArgoCD read; gating it
behind a scope would satisfy the suite and break every consumer. The
other is `client_id`, which duplicates `azp` and comes from the
library's own claims struct rather than from anything here.

**One warning was a real defect and is fixed** (v0.15.2): a reused
authorization code must revoke what it issued, and `userinfo` went on
answering with the access token from the first redemption.

## Back-Channel is witnessed from a suite the issuer can reach

The Foundation requires a logout submission to carry RP-Initiated Logout
OP *and at least one of* Session Management, Front-Channel or
Back-Channel logout. Back-Channel is served since 0.16.0, opt-in per
client, and it is the only one of the three worth serving: the other two
load an iframe from the issuer inside the application's page, which
browsers block by default, so both fail quietly in exactly the case they
exist for.

Its end-to-end module is the one place the **issuer has to reach the
suite**: a logout token is a server-to-server POST. A suite on a laptop
at a name that resolves to `127.0.0.1` is, from the pod, the pod's own
loopback, and pods cannot reach the tailnet either. So the suite runs in
the cluster, at a kernel hostname of its own, exactly while the
conformance client rows are declared — see
[operations/conformance.md](operations/conformance.md). Only its
relying-party paths are public; the control plane is reached over the
tailnet.

**The first run that could receive a token found two defects**, both
fixed in 0.17.1 and both pinned by end-to-end tests that drive a real
code flow and read what the listening relying party is sent:

- A client that asked for `openid` alone holds no refresh token, and a
  session here *is* a refresh token — so the issuer recorded nothing for
  it and, at sign-out, announced nothing. The sign-in now remembers which
  clients were issued an ID token under it, and every one is told.
- The logout token named the browser sign-in as `sid` while the ID token
  had named the per-client session (INF-681). A relying party matches
  the two by that value; a token that verified and matched nothing was a
  sign-out that silently did not happen. The logout token now names the
  `sid` the ID token did, and a client whose ID token carried none is
  told by `sub` alone.

Neither would have been found by reading. The suite noticed the first by
waiting for a POST that never came, and would have noticed the second
the moment one did.

## How it is run

**By a person, at every major and minor release**, as a whole. It used to
run the Config profile nightly and nothing else, which is worse than no
check: one profile passing daily reads as *conformance passes* while the
two that actually sign somebody in have not run for weeks — and those
two are where every defect has been. The Config workflow is still one
click away
([.github/workflows/conformance.yaml](../.github/workflows/conformance.yaml)),
because it needs no credential and guards the discovery document, which
changes silently when a provider option changes.

[operations/conformance.md](operations/conformance.md) is the
procedure, and [hack/conformance_drive.py](../hack/conformance_drive.py)
drives headless Chrome through the browser half — signing in through
recovery, and answering the suite's manual steps with a screenshot of the
page it is looking at — so thirty-five modules are one command rather
than thirty-five sign-ins. `--manual` hands one module's browser step to
a person instead, which is how the profile and email claims above were
checked with a real account.
