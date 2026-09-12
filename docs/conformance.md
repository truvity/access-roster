# OpenID Foundation conformance


access-roster targets four OpenID Foundation profiles. A profile is
claimed only once the suite says so, which is why this page carries
the last run rather than an intention. The procedure for producing a
run is [operations/conformance.md](operations/conformance.md); this page
is what the last one said and what each of its columns means.

**Last run 2026-09-12 against the deployed issuer at v0.17.0.**

| Profile | Passed | Review | Skipped | Warning | **Failed** |
|---|--:|--:|--:|--:|--:|
| [Config OP](https://openid.net/certification/connect_op_testing/) | 1 | 0 | 0 | 0 | **0** |
| [Basic OP](https://openid.net/certification/connect_op_testing/) | 21 | 4 | 4 | 6 | **0** |
| [RP-Initiated Logout OP](https://openid.net/certification/connect_op_logout_testing/) | 3 | 8 | 0 | 0 | **0** |
| [Back-Channel Logout OP](https://openid.net/certification/connect_op_logout_testing/) | 1 | 0 | 0 | 0 | **0**† |

† The Back-Channel discovery module passes. The end-to-end module needs
the issuer and the suite on one network, which the laptop suite and the
in-cluster issuer are not — see *Back-Channel needs a reachable suite*
below. The mechanism itself is proven: the issuer mints the logout token
and POSTs it to the registered URL, pinned by unit tests for `typ` and
the absent `nonce`, and shown in the issuer's own log against the live
suite.

The Foundation's rule is that **PASSED, REVIEW, WARNING and SKIPPED all
count, and only FAILED or INTERRUPTED disqualify** a profile. On that
rule all four are certifiable. The columns are here rather than a word
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

## Back-Channel needs a reachable suite

The Foundation requires a logout submission to carry RP-Initiated Logout
OP *and at least one of* Session Management, Front-Channel or
Back-Channel logout. Back-Channel is served since 0.16.0, opt-in per
client, and it is the only one of the three worth serving: the other two
load an iframe from the issuer inside the application's page, which
browsers block by default, so both fail quietly in exactly the case they
exist for.

Its certification module is the one place the **issuer has to reach the
suite**. Every other module is driven by the browser, so a suite on a
laptop at a name that resolves to `127.0.0.1` works against an issuer
anywhere. A logout token is a server-to-server POST, and from the pod
that address is its own loopback:

```
a client could not be told its session ended
  client_id=conformance
  error=Post "https://localhost.emobix.co.uk:8443/test/a/access-issuer/backchannel_logout":
        dial tcp 127.0.0.1:8443: connect: connection refused
```

That line is the run's evidence: the token was minted for the right
client and sent to the registered URL, and the network said no. Closing
the module is a topology change, not a code change — the suite on a host
the cluster can reach with a certificate the issuer trusts, or the
Foundation's hosted suite, which is what an actual submission uses
anyway. Until then the pair reads as RP-Initiated green and Back-Channel
proven but not witnessed.

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
