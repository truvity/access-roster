# access-proxy — the console exposure

**Status:** designed 2026-09-07; chart built 2026-09-08.

**Decided 2026-09-08:** built with a **static client**, not a self-registered
one. `/register` is designed (see *Self-registration* below) and the issuer
does not serve it yet, so `registration.enabled` defaults to `false` and an
installation names a Secret holding the client. This is an interim with an
end: when the issuer serves `/register`, the default flips and no client
appears in any values file. Recorded here rather than discovered later,
because a static client is the thing this component exists to remove.

**Decided 2026-09-08:** the chart never mints the **cookie secret** either,
and that one is not interim. A chart that generated it would generate a new
one on every render that cannot read cluster state — which is what ArgoCD
does — and every sync would sign everyone out.

**Decided 2026-09-08:** a console behind this proxy must publish a
**bootstrap surface** the proxy does not cover — its sign-in page, recovery,
and the consent callback. Found the hard way on the first real install: the
operator connecting the first directory is one no directory can vouch for, so
the gateway sent them to sign in against a directory that did not exist, and
Google's consent redirect came back to a callback the proxy swallowed. It
presents as a second account picker, not as a refusal. directory-roster
renders those paths on a second HTTPRoute (`route.bootstrapPaths`) and the
proxy attaches only to the main one.

The corollary, learned 2026-09-09 on the second real install step: a
request on the bootstrap surface carries **no identity from the gateway**,
so the consent callback cannot demand one — it takes its operator from
the state the hub signed when an operator started the flow. A callback
that checked the request instead refused the one flow the surface exists
to finish.

**Decided 2026-09-08:** its first consumer is the **directory-roster
console**, in the `authenticated` posture. The hub resolves viewer/operator
from the directory it owns, so the gateway gates on "signed in" and the
application decides the rest; a `groups` rule here would be a second copy of
that decision, and the stale one.

## Purpose

Every web console behind the gateway needs the same five things: a login
against the issuer, a session that outlives a token, a bearer forwarded
to the backend, a place to sign out from everywhere, and a decision about
who may pass. `access-proxy` is one chart that gives a console all five
from a hostname and a backend name, and nothing the console has to
implement.

**It is a chart, not a service of ours.** The process inside it is the
upstream oauth2-proxy image, deployed as Envoy Gateway's external
authorization backend with sessions in Valkey — the shape that earned its
place. The chart contributes the wiring around it (routes, policies,
labels), the conventions (client from hostname, fleet values, postures),
and one small init step that registers the proxy as a client at the
issuer. No request ever passes through code written here. That shape was
chosen over the gateway's native OIDC filter for four properties a token
in a cookie cannot give — real session management, room for large
tokens, global logout, and token refresh in the background — and the
issuer changes none of them. What changes is the issuer it talks to and
how it gets a client: it **registers itself**.

## One exposure, eight lines

```yaml
exposure:
  hostname: roster.example.internal
  backend: { name: github-roster, port: 8080 }
  posture: groups
  allow: [roster:operator, roster:viewer]
```

Everything else is derived or fleet-wide: the client id is the hostname,
the redirect is `https://<hostname>/oauth2/callback`, the cookie domain is
the hostname, the HTTPRoute and the gateway's SecurityPolicy are rendered
from the same values, the proxy image, node placement and issuer URL come
from a values file the deployment shares across every exposure, and the
session store is either a Valkey the chart is pointed at or one shared per
cluster by every proxy.

## One anchor, two gates

A console is for people, so the proxy lives on the **issuer anchor only**
([trust.md](trust.md)): it never accepts a ServiceAccount token, and
there is no reason it should — nothing in a cluster opens a web page.

Two gates decide who gets in, and they are not duplicates. The
**issuer's `requires`** on the console's client is primary: a caller in
none of its groups is refused before a token exists, so the proxy never
sees a session at all. The **proxy's posture** is defence in depth and
route-level narrowing — *this path needs a stricter group than the client
as a whole*. Keep both; know which is which, so nobody maintains two
allow-lists believing one of them is dead.

## Two postures

| Posture | Passes | For |
|---|---|---|
| `groups` | only callers whose token carries one of the listed `groups` values; the bearer is forwarded | platform consoles that gate on roles |
| `authenticated` | any signed-in identity; the bearer is forwarded and the application authorizes itself | business surfaces opened to employees for testing, where the application's own rules apply; and a console that already resolves roles from a directory it owns, where a `groups` rule here would be the stale copy |

Both forward the bearer in the `Authorization` header and the proxy's
own identity headers; the Go module's `identity` package reads the
bearer and verifies it — the headers are for a local run.

## Self-registration

At start, an init step presents the proxy's ServiceAccount token to the
issuer's registration endpoint with its redirect URI. The issuer checks
the token with TokenReview, checks the hostname against the pattern
allowed for that namespace, and answers with a client id and secret, the
same on every restart. Rotation is a re-registration. No per-console
client appears in any values file, and no operator mints one anywhere.

## What the chart renders and expects

| Renders | Expects |
|---|---|
| the proxy Deployment and Service, the registration init step, the HTTPRoute for the hostname, the gateway SecurityPolicy pointing the route's external authorization at the proxy, a NetworkPolicy admitting the gateway to the proxy and the proxy to the backend, and the namespace label a fleet-wide egress policy can select | a Gateway to attach to, the issuer, a Valkey, DNS for the hostname |

The namespace label is the convention that removes one hand edit per
console: a fleet egress policy that selects namespaces labelled
`access-roster.io/exposed=true` needs no per-console entry.

## The session store

Valkey, external to the chart, exactly as for the hub and the issuer: the
chart takes an address and optional credentials and ships no Valkey of its
own, because upstream's chart and the valkey.io operator already do that
job. Two topologies, both a one-line value:

| Topology | When |
|---|---|
| **one Valkey per cluster, shared by every proxy** | the default recommendation: fewer pods, one thing to watch. Sessions are keyed by random tickets, so proxies cannot collide; give each proxy its own ACL user if you want isolation inside the instance |
| **one Valkey per exposure** | when an exposure must not share a failure domain or an operator with the others |

The configuration reference carries an example `ValkeyCluster` for the
operator. Nothing else is needed to make them work together.

## Sign-out

Two halves, and both are needed. `/oauth2/sign_out` ends **this
proxy's** session — one application's cookie. The issuer still holds the
sign-in, so on its own that half leaves the next click, here or at any
other console, admitted again with no password; the screen says signed
out either way, which is why the near half alone is worse than none. So
its `rd` continues to the issuer's `end_session`, which ends the sign-in
itself, and lands the person back on the console's front page.

Built 0.9.x, and three things were learned building it. The proxy's
`whitelist_domains` must name the issuer's host or oauth2-proxy refuses
the redirect. The chain must carry **`client_id`**: a plain `rd` has no
`id_token_hint`, so without a client the issuer has no `signed_out` list
to match the landing page against and puts the person on its own page
instead. And the landing page is the policy client's `signed_out`, a
list kept **separate from `redirects`**, because a redirect URI starts a
sign-in and landing there after a sign-out begins the login just ended.
The console's own chart builds the whole chain from what it already
knows (`access.signOutThroughIssuer` in directory-roster) and refuses to
render half of it.

A revoked person is stopped by the issuer refusing to refresh, with the
hub's liveness signal behind it; the proxy's session then dies at its
next refresh.

## Why not something else

- **Not Envoy's native OIDC filter alone:** no session store, so no global
  sign-out and no background refresh, and tokens in cookies with size
  limits — the reasons oauth2-proxy was chosen in the first place.
- **Not a proxy of ours:** identity-critical code on every request path
  to every console, for no capability oauth2-proxy lacks.
- **Not the issuer as the authorization backend:** that would make the
  issuer hold per-user sessions and sit on every console's request path,
  which is oauth2-proxy rebuilt inside it — the identity-provider creep
  the guardrail forbids.

## Failure semantics

| Situation | Effect |
|---|---|
| the issuer is down | existing sessions keep working until their token refresh is due; no new logins |
| Valkey is down | every caller is logged out; sessions rebuild on login |
| registration refused | the proxy does not start; the log names the host and the pattern |
