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

## Two postures

| Posture | Passes | For |
|---|---|---|
| `groups` | only callers whose token carries one of the listed `groups` values; the bearer is forwarded | platform consoles that gate on roles |
| `authenticated` | any signed-in identity; the bearer is forwarded and the application authorizes itself | business surfaces opened to employees for testing, where the application's own rules apply |

Both forward the bearer in the `Authorization` header and the proxy's
own identity headers; the Go module's `identity` package reads either.

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

`/oauth2/sign_out` ends the proxy session and redirects to the issuer's
end-session endpoint, which ends the issuer session too. A revoked person
is stopped by the issuer refusing to refresh, with the hub's liveness
signal behind it; the proxy's session then dies at its next refresh.

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
