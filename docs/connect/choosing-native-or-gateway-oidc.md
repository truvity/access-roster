# Choosing native OIDC or gateway OIDC

Every new app that needs a login asks the same question first: does it
sign itself in, or does something in front of it do that on its behalf?
Get it wrong and the symptom does not show up at review time — it shows
up the day somebody is revoked and their console keeps answering anyway.
This page is the decision, and [envoy-gateway-oidc.md](envoy-gateway-oidc.md)
is how to build the gateway-native shape once you have made it.

## Three sessions, and one absolute limit

There are three things that get called a session here, and only one of
them is this issuer's to reach directly
([design/access-roster.md#sessions-and-sign-out](../design/access-roster.md#sessions-and-sign-out)):

- the **SSO session**, a cookie at the issuer's own host;
- a **per-client refresh chain** — one refresh token per identity and
  client, which is what kubelogin, `accessctl` and every gateway-native
  filter actually hold;
- the **application's own local session**, on its own clock, once it has
  signed somebody in.

The installation's absolute limit — `lifetimes.absolute`, 24 hours from
`auth_time` by default — is enforced at the first two, three ways: a
refresh at or after the limit is refused (`invalid_grant`) and the
session revoked; an access or ID token's `exp` is capped at
`auth_time+absolute` even when its ordinary lifetime would reach
further; and a silent `/authorize` against an SSO session already past
the limit ends that session first rather than completing against it
([design/access-roster.md#the-absolute-session-limit](../design/access-roster.md#the-absolute-session-limit),
[reference/configuration.md#values](../reference/configuration.md#values),
[ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)). It
reaches the third session — the application's own — only if that
application comes back to ask. That is the whole of the boundary, and it
is worth stating plainly: **a session this issuer never sees again is a
session this issuer cannot end.**

## Class A and class B

Every relying party falls into one of two shapes
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)):

| Class | Shape | How the 24h limit reaches it |
|---|---|---|
| **A** | refreshes against the issuer to stay signed in: a gateway-fronted console, an application with its own refresh enabled, `accessctl`, kubelogin | directly, with lag no worse than the token's own lifetime or the client's `ttl_cap` |
| **B** | mints its own session after one sign-in and does not come back on its own | not automatically — it must cap its own session at 24 hours or less, or accept Back-Channel Logout and live with the window that leaves |

**Class B is a deliberate choice an application's operator makes, never a
default to fall into.** Silence on it is not safe
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)).

A few real ones, each checked against how this repository or the
application itself documents it:

- **Kargo is class A.** Its UI holds the access, ID and refresh tokens
  from its own OIDC flow and renews them itself; a revoked session stops
  Kargo within its client's `ttl_cap` because that renewal starts
  failing ([connect/kargo.md](kargo.md)). It refreshes against the
  issuer, which is the definition of class A — despite minting nothing
  of its own once signed in.
- **ArgoCD is class B.** After its own OIDC flow completes, ArgoCD issues
  its own signed token for the browser, good for
  `users.session.duration` in `argocd-cm` ("specifies token expiration
  duration" in ArgoCD's own reference; not this repository's setting).
  ArgoCD also refreshes the OIDC ID token in the background
  (`oidc.refreshTokenThreshold`) to keep its own claims current, and
  [connect/argocd.md](argocd.md) says a revoke at the issuer "reaches it
  at its next token refresh" — but nothing here bounds *how soon* that
  is, because ArgoCD's own session is what actually authorizes a
  request. Set `users.session.duration` to 24 hours or less yourself;
  the issuer's absolute limit does not set it for you.
- **OpenBAO is two different things wearing one name.** `openbao-ui`,
  the console, is a confidential client running its own code flow,
  capped by `ttl_cap: 5m` on its policy row
  ([integrations/openbao.md](../integrations/openbao.md)) — class A,
  same shape as any gateway-fronted app. The **Vault-style token**
  OpenBAO mints once a login succeeds on `jwt-roster` is class B: it
  carries its own time-to-live and renews against OpenBAO itself, never
  coming back here. Cap that role's own maximum TTL at 24 hours too, the
  same reasoning applied a second time. *(OpenBAO's own field names for
  a role's token lifetime are not documented on this repository's side
  of the contract — see
  [truvity/openbao](https://github.com/truvity/openbao/blob/master/docs/integrations/access-roster.md)
  for those.)*
- **A CLI is class A by definition** — `accessctl` and kubelogin are
  named as class A in [ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)
  itself, because the whole point of a laptop credential is that it asks
  again.
- **Grafana and Headlamp are not documented in this repository**, so
  treat each on its own evidence rather than by name. Grafana's
  `generic_oauth` provider is class B by design: Grafana's own
  documentation names `login_maximum_lifetime_duration` under `[auth]`
  (default 30 days) as the setting that ends a login regardless of
  activity — exactly the "multi-day session of its own" this page's ADR
  warns about, and exactly what to set to 24 hours or less. *(Verified
  against Grafana's own configuration reference, not this repository —
  check it against the version you run.)* Headlamp's own docs do not say
  whether it refreshes its OIDC tokens client-side or mints an
  independent session; that is **not verified**, so check before
  assuming either shape for it.

## A table of common apps

| App | Class | What it needs from the policy |
|---|---|---|
| ArgoCD | B — own `users.session.duration` | confidential client, own redirect; no `signing_alg` pin — its verifier (go-oidc's provider verifier) accepts whatever the issuer's discovery document advertises ([connect/argocd.md](argocd.md)) |
| Kargo | A — refreshes, capped by `ttl_cap` | two public clients (UI + CLI); **needs `signing_alg: RS256`** — its verifier is built with no `SupportedSigningAlgs` and defaults to RS256 without reading discovery ([connect/kargo.md](kargo.md), [ADR 0009](../decisions/0009-a-default-signing-algorithm-and-per-audience-exceptions.md)) |
| Kubernetes API server (kube-apiserver / a managed control plane's OIDC identity provider) | A — `accessctl`/kubelogin refresh it | one public client per cluster; **often needs `signing_alg: RS256`** — `--oidc-signing-algs` defaults to RS256 and a managed control plane's associated identity provider may accept only RS256 with no algorithm setting exposed at all ([connect/kubernetes-cluster.md](kubernetes-cluster.md)) |
| OpenBAO UI | A — own OIDC flow, `ttl_cap: 5m` | confidential client; no `signing_alg` pin needed — OpenBAO's JWT auth reads whichever algorithm discovery advertises unless `jwt_supported_algs` is set to pin one ([integrations/openbao.md](../integrations/openbao.md)) |
| Grafana (`generic_oauth`) | B — own session; cap `login_maximum_lifetime_duration` yourself | confidential client (Grafana redeems the code server-side); its own signing-algorithm acceptance is not verified here |
| Headlamp | not verified — confirm whether it refreshes or mints its own session before choosing | not verified |
| A simple internal console, no auth of its own | A — entirely through the gateway's own OIDC filter; the console holds no session at all | confidential client (the filter holds the secret); `signing_alg` only if something downstream reads the forwarded ID token with a fixed-algorithm verifier |

## The rule

- **Native OIDC** when the app needs identity *inside itself*: per-user
  authorization from `groups`, per-user audit, tokens of its own to call
  something else — the way ArgoCD and Kargo do
  ([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)).
- **Gateway-native OIDC** when the app has no authorization model of its
  own, or only needs to answer "may this person reach it at all" — an
  Envoy Gateway `SecurityPolicy`'s `oidc` block running a declared
  confidential client of this issuer in front of it
  ([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md),
  [ADR 0003](../decisions/0003-deprecate-access-proxy.md)). See
  [envoy-gateway-oidc.md](envoy-gateway-oidc.md) for how.
- **Never both on one application.** A second door doubles the sign-out
  surface that has to be reasoned about, which is exactly where this
  repository has found real bugs before: a revoke path that ended one
  session and left its parent SSO session standing looked, from the
  console, like a complete sign-out
  ([design/access-roster.md#telling-the-relying-party-back-channel-logout](../design/access-roster.md#telling-the-relying-party-back-channel-logout)).

## oauth2-proxy, and when it is still the answer

Not never — just narrower than it used to be. `access-proxy`, this
repository's own chart, has only ever been Envoy Gateway's external
authorization backend, and gateway-native OIDC on that same Envoy
Gateway is now the default replacement for it
([ADR 0003](../decisions/0003-deprecate-access-proxy.md),
[design/access-proxy.md](../design/access-proxy.md)). **For a gateway
that is not Envoy Gateway, this chart was never an option, and still is
not**: the path there is to run upstream `oauth2-proxy` yourself, with a
declared confidential client of this issuer, the way `access-proxy`
already wires it — see [design/access-proxy.md](../design/access-proxy.md)
for the shape to copy. Its server-side session store is not a reason to
prefer it over gateway-native OIDC: `oauth2-proxy` encrypts each session
with a key that lives only in the browser's own cookie, so nothing
server-side — a Back-Channel Logout receiver included — can ever open
one either way.

## Read next

- [envoy-gateway-oidc.md](envoy-gateway-oidc.md) — building the
  gateway-native shape, and its traps
- [console-app.md](console-app.md) — a console with its own backend API:
  what you write and deploy for each shape
- [reference/policy.md#clients--audience-and-gate](../reference/policy.md#clients--audience-and-gate) —
  every field a client row takes
