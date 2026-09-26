# Front a console with Envoy Gateway's own OIDC filter

**Anchor:** the issuer; the console runs no OpenID flow of its own —
Envoy Gateway's `SecurityPolicy` runs it, attached to the console's own
`HTTPRoute`. Read [choosing-native-or-gateway-oidc.md](choosing-native-or-gateway-oidc.md)
first if you have not already decided this is the shape you want; this
page is only how to build it, and where it bites.

Every field name and default below is checked against Envoy Gateway
**v1.9**'s own API types
([`api/v1alpha1/oidc_types.go`](https://github.com/envoyproxy/gateway/blob/release/v1.9/api/v1alpha1/oidc_types.go),
[`jwt_types.go`](https://github.com/envoyproxy/gateway/blob/release/v1.9/api/v1alpha1/jwt_types.go),
[`authorization_types.go`](https://github.com/envoyproxy/gateway/blob/release/v1.9/api/v1alpha1/authorization_types.go))
and, for the traps, its translator
([`internal/xds/translator/utils.go`](https://github.com/envoyproxy/gateway/blob/release/v1.9/internal/xds/translator/utils.go)) —
verify field names against a newer release before copying this on one.

## The client row

```yaml
clients:
  myconsole.example.internal:
    kind: confidential          # the filter holds the secret and redeems the code itself
    secret: myconsole-oidc-client
    display_name: My Console
    description: the team's dashboard
    redirects:  [https://myconsole.example.internal/oauth2/callback]
    signed_out: [https://myconsole.example.internal/]
    requires:   [all:myconsole:operator, all:myconsole:viewer]
    ttl_cap: 15m
    # signing_alg: RS256   # only if something downstream reads the forwarded
                            # ID token with a fixed-algorithm verifier
```

`kind: confidential` for the same reason `access-proxy`'s client is
confidential: the filter, not the browser, holds the secret and redeems
the authorization code
([reference/policy.md#clients--audience-and-gate](../reference/policy.md#clients--audience-and-gate)).
`requires` is checked at sign-in and again at every refresh — the second
check is why a grant withdrawn after a token was issued still ends at
the next refresh rather than living out the token's full lifetime
([design/access-roster.md#who-may-open-which-console](../design/access-roster.md#who-may-open-which-console)).
`ttl_cap` is the whole of this shape's revocation story, because there is
no Back-Channel Logout receiver here (below) — see
[Trap 1](#trap-1-per-request-refresh-races-rotating-refresh-tokens) before
setting it very short.

## The app must own an `HTTPRoute`

A `SecurityPolicy` targets a `Gateway`, a `ListenerSet`, an `HTTPRoute`, a
`GRPCRoute` or a `TCPRoute` — never a hostname or a path by itself. Attach
it to a `Gateway` or a shared `ListenerSet` and it fronts *everything*
routed through that listener, which is very rarely what one console
wants. So the console's own chart renders its own `HTTPRoute`, and the
policy's `targetRefs` names that route — the same reason this issuer's
own chart gives the console's path a second `HTTPRoute` rather than
sharing the one carrying `/token` and `/keys`
([reference/configuration.md](../reference/configuration.md)).

## The `SecurityPolicy`

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: myconsole-oidc
  namespace: myconsole
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: myconsole
  oidc:
    provider:
      issuer: https://issuer.example.internal
      authorizationEndpoint: https://issuer.example.internal/authorize
      tokenEndpoint: https://issuer.example.internal/token
      endSessionEndpoint: https://issuer.example.internal/end_session
    clientID: myconsole.example.internal
    clientSecret:
      group: ""
      kind: Secret
      name: myconsole-oidc-client
    redirectURL: https://myconsole.example.internal/oauth2/callback
    logoutPath: /oauth2/sign_out
    refreshToken: true
    forwardAccessToken: true
  jwt:
    providers:
      - name: myconsole-idtoken
        issuer: https://issuer.example.internal
        remoteJWKS:
          uri: https://issuer.example.internal/keys
          cacheDuration: 5m
        extractFrom:
          headers:
            - name: x-id-token
        claimToHeaders:
          - header: x-groups
            claim: groups
  authorization:
    defaultAction: Deny
    rules:
      - name: operators-and-viewers
        action: Allow
        principal:
          jwt:
            provider: myconsole-idtoken
            claims:
              - name: groups
                valueType: StringArray
                values: [all:myconsole:operator, all:myconsole:viewer]
```

A few fields worth explaining rather than copying blind:

- **`oidc.provider`** takes `authorizationEndpoint` and `tokenEndpoint`
  explicitly here on purpose, not because they are required — either is
  discovered from `issuer`'s `.well-known/openid-configuration` when left
  unset. **`endSessionEndpoint` is only auto-discovered when you leave
  *both* of the other two unset too** — the source comment says so
  plainly: state it by hand the moment you state the other two, or a
  console that logs a person out locally never ends their SSO session at
  the issuer, and nothing in the render tells you it didn't.
- **`clientSecret`** is a `SecretObjectReference` — `name` mandatory,
  `group` and `kind` optional and defaulted (`""` for the core API group,
  `Secret`). Write them anyway: a GitOps controller that diffs rendered
  manifests against live state reads an omitted field as drift the
  moment the API server fills it in, the same trap this repository
  already names for a `ListenerSet` parent reference
  ([reference/access-proxy.md](../reference/access-proxy.md)).
- **`refreshToken: true`** is also the library default — stating it is
  for the reader, not the render — and it is what makes
  [Trap 1](#trap-1-per-request-refresh-races-rotating-refresh-tokens)
  possible at all: no refresh, no race, but also no session that outlives
  its first access token.
- **`forwardAccessToken: true`** puts the issuer's access token in the
  upstream `Authorization` header, which is what an app's own backend
  reads with the Go or TypeScript `identity` verifier exactly as it would
  behind `access-proxy`
  ([connect/console-app.md](console-app.md)).
- **The `jwt` block is not there to authenticate the request again** —
  `oidc` already did that. It exists so `groups` can be read out of a
  **header** rather than out of a cookie (see
  [Trap 3](#trap-3-cookie-size)), and so `authorization` can gate on it.
  `extractFrom.headers` names `x-id-token`, not `Authorization`, because
  `Authorization` already carries the forwarded access token above, and
  the default extraction point for a JWT provider **is** `Authorization`
  — naming a header of its own is what keeps the two from reading each
  other's token. Reaching `x-id-token` in the first place needs one more
  field this example leans on implicitly: `oidc.forwardIDToken.header:
  x-id-token` (omitted above for brevity — add it, or the JWT provider
  has nothing to extract). The schema itself refuses the one adjacent
  mistake: `forwardIDToken.header` may not be `Authorization` while
  `forwardAccessToken` is `true` — the validation error names both
  fields if you try.
- **`valueType: StringArray` on the `groups` claim is not optional in
  practice, only in the schema.** The field defaults to `String`, which
  matches a single scalar claim exactly — never this issuer's `groups`,
  which is always a flat array of internal group names
  ([reference/policy.md#groups--token-by-deep-merge](../reference/policy.md#groups--token-by-deep-merge)).
  Leave it out and the rule silently never matches, because a
  string-typed match against an array claim is not the same comparison.
- **`authorization.defaultAction: Deny`** is also the library default
  when neither `rules` nor `defaultAction` is set — stated here so a
  reader does not have to know that to trust the policy denies anyone
  outside the one `Allow` rule.

## Sign-out

The filter serves `logoutPath` (default `/logout` if you don't set one;
this example moves it to `/oauth2/sign_out` only to keep a link a former
`access-proxy` console already has). Visiting it clears the filter's own
cookies, and — because `endSessionEndpoint` is set above — redirects on
to the issuer's own sign-out, ending that person's SSO session too. That
half is real RP-initiated logout, and it works today.

**What it does not do is receive one.** There is no Back-Channel Logout
receiver behind this filter — no field in the `SecurityPolicy` schema
takes a `backchannel_logout_uri`, and nothing here could open a session
that lives entirely in an encrypted browser cookie even if one existed.
So an operator's revoke somewhere else — the console's *Revoke a session*
or *sign out everywhere*, a directory suspension — reaches this console
only at its next refresh, bounded by the access token's own lifetime and
the client's `ttl_cap`
([design/access-roster.md#telling-the-relying-party-back-channel-logout](../design/access-roster.md#telling-the-relying-party-back-channel-logout)).
That is exactly the shape `access-proxy` always had, at the shorter of
the two dials — this filter's own refresh cadence versus this client's
`ttl_cap` — rather than a fixed one-minute `session.refresh`
([design/access-proxy.md](../design/access-proxy.md)).

## Traps

### Trap 1: per-request refresh races rotating refresh tokens

**Symptom:** an intermittent sign-in loop or a spurious 401 under load,
worse with more replicas of the gateway.

Envoy's OAuth2 filter refreshes per request, independently on every
replica, and a rotating refresh token is single-use: two concurrent
requests on two replicas can each try to redeem the same refresh token
within the same second. The issuer tolerates a short grace window for
exactly this reason
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)). **Fix:**
never give a client fronted this way a very short `ttl_cap` (a minute or
two) — it does not tighten revocation meaningfully at this shape's own
floor, and it multiplies how often this race is tried.

### Trap 2: cluster-name collision

**Symptom:** the OIDC token endpoint and the JWT `remoteJWKS` share one
host, and a setting given to only one of them — a longer request
timeout, a retry policy, a client TLS bundle — silently never applies to
whichever of the two lost.

Verified against the v1.9 translator: with no explicit `backendRefs`,
both `oidc.provider`'s token endpoint and `jwt.providers[].remoteJWKS`
resolve to an implicit cluster named `clusterName(host, port)` —
literally the host with dots turned to underscores, plus the port
(`internal/xds/translator/utils.go`). Same issuer host, same port, same
derived name: **one Envoy cluster serves both.** Whichever backend's
settings are translated first wins the registration; the second call to
create a cluster of the same name is a documented no-op
(`addXdsCluster`: "if the cluster already exists, it skips adding the
cluster"). The tell is exactly that: the cluster's connection options
stay whatever the first side set, and changing the *other* side's
`backendSettings` in the policy renders successfully and does nothing.

**Fix:** give the JWKS side its own `backendRefs` (or state identical
`backendSettings` on both, so it does not matter which one wins):

```yaml
jwt:
  providers:
    - name: myconsole-idtoken
      remoteJWKS:
        uri: https://issuer.example.internal/keys
        cacheDuration: 5m
        backendRefs:
          - name: access-issuer
            port: 443
```

### Trap 3: cookie size

Tokens ride in cookies the filter names for you
(`AccessToken-<uid>`, `IdToken-<uid>`), and browsers cap a single cookie
around 4 KB. A large `groups` claim pushes toward that ceiling faster
than anything else in the token, because nothing else here grows with
the size of the installation. Two mitigations, not one:

- fewer groups per audience — the per-audience `groups` scoping this
  repository has decided and not yet shipped
  ([ADR 0006](../decisions/0006-groups-claim-scoped-per-audience.md));
  ask what stage it is at before assuming it is live;
- forward the ID token in a **header** rather than reading it from the
  cookie downstream — `oidc.forwardIDToken.header`, read by the `jwt`
  block's `extractFrom` above, is exactly that: the claims the app needs
  travel once, on the request, and never touch the browser's own cookie
  jar at all.

### Trap 4: fail-open on misconfiguration

A `SecurityPolicy` that does not attach to the route you meant leaves
that console **open** — this is a named caveat, not a hypothetical
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)).
**Verify with an unauthenticated request**, every time the policy or the
route changes:

```sh
curl -sD - -o /dev/null https://myconsole.example.internal/
```

A `302` to the issuer's `authorizationEndpoint` is the policy working. A
`200` is the policy not attached at all.

### Trap 5: leftover paths from a former oauth2-proxy

`/oauth2/sign_out` and `/oauth2/start` are oauth2-proxy's own paths (as
its own docs name them), not Envoy Gateway's. This filter serves **no
sign-in path at all** — loading any protected page is what redirects to
the issuer, because there is no separate "start" step — and its own
logout path defaults to `/logout`, not `/oauth2/sign_out`, unless you
move it as this page's example does. A console migrated off
`access-proxy` that still links `/oauth2/start` anywhere is linking a
path nothing here serves.

### Trap 6: declare defaults explicitly

`cacheDuration` on `remoteJWKS` defaults to `300s` if you leave it out;
`clientSecret`'s `group` and `kind` default to `""` and `Secret`. Both
are exactly what this example already writes out, and for the reason
[the `SecretObjectReference` note above](#the-securitypolicy) gives: a
GitOps controller diffing rendered YAML against a live object sees a
field the API server filled in as drift, forever, if the rendered
manifest never named it.

## Verify it works

1. **Unauthenticated → redirect.** `curl -sD - -o /dev/null
   https://myconsole.example.internal/` returns `302` to
   `authorizationEndpoint`, never `200` ([Trap 4](#trap-4-fail-open-on-misconfiguration)).
2. **Sign in once → one issuer session.** After completing the flow,
   the issuer's own console lists exactly one session for that identity
   and client, not one per tab.
3. **After `ttl_cap` elapses, still signed in.** Reload past the cap:
   the filter's background refresh should renew silently, with no
   redirect back to the login page.
4. **Logout path → the issuer session ends.** Visit the configured
   `logoutPath`; the issuer's own session listing for that identity
   should drop this client's session, and a fresh unauthenticated
   request to *another* console signed in under the same SSO session
   should now prompt for a password rather than completing silently.
