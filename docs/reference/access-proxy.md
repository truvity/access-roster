# access-proxy — values

| Value | Default | Meaning |
|---|---|---|
| `exposure.hostname` | required | the console host; also the client id and the cookie domain |
| `exposure.backend.name`, `.port` | required | the console's Service |
| `exposure.posture` | `groups` | `groups` or `authenticated` |
| `exposure.allow[]` | `[]` | `groups` values that pass, for the `groups` posture |
| `exposure.gateway.name`, `.namespace`, `.sectionName` | from the fleet values | the Gateway listener to attach the HTTPRoute to |
| `exposure.paths[]` | `["/"]` | routes to protect; anything unlisted gets no route |
| `exposure.forward.authorizationHeader` | `true` | forward the bearer as `Authorization` besides the proxy's identity headers |
| `exposure.forward.extraExtAuthHeaders[]` | `[]` | extra client request headers Envoy includes in the *check* request to this proxy. The ones a session needs are always sent and are not configurable — see below |
| `issuer.url` | from the fleet values | |
| `session.valkey.address` | from the fleet values | external to the chart: one Valkey per cluster shared by every proxy (recommended), or one per exposure |
| `session.valkey.username`, `.passwordSecret` | `""` | an ACL user per proxy for isolation inside a shared instance, optional |
| `session.lifetime`, `session.refresh` | `12h`, `5m` | |
| `client.secret.name`, `.keys.clientId`, `.keys.clientSecret` | `""`, `client-id`, `client-secret` | a Secret holding the client, and what its keys are called — the same shape the hub and the issuer use |
| `session.cookieSecret.name`, `.key` | required, `cookie-secret` | **an existing Secret; this chart will not mint one.** A generated cookie secret would be regenerated on every render that cannot read cluster state — which is what ArgoCD does — and every sync would sign everyone out |
| `exposure.attachRouteName` | `""` | ATTACH mode: bind the `SecurityPolicy` to an `HTTPRoute` another chart owns, and render no app route here. The normal case for a console whose own chart routes its hostname |
| `exposure.routes[]` | `[]` | more than one protected route on the same host, each `{name, attachRouteName \| backend+paths, posture, allow}` — a surface where a demo path is open to any employee and the app behind it is not. **Mutually exclusive** with the single-route fields above, which describe one route between them; setting both is refused, because the ignored one would be the protection somebody thought they had configured |
| `proxy.topologySpreadConstraints` | `[]` | passthrough |
| `exposure.proxyPrefix` | `/oauth2` | the paths this proxy owns; must agree with the client's registered redirect |
| `issuer.jwksUri` | derived | `{issuer}/keys`. Zitadel is the exception at `/oauth/v2/keys` |
| `session.scopes` | `""` | empty asks for openid, profile and email, plus `groups` when `allow` is set and `offline_access` when `refresh` is. Setting it by hand alongside `refresh` without `offline_access` **fails the render**: refresh cannot work without a refresh token, and the install would otherwise look correct and silently never refresh |
| `registration.enabled` | `false` | self-register at start. **Off, because the issuer does not serve `/register` yet** (RFC 7591); until it does, `client.secret.name` must name a static client |
| `proxy.image`, `proxy.replicaCount`, `proxy.resources`, `proxy.nodeSelector`, `proxy.tolerations` | from the fleet values | |
| `networkPolicy.enabled`, `.gatewayNamespace` | `false`, `""` | admits only the gateway to the proxy. Off by default, like the family's other charts: it is the second layer, not the trust boundary — the backend verifies the forwarded token, so reaching a port proves nothing |

The fleet values file carries everything an installation sets once for
every exposure; a console's own values are the four lines under
`exposure`.

Two things the chart does without being asked. `whitelist_domains`
always carries the **issuer's host** beside the console's, so a sign-out
can continue from the proxy's `/oauth2/sign_out` to the issuer's
`end_session` — without it oauth2-proxy refuses the redirect and a
sign-out ends one cookie while the issuer keeps the session. And the
proxy accepts **the issuer's tokens only**: a console is for people, and
a ServiceAccount token has no business at one
([../design/trust.md](../design/trust.md)).

## A Valkey for the proxies

With the valkey.io operator, one per cluster is enough:

```yaml
apiVersion: valkey.io/v1alpha1
kind: ValkeyCluster
metadata:
  name: access-proxy-sessions
  namespace: access-system
spec:
  # One shard, no replica. The operator still forms a real Valkey Cluster,
  # so `session.valkey.cluster` stays true here exactly as it would at
  # more shards.
  shards: 1
  replicas: 0
```

Point every exposure's fleet values at
`access-proxy-sessions.access-system.svc:6379`. Persistence is optional:
losing the store logs everyone out once.

## The headers Envoy sends the proxy

An HTTP ext_authz service is sent only `Host`, `Method`, `Path`,
`Content-Length` and `Authorization` unless the `SecurityPolicy` names
more, and **`Cookie` is not in that set**. This chart therefore always
names `cookie` — along with `x-forwarded-proto`, `x-forwarded-host`,
`x-forwarded-for`, `accept` and `user-agent` — and does not let a value
take it away.

The failure it prevents does not look like a missing header. Sign-in
completes, the callback returns a 302 with a `Set-Cookie`, and the very
next request logs `No valid authentication in request. Initiating
login.` — an endless loop through a login that works every time. The
tell is the access log: the looping request has an **empty user-agent**,
because it is not the browser's request at all, it is Envoy's check.
