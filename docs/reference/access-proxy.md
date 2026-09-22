# access-proxy — values

| Value | Default | Meaning |
|---|---|---|
| `exposure.hostname` | required | the console host; also the client id and the cookie domain |
| `exposure.backend.name`, `.port` | required unless `attachRouteName` is set; `.port` `8080` | the console's Service |
| `exposure.posture` | `groups` | `groups` or `authenticated` |
| `exposure.allow[]` | `[]` | `groups` values that pass, for the `groups` posture |
| `exposure.gateway.name`, `.namespace`, `.sectionName` | from the fleet values | the Gateway listener to attach the HTTPRoute to |
| `exposure.parentRefs[]` | `[]` | parents for every route, written out in full; **replaces `gateway` when set**. For a `ListenerSet`, or a Gateway and a ListenerSet together while a hostname moves from one to the other. Write `group` and `kind` out (`gateway.networking.k8s.io` / `ListenerSet`): the API server fills them in, and a tool that compares desired with live state reads a missing field as drift |
| `exposure.paths[]` | `["/"]` | routes to protect; anything unlisted gets no route |
| `exposure.forward.authorizationHeader` | `true` | forward the bearer as `Authorization` besides the proxy's identity headers |
| `exposure.forward.extraExtAuthHeaders[]` | `[]` | extra client request headers Envoy includes in the *check* request to this proxy. The ones a session needs are always sent and are not configurable — see below |
| `issuer.url` | from the fleet values | |
| `session.valkey.address` | from the fleet values | external to the chart: one Valkey per cluster shared by every proxy (recommended), or one per exposure |
| `session.valkey.username`, `.passwordSecret` | `""` | an ACL user per proxy for isolation inside a shared instance, optional |
| `session.lifetime`, `session.refresh` | `12h`, `1m` | the refresh is the revocation window: a proxied console cannot receive a back-channel logout, so a revoke at the issuer reaches it at the next refresh, and a minute is what "how long until they are out" answers |
| `session.valkey.cluster` | `false` | the cluster protocol. Off with one shard: in cluster mode the client pins to node addresses, and a Valkey that moves never comes back |
| `session.identityClaim` | `sub` | the claim the session is keyed by. Getting it wrong locks the recovery sign-in out with "neither the id_token nor the profileURL set an email" |
| `proxy.port` | `4180` | |
| `client.secret.name`, `.keys.clientId`, `.keys.clientSecret` | `""`, `client-id`, `client-secret` | a Secret holding the client, and what its keys are called — the same shape the issuer uses |
| `session.cookieSecret.name`, `.key` | required, `cookie-secret` | **an existing Secret; this chart will not mint one.** A generated cookie secret would be regenerated on every render that cannot read cluster state — which is what ArgoCD does — and every sync would sign everyone out |
| `exposure.attachRouteName` | `""` | ATTACH mode: bind the `SecurityPolicy` to an `HTTPRoute` another chart owns, and render no app route here. The normal case for a console whose own chart routes its hostname |
| `exposure.routes[]` | `[]` | more than one protected route on the same host, each `{name, attachRouteName \| backend+paths, posture, allow}` — a surface where a demo path is open to any employee and the app behind it is not. **Mutually exclusive** with the single-route fields above, which describe one route between them; setting both is refused, because the ignored one would be the protection somebody thought they had configured |
| `proxy.topologySpreadConstraints`, `proxy.podAnnotations` | `[]`, `{}` | passthrough |
| `exposure.proxyPrefix` | `/oauth2` | the paths this proxy owns; must agree with the client's registered redirect. For a console mounted under a path of its host (the directory console at `/console/`), the prefix moves under it: `/console/oauth2` |
| `issuer.jwksUri` | derived | `{issuer}/keys`. Zitadel is the exception at `/oauth/v2/keys` |
| `session.scopes` | `""` | empty asks for openid, profile and email, plus `groups` when `allow` is set and `offline_access` when `refresh` is. Setting it by hand alongside `refresh` without `offline_access` **fails the render**: refresh cannot work without a refresh token, and the install would otherwise look correct and silently never refresh |
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
  # One shard, no replica. Leave `session.valkey.cluster` at its default,
  # false: with one shard there is nothing to shard, and cluster mode
  # would make the client pin to a node address a moved Valkey no longer
  # answers on.
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
