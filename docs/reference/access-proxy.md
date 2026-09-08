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
| `issuer.url` | from the fleet values | |
| `session.valkey.address` | from the fleet values | external to the chart: one Valkey per cluster shared by every proxy (recommended), or one per exposure |
| `session.valkey.username`, `.passwordSecret` | `""` | an ACL user per proxy for isolation inside a shared instance, optional |
| `session.lifetime`, `session.refresh` | `12h`, `5m` | |
| `client.secret.name`, `.keys.clientId`, `.keys.clientSecret` | `""`, `client-id`, `client-secret` | a Secret holding the client, and what its keys are called — the same shape the hub and the issuer use |
| `session.cookieSecret.name`, `.key` | required, `cookie-secret` | **an existing Secret; this chart will not mint one.** A generated cookie secret would be regenerated on every render that cannot read cluster state — which is what ArgoCD does — and every sync would sign everyone out |
| `exposure.attachRouteName` | `""` | ATTACH mode: bind the `SecurityPolicy` to an `HTTPRoute` another chart owns, and render no app route here. The normal case for a console whose own chart routes its hostname |
| `exposure.proxyPrefix` | `/oauth2` | the paths this proxy owns; must agree with the client's registered redirect |
| `issuer.jwksUri` | derived | `{issuer}/keys`. Zitadel is the exception at `/oauth/v2/keys` |
| `session.scopes` | `""` | empty asks for openid, profile and email, plus `groups` when `allow` is set and `offline_access` when `refresh` is. Setting it by hand alongside `refresh` without `offline_access` **fails the render**: refresh cannot work without a refresh token, and the install would otherwise look correct and silently never refresh |
| `registration.enabled` | `false` | self-register at start. **Off, because the issuer does not serve `/register` yet** (RFC 7591); until it does, `client.secret.name` must name a static client |
| `proxy.image`, `proxy.replicaCount`, `proxy.resources`, `proxy.nodeSelector`, `proxy.tolerations` | from the fleet values | |
| `networkPolicy.enabled`, `.gatewayNamespace` | `false`, `""` | admits only the gateway to the proxy. Off by default, like the family's other charts: it is the second layer, not the trust boundary — the backend verifies the forwarded token, so reaching a port proves nothing |

The fleet values file carries everything an installation sets once for
every exposure; a console's own values are the four lines under
`exposure`.

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
