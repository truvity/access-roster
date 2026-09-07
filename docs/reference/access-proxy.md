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
| `session.valkey.address` | from the fleet values | one Valkey per cluster shared by every proxy, or one per exposure |
| `session.lifetime`, `session.refresh` | `12h`, `5m` | |
| `registration.enabled` | `true` | self-register at start; off means `client.existingSecret` must name a static client |
| `proxy.image`, `proxy.nodeSelector`, `proxy.tolerations`, `proxy.topologySpreadConstraints` | from the fleet values | |
| `networkPolicy.enabled` | `true` | gateway → proxy, proxy → backend; the namespace label for the fleet egress policy |

The fleet values file carries everything an installation sets once for
every exposure; a console's own values are the four lines under
`exposure`.
