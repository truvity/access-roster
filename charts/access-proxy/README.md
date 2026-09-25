# access-proxy

Login, session and forwarded bearer in front of one console.

Upstream oauth2-proxy runs as Envoy Gateway's external authorization
backend, with sessions in Valkey. **No request passes through code written
here**: the chart contributes the wiring and the conventions, and the
console implements none of it.

```yaml
exposure:
  hostname: myconsole.example.internal
  backend: { name: myconsole, port: 8080 }
  posture: authenticated
```

Everything else — the issuer, the Valkey, the proxy image, node placement —
is what an installation sets once for every exposure it has.

## Two postures

| Posture | Passes | For |
|---|---|---|
| `groups` | only callers whose token carries one of `allow`; the bearer is forwarded | consoles that gate on roles at the gateway |
| `authenticated` | any signed-in identity; the application authorizes itself | an application that already resolves roles from a directory it owns — a second copy of that decision here would be the stale one |

## Attach mode

A console whose own chart already routes its hostname sets
`exposure.attachRouteName` to that route's name. This chart then renders
only the `SecurityPolicy` and its own `/oauth2` route, and never claims the
hostname twice.

## Where the routes attach

By default every route this chart renders attaches to one Gateway
listener, named in `exposure.gateway`. Set `exposure.parentRefs` instead
to attach to anything the Gateway API accepts as a parent — a
`ListenerSet` that carries the hostname, or a Gateway and a ListenerSet
together while the hostname moves from one to the other:

```yaml
exposure:
  hostname: myconsole.example.internal
  parentRefs:
    - group: gateway.networking.k8s.io
      kind: ListenerSet
      name: myconsole
      namespace: gateway-system
```

The list is used as written, for the proxy's own route and the console's
alike. Write `group` and `kind` out: the API server fills them in, and a
tool comparing desired with live state reads their absence as drift.

## What it will not do for you

**Mint the cookie secret.** A chart that generated one would generate a new
one on every render that cannot read cluster state — which is what ArgoCD
does — and every sync would sign everyone out. Name an existing Secret;
what produced it is your business.

**Mint the client.** A confidential client like this one is always
**declared**, so that
the set of them is answerable by reading a repository rather than by
querying the running service. Name the Secret holding this one in
`client.secret.name`. Self-registration was designed and dropped:
only a proxy could ever have called such an endpoint, and an
endpoint that mints clients is the one surface an issuer least wants.

See [docs/reference/access-proxy.md](../../docs/reference/access-proxy.md)
for every value, and [docs/design/access-proxy.md](../../docs/design/access-proxy.md)
for why it is shaped this way.

The console of access-roster itself needs none of this: it signs in as
a client of the issuer it shares an origin with.
