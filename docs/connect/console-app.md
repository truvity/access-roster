# Connect a console

**Anchor:** the issuer, through `access-proxy` — a console is for
people. If the same service also has an API that workloads call, that
API is a second listener on the other anchor:
[service-to-service.md](service-to-service.md).

A web UI with a service API, behind the gateway, with two roles. What you
write, what you deploy, what you never implement.

## What you write

- **Backend in Go**: mount `identity/httpmw` (or fiber, gRPC, connect) with
  a bearer verifier for the issuer and your hostname as audience; gate
  write handlers with `authz.Role("operator")`. That serves
  `/.access/whoami` too.
- **Frontend**: `useIdentity()` and `<UserBadge/>` from the TypeScript
  package. Views in the URL fragment, dist embedded in the binary.
- **Nothing else**: no login page, no session, no token parsing, no
  sign-out logic.

## What you deploy

Your chart, plus one `access-proxy` release:

```yaml
exposure:
  hostname: myconsole.example.internal
  backend: { name: myconsole, port: 8080 }
  posture: groups
  allow: [all:myconsole:operator, all:myconsole:viewer]
```

Your console keeps **its own hostname**. The one exception in the family
is the directory console itself, which shares its issuer's hostname under
`/console/` so that its session pages are same-origin with the issuer;
that is a property of that pair, not a pattern for yours.

and the policy that puts people in those groups and admits them to the
client — the group's **name** is the value in the token, so name it what
the console checks:

```yaml
groups:
  all:myconsole:operator: { members: [myconsole-admins@example.com] }
  all:myconsole:viewer:   { members: [everyone@example.com] }
clients:
  myconsole.example.internal:
    kind: confidential
    secret: myconsole-client
    redirects:  [https://myconsole.example.internal/oauth2/callback]
    signed_out: [https://myconsole.example.internal/]
    requires:   [all:myconsole:operator, all:myconsole:viewer]
```

`all:<app>:<role>` is an application role under the
[naming rule](../design/trust.md#naming): scoped to the tenant the app
serves, and `all` until the app can tell tenants apart. A console that
is really a view onto one cluster binds that cluster's tier instead
(`kernel:k8s:viewer`), the way ArgoCD does.

`requires` is the primary gate — nobody outside those groups gets a
token, so the proxy never sees a session. The proxy's `allow` above is
defence in depth and the place to narrow one route further.

DNS for the hostname, and the namespace label the fleet egress policy
selects, are the deployment's two remaining edits.

## Traps that were real

- Long work inside a request dies at the gateway's route timeout: trigger
  and poll.
- Test authorization at the handler level, not on the pure function; a
  role check that exists and is never wired passes its unit test.
- The console listener and the service API are two listeners for a
  reason; never mount an operator RPC on the API port.
