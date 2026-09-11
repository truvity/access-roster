# Connect a console

**Anchor:** the issuer — a console is for people. If the same service
also has an API that workloads call, that API is a second listener on the
other anchor: [service-to-service.md](service-to-service.md).

A web UI with a service API, behind the gateway, with two roles. What you
write, what you deploy, what you never implement.

## Two shapes, and which one is yours

|  | `access-proxy` in front | its own flow |
|---|---|---|
| **Use when** | the console has no OpenID flow of its own, or is not yours to change — hubble, and most third-party UIs | you are writing it |
| **Who runs the login** | the proxy, and it forwards a verified bearer | the console: it sends a browser to `/authorize` and reads what comes back |
| **You deploy** | your chart plus one `access-proxy` release | your chart |
| **The client is** | confidential: oauth2-proxy refuses to start without a secret | public, with PKCE — no secret to rotate |

**A third shape exists and is not yours**: a console the issuer itself
serves, mounted on the issuer's own origin. It signs in as a client of
the issuer and then reads the SSO session directly rather than redeeming
the code, because the process holding the session is the one serving the
page. That is the directory console (INF-701), and it is a property of
that pair rather than a pattern to copy.

## What you write

- **Backend in Go**: wrap everything in `identity.Middleware(issuer)` and
  put `identity.Require("all:myconsole:operator")` on the routes that
  need it. `Middleware` establishes and `Require` refuses — separate,
  because a health endpoint and a landing page run before anybody is
  established. Serve `identity.WhoAmI(version)` at
  `identity.WhoAmIPath`, which is what the frontend asks.
- **Frontend**: `useIdentity()` and `<UserBadge/>` from the TypeScript
  package. Views in the URL fragment, dist embedded in the binary.
- **Nothing else**: no login page, no session, no token parsing, no
  sign-out logic.

```go
issuer := &identity.Issuer{URL: "https://access.example", Audience: "myconsole.example.internal"}

mux := http.NewServeMux()
mux.Handle(identity.WhoAmIPath, identity.WhoAmI(version))
mux.Handle("/admin/", identity.Require("all:myconsole:operator")(admin))

http.ListenAndServe(":8080", identity.Middleware(issuer)(mux))
```

There is no `authz` package: role helpers over `Verified` are designed
and not built ([../reference/go-module.md](../reference/go-module.md)).
`Require` is what exists, and it takes the group names as the policy
spells them — the name in the policy is the name in the token is the name
in the check.

## What you deploy

For the proxied shape, your chart plus one `access-proxy` release. For
your own flow, your chart alone and no block like this at all:

```yaml
exposure:
  hostname: myconsole.example.internal
  backend: { name: myconsole, port: 8080 }
  posture: groups
  allow: [all:myconsole:operator, all:myconsole:viewer]
```

Your console keeps **its own hostname**. The one exception in the family
is the directory console, which shares its issuer's hostname under
`/console/` so that its session pages are same-origin with the issuer —
the third shape above, and a property of that pair rather than a pattern
for yours.

and the policy that puts people in those groups and admits them to the
client — the group's **name** is the value in the token, so name it what
the console checks:

```yaml
groups:
  all:myconsole:operator: { members: [myconsole-admins@example.com] }
  all:myconsole:viewer:   { members: [everyone@example.com] }
clients:
  myconsole.example.internal:
    # Proxied: confidential, because oauth2-proxy refuses to start with
    # no secret. Running your own flow in a browser: `kind: public`, no
    # secret, and the redirect is your own callback rather than the
    # proxy's.
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
token at all, so on the proxied shape the proxy never sees a session. The
proxy's `allow` above is defence in depth and the place to narrow one
route further.

**Never register your sign-out landing page as a redirect too.** Landing
on a redirect URI starts the sign-in the person just ended, and the
render refuses the combination for that reason. If your front page sends
an unauthenticated browser to `/authorize`, then your front page is not a
place to land after signing out — leave `signed_out` off and the issuer
shows its own page, which says what happened.

DNS for the hostname, and the namespace label the fleet egress policy
selects, are the deployment's two remaining edits.

## Traps that were real

- Long work inside a request dies at the gateway's route timeout: trigger
  and poll.
- Test authorization at the handler level, not on the pure function; a
  role check that exists and is never wired passes its unit test.
- The console listener and the service API are two listeners for a
  reason; never mount an operator RPC on the API port.
