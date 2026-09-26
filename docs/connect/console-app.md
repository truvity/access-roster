# Connect a console

**Anchor:** the issuer — a console is for people. If the same service
also has an API that workloads call, that API is a second listener on the
other anchor: [service-to-service.md](service-to-service.md).

A web UI with a service API, behind the gateway, with two roles. What you
write, what you deploy, what you never implement.

## Three shapes, and which one is yours

|  | gateway-native OIDC | `access-proxy` in front (deprecated) | its own flow |
|---|---|---|---|
| **Use when** | the console has no authorization model of its own, or is not yours to change, and it sits behind Envoy Gateway | the same, on Envoy Gateway, until the chart is removed | you are writing it, and it needs identity *inside* itself |
| **Who runs the login** | the gateway's `SecurityPolicy`, which forwards a verified bearer | the proxy, and it forwards a verified bearer | the console: it sends a browser to `/authorize` and reads what comes back |
| **You deploy** | your chart plus a `SecurityPolicy` — no chart of ours | your chart plus one `access-proxy` release — Envoy Gateway only, it runs nowhere else | your chart |
| **The client is** | confidential: the gateway holds the secret, same as a proxy would | confidential: oauth2-proxy refuses to start without a secret | public, with PKCE — no secret to rotate |

**Gateway-native OIDC is the default for a console with no authorization
model of its own, on Envoy Gateway** — a `SecurityPolicy` with `oidc:`
against a declared client, gated by that client's `requires`, nothing of
ours in front
([ADR 0001](../decisions/0001-sessions-and-an-absolute-limit.md)).
`access-proxy` is deprecated, with removal planned
([ADR 0003](../decisions/0003-deprecate-access-proxy.md)): it is, and has
only ever been, Envoy Gateway's own external authorization backend, so
gateway-native OIDC replaces it there directly. **For a gateway that is
not Envoy Gateway**, this chart was never an option: the path is to run
upstream `oauth2-proxy` yourself, with a declared confidential client row
of this issuer, the way this chart already wires it — a documentation
page for that is planned, and it will not be a chart of ours. Write your
own flow (the right column above) when the console needs identity
*inside* itself: per-user authorization from `groups`, per-user audit, or
tokens of its own to call something else. `access-proxy`'s server-side
session store is not a reason to choose either gateway-fronted shape —
oauth2-proxy's encrypted cookie means nothing server-side, Back-Channel
Logout included, can end a session it holds
([design/access-proxy.md](../design/access-proxy.md)).

**A third shape exists and is not yours**: a console the issuer itself
serves, mounted on the issuer's own origin. It signs in as a client of
the issuer and then reads the SSO session directly rather than redeeming
the code, because the process holding the session is the one serving the
page. That is the directory console, and it is a property of that pair
rather than a pattern to copy.

## What you write

- **Backend in Go**: wrap everything in `identity.Middleware(issuer)` and
  put `identity.Require("all:myconsole:operator")` on the routes that
  need it. `Middleware` establishes and `Require` refuses — separate,
  because a health endpoint and a landing page run before anybody is
  established. Serve `identity.WhoAmI(version)` at
  `identity.WhoAmIPath`, which is what the frontend asks.
- **Backend in Node**: the same three pieces from
  `@truvity/access-roster/server` — `middleware(issuer)`,
  `requireGroups(...)`, and `whoami(version)` at `whoamiPath`, answering
  the same body Go does. Connect-style, so Express and Nest on Express
  take them as they are.
- **Frontend**: `useIdentity()` and `<UserBadge/>` from the TypeScript
  package, `@truvity/access-roster` on GitHub Packages
  ([installing it](../reference/typescript.md)). Views in the URL
  fragment, dist embedded in the binary.
- **Nothing else**: no login page, no session, no token parsing, no
  sign-out logic — and no signing-algorithm setting. Both verifiers accept
  what the issuer's discovery document advertises, so they follow the
  installation's key (ES384 with the chart's default, RS256 with an RSA
  key set at `signingKey.certificate`, e.g. `{algorithm: RSA, size: 2048,
  encoding: PKCS1}` for an installation whose other relying parties need
  RS256 — [reference](../reference/configuration.md)).

```go
issuer := &identity.Issuer{URL: "https://access.example", Audience: "myconsole.example.internal"}

mux := http.NewServeMux()
mux.Handle(identity.WhoAmIPath, identity.WhoAmI(version))
mux.Handle("/admin/", identity.Require("all:myconsole:operator")(admin))

http.ListenAndServe(":8080", identity.Middleware(issuer)(mux))
```

```ts
import express from "express";
import { Issuer, middleware, requireGroups, whoami, whoamiPath } from "@truvity/access-roster/server";

const issuer = new Issuer({ url: "https://access.example", audience: "myconsole.example.internal" });

const app = express();
app.use(middleware(issuer));
app.get(whoamiPath, whoami(version));
app.use("/admin", requireGroups("all:myconsole:operator"), admin);
```

Either way the caller carries `name`, `givenName` and `familyName` beside
the address and the groups, read from the access token. A console that
shows who is signed in has no userinfo call to make.

There is no `authz` package: role helpers over `Verified` are designed
and not built ([../reference/go-module.md](../reference/go-module.md)).
`Require` is what exists, and it takes the group names as the policy
spells them — the name in the policy is the name in the token is the name
in the check.

## What you deploy

The block below is `access-proxy`'s own shape — Envoy Gateway only, and
deprecated there in favour of a `SecurityPolicy` of the gateway's own
(not an access-roster chart, and not shown here). For a gateway that is
not Envoy Gateway, there is no chart at all: run `oauth2-proxy` yourself,
the way this one wires it. For your own flow, your chart alone and no
block like this at all:

```yaml
exposure:
  hostname: myconsole.example.internal
  backend: { name: myconsole, port: 8080 }
  posture: groups
  allow: [all:myconsole:operator, all:myconsole:viewer]
```

A platform that publishes its listeners as a `ListenerSet` is attached
to with `exposure.parentRefs` written out in full — `group`, `kind`,
`name`, `namespace` — in place of `exposure.gateway`
([values](../reference/access-proxy.md)).

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
    display_name: My Console            # what the sign-in page says: "Sign in to continue to My Console"
    description: the team's dashboard  # one line under it; both are shown to anyone who starts a sign-in
    redirects:  [https://myconsole.example.internal/oauth2/callback]
    signed_out: [https://myconsole.example.internal/]
    requires:   [all:myconsole:operator, all:myconsole:viewer]
    # backchannel_logout_uri: https://myconsole.example.internal/backchannel   # only a console running its own flow can take one
```

`display_name` and `description` are what the sign-in page shows in
place of "the application that sent you here", which is what every
phishing page also says; keep them free of anything a stranger should
not read. A console behind `access-proxy` cannot receive a back-channel
logout — oauth2-proxy keeps each session under a key only the browser's
cookie holds — so its window after a revoke is the proxy's refresh
interval; a console running its own flow may opt in with
`backchannel_logout_uri`.

`all:<app>:<role>` is an application role under the
[naming rule](../design/trust.md#naming): scoped to the tenant the app
serves, and `all` until the app can tell tenants apart. A console that
is really a view onto one cluster binds that cluster's tier instead
(`prod:k8s:viewer`), the way ArgoCD does.

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
