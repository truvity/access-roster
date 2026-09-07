# Connect a console

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
  allow: [myconsole:operator, myconsole:viewer]
```

and two lines of policy that mint those values:

```yaml
groups: { myconsole-admins: { members: [myconsole-admins@example.com] } }
claims: { myconsole-admins: { groups: [myconsole:operator] } }
```

DNS for the hostname, and the namespace label the fleet egress policy
selects, are the deployment's two remaining edits.

## Traps that were real

- Long work inside a request dies at the gateway's route timeout: trigger
  and poll.
- Test authorization at the handler level, not on the pure function; a
  role check that exists and is never wired passes its unit test.
- The console listener and the service API are two listeners for a
  reason; never mount an operator RPC on the API port.
