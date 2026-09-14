# TypeScript package `@truvity/access-roster`

What a console needs from the identity it is behind: who the caller is,
what that gets them, and the way out. The browser half parses no token —
the browser asks the application it is already talking to, and the
application, which has verified whatever the gateway or the issuer gave
it, answers. A package that verified tokens in a browser would need the
issuer's keys, its clock and its rules in every console.

That verification is the server half, under `/server`, for an
application whose backend is Node. It is the Go `identity` package's
issuer anchor in TypeScript: the same checks, the same caller, the same
`whoami` body — see [The server half](#the-server-half).

Published to GitHub Packages by each release, at the tag's version
(`v1.5.0` publishes `1.5.0`), built and tested once in the release
workflow. The package is the repository root — `ts/package.json` is the
inner build and is not what anybody installs — which is why the import
path has no `-ts` in it.

GitHub's npm registry needs a token to install, even a public package:
one with `read:packages` (a job's `GITHUB_TOKEN` with
`packages: read`, or `gh auth token` after `gh auth refresh -s
read:packages` on a laptop). Point the `@truvity` scope at it:

```yaml
# .yarnrc.yml (yarn 4)
npmScopes:
  truvity:
    npmRegistryServer: "https://npm.pkg.github.com"
    npmAuthToken: "${GITHUB_PACKAGES_TOKEN}"
```

```ini
# .npmrc (npm)
@truvity:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_PACKAGES_TOKEN}
```

```sh
yarn add @truvity/access-roster@^1.8.0
```

A git install (`github:truvity/access-roster#<tag>`) no longer works:
`ts/dist` is not committed, and nothing builds it on install. `react` and `@mui/material` are optional peers: an
application with neither pays for neither.

```tsx
import { useIdentity, UserBadge } from "@truvity/access-roster/react";

function Header() {
  const me = useIdentity();          // asks /.access/whoami once
  return <UserBadge identity={me} />;
}
```

## Four states, not three

```ts
type Status = "loading" | "signed-in" | "signed-out" | "unknown";
```

`unknown` is the one worth explaining, and the reason this returns a
status rather than an identity or null: it means the question could not
be *asked*. A console that showed a sign-in button because one request
failed would send a signed-in person to authenticate again for nothing —
the same mistake, in a browser, that this project refuses to make in a
directory. A 401 or a 403 is an answer and reads as `signed-out`; a
network failure or a 502 does not.

`UserBadge` renders all four, including that one.

## What comes back

```ts
interface Identity {
  status: Status;
  email?: string;
  name?: string;
  givenName?: string;
  familyName?: string;
  roles?: string[];    // what the policy grants: ["operator", "viewer"]
  groups?: string[];   // the internal groups behind those roles
  source?: string;     // "directory" | "forwarded" | "recovery"
  version?: string;    // the build the application is running
  signOutUrl?: string;
  error?: string;      // only when status is "unknown"
}
```

Those are the fields `/.access/whoami` actually serves, which every Go
adapter in this family answers with. `useIdentity()` asks once on mount
and aborts on unmount: the answer changes when a session ends, and that is
something the application discovers on its next call rather than something
a poll would catch usefully.

## Not here

Generated Connect-Web clients for the console's services. The console
is in this repository and generates them itself; no other
console calls those services, so shipping them would be surface with no
consumer. `fetchIdentity` is deliberately the whole of the network code.

## The server half

```ts
import { Issuer, middleware, requireGroups, whoami, whoamiPath, identityOf } from "@truvity/access-roster/server";

const issuer = new Issuer({ url: "https://access.example", audience: "url-shortener-devel" });

app.use(middleware(issuer));                       // establishes, never refuses
app.get(whoamiPath, whoami(version));              // what useIdentity() asks
app.use("/admin", requireGroups("devel:url-shortener:deployer"));
app.get("/me", (req, res) => res.json(identityOf(req)));
```

- **`Issuer`** verifies an access token against the issuer's published
  keys: signature, `iss`, expiry, and an `aud` of this service's own client
  id. The audience is required — a token minted for another service is a
  valid token, and accepting it would make every audience the issuer
  serves a way in. Discovery is lazy, so the service starts whether or not
  the issuer is up.
- **Two errors, not one.** `Unverified` is a token that did not verify,
  and says nothing about why. `IssuerUnreachable` is an outage; never
  answer it with a 401, which would send a signed-in person back to sign in
  for nothing.
- **`middleware`** reads the token from `x-auth-request-access-token` or
  the bearer, and establishes the caller for `identityOf(request)`. It
  refuses nothing, because some routes run before anybody is established.
  `requireGroups` refuses: 401 for nobody, 403 for the wrong groups, and it
  never names the groups that would have worked.
- **What a caller is:** `subject`, `email`, `name`, `givenName`,
  `familyName`, `groups`, and `serviceAccount` for a workload. The names are
  for display; never authorize on them.

Only the issuer anchor is here. A ServiceAccount token from the pod next
door is verified with the Kubernetes API, which is Go's `Cluster`; a Node
service reaches its callers through the issuer.
