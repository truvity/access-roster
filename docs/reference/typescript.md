# TypeScript package `access-roster`

> **Not built yet, as of v0.1.0.** This page is the design of the package,
> written in the present tense because that is how the interface will
> read. What exists at that tag is the policy engine (`policy`) and the
> backend interface (`backend`); the rest is the work that replaces
> gateway-auth in the consoles. Nothing in the hub's rollout depends on
> it.


```sh
npm install github:truvity/access-roster#v1
```

```tsx
import { useIdentity, UserBadge } from "access-roster/react";

function Header() {
  const me = useIdentity();            // fetches /.access/whoami once
  return <UserBadge identity={me} />;  // name, roles, sign out
}
```

`useIdentity()` returns `{status: "loading" | "signed-in" | "signed-out",
email?, name?, roles?, expiresAt?, signOutUrl?}`. It parses no token; it
trusts the application's own origin to answer `/.access/whoami`, which
every Go adapter serves. Generated Connect-Web clients for the hub's
console services are under `access-roster/gen`.
