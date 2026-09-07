# TypeScript package `access-roster`

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
