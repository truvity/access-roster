# TypeScript package `access-roster`

What a console needs from the identity it is behind: who the caller is,
what that gets them, and the way out. It parses no token — the browser
asks the application it is already talking to, and the application, which
has verified whatever the proxy or the issuer gave it, answers. A package
that verified tokens in a browser would need the issuer's keys, its clock
and its rules in every console.

```sh
npm install github:truvity/access-roster#v0.2.0
```

Installed from git, with `ts/dist` committed, so it needs no toolchain and
no registry. `react` and `@mui/material` are optional peers: an
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

Generated Connect-Web clients for the hub's console services. The hub's
own console is in this repository and generates them itself; no other
console calls those services, so shipping them would be surface with no
consumer. `fetchIdentity` is deliberately the whole of the network code.
