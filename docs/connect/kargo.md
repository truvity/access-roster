# Connect Kargo

**Anchor:** the issuer; Kargo runs its own OIDC flow. It maps claims to
its own roles and has a CLI that signs in on a loopback port, so it needs two
clients:

```yaml
clients:
  kargo:
    kind: public              # PKCE in the browser; Kargo's UI holds no secret
    redirects:
      - https://kargo.example.internal/
      - https://kargo.example.internal/login
    signed_out: [https://kargo.example.internal]
    requires:   [kernel:k8s:admin, kernel:k8s:viewer]
    ttl_cap: 5m               # the revocation window, see below
  kargo-cli:
    kind: public              # PKCE; the CLI's redirect is a loopback port
    loopback: true
    requires:   [kernel:k8s:admin, kernel:k8s:viewer]
```

Both are **public**: Kargo's UI is a single-page application that runs
the code flow itself with PKCE, and a secret it held would be a secret
in every browser. `groups` is on every token this issuer mints, so no
`additionalScopes` is needed to receive it.

Kargo's values:

```yaml
api:
  oidc:
    enabled: true
    issuerURL: https://issuer.example.internal
    clientID: kargo
    cliClientID: kargo-cli
    admins: { claims: { groups: [kernel:k8s:admin] } }   # the cluster tier, reused
```

Per-project roles bind on the `groups` claim through Kargo's own RBAC —
`<env>:<project>:approver` is the promotion gate, the same name the
policy mints for the project's approver unit.
Keep Kargo's admin account until a policy-granted admin has logged in.

## Sign-out and revocation, as Kargo actually does them

Kargo runs the flow itself, so what its buttons mean differs from a
console behind access-proxy — and it is worth knowing before somebody
reports it. Verified against Kargo 1.11.2 on 2026-09-12
([hack/verify_kargo.py](../../hack/verify_kargo.py) repeats it).

**Kargo's Logout drops its own tokens and nothing else.** The issuer
session stays listed, the sign-in stays, and the next click on *SSO
Login* is admitted with no password. Kargo has no RP-initiated logout —
there is no `end_session` anywhere in its source — so its button cannot
end the sign-in. Ending it is the console's **Sign out**, or the
issuer's `/logout`; after either, Kargo's next renewal is refused and
it asks again.

**A revoked session stops Kargo within `ttl_cap`.** There is no proxy to
refresh early: Kargo serves on its access token until it next renews,
the renewal is refused, and it drops its tokens and shows its login page
— about four minutes on a five-minute cap. Nothing replaces the session,
because Kargo does not start a new authorization on its own.

**A known Kargo defect, and why it looks like ours.** After a *silent*
sign-in — one the standing issuer sign-in admits without a prompt,
which is exactly what follows Kargo's own Logout — Kargo stores the
tokens, the issuer lists the session, and the page stays on
`/login?code=…` still showing the *SSO Login* button. Opening the root
shows the projects; the tokens were there all along. Reloading that URL
replays the authorization code, which the issuer refuses and, as the
specification requires, punishes by revoking what the code issued; Kargo
then renews, is refused, and signs in again — a fresh session for every
reload. Both were reported here as issuer faults ("session appears but
the page shows SSO Login", "refresh opens a new session").

The cause is in `ui/src/features/auth/oidc-login.tsx`: after a
successful exchange Kargo navigates only when a `redirectTo` was carried
into the flow, and its Logout lands on `/login` without one. The fix is
upstream and three lines — fall back to the home path when there is no
safe redirect. Until it lands: after a Logout-then-login, open the root
rather than reloading.
