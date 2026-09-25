# Migrating from an identity provider run for infrastructure

You run an IdP whose only job is infrastructure access, plus the pieces
around it: a directory reader per tenant, a login hook that computes
roles, a broker that mints machine tokens, a per-console client minted by
an operator. This is the order that retires them without a day of broken
logins.

1. **The service first, beside everything.** Deploy access-issuer with
   the existing service-account keys as declared workspaces, an audit
   installation connected, and the policy rendered from the same access matrix the login
   hook reads, so the internal group **names** are the strings the IdP
   mints today — **decode a live token from each and diff the two
   `groups` lists before anything is rewired.** The differences are what
   would turn a provider flip into a rebind; fix them in the derivation,
   not in the bindings. No relying party trusts the issuer yet, and
   nothing user-visible changes.
2. **The directory reads move.** Whatever the login hook read per tenant
   is answered by the console's `Explain` and `ListHolders` now,
   honouring `authoritative`; the per-tenant readers retire.
3. **One console as the pilot.** Point it at the new issuer: on Envoy
   Gateway, gateway-native OIDC (a `SecurityPolicy` with `oidc:` against a
   declared client) — `access-proxy` is deprecated and runs only there
   too ([ADR 0003](../decisions/0003-deprecate-access-proxy.md)). On any
   other gateway, run upstream oauth2-proxy yourself with a declared
   confidential client row. Its role checks do not change, because the
   `groups` values did not. Make sure sign-out ends the issuer session,
   not only the gateway's or the proxy's, before the second console — or
   the first report from every pilot is "it signed me straight back in".
   Watch a day of logins.
4. **Clusters.** Add the new issuer as the API server's OIDC provider; on
   platforms that allow one provider per cluster, this is a flip per
   cluster, non-production first. Put `accessctl` on every laptop through
   its Nix flake, and distribute kubeconfigs with `accessctl setup`.
5. **Cloud accounts.** Add the IAM OIDC provider for the new issuer and a
   trust condition on the audience beside the old one; move people to
   `accessctl aws`; remove the old condition.
6. **CI.** Replace the broker's client in workflows with the action, or
   with the same `accessctl` files a laptop uses. Rules on repository,
   ref and visibility replace the broker's mapping.
7. **The rest of the consoles**, the CD system, the CLIs.
8. **GitHub organisations.** Bind their teams in the policy, connect each
   from the console, read the dry run on its page, then list it in
   `githubRoster.actsIn`; the tool that synced teams before retires with
   it, and the pairings it approved are imported once.
9. **Retire.** When the old IdP has no relying party left: the IdP, its
   database and operator, the login hook, the broker, the minted clients,
   and its audit log, which the audit installation's trail replaces.

Every step is reversible by pointing one consumer back at the old issuer,
which keeps running until step 9.
