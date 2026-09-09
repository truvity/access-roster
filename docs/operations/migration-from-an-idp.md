# Migrating from an identity provider run for infrastructure

You run an IdP whose only job is infrastructure access, plus the pieces
around it: a directory reader per tenant, a login hook that computes
roles, a broker that mints machine tokens, a per-console client minted by
an operator. This is the order that retires them without a day of broken
logins.

1. **Hub first, beside everything.** Deploy directory-roster with the
   existing service-account keys as declared workspaces. Move the login
   hook's directory reads to the hub's Connect client, honouring
   `authoritative`. Nothing user-visible changes; the per-tenant readers
   retire.
2. **Issuer beside the IdP.** Deploy access-issuer with the policy
   rendered from the same access matrix the login hook reads, so the
   internal group **names** are the strings the IdP mints today —
   **decode a live token from each and diff the two `groups` lists
   before anything is rewired.** The differences are what would turn a
   provider flip into a rebind; fix them in the derivation, not in the
   bindings. No relying party trusts the issuer yet.
3. **One console as the pilot.** Put it behind access-proxy pointed at the
   new issuer. Its role checks do not change, because the `groups` values
   did not. Make sure sign-out ends the issuer session, not only the
   proxy's, before the second console — or the first report from every
   pilot is "it signed me straight back in". Watch a day of logins.
4. **Clusters.** Add the new issuer as the API server's OIDC provider; on
   platforms that allow one provider per cluster, this is a flip per
   cluster, non-production first. Distribute kubeconfigs with
   `accessctl kubeconfig`.
5. **Cloud accounts.** Add the IAM OIDC provider for the new issuer and a
   trust condition on the audience beside the old one; move people to
   `accessctl aws`; remove the old condition.
6. **CI.** Replace the broker's client in workflows with the action.
   Rules on repository and ref replace the broker's mapping.
7. **The rest of the consoles**, the CD system, the CLIs.
8. **Retire.** When the old IdP has no relying party left: the IdP, its
   database and operator, the login hook, the broker, the minted clients.

Every step is reversible by pointing one consumer back at the old issuer,
which keeps running until step 8.
