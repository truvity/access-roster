# Connect a corporate directory

Google Workspace today, read through the Admin SDK Directory API. Microsoft
Entra is designed behind the same workspace record but not built: no
`entra` backend exists yet, and adding one is described in
[development/extending.md](../development/extending.md).

## Two ways in, one set of scopes

Both credential types read the same four read-only scopes, and nothing
wider — no mail, no drive, nothing writable:

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
- `https://www.googleapis.com/auth/admin.directory.domain.readonly`

The domain scope is what makes domain discovery possible at all: which
addresses this service answers for is decided by reading a tenant's own
domain list, not by configuration.

**Admin consent, through the console.** The installation registers one
OAuth client, the way a SaaS vendor would, and every company connects by
clicking through consent — once per installation, not per company. An
operator presses *Connect Google Workspace*, a Super Admin of the tenant
signs in and consents, and the service stores the resulting refresh
token, discovers the tenant id and its domains, and takes the first
snapshot. The refresh token acts as whoever consented and is bounded by
exactly those four scopes; it dies with the admin account, not with a
person's tenure in it.

**A service-account key, with domain-wide delegation.** For an
installation that prefers a robot identity, or cannot publish an external
consent screen: a service account's JSON key, with domain-wide delegation
granted in the Workspace admin console to the service account's client id
for the same four scopes. The key impersonates a chosen admin address
(`Subject` in the credential, not a separate sign-in) and reads exactly
what the consent flow's refresh token would. Revocation differs by type
too: a console *Disconnect* revokes an OAuth refresh token at Google, but
a service-account key has nothing to revoke there — deleting the key or
the delegation grant is what ends it.

The full click-through for both — the one-time Google Cloud project and
OAuth client, the consent-screen traps (Testing mode's seven-day refresh
tokens, the Admin SDK API that must be enabled before the first read),
and the per-workspace steps — is
[operations/connect-runbook.md](../operations/connect-runbook.md).

## Chart values

The OAuth client is named once per installation:

```yaml
oauthClient:
  secret: { name: google-oauth-client }   # keys client-id and client-secret
```

A service-account key is a **declared workspace**, in the chart's
overlay, rather than a console click — this is how an installation that
already holds keys goes live on day one:

```yaml
directory:
  workspaces:
    - id: C0example              # the backend's tenant id (Google: the customer id)
      backend: google
      admin: admin@example.com   # the account the key impersonates
      secretName: example-sa-key # a Secret in this namespace, key.json holding the JSON key
      serve: [example.com]       # optional; omitted serves every domain the tenant owns
```

Every value, including `syncGroups` and what the chart renders from this
block, is in
[reference/configuration.md#declared-workspaces-the-overlay](../reference/configuration.md#declared-workspaces-the-overlay).
A declared workspace is read-only in the console: remove it from the
values to disconnect it, rather than clicking there.

## What connecting leaves behind

A record in a ConfigMap the console shows and a credential in
`Secret <release>-workspace-credentials`, one key per workspace, the
credential carrying a copy of its record. That Secret, with the three the
GitHub page writes, is the whole backup of what a console added: put them
back and the next start rebuilds the records
([configuration](../reference/configuration.md#restoring-from-the-secrets-alone)).
Connecting and disconnecting are recorded in the audit trail.
