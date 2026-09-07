# Connecting a Google Workspace

Two parts: a one-time prerequisite per installation, and a repeatable
per-workspace step. The one-time part is the only place a cloud console is
involved.

## One-time, per installation: the OAuth client

The admin-consent flow works the way a SaaS vendor's does — the vendor
registers one OAuth client, every tenant connects by clicking through
consent. Here the installation is its own vendor, so this is done once per
installation, never per company. About fifteen minutes.

1. **A Google Cloud project owned by the installation.** Any name; it will
   hold exactly one OAuth client and nothing else. Enable the
   **Admin SDK API** on it.
2. **The consent screen** (Google Auth Platform → Branding / Audience):
   - Audience: **External**. Internal accepts only the tenant that owns the
     project; an installation serves several.
   - Publishing status: **In production**. In Testing, refresh tokens
     expire after seven days and the workspace goes stale silently.
   - App name, support email, developer contact: whatever identifies the
     installation to the admins who will consent.
3. **Scopes** (Data access), all read-only:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`

   The domain scope is what makes domain discovery possible. Restricted
   scopes trigger Google's verification process; these four are
   "sensitive", which only produces the unverified-app interstitial.
4. **The OAuth client** (Clients → Create → Web application):
   - Authorised redirect URI: `https://<hub host>/connect/google/callback`.
   - While the hub is being tried on a workstation, a second URI
     `http://localhost:8080/connect/google/callback` may be added; remove
     it once the hub runs behind its real host.
5. **Hand the client to the hub**, one of two ways:
   - paste the client id and secret into the console's Settings once; or
   - create a Secret with keys `client-id` and `client-secret` in the hub's
     namespace and set `oauthClient.existingSecret` — the console then
     shows the client read-only.

Verification by Google is optional. Unverified, the consent screen shows
"Google hasn't verified this app" and the admin clicks *Advanced → Go to
… (unsafe)*. A tenant admin can also mark the client id as trusted in the
Workspace admin console (Security → API controls → Manage third-party app
access), which removes the interstitial for that tenant and is required
where the tenant's policy blocks unconfigured apps. Verification needs a
public homepage, a privacy policy and a scope justification, takes days,
and only removes the interstitial.

## Per workspace, repeatable

1. In the console, an operator presses **Connect Google Workspace**.
   Nothing to fill in.
2. The browser lands on Google's consent screen. Sign in as the tenant's
   **admin role account** — a role account, not a person: the refresh
   token acts as whoever consents and dies with that account. It needs the
   Admin console privileges *Users → Read* and *Groups → Read*, and
   *Domain management → Read* for discovery. A Super Admin has them; a
   custom admin role with exactly those is better.
3. Click through the unverified-app interstitial if it appears, then
   consent. The redirect brings the browser back to the hub.
4. The hub records the consenting account, reads the customer id and the
   domain list, runs a first probe and stores the workspace. The
   Workspaces view shows the discovered domains; they become
   authoritative as soon as the first snapshot lands (seconds to a
   minute, depending on directory size).

### The second way in: a service-account key

For installations that prefer a robot identity or cannot publish an
external consent screen. In the Google Cloud project: a service account,
a JSON key, and **domain-wide delegation** granted in the Workspace admin
console to the service account's client id for the same four scopes. Then
in the console: **Upload key**, the JSON file and the admin address to
impersonate. Same record, different credential type. A declared
(overlay) workspace is this path expressed in chart values.

## Afterwards

- **Reconnect** is the same button on an existing workspace. Use it when
  the probe fails: a revoked token, a suspended or deleted admin account,
  a changed tenant policy. The consenting tenant must be the same
  workspace; a different one is refused.
- **Disconnect** revokes the token at Google and deletes the credential
  and the record. The domains stop being served — consumers get
  `in_domain=false`, no opinion, for those addresses.
- **A domain moves** to another tenant: connect the new workspace; on its
  next probe the old one stops listing the domain and the new one lists
  it. During the overlap the domain is authoritative for neither; the
  console shows the conflict.
