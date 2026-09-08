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
   **Admin SDK API** on it. Missing this step does not fail where you would
   look for it: the consent screen appears, the administrator grants it,
   and the *first read* is refused. The console says so on the consent
   page, quoting Google's own message — which names the project number and
   links the page that enables the API — so the fix is a click from the
   failure rather than a search from it.
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
   - Authorised redirect URIs, **both** of them:
     - `https://<hub host>/connect/google/callback` — an administrator
       granting this hub read access to a company.
     - `https://<hub host>/login/google/callback` — a person signing in.

     They are separate because the two endpoints have opposite
     authorisation: the first adopts a workspace and demands an operator,
     the second is how a person becomes anyone at all. A client missing
     the second one works perfectly until somebody tries to sign in.
   - While the hub is being tried on a workstation, the same **pair** on
     `http://localhost:8081` may sit on the client — 8081 is the console
     listener, which is where both flows return. Remove them once the hub
     runs behind its real host.
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
   token acts as whoever consents and dies with that account.

   Use a **Super Admin**. The reads need *Users → Read*, *Groups → Read*
   and *Domain management → Read*, and the last of those is the one a
   narrower role tends not to satisfy: Google treats reading a customer's
   domain list as a super-admin act, and domain discovery is not optional
   here — it is what decides which addresses this hub answers for at all.
   A custom role carrying exactly the three may work; it fails as a 403 on
   the first read rather than at consent, which is a bad place to find
   out. This is also what Tailscale asks for, for the same scope.

   Super Admin is who CONSENTS, not what the token can do. The refresh
   token stays bounded by the four read-only scopes granted: it can read
   users, groups, memberships and domains, and nothing else — not mail,
   not drive, and nothing writable.
3. Click through the unverified-app interstitial if it appears, then
   consent. The redirect brings the browser back to the hub.
4. The hub records the consenting account, reads the tenant id and the
   domain list, and stores the workspace. If anything goes wrong here the
   console says so on a page, quoting the directory's own message. A
   consent Google granted and then refused on the first read is almost
   always the Admin SDK API not being enabled on the project (step 1 of
   the one-time setup); the message names the project and links the page
   that enables it.
5. **Choose the domains** *(0.8)*. The consenting administrator's own
   domain is pre-selected; the tenant's other domains are listed and off;
   *all, including ones added later* is an explicit option. Pick what
   this hub should answer for — the rest stays discovered and visible,
   but nothing routes to it and its accounts are never read.
6. The first snapshot runs in the background. The tenant's page shows
   *first snapshot pending* until it lands — seconds for a small tenant,
   a minute or two for a large one — then the served domains turn
   authoritative.

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
