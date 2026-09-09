# Runbook

Day-two operations. Everything here is visible on a tenant's page in the
console and in `Describe`; nothing needs a shell except the export.

## Day one

**A deployment that declares its own way in has no day one.** Values that
carry a workspace and a non-empty `hub-operators` are signed into through
the directory from the first boot. Nothing below applies; go to
[the connect runbook](connect-runbook.md) when you add the next tenant.

**A standalone installation configures itself through the console**, and
the console leads it. Overview shows what is left to do until nothing is,
with this installation's own values to copy rather than a placeholder to
translate — the redirect URI is its hostname, and that is where a day-one
setup goes wrong.

1. Install. The hub generates `Secret <release>-session-key` and creates
   the ServiceAccount `<release>-recovery`. There is no password anywhere.
2. Mint a recovery token — a cluster administrator already has the RBAC
   for this, and granting `create` on `serviceaccounts/token` for that
   account is how you give it to somebody else:

   ```sh
   kubectl -n directory-roster create token <release>-recovery \
     --audience <release>-recovery --duration 10m
   ```

3. Port-forward the console port (or go through the gateway), open
   `/login`, expand **Recovery sign-in** and paste the token.
4. Follow Overview. It walks the four steps: register an OAuth client with
   the directory, give it to the hub, connect the first directory, and
   attach a directory group to `hub-operators`. Each disappears as it
   completes.
5. Sign out; sign in with the directory as yourself. Search for yourself:
   your page shows operator and the membership that granted it.

Outside a cluster there is nothing to prove access to, so the hub prints a
generated recovery password once at start and step 2 is reading it off the
log. That installation gets a fifth setup step — turn the password off —
because a stored password *is* a standing credential, which the token is
not.

Step 4's first item is the only one that leaves the console:
[the connect runbook](connect-runbook.md) has the full walk-through of the
cloud-console visit, and Overview has the two values to paste into it.

Behind an authenticating proxy, steps 3 and 5 go through the proxy's
login; attaching the membership is unchanged, because the hub resolves the
forwarded identity's address through the directory like any other;
recovery stays reachable by port-forward.

## Lost operator access

Nobody is in the operators group, or the group was renamed, or the directory
sign-in is what is broken:

- **recovery enabled (the default):** mint a token as in day one, sign in
  at `/login` under *Recovery sign-in*, fix the membership. Who did it is
  in the hub's log and in the cluster's audit log, by name.
- **recovery disabled:** set `access.recovery.enabled: true` in the values,
  roll the deployment, then as above. There is no password to recover,
  only RBAC to hold.
- **`503 recovery could not be checked`:** the check did not run — the API
  server is unreachable, or the hub may not create TokenReviews (the
  ClusterRole `<release>-<namespace>-tokenreview`). It is not a wrong
  token; do not go looking for one.
- **`401 that proof was not accepted`:** the token expired (they are
  minted for minutes), was minted for another audience, or belongs to an
  account that may not recover. Mint another with both flags.
- **outside a cluster, `429 too many attempts`:** ten wrong passwords stop
  the password answering for a minute — the correct one included, so that
  the limit is not a hint about which guess was close. Wait, then try
  once.

Sessions are stateless signed cookies. To log everyone out at once,
delete `Secret <release>-session-key`; the hub generates a new one on restart.

Behind a proxy those cookies are not what signs anybody in, so neither is
what signs them out: set `access.signOutThroughIssuer: true`, and the
chart builds the whole chain — the proxy's `/oauth2/sign_out`, then the
issuer's `end_session` with this console's client id, then back to the
front page. Without it the console's sign-out clears a cookie nothing was
using and the person comes back signed in ("sign out does nothing");
with only the proxy's half, the issuer keeps the session and the next
click at any console signs them straight back in, which looks exactly
like success. The issuer's client must list the console's front page in
`signed_out`, or the person lands on the issuer's own page instead.

Recovery, for the record, is the **cluster anchor used as the floor**
([../design/trust.md](../design/trust.md)): the issuer depends on the
directory, the directory is what this section assumes is broken, so the
only thing left to trust is the API server.

## What "unhealthy" means and what to do

| Symptom (console) | Cause | Action |
|---|---|---|
| Health: error, domains *provisional — probe failed* | token revoked, admin suspended, tenant policy changed, scopes withdrawn | **Reconnect** (consent) or upload a new key. Nothing is lost meanwhile: the last snapshot is served, non-authoritative |
| Health ok, domains *provisional — snapshot stale* | refresher cannot complete a full read (a page fails, quota, timeouts) | check the hub logs for the failing page; **Refresh** to retry now; the snapshot recovers on the next successful pass |
| Health ok, domains *provisional — first snapshot pending* | the workspace was connected moments ago, or its served list was just changed; the first snapshot runs detached | wait — seconds for a small tenant, a minute or two for a large one. Longer than a refresh interval: read the log for the failing page |
| One replica answers *workspace not found* for a directory the other serves | before 0.8 the reader map was filled only at start, so a workspace connected on one replica was unknown to the other | restart the replica; from 0.8 a missing reader is opened from the stored credential on first use |
| The consent callback shows the CDN's own *Bad gateway* page | the hub answered 5xx and the CDN replaced it — since 0.7.2 the callback never answers 5xx, so the request did not reach the hub | the gateway, the route, or the egress policy; the hub's log has nothing because nothing arrived |
| One domain not authoritative on two workspaces, marked *conflict* | both tenants list the domain **and both serve it** — a move in progress, or a misconfiguration | wait for the move to complete, or narrow one of them: *Choose which to serve* on the directory's page, leaving the domain out of the tenant that should not answer for it |
| A domain shows *not served* | this hub was narrowed to a subset of the tenant's domains, so nothing routes to it and its accounts are not cached | intended in most cases; *Choose which to serve* changes it. A declared workspace says so in the values (`workspaces[].serve`) |
| A domain shows *no longer owned* | the served list names a domain the directory no longer lists — it has moved to another tenant | the hand-over already happened: the other workspace serves it as soon as its own discovery returns it. Drop the entry here so the list matches reality |
| Every domain non-authoritative at once | Valkey unreachable | restore Valkey; the hub refills it within one refresh interval |
| A workspace shows *declared* and no Reconnect/Disconnect | it comes from the chart's overlay | change the deployment's values, not the console |
| After a restart, a workspace is unhealthy with "no backend: the credential is not loaded" | its `Secret <release>-credential-<tenant>` is gone or unreadable — restored namespace, hand-edited object, a Secret deleted with the wrong selector | **Reconnect** (consent) or upload the key again. The record, its served domains and its memberships are intact; only the credential is missing. The hub logs the workspace id at start |

The rule consumers follow makes every row above safe: **a
non-authoritative answer holds, it never removes.**

## Recovering a lost credential

Delete the Secret and the record for a workspace, or lose the namespace,
and the workspace is simply gone from the list. Press **Connect** again as
the same admin role account; the tenant id matches and the domains return
authoritative after the first snapshot. There is no backup mechanism by
design: the credential is cheaper to mint than to guard a copy of.

## Rotating

- **Consent credential:** Reconnect. The old refresh token is revoked at
  Google as part of it.
- **Service-account key, connected through the console:** Upload key
  again with the new JSON; the old one is replaced.
- **Service-account key, declared:** replace the named Secret; the hub
  picks up the mounted file within a minute. Delete the old key in
  Google Cloud afterwards.
- **OAuth client secret:** Settings → set the new secret (or update the
  declared Secret). Existing refresh tokens keep working; the secret is
  used only to exchange and refresh.

## Export

```sh
kubectl -n directory-roster get secret,configmap \
  -l app.kubernetes.io/managed-by=directory-roster -o yaml > directory-roster-export.yaml
```

The export contains credentials. Treat it as one.

## Scaling and cache

Two replicas are the default; the shared Valkey makes them answer from
the same snapshot and lets one refresher run for both. A single replica
may run without Valkey (`valkey.address` empty), at the cost of a cold
cache on every restart. Memory in Valkey is the size of the directories.
Every replica serves every workspace: one connected through the console
on the other replica is opened from its stored credential on first use
*(0.8; before that, only a restart taught a replica about it)*.

## Logs

Structured JSON on stdout. The hub never logs a credential, a token or a
key file, and never logs the members of a group; it logs workspace ids,
domains, counts, durations and errors.
