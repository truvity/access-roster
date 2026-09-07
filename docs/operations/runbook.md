# Runbook

Day-two operations. Everything here is visible on a tenant's page in the
console and in `Describe`; nothing needs a shell except the export.

## Day one

**A deployment that declares its own way in has no day one.** Values that
carry a workspace and a non-empty `hub-operators` are signed into through
the directory from the first boot, and the break-glass account never
turns itself on. Nothing below applies; go to
[the connect runbook](connect-runbook.md) when you add the next tenant.

**A standalone installation configures itself through the console**, and
the console leads it. Overview shows what is left to do until nothing is,
with this installation's own values to copy rather than a placeholder to
translate — the redirect URI is its hostname, and that is where a day-one
setup goes wrong.

1. Install; the hub generates `Secret hub-admin` and `Secret hub-session-key`.
2. Read the admin password: `kubectl -n directory-roster get secret hub-admin -o jsonpath='{.data.password}' | base64 -d`.
3. Port-forward the console port (or go through the gateway) and sign in at `/admin/login`.
4. Follow Overview. It walks the same five steps: register an OAuth client
   with the directory, give it to the hub, connect the first directory,
   attach a directory group to `hub-operators`, and turn the break-glass
   account off. Each disappears as it completes.
5. Sign out; sign in with the directory as yourself. Search for yourself:
   your page shows operator and the membership that granted it.

Step 4's first item is the only one that leaves the console:
[the connect runbook](connect-runbook.md) has the full walk-through of the
cloud-console visit, and Overview has the two values to paste into it.

Behind an authenticating proxy, steps 3 and 5 go through the proxy's
login; attaching the membership is unchanged, because the hub resolves the
forwarded identity's address through the directory like any other; the
admin account stays as break-glass by port-forward.

## Lost operator access

Nobody is in the operators group, or the group was renamed, or the directory
sign-in is what is broken:

- **admin still enabled:** port-forward, `/admin/login`, fix the membership.
- **admin disabled:** set `access.admin.enabled: true` in the values, roll
  the deployment, then as above. The password is still in `hub-admin`.
- **forgotten password:** delete `Secret hub-admin`; the hub generates a
  new one on restart.

Sessions are stateless signed cookies. To log everyone out at once,
delete `Secret hub-session-key`; the hub generates a new one on restart.

## What "unhealthy" means and what to do

| Symptom (console) | Cause | Action |
|---|---|---|
| Health: error, domains not authoritative | probe failed: token revoked, admin suspended, tenant policy changed, scopes withdrawn | **Reconnect** (consent) or upload a new key. Nothing is lost meanwhile: the last snapshot is served, non-authoritative |
| Health ok, domains not authoritative, snapshot old | refresher cannot complete a full read (a page fails, quota, timeouts) | check the hub logs for the failing page; **Refresh** to retry now; the snapshot recovers on the next successful pass |
| One domain not authoritative on two workspaces, marked *conflict* | both tenants list the domain — a move in progress, or a misconfiguration | wait for the move to complete, or remove the domain from the tenant that should not have it |
| Every domain non-authoritative at once | Valkey unreachable | restore Valkey; the hub refills it within one refresh interval |
| A workspace shows *declared* and no Reconnect/Disconnect | it comes from the chart's overlay | change the deployment's values, not the console |

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

## Logs

Structured JSON on stdout. The hub never logs a credential, a token or a
key file, and never logs the members of a group; it logs workspace ids,
domains, counts, durations and errors.
