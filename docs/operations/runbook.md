# Runbook

Day-two operations. Everything here is visible in the console's
Workspaces view and in `Describe`; nothing needs a shell except the export.

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
