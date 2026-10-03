# Moving the State: `access-roster migrate`

How to move an installation's State from one storage to another with
`access-roster migrate`, and how to undo it. The decision is
[0031](../decisions/0031-a-generic-migration-tool.md): one generic command, the
move order **Kubernetes objects, then NATS, then DynamoDB**, and **data and
runtime never move in the same step**. This page is the first step: today's
ConfigMaps, Secrets and Valkey to a NATS JetStream bucket, with every login kept
alive. The same command, with the two files the other way round, is the rollback.

## What it does

```
access-roster migrate --from <old serve config> --to <new serve config> [flags]
```

Each side is the **`serve` configuration file** of that storage, the same file the
Deployment reads: `ports.*` (and for the legacy storage `store`, `release` and
`valkey`) say where the State is, and the file is validated against the same
schema. There is no second configuration to keep in step.

It copies **through the business interfaces, never as bytes**: a workspace and its
credential are read from the source's own store and written to the destination's,
so a secret is sealed under the destination's Sealer with the destination's key as
its binding, and a record lands in the layout its adapter keeps. (For the same
reason both sides' Sealers must work: a copy is an open and a seal, not a copy of
ciphertext. Moving to a new key-encryption key is therefore what a copy between two
sealed stores already is.)

| Domain | What | How the lifetime is kept |
|---|---|---|
| `directory` | workspaces and their credentials | permanent |
| `github` | organisations with the App key, the link App, runner and catalogue Apps, people's links (token pairs and the `Revision` counter exactly as they were), the operators' confirmations and requests for a pass | permanent; a confirmation or request keeps its own timestamp and the destination's store ages it as it ages its own |
| `slack` | workspaces with their secrets, catalogue Apps, Slack Connect and console channel records, confirmations and requests for a pass | the same |
| `console` | the console's session-signing key | permanent |
| `issuer` | sessions with their person and client indices, refresh tokens and the markers of spent ones, the browser SSO, minted tokens' records, the signing keys' schedule, and the authorization requests and codes in flight | **each record is written with the lifetime it has left on the source**, so nobody signs in again and a session expires when it would have |
| `blobs` | the controllers' last reports | none |

Left out on purpose: **leases** (transient, and owned by whoever runs), the hub's
**snapshots** (a cache it rewrites on its first refresh), and the controllers'
hand-offs and caches (`share.`, `cache.`, `dedupe.`), which a tick rebuilds.
`--skip` names domains to leave out (`directory`, `github`, `slack`, `console`,
`issuer`, `blobs`). The reports are copied only when the two sides keep them in
different places (`--blobs auto`, the default: legacy objects to S3 is a copy, S3
to the same S3 prefix is not); `--blobs copy|skip` forces either.

**A backup or export to a file** (`--backup <file>`, a file adapter as one end) is
not built: there is no file adapter yet. A backup today is a copy to a second
bucket, which is the same command with a second `--to`.

## The safety it holds

1. **It refuses unless the source is quiet.** A copy is a snapshot: a session
   opened or a link refreshed while it runs is a copy of neither state. A run that
   writes needs `--i-have-stopped-writers`. This is a statement the operator
   makes, not a check, and it is the **simpler safe option** over a console
   "maintenance" switch: the writers are not only the console. The issuer writes a
   session on every sign-in and every refresh, and both controllers write
   reports and refresh links, so a switch in the console would leave three of the
   four writers running, and one in all four is a change to every write path
   (and to a chart) for a thing that happens once per installation. Scaling the
   Deployments to 0 stops all of them with what the chart already has. The cost is
   that sign-in is down for the window, which is minutes (the run is a few hundred
   small reads and writes), and which the runbook below makes explicit.
2. **A plan comes first and writes nothing.** The run reads both sides and says,
   for every item, whether it is new, already there with the same value, or there
   with another one. Without `--overwrite` a destination that **holds a different
   value fails the run, naming the key, before a single write**. With `--overwrite`
   the destination takes the source's value.
3. **`--dry-run` is the plan and stops.** It prints the counts per domain and kind
   and touches nothing, not even the objects a legacy destination would need
   created. It needs no `--i-have-stopped-writers`, so it can run against the live
   installation, and should, first.
4. **It verifies.** After the copy it reads the source and the destination again,
   fresh, through the same interfaces, decrypted where sealed, and compares every
   source item with the destination's. A source that changed during the copy shows
   as a mismatch, so a missed writer is found, not hidden. For the issuer's state
   it also checks that each copy has no lifetime longer than the source's, and not
   none where the source had some.
5. **It is idempotent.** A re-run after a failure plans again, finds what is
   already there equal, and copies what is missing; a record already equal is not
   rewritten. A store that fails half way leaves a destination that the next run
   completes.
6. **It prints no value.** The report names keys and counts. The issuer's keys
   carry bearer values (a code, a session id, an address), so a report names them
   by kind and a short hash (`issuer:session:#3fa9c1d2`), enough to find one on
   either side.

## The report

JSON on stdout (the log is on stderr); `--report-blob <name>` also writes it to a
Blob name on the destination. The exit status is `0` only when `ok` is true.

```json
{
  "from": "old.yaml", "to": "new.yaml", "fromAdapter": "legacy", "toAdapter": "nats",
  "dryRun": false, "overwrite": false,
  "startedAt": "...", "finishedAt": "...",
  "steps": [
    {"domain": "github", "kind": "organisations", "source": 3, "new": 3, "present": 0,
     "copied": 3, "verified": 3},
    {"domain": "issuer", "kind": "state", "source": 412, "new": 412, "present": 0,
     "copied": 412, "verified": 412}
  ],
  "totals": {"domain": "all", "kind": "all", "source": 415, "new": 415, "present": 0,
             "copied": 415, "verified": 415},
  "conflicts": [], "unreadable": [], "mismatches": [], "notes": [],
  "ok": true
}
```

`source` is the readable items on the source; `new`, `present` and `conflicts`
are the plan; `copied` is what was written; `verified` and `mismatched` are the
second read. `unreadable` lists what the source's own store cannot present (a
record that does not decode): it is reported, not copied, and everything else is
still copied and verified, then the run ends non-zero. `notes` say what was left
out and why.

## Procedure: Kubernetes objects to NATS

Before the window, with nothing stopped:

1. **Prepare the new configuration.** A copy of the Deployment's `serve` file with
   `ports.adapter: nats`, `ports.nats` (the URL, the bucket, how this workload
   authenticates), `ports.sealer` (KMS, which NATS requires) and, if the reports
   are to move, `ports.blob` (S3). **Remove `valkey.address`**: NATS holds the
   shared state and the start is refused with both. Keep `store`, `release` and
   `inCluster` as they are: they are what the console's cluster-only objects
   (the token review, the declared OAuth client) still use.
2. **Dry-run against the live installation.** It reads the old objects and
   Valkey and the new bucket, and writes nothing:

   ```
   access-roster migrate --from old.yaml --to new.yaml --dry-run
   ```

   Read `totals`, `conflicts` (the destination should be empty, so there should be
   none) and `unreadable`. Fix what it names before the window.

In the window:

3. **Stop every writer.** Scale to 0 the issuer and console (`serve`), the GitHub
   controller and the Slack controller. Sign-in is down from here until step 7,
   and a relying party holding a valid access token keeps working until it expires.
   Wait until the pods are gone.
4. **Run it**, as a one-off pod from the chart's image, with the chart's
   ServiceAccount (it needs the Role the Deployments have, to read the objects),
   the Deployment's environment (the Valkey password a file names) and both files
   mounted. A sketch to adapt from the `serve` Deployment's pod template (the
   volumes that carry the NATS credential and the KMS identity must be the same
   ones):

   ```yaml
   apiVersion: batch/v1
   kind: Job
   metadata: {name: access-roster-migrate}
   spec:
     backoffLimit: 0
     template:
       spec:
         restartPolicy: Never
         serviceAccountName: <the chart's ServiceAccount>
         containers:
           - name: migrate
             image: <the chart's image, the same tag>
             args: [migrate, --from=/etc/migrate/old.yaml, --to=/etc/migrate/new.yaml,
                    --i-have-stopped-writers, --report-blob=reports/migrate-<date>.json]
             # env, volumeMounts and volumes as the serve Deployment's, plus
             # the two files above (a ConfigMap).
   ```

   `kubectl logs job/access-roster-migrate` is the report on stdout and the log on
   stderr; `kubectl wait --for=condition=complete` is the gate.
5. **Read the report.** `ok: true`, `mismatches: []`, `conflicts: []`,
   `unreadable: []`, and `totals.verified` equal to `totals.source`. If a run
   failed part way, **run the same command again**: it completes the copy. If
   `conflicts` is not empty the destination was not empty: decide whether it is
   stale (`--overwrite`) or the wrong bucket.
6. **Switch and roll.** Put the new `config` (the file of step 1) into the chart's
   values and upgrade, with the Deployments' replicas back up. Nothing was written
   to the source, so the old objects and Valkey are exactly as they were.
7. **Check.** The console loads and shows the same workspaces, organisations and
   Slack workspaces; a person signed in before the window **is still signed in**
   and a refresh token from before it refreshes; the GitHub and Slack controllers
   tick (`access_roster.ticks` in [telemetry.md](telemetry.md)); the log says
   `keeping state in NATS JetStream` and `the domain records in the state port,
   credentials sealed`.
8. **Leave the old store in place** (ADR 0031) until the step after it has been
   green for a day: do not delete the ConfigMaps, the Secrets or the Valkey.

Data and runtime do not move together: this step moves only where the State is.
The runtime (the same pods, then the Lambda platform beside them, then the origin)
is a later step, released and proven separately.

## Rollback

**Before step 6** nothing has changed on the source: scale the writers back up with
the old values.

**After step 6**, while the old objects are still there, stop the writers again and
copy back with the files the other way round:

```
access-roster migrate --from new.yaml --to old.yaml --overwrite --i-have-stopped-writers
```

`--overwrite` is needed because the old objects hold the older values. It writes
today's ConfigMaps, Secrets and Valkey (creating any object that is gone, as the
service does at its start), carrying every record, secret and session, with the
lifetimes they have left. Then put `ports.adapter` back (and `valkey.address`) and
roll. The report says the same things in this direction.

## When it says no

| It says | Meaning and what to do |
|---|---|
| `refusing to copy while the source can still change` | `--i-have-stopped-writers` is missing: stop the writers, then pass it. |
| `the destination already holds a different value`, naming `<domain>/<kind> <key>` | Nothing was written. The destination is not empty or is the wrong one. Look, then `--overwrite` if the destination's value is the stale one. |
| `the destination does not match the source after the copy` | A key whose second read differs: a writer was still running, or an adapter lost a write. The `mismatches` name them; stop what writes, and run again. |
| `the source holds items its store cannot read` | A record that does not decode. The rest is copied and verified; fix or delete the named record and run again to confirm. |
| `ports.adapter nats: ... ports.sealer` | The destination has no working Sealer: the credentials are sealed before they are stored. |
| `store unavailable` while copying | The destination (or source) went away. Run the same command again. |
