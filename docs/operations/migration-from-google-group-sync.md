# Migrating from google-group-sync

google-group-sync served one Workspace per process, from a service-account
key in an environment variable or a mounted Secret, over REST and (later)
`DirectoryService`. The hub serves every Workspace from one deployment,
over `DirectoryService` only. The move is four steps, each reversible until
the last.

1. **Overlay first.** Deploy the hub with every existing service-account
   key as a declared workspace (`workspaces[]`, the key Secrets delivered
   the way they were delivered to google-group-sync). No Connect step.
   Confirm: `Describe` lists every domain the old instances served, all
   authoritative; spot-check `ResolveUser` against the old instances for a
   sample of addresses.
2. **Consumers move.** Each consumer swaps its google-group-sync client
   for the `DirectoryService` Connect client — a consumer that spoke REST
   gets a generated client; a consumer that already spoke
   `DirectoryService` changes one URL — and learns to read
   `authoritative` before acting on a removal. One hub address replaces
   N per-instance addresses; the hub routes by domain. Watch the
   consumers' decisions for a day.
3. **Connect through consent, at leisure.** For each workspace, press
   Connect as its admin role account, then remove the declared entry from
   the values. The console shows the connected workspace taking over the
   domains; the service-account key can then be deleted in Google Cloud.
4. **Retire.** Remove the google-group-sync deployments and their key
   Secrets; archive the repository.

What is not carried: the Lambda and Lambda-extension flavours (single
workspace by construction), the per-process configuration, the REST
routes, and the environment-variable credential path.
