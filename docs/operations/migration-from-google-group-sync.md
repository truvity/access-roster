# Migrating from google-group-sync

google-group-sync served one Workspace per process, from a service-account
key in an environment variable or a mounted Secret, over REST and (later)
`DirectoryService`. access-issuer serves every Workspace from one
deployment, and its answers reach consumers through the policy and the
console's API. The move is four steps, each reversible until the last.

1. **Overlay first.** Deploy the service with every existing
   service-account key as a declared workspace (`directory.workspaces[]`,
   the key Secrets delivered the way they were delivered to
   google-group-sync). No Connect step. Confirm: the console's
   Directories page lists every domain the old instances served, all
   authoritative; spot-check a sample of addresses with `Explain`
   against the old instances' answers.
2. **Consumers move.** What read google-group-sync's answers moves onto
   the service: a GitHub team sync becomes `github` bindings in the
   policy and the controller beside the service; anything else asks the
   console's `AccessService` with its own ServiceAccount token, and reads
   `authoritative` before acting on a removal. One address replaces N
   per-instance addresses; the service routes by domain. Watch the
   consumers' decisions for a day.
3. **Connect through consent, at leisure.** For each workspace, press
   Connect as its admin role account, then remove the declared entry from
   the values. The console shows the connected workspace taking over the
   domains; the service-account key can then be deleted in Google Cloud.
   From here the credential lives in `Secret <release>-workspace-credentials`
   rather than in your delivery, so add that Secret to your backups
   ([runbook](runbook.md#backing-up-and-restoring-what-the-console-holds)).
4. **Retire.** Remove the google-group-sync deployments and their key
   Secrets; archive the repository.

What is not carried: the Lambda and Lambda-extension flavours (single
workspace by construction), the per-process configuration, the REST
routes, and the environment-variable credential path.
