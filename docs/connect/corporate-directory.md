# Connect a corporate directory

Google Workspace today: [operations/connect-runbook.md](../operations/connect-runbook.md)
— the one-time OAuth client, then one consent click per Workspace, or a
service-account key. Microsoft Entra is the next backend and follows the
same record and the same runbook shape; adding it is described in
[development/extending.md](../development/extending.md).

What connecting leaves behind is a record in a ConfigMap the console
shows and a credential in `Secret <release>-workspace-credentials`, one
key per workspace, the credential carrying a copy of its record. That
Secret, with the three the GitHub page writes, is the whole backup of
what a console added: put them back and the next start rebuilds the
records ([configuration](../reference/configuration.md#restoring-from-the-secrets-alone)).
Connecting and disconnecting are recorded in the audit trail.
