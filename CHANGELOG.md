# Changelog

## Unreleased

- The `sluis` command-line tool: `sluis login`, `sluis token` and `sluis audit verify`, which checks a tiled audit log offline.
- The local installation: `just local-up` builds the images and starts every merged actor and driver under Docker Compose, each as its pinned uid, with config signed by a harness publisher key and TLS from a harness CA. `just local-status`, `local-logs` and `local-down` report on it and remove it.
- Audit search on the local installation: the indexer, the reader and the audit front (`sluis-audit.dev.local.test`) run under Compose, and `just local-audit-search 'action:signer.sign'` prints the matching audit records. A new read-only blob driver, `driver-indexer-fs`, lets the indexer and the reader read the log the writer keeps.
