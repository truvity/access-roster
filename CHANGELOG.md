# Changelog

## Unreleased

- `key@` wraps a data key only to the recipients listed in the signed `KeyPlan` (`recipients`, each the RFC 7638 thumbprint of a node's wrapping key). A `KeyCertificate` in the store only supplies the key of a listed recipient, and one that is not listed is refused and audited. `key@ check` prints the node's wrapping key id and fails while a listed recipient has no key. The local installation starts in two phases to learn the id (`deploy/local/README.md`).
- The status page shows build progress: requirements that are partial next to those done, issues in progress on the board next to those closed, and a Design caption that says "not built" only while nothing is done, partial or in progress.
- The `sluis` command-line tool: `sluis login`, `sluis token` and `sluis audit verify`, which checks a tiled audit log offline.
- The local installation: `just local-up` builds the images and starts every merged actor and driver under Docker Compose, each as its pinned uid, with config signed by a harness publisher key and TLS from a harness CA. `just local-status`, `local-logs` and `local-down` report on it and remove it.
- Audit search on the local installation: the indexer, the reader and the audit front (`sluis-audit.dev.local.test`) run under Compose, and `just local-audit-search 'action:signer.sign'` prints the matching audit records. A new read-only blob driver, `driver-indexer-fs`, lets the indexer and the reader read the log the writer keeps.
