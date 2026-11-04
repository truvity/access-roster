# Changelog

## Unreleased

- The YubiKey PIV key driver (`drivers/key/yubikey-piv`): key@'s key-store port over the keys of a board's card, with the keys of the slot plan generated on the card, their attestation verified against Yubico's root, a firmware floor of 5.7 and exclusive card access. It starts locked and takes the PIN once, on a local admin socket, with the new `sluis node unlock NODE`; a wrong PIN is never retried. The executable that talks to a card is built natively with the tag `sluis_card`.
- The `sluis` command-line tool: `sluis login`, `sluis token` and `sluis audit verify`, which checks a tiled audit log offline.
- The local installation: `just local-up` builds the images and starts every merged actor and driver under Docker Compose, each as its pinned uid, with config signed by a harness publisher key and TLS from a harness CA. `just local-status`, `local-logs` and `local-down` report on it and remove it.
- Audit search on the local installation: the indexer, the reader and the audit front (`sluis-audit.dev.local.test`) run under Compose, and `just local-audit-search 'action:signer.sign'` prints the matching audit records. A new read-only blob driver, `driver-indexer-fs`, lets the indexer and the reader read the log the writer keeps.
