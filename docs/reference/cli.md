---
title: Commands
description: "The sluis command tree of the first working version: conventions, global flags, each command, the JSON output and the exit codes."
status: target
sidebar:
  order: 2
---

sluis has one command-line tool, `sluis`, a Go binary with subcommands for operators and users ([0013](/decisions/0013-release-train-packaging-and-distribution/#one-version), [0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). This page fixes the commands of the first working version, their flags, their output and their exit codes ([#1097](https://github.com/truvity/sluis/issues/1097)). The rest of the tree belongs to the parity milestone and follows the same conventions ([Later commands](#later-commands)).

The exit codes and the JSON output follow ritueel's [commands](https://ritueel.id/reference/cli/#exit-codes), so an operator who runs both tools learns one scheme.

## Conventions

- **Noun, then verb:** `sluis key request`, `sluis config check`. A command that acts on the whole installation has no noun (`sluis doctor`).
- **Long flags only,** written `--flag value` or `--flag=value`. Positional arguments are used only where this page shows one.
- **Results go to standard output, everything a person reads goes to standard error:** prompts, progress, warnings. A script reads standard output and the exit code.
- **A PIN, a passphrase or a secret is never a flag or an environment variable.** It is typed at the terminal, or read from a file descriptor the caller names (`--secret-fd N`). A command that needs one and has no terminal and no descriptor exits 2.
- **Offline by default.** Only `--live`, `sluis login` and `sluis token` talk to a running sluis; `config check`, `config explain`, `doctor` and the key commands read the host.
- **Colour** is off when standard output is not a terminal, with `--no-color`, or when `NO_COLOR` is set.
- **Errors name a path, never a value** ([0004](/decisions/0004-the-data-model/#schemas-are-protobuf)): `clients.example-app.redirects[0]: not an https URL`, not the URL.

## Global flags

| Flag | Meaning |
|---|---|
| `--bootstrap FILE` | The bootstrap file ([Where it lives](/reference/bootstrap-file/#where-it-lives)). The commands that read the host need it. |
| `--boundary NAME` | The boundary a command acts on. Needed when the host serves more than one boundary and the command is per boundary (the key commands, `token`). |
| `--output text\|json` | `text` by default. `json` prints one object on standard output ([JSON output](#json-output)). |
| `--no-color` | No colour in text output. |
| `--help` | The command's help, on standard output, exit 0. |

## The first working version's commands

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `sluis version` | Nothing | The version and the commit it was built from | 0 |
| `sluis config check [DIR] [--live] [--against OLD]` | The bootstrap file and the signed config documents in `DIR`; with `--live`, the durable kinds through the console API; with `--against`, the previous bootstrap file | Nothing | 0, 1, 2, 3 |
| `sluis config explain [DIR] [--live] [--field PATH]` | As `check` | Nothing | 0, 1, 2, 3 |
| `sluis doctor` | The host: kernel, randomness, the platform's floor, key@'s driver, the intermediates | Nothing | 0, 1, 2, 3, 10, 11, 12 |
| `sluis key request [--purpose PURPOSE] [--out DIR]` | The key plan and the trust anchors (`KeyPlan`, `TrustAnchors`) | A key in its store if it does not exist; the requests and proofs in `DIR` | 0, 1, 2, 3, 4 |
| `sluis key install DIR` | The answers in `DIR`, the trust anchors | The certificate or the binding, as the kind `KeyCertificate`, through key@ | 0, 1, 2, 3, 4 |
| `sluis key status` | The keys and their certificates, through key@ | Nothing | 0, 1, 2, 10, 11, 12 |
| `sluis login [--issuer URL]` | The group issuer; the boundaries' token endpoints | Tokens in the user's cache | 0, 1, 2, 3 |
| `sluis token --audience CLIENT_ID` | The user's cache; the token endpoint | A refreshed or exchanged token in the cache; the access token on standard output | 0, 1, 2, 3 |
| `sluis audit verify DIR --key VKEY` | The files of a tiled audit log in `DIR`: the checkpoints, the hash tiles and the entry bundles | Nothing | 0, 1, 2, 3 |
| `sluis node unlock NODE [--socket PATH] [--secret-fd N]` | The PIN, from standard input or the descriptor; the card driver's status | The PIN into the locked card driver of the node it runs on | 0, 1, 2, 3 |
| `sluis key revoke --kid KID --reason REASON [--out FILE]` | Nothing | A key revocation declaration, to `FILE` or standard output | 0, 2 |
| `sluis key revoke --declaration FILE [--socket PATH]` | The signed declaration | The revocations, through key@ on the node it runs on | 0, 1, 2, 3 |

### `sluis config check` and `explain`

`check` validates the bootstrap file and the signed config documents in `DIR` the way store@ does at start: the schema embedded in the binary and protovalidate, the signature of each document against the publisher keys the bootstrap file pins, the sequence, and then the whole set against the registries ([What `sluis config check` checks](/reference/bootstrap-file/#what-sluis-config-check-checks), [Verifying a document](/reference/signed-config/#verifying-a-document)). It also checks the installation: a driver that does not fit the runtime, a unit that holds a holder and a work actor, an enabled key purpose with no key or slot, and a production backup plan without a schedule or a retention ([0005](/decisions/0005-the-store/#drivers), [0003](/decisions/0003-units-transports-and-fusion/#fusion), [0006](/decisions/0006-keys-and-sealing/#key-purposes), [0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)). It prints one line per check, `ok`, `warn` or `fail`. A `fail` exits 3; warnings, such as an audit log with no witness, exit 0. `DIR` defaults to the directory of the `file` config source that the bootstrap file names.

With `--against OLD`, `check` compares the bootstrap file with the previous version and prints one `warn` line for each changed path, with the path and never the value, because a changed bootstrap file is a restart of store@ ([A change needs a restart](/reference/bootstrap-file/#a-change-needs-a-restart)). A signed config document needs no such line: every config change reloads as a whole snapshot. A pipeline that must not publish a bootstrap change reads the `warn` lines in the JSON output.

`explain` prints each field's effective value with its provenance: the storage class, the layer that set it and the version. A secret is shown as its reference, never resolved. `--field PATH` limits the output to one subtree. With `--live` both read the durable kinds through the console API with the operator's own token, and `check` lists held changes ([Configuration](/concepts/data/#configuration)).

### `sluis doctor`

`doctor` checks the platform before a key is created: the kernel is 5.18 or newer, a hardware random generator is present or deliberately absent, the entropy pool is initialised, the systemd floor or its declared exception, and key@'s driver ([0006](/decisions/0006-keys-and-sealing/#algorithms)). It also prints the expiry warnings of `key status`. It exits 3 on a `fail`, otherwise with the highest finding: a `warn` line is a notice (10), and an expiry warning is its level.

### The key commands

The hand-off is ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/); sluis refuses a version it does not know ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

- **`sluis key request`** creates each enabled key that does not exist, in its store, then writes one request per key that the hand-off covers into `DIR` (default `/var/lib/sluis/keys/request/`), and prints each key's fingerprint. An X.509 intermediate request is `<stem>.csr.pem` and `<stem>.proof.json`; an OpenPGP signing subkey request is `<stem>.subkey.pgp`, with one back-signature for every active primary on the root list sluis holds, and `<stem>.proof.json`. The stem is `<boundary>-<purpose>`, for example `dev-x509-intermediate`. `--purpose` limits the run to one purpose. The first working version requests the boundary's X.509 intermediate; the release-signing subkey joins with the signing API ([#890](https://github.com/truvity/sluis/issues/890)). A key the store cannot attest is still requested, and the proof says which store it is in (`software` on local).
- **`sluis key install DIR`** reads each `<stem>.result.json` and its files, and installs a certificate only after the requester's checks of the contract pass: the certificate verifies to an anchor of the CA bundle, the root list, when sluis holds one, is at least as recent as the answer's `trust_sequence`, the certificate matches the key, and its validity and constraints are as expected. A refusal exits 3 with the contract's code (`issuer`, `malformed` and the others). The token certificate is then issued on the node by the new intermediate ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)).
- **`sluis key status`** lists each enabled key: its purpose, its slot on a card, its store, its fingerprint, its expiry and its warning level. It exits with the highest finding: a notice 60 days before an expiry (10), an alert 30 days before (11) and a critical alert 14 days before (12) ([0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)).

The root list is part of `TrustAnchors`, the config kind that holds the root list, the CA bundle and the SSH CA key list ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)); `sluis trust sync` fetches it at parity.

### `sluis node unlock`

A board starts locked: the card driver has no PIN ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)). `sluis node unlock NODE` gives it the PIN, and runs on the node itself, as root, because the driver's admin socket is mode `0600` and refuses any other user. An operator reaches it through a shell on the node (SSH, then `sudo`) and pipes the PIN, so the PIN crosses the network only inside that session.

- **The PIN is read from standard input** (one line), or from the descriptor named by `--secret-fd`. It is never a flag or an environment variable, and a terminal is refused because this tool cannot turn the echo off.
- **`NODE` must be the node the driver serves.** The command asks the driver first, and a different name exits 3 with the reason `node` before any PIN is sent.
- **A wrong PIN is tried once.** The driver never retries it, because the card blocks after three wrong attempts. The command exits 3 with the reason `pin` and prints how many attempts the card still allows. With one attempt left the PIN is not sent at all: the command exits 3 with the reason `pin_retries`, because one more wrong PIN would block the card and the PUK procedure is the owners'. A blocked card exits 3 with `pin_blocked`; the PUK is a ceremony of the owners and not a command.
- **`--socket PATH`** names the admin socket; by default it is `/run/sluis-drv-key-yubikey-piv-BOUNDARY/admin.sock`, from `--boundary`.
- **The driver keeps the PIN in locked memory** and nowhere else; a restart of the driver locks it again.

### `sluis key revoke`

An operator revokes keys in two steps, with the publisher's signature between them, because the publisher key lives where the config is signed and never on a node ([0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-declaration)). Neither step needs the token keys or sign-in.

1. **`sluis key revoke --boundary B --kid KID --reason REASON [--out FILE]`** writes the declaration for the keys: `--kid` is an RFC 7638 thumbprint and is repeated for each key, and `REASON` is `compromise`, `suspicion`, `lost-board` or `drill`. It names keys, never a purpose. A key id that is not a thumbprint, a key named twice or another reason exits 2.
2. **The publisher signs it** as a `KeyRevocationDeclaration`, with the key that signs the `KeyPlan` ([Declarations](/reference/signed-config/#declarations)). On the boards it is the harness: `go run ./tools/harness/sign-config -key-dir .cache/boards/publisher -declaration FILE -declaration-out FILE.jws`.
3. **`sluis key revoke --boundary B --declaration FILE.jws`** runs on any node of the boundary, as root, and delivers the signed declaration to key@'s admin socket, `/run/sluis/key/BOUNDARY/admin.sock` (`--socket PATH` names another). It prints each key with `revoked` or `already revoked`. A refusal of key@ exits 3 with its reason and path: `declaration`, `seq`, `schema`, `other-boundary` or `unknown-kid`. A key@ that cannot be reached, or an audit fact that key@ could not make durable, exits 1; in the second case the keys are revoked.

The command prints `not confirmed` on standard error: this build does not yet fetch the published key set to check that the keys left it ([REQ-KEYS-088](/requirements/keys/#REQ-KEYS-088)).

### `sluis login` and `sluis token`

- **`sluis login`** signs a person in at the group issuer with the authorization code flow, PKCE `S256` and a loopback redirect on `127.0.0.1` (RFC 8252), as the public client that config declares for the CLI, an `InstallationClient` ([0021](/decisions/0021-clients/#the-client-declaration)). It then exchanges that token silently (RFC 8693) at each boundary's own token endpoint, so the front never sees a boundary's tokens ([0017](/decisions/0017-identity-and-sign-in/#step-up)). `--issuer` names the group issuer the first time; afterwards it comes from the cache. A browser opens; with no browser the command prints the URL to standard error.
- **`sluis token --audience CLIENT_ID`** prints an access token for that audience at the boundary given by `--boundary`, from the cache while it is valid, otherwise by a refresh or an exchange. The exchange is the public client's own: the CLI names itself with `client_id` and sends no secret, which the issuer serves only for a token issued to that same client ([0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). A refusal exits 3 and looks the same for an unknown and a refused audience ([Contracts and errors](/reference/contracts/#oauth-and-openid-connect-endpoints)).
- **The flags** `--issuer URL` (login and token), `--client-id ID` (the client the CLI signs in as; `sluis-cli` unless named), `--no-browser` (print the URL, open nothing) and `--timeout DURATION` (how long login waits for the browser). An issuer that registers the CLI as a confidential client, as a development realm may, needs its secret on `--secret-fd N` for both commands. An `http://` issuer is accepted only on `127.0.0.1` or `[::1]`; otherwise the issuer must be `https://`, and the trust roots are the system's, extended by `SSL_CERT_FILE`.
- **The cache** is `$XDG_CONFIG_HOME/sluis/tokens/` (`~/.config/sluis/tokens/` when the variable is unset), one file per issuer, mode `0600`. A file that another user can read is refused, not used.

### `sluis audit verify`

`sluis audit verify DIR --key VKEY` checks a tiled log ([0029](/decisions/0029-the-audit-log/#tiled-log)) from its files alone, offline, with no server. `DIR` is the log's prefix: the `checkpoint` object, `checkpoints/<size>` and the `tile/` tree of C2SP tlog-tiles. `VKEY` is the log's verifier key, `name+hash+key`, and `--key-file FILE` reads it from a file. `--origin LINE` also requires the origin line the checkpoints name. <!-- terms-allow: origin (the C2SP checkpoint origin line) -->

It verifies the signature of the checkpoint and of every checkpoint in `checkpoints/`, takes the largest as the head, and rebuilds the tree from the hash tiles with the RFC 6962 hashes, so a tile that does not belong to the head is refused. It hashes every entry bundle to the leaf hashes, and checks that each earlier checkpoint is a prefix of the head. It prints `ok` with the origin, the size and the root hash, and exits 0. It exits 3, naming the file in `reasons`, for a bad signature, a tile or an entry that was changed or is missing, or a checkpoint whose size or hash does not fit the tree; and 1 for a directory it cannot read. <!-- terms-allow: origin (the C2SP checkpoint origin line) -->

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `key status` and `doctor`, nothing due. |
| 1 | Failure: something that should have worked did not, such as an unreadable file or a store that did not answer. |
| 2 | Usage error: an unknown command or flag, a missing argument, or a secret with no terminal and no descriptor. |
| 3 | Refused by a check or by policy: a schema error, a failed `doctor` or `config check` line, a hand-off answer that fails the requester's checks, a refused sign-in or token. |
| 4 | Refused by key@ or the card: a card that is locked or blocked, a PIN not delivered, a store that refuses the key's policy. |
| 5 | Reserved: not confirmed. No command of the first working version asks for a confirmation. |
| 10, 11, 12 | `key status` and `doctor` only: notice, alert and critical. The highest finding wins. |

## JSON output

With `--output json`, a command prints **one JSON object on standard output** when it ends, followed by a newline, whatever its outcome. Only arguments so broken that `--output json` cannot be read print no object; the exit code is then 2.

Every object has these members:

| Member | Meaning |
|---|---|
| `output` | The version of this format, `1`. |
| `command` | The command, such as `key install`. |
| `exit_code` | The exit code the command returns. |
| `outcome` | `done`, `refused`, `usage` or `failed`, matching the exit code; `done` for 10 to 12. |
| `reasons` | When refused: the codes, such as the hand-off contract's or a schema path. |
| `error` | When failed or a usage error: a message for a person. Its wording is not part of the format. |

And these where they apply:

| Member | Commands | Meaning |
|---|---|---|
| `version`, `commit` | `version` | The release version and the commit. |
| `checks` | `config check`, `doctor` | A list of `{ "name", "result", "path" }`; `result` is `ok`, `warn`, `fail` or `not-run`, and `path` names the field a check is about. |
| `fields` | `config explain` | A list of `{ "path", "value", "class", "layer", "version", "source" }`; `source` names the document or the item the value came from. A secret's `value` is its reference. |
| `keys` | `key request`, `key status` | A list of `{ "purpose", "boundary", "store", "slot", "fingerprint", "not_after", "days_left", "level" }`; `level` is `none`, `notice`, `alert` or `critical`. |
| `requests` | `key request` | A list of `{ "stem", "kind", "files": [{ "path", "sha256" }] }`. |
| `installed` | `key install` | A list of `{ "stem", "outcome", "reasons" }`. |
| `token` | `token` | `{ "access_token", "expires_at", "audience", "issuer" }`. |
| `login` | `login` | `{ "issuer", "client_id", "subject", "expires_at" }`; no token. |
| `audit` | `audit verify` | `{ "origin", "size", "root_hash", "checkpoints", "entries" }`. | <!-- terms-allow: origin (the C2SP checkpoint origin line) -->
| `node` | `node unlock` | `{ "node", "locked" }`; no PIN. |

Members are lower-case words with underscores; times are RFC 3339 in UTC; the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.

## Later commands

These come with the parity milestone and follow the conventions above ([#1097](https://github.com/truvity/sluis/issues/1097)): `sluis trust sync` and `trust enroll` ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)), `sluis restore`, a command of store@ with a plan by default, `--apply` to write and `--overwrite` to replace ([0010](/decisions/0010-backup-and-recovery/#restore)), the rest of `sluis audit` ([0028](/decisions/0028-audit-pieces/#the-audit-front)), `sluis pki` and `sluis ssh`, the commands for integrations, clients and credentials, and the replacements for v1's `sluisctl` sign-in helpers (kubeconfig, cloud profiles, database and vendor wrappers). The backup is a job of exporter@, not a command ([0009](/decisions/0009-export/)). Until then, commands that the integration pages show and this page does not list show the shape, not decided names ([Examples are illustrative](/integrations/#examples-are-illustrative)).
