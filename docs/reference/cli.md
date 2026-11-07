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
- **Offline by default.** Only `--live`, `sluis login`, `sluis token` and the confirmation of `sluis key revoke --declaration` talk to a running sluis; `config check`, `config explain`, `doctor` and the key commands read the host.
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
| `sluis config check DIR [--bootstrap FILE] [--helper PATH] [--runtime RUNTIME] [--against OLD]` | The bootstrap file and the signed config documents in `DIR`; with `--against`, the previous bootstrap file | Nothing | 0, 1, 2, 3 |
| `sluis config explain DIR [--bootstrap FILE] [--helper PATH] [--field PATH]` | As `check` | Nothing | 0, 1, 2, 3 |
| `sluis doctor [--socket PATH]` | The host: kernel, randomness, the platform's floor, the clock; with `--boundary`, key@'s driver and the intermediates, through key@ | Nothing | 0, 1, 2, 3, 10, 11, 12 |
| `sluis key request [--purpose PURPOSE] [--out DIR]` | The key plan and the trust anchors (`KeyPlan`, `TrustAnchors`) | A key in its store if it does not exist; the requests and proofs in `DIR` | 0, 1, 2, 3, 4 |
| `sluis key install DIR` | The answers in `DIR`, the trust anchors | The certificate or the binding, as the kind `KeyCertificate`, through key@ | 0, 1, 2, 3, 4 |
| `sluis key status [--socket PATH]` | The keys and their certificates, through key@ | Nothing | 0, 1, 2, 10, 11, 12 |
| `sluis login [--issuer URL]` | The group issuer; the boundaries' token endpoints | Tokens in the user's cache | 0, 1, 2, 3 |
| `sluis token --audience CLIENT_ID` | The user's cache; the token endpoint | A refreshed or exchanged token in the cache; the access token on standard output | 0, 1, 2, 3 |
| `sluis audit verify DIR --key VKEY` | The files of a tiled audit log in `DIR`: the checkpoints, the hash tiles and the entry bundles | Nothing | 0, 1, 2, 3 |
| `sluis node unlock NODE [--socket PATH] [--secret-fd N]` | The PIN, from standard input or the descriptor; the card driver's status | The PIN into the locked card driver of the node it runs on | 0, 1, 2, 3 |
| `sluis node status NODE [--socket PATH]` | The card driver's status: whether it holds the PIN | Nothing | 0, 1, 2, 3 |
| `sluis key revoke --kid KID --reason REASON [--out FILE]` | Nothing | A key revocation declaration, to `FILE` or standard output | 0, 2 |
| `sluis key revoke --declaration FILE [--socket PATH] [--issuer URL] [--entry-socket PATH] [--wait DURATION]` | The signed declaration; the issuer's discovery document and key set, and `entry`'s | The revocations, through key@ on the node it runs on, and whether the keys left the key sets | 0, 1, 2, 3, 5 |
| `sluis key revoke --check (--declaration FILE \| --kid KID ...) [--issuer URL] [--entry-socket PATH] [--wait DURATION]` | The declaration file or the keys; the issuer's discovery document and key set, and `entry`'s | Whether the keys left the key sets; nothing is delivered | 0, 1, 2, 5 |

### `sluis config check` and `explain`

`check` validates the bootstrap file and the signed config documents in `DIR` the way store@ does at start, with store@'s own code: the CLI runs the store executable of its release as a helper, so the check and store@ cannot disagree ([0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). It checks the strict profile and the rules of each kind, the signature of each document against the publisher keys the bootstrap file pins, the sequence, and then the whole set against the registries ([What `sluis config check` checks](/reference/bootstrap-file/#what-sluis-config-check-checks), [Verifying a document](/reference/signed-config/#verifying-a-document)). It also checks the installation: a driver that does not fit the runtime, a unit that holds a holder and a work actor, an enabled key purpose with no key or slot, and a production backup plan without a schedule or a retention ([0005](/decisions/0005-the-store/#drivers), [0003](/decisions/0003-units-transports-and-fusion/#fusion), [0006](/decisions/0006-keys-and-sealing/#key-purposes), [0010](/decisions/0010-backup-and-recovery/#what-the-archive-holds)). It prints one line per check, `ok`, `warn`, `fail` or `not-run`. For a set that declares an `AuditLog`, the line `lock-mode` reports the lock mode the document declares for the logs' blob, `none`, `removable` or `compliance`, in its rule ([REQ-AUDIT-028](/requirements/audit/#REQ-AUDIT-028)); the document must declare one of the three. No file yet names the blob driver, so the report is the declared mode, not one read from the driver, and the rules that compare it with the boundary's environment and with a witness come with the document that declares the witnesses. A `fail` exits 3; warnings, such as an audit log with no witness, exit 0. `DIR` defaults to the directory of the `file` config source that the bootstrap file names. The KeyPlan's card slot map is part of the set: two purposes in one slot, an enabled card-key purpose with no slot, a slot that is no slot of a board and a purpose listed twice are a `fail` of the `set` line that names the entry (`default.purposes[1].slot: shared with wrapping`), by the slot map rules that key@'s own check shares with it, on the same vectors: the rules common to all stores, while a card adds limits that only key@'s check applies, such as no override of a card's default slot ([REQ-PKI-037](/requirements/pki/#REQ-PKI-037), [REQ-PKI-038](/requirements/pki/#REQ-PKI-038), [REQ-PKI-042](/requirements/pki/#REQ-PKI-042)); a purpose the plan does not list needs no slot. The CLI finds the helper through `--helper`, the `SLUIS_STORE_HELPER` variable or the install path beside it, refuses a helper of another release, and `config check` runs on Linux only ([0013](/decisions/0013-release-train-packaging-and-distribution/#one-version)).

**The installation.** No file carries the runtime of an installation, because "installation" is not a configuration key ([0011](/decisions/0011-runtimes-and-installations/#runtime-kinds)), so the caller names it: `--runtime bare-metal`, `serverless` or `kubernetes`. With it `check` tests each driver of the bootstrap file against what the driver declares it fits ([Which drivers fit which runtime](/runtimes/#which-drivers-fit-which-runtime)) and prints one `installation` line for each port, with the path of its `driver` field. A driver that does not fit is a `fail` that names the field and the runtime, never the driver ([REQ-DATA-072](/requirements/data/#REQ-DATA-072)). Without `--runtime` the line is `not-run`, with the flag to give: a check that cannot run is never reported as passed. `not-run` is not a `fail`, so the exit code stays 0 when every other check passes: a pipeline that must have the drivers checked passes `--runtime`, or reads the `result` of each line in the JSON output and refuses a `not-run`. An empty `--runtime` is a usage error (exit 2), so an unset variable in `--runtime "$RUNTIME"` cannot turn the check off. The model is that one fact and a table of drivers in code (`actors/store/src/install.rs`), which also lists the drivers each port of the bootstrap file accepts. It grows when a rule needs more: the node count with the first driver that cares about it, and the drivers of key@ and the audit pieces once a file names them. The roads not taken are a file of its own for the installation (a second description of what the bootstrap file and the signed documents already say, to keep in step with them), a `runtime` key in the bootstrap file (a restart of store@ for a fact it never uses) and the host's own state (a CI runner is not the host).

With `--against OLD`, `check` compares the bootstrap file with the previous version and prints one `warn` line for each changed path, `added`, `changed` or `removed`, with the path and never the value, because a changed bootstrap file is a restart of store@ ([A change needs a restart](/reference/bootstrap-file/#a-change-needs-a-restart)). It compares the settings that `explain` prints, so a key that a file leaves out has the binary's default, and writing that default is no change. When nothing differs the line is `ok against`. A previous file that cannot be read is a `fail` of the `against` check, because the comparison did not run ([REQ-OPS-130](/requirements/ops/#REQ-OPS-130)). A signed config document needs no such line: every config change reloads as a whole snapshot. A pipeline that must not publish a bootstrap change reads the `warn` lines in the JSON output.

With `--live`, `check` and `explain` read the durable kinds through the console API with the operator's own token, and `check` lists held changes ([Configuration](/concepts/data/#configuration)). The first version has no console API, so the flag is not available: both commands refuse it with a usage error (exit 2) that says why, and run nothing, so that a pipeline never reads the answer of the files as the answer of a running installation.

`explain` prints what each setting of the bootstrap file and of the signed config documents in `DIR` resolves to, and where the value comes from. It runs the same helper as `check`, with `--explain`, so the values are those store@ would run with and the CLI reads no document itself ([0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). It explains a set that passes the checks of `check` and nothing else: an effective value exists only for a set store@ would load, so a set that fails is not explained, the failed lines are printed as `check` prints them, and the command exits 3. It names no runtime and judges no driver, so it takes no `--runtime`. `DIR` is required, and `--bootstrap` names the file (or `--boundary` finds it in `/etc/sluis/bootstrap.d/`). Not built yet: `--live` for both commands (above) and a default `DIR`. Each setting has:

| Member | Meaning |
|---|---|
| `path` | Where the setting is. In the bootstrap file it is the path `check` names (`durable.driver`, `publishers[0].kid`). In a document it is `Kind.item.path` (`Upstream.workforce.issuer`, `TokenLifetime.default.access_token`); a kind with one item has the item `default`, and a list element is `[0]`. A `check` line and a path of `explain` name the same place, so one can be pasted into `--field`. |
| `value` | The effective value, as text, printed by the rules below. |
| `class` | The storage class of the kind, `config`. A setting of the bootstrap file, which is not a kind, and a built-in have `-`. |
| `layer` | The layer that set the value: `bootstrap` (the bootstrap file), `config` (a signed document) or `built-in` (what the binary carries; the one built-in today is the default `start_timeout` of 30 seconds when the file leaves it out) ([0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule)). |
| `version` | The `seq` of the document, or the release for a built-in; empty for the bootstrap file, which has none. |
| `source` | `bootstrap` for the file, `store@` for a built-in, or the document as the audit fact of a start names it, `Kind:seq:sha384` ([0005](/decisions/0005-the-store/#configuration-loading)). The text output shows the first twelve digits of the digest. |
| `checks` | JSON only: the checks of `check` that cover the setting, `bootstrap` and `installation` for a driver, `document` and `set` for a document setting. |
| `secret` | JSON only, and only when `true`: the value is the name of a credential in the secret source. |
| `digest` | JSON only, and only when `true`: the value is `sha384:` and the digest of what the file holds, not the value. |

`--field PATH` limits the output to the setting at `PATH` and the ones under it, at a boundary of the path (a `.` or a `[`): `durable` holds `durable.driver`, and `Up` holds nothing. An item id may hold a dot, so with the items `corp` and `corp.example` the path `Upstream.corp` holds the settings of both. A path that names no setting is a usage error (exit 2), and so is an empty one, so that an unset variable in `--field "$FIELD"` cannot explain everything. A setting that a file leaves out has no entry: the built-in layer of the documents is not built, so a field with a default that an actor applies is listed only when a document sets it. The text output is a table, a line for each setting; `--output json` prints the `fields` and the `checks` that ran. `--live`, which adds the operator and tenant layers, and the built-in layer of the documents, which the actor that reads a kind applies today, come with the first command or actor that needs them ([REQ-OPS-023](/requirements/ops/#REQ-OPS-023)).

**What `explain` prints, and what it never prints.** The bootstrap file and a config document are written by hand, reviewed in git and hold no credential by construction ([The bootstrap file](/reference/bootstrap-file/), [0004](/decisions/0004-the-data-model/#storage-classes)), which is why a config value is printed where an error prints only a path. Even so, `explain` fails closed: store@ holds a closed table of the fields of each kind it reads, each with the way it is printed (`actors/store/src/config/explain.rs`), and a field the table does not list, such as a new field or the field of a kind added later, is printed as its digest until someone has decided that it may be shown. A test fails when the payload reads a key that the table does not cover. The ways are:

- **Shown:** a name, a number, an identifier. **A duration** is shown in its largest whole unit (`60s` is `1m`), in a document as in the bootstrap file.
- **A credential is its reference.** The `secret` of an `Upstream` or an `InstallationClient` is the name of a credential, and that name is printed and marked. The command opens no socket, so it cannot resolve one, and the value of a secret is never in a file it reads.
- **A URL has no query and no fragment,** which carry tokens more often than any other part of a URL: `https://app.example.com/callback?<elided>`. A URL that holds user information (`user:password@host`) is refused by `check` at load, for the issuer of the boundary, an upstream or an exchange trust, a key set and a redirect, and `explain` would print it as a digest.
- **A public key is its pin,** the SHA-384 of its bytes (the public key of a slot of the `KeyPlan`), and an attestation is its digest. A publisher key of the bootstrap file is its pin there too.
- **A value that is longer than 256 bytes or holds an unsafe character is its digest,** `sha384:` and the SHA-384 of its bytes: a control character, an invisible format character (a bidirectional control, a zero-width character, a tag) or a line or paragraph separator. A line stays a line, and a document cannot write an escape sequence or reorder text on a terminal. A Cedar text and a grant vocabulary, which store@ does not interpret, are one setting each, identified by the digest that `sha384sum` of the reviewed file gives. The CLI also shows such a character as `?` in text.
- **A refusal names a path and a rule, never a value,** as in `check`.

The roads not taken are a walk over every field of the Protobuf messages (it needs a reflection that the Rust messages do not have, and the YAML of the verified payload says the same; a test compares the two on the fixtures), printing every leaf of the YAML that the payload accepted (it prints in clear a field nobody has looked at), and a value shown with the secret masked in place (a mask hides which credential a client uses, which is what an operator asks).

### `sluis doctor`

`doctor` checks the platform before a key is created: the kernel is 5.18 or newer, a hardware random generator is present or deliberately absent, the entropy pool is initialised, the systemd floor or its declared exception, and key@'s driver ([0006](/decisions/0006-keys-and-sealing/#algorithms)). It checks the clock too, because the seals of the audit log carry its time ([REQ-AUDIT-017](/requirements/audit/#REQ-AUDIT-017)). It also prints the expiry warnings of `key status`. It exits 3 on a `fail`, then 1 when `kernel` or `entropy` did not run, otherwise with the highest finding: a `warn` line is a notice (10), and an expiry warning is its level. The version of systemd comes from the host's `systemctl` at a fixed path (`/usr/bin/systemctl`, then `/bin/systemctl`) and never from `$PATH`: a script earlier in the path, run as root under `sudo -E`, must not decide the floor check.

It only reads. It writes nothing, sets nothing (not the clock either), makes no key and prints no value of a key, a credential or a file: a line says what was found about the machine, such as a version. It takes no argument.

| Check (`name`, `path`) | `ok` | `warn` | `fail` | `not-run` |
|---|---|---|---|---|
| `kernel`, `kernel.release` | 5.18 or newer | older: do not make a key on a clone of the host | | not Linux, or a release it cannot read |
| `entropy`, `random.crng` | the kernel's generator is initialised (`getrandom` without waiting) | | not initialised: make no key until it is | not Linux, or the call was refused |
| `hwrng`, `random.hwrng` | always: it names the hardware generator, or says that there is none and that the kernel's own generator is then the only source | | | not Linux |
| `systemd`, `systemd.version` | 252 or newer | older: the declared exception, not a supported platform | | systemd is not the init (a container), or the version cannot be read |
| `clock`, `clock.sync` | the kernel says its clock is synchronised, with the offset | not synchronised (below) | | the kernel does not answer, as under a system-call filter that refuses `adjtimex`, or not Linux |

A missing hardware generator is a note and never a warning: a board's SoC generator is left out of the mainline kernel on purpose, and the kernel's own generator is sluis's only source of randomness. A check that cannot run is `not-run` and is never read as passed. If it is `kernel` or `entropy`, the checks that decide whether a key may be made here, the command exits 1 after it prints every line, so that `sluis doctor && make-key` cannot pass on a host where the generator was never asked. A `not-run` of another check (the systemd floor in a container, the clock where the kernel does not answer) changes no exit code; a pipeline that must have it run reads its `result` in the JSON output.

**The clock.** A board's backup clock loses its time in a power cut, and the system then starts at a date years back (2017 on the boards) until the time service sets it, about 35 seconds after boot ([Bare-metal](/runtimes/bare-metal/#the-end-of-a-deploy)). The check does not trust the kernel's flag alone: a date before sluis existed is a `warn` whatever the flag says, because the flag can say synchronised before the time service has set the clock. So an unsynchronised clock is a `warn`, a notice with exit 10, and never a `fail`: the line says that this is the usual state of the first minute after a power cut and to run `doctor` again, and that a clock that stays so means the host has no working time source and that the audit writer then seals without checking times. When the date is before sluis existed, the line names the date. The check asks the kernel with `adjtimex` and an empty request, which reads and sets nothing.

**Key@.** With `--boundary` (or `--socket PATH`), `doctor` also asks key@ on this node, over the status call of [`key status`](#the-key-commands) (root only), for where its keys are held and for the expiry of their certificates:

| Check (`name`, `path`) | `ok` | `warn` | `fail` |
|---|---|---|---|
| `key-store`, `key.store` | a card, or software in a development boundary | software in a staging boundary: the keys are not hardware-held | software in a production boundary, which key@'s floor refuses |
| `expiry`, the purpose | a certificate with time left, with the days | a notice, an alert or a critical alert, as `key status` says it; the exit code is its level (10, 11 or 12) | |
| `certificate`, the purpose | | the intermediate (`x509-intermediate`) has no certificate installed | |

With no `--boundary`, or where key@ has no admin socket on this host, the `key-store` check is `not-run` and says why: `doctor` is also run before key@ exists. A key@ that has a socket and cannot answer (a peer that is not root, key@ cannot reach its store) ends the command with exit 1 after every line is printed, never as a pass. The exit code is 3 for a `fail`, then 1 for a key@ that could not be asked, then the highest level among the `warn` lines and the expiry levels.

### The key commands

The hand-off is ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/); sluis refuses a version it does not know ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

- **`sluis key request`** creates each enabled key that does not exist, in its store, then writes one request per key that the hand-off covers into `DIR` (default `/var/lib/sluis/keys/request/`), and prints each key's fingerprint. An X.509 intermediate request is `<stem>.csr.pem` and `<stem>.proof.json`; an OpenPGP signing subkey request is `<stem>.subkey.pgp`, with one back-signature for every active primary on the root list sluis holds, and `<stem>.proof.json`. The stem is `<boundary>-<purpose>`, for example `dev-x509-intermediate`. `--purpose` limits the run to one purpose. The first working version requests the boundary's X.509 intermediate; the release-signing subkey joins with the signing API ([#890](https://github.com/truvity/sluis/issues/890)). A key the store cannot attest is still requested, and the proof says which store it is in (`software` on local).
- **`sluis key install DIR`** reads each `<stem>.result.json` and its files, and installs a certificate only after the requester's checks of the contract pass: the certificate verifies to an anchor of the CA bundle, the root list, when sluis holds one, is at least as recent as the answer's `trust_sequence`, the certificate matches the key, and its validity and constraints are as expected. A refusal exits 3 with the contract's code (`issuer`, `malformed` and the others). The token certificate is then issued on the node by the new intermediate ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)).
- **`sluis key status`** lists each enabled key: its purpose, its slot on a card, its store, its fingerprint, its expiry and its warning level. It exits with the highest finding: a notice 60 days before an expiry (10), an alert 30 days before (11) and a critical alert 14 days before (12) ([0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)). It asks key@ on the node it runs on, over key@'s admin socket (`/run/sluis/key/BOUNDARY/admin.sock`, `--socket PATH` names another), which only root reaches, so it names the boundary with `--boundary` and runs as root. The call reads and writes nothing: key@ answers from the keys it holds, lists the `KeyCertificate` items and asks for none that may be absent, and makes no audit record, so a status can be run as often as a person likes.
  - **The expiry of a key** is the earliest end of validity among the certificates of the chain installed for it, in UTC, with the whole days left (negative once it has ended). A chain that has ended is critical (12) and the line says it has expired: the renewal is overdue, which is an error and not a warning. A key with no chain has no expiry and no level; the intermediate (`x509-intermediate`) with no chain is named on standard error, and exit stays 0, because the window between `key request` and `key install` is part of the hand-off. The exit code of a key that does not need a certificate is never raised by the absence of one.
  - **The fingerprint** is the SHA-256 of the DER public key, the one `key request` prints and the certifier shows. The text output cuts it to its first 16 digits; the JSON object holds all 64. The slot is named on a card store and left out elsewhere.
  - **A clock that is not set is not judged.** A board just rebooted after a power cut shows a date in 2017 until its time service sets the clock, and on that date a chain that ended long ago would have thousands of days left. When the date is before 2026, or before a certificate of an installed chain began, `key status` judges no expiry: it lists the keys with no days left and no level, says why on standard error and exits 1. Run it again in a minute. A key with no chain needs no clock.
  - **A certificate is installed or it is not,** and the JSON object says so for every key (`certificate` is `installed` or `none`), apart from the expiry: a key with no certificate has no expiry and no level, which a script must not read as a key with time left. The text shows `no certificate` where the expiry would be. An empty list of keys is a failure too, because key@ always holds at least its wrapping key.
  - **Which chain.** key@ takes the chain of a key from the certificate whose first certificate holds that very key (not from the key the item names for itself), and, of several, the one whose leaf lives longest: the time at which key@ published an item is its own clock's.
  - **A key@ that cannot be asked is a failure (exit 1),** never an empty list: the socket is not there, the peer is not root, key@ cannot reach its store or driver, or a chain it returned does not parse. Warnings go to standard error and the table to standard output.
  - **Not built yet:** the metric `sluis.key.expiry` and its alert rule ([REQ-PKI-031](/requirements/pki/#REQ-PKI-031), [#1068](https://github.com/truvity/sluis/issues/1068)) wait for the telemetry kit, which no Go executable has yet. The OpenPGP subkey joins with the signing API.

The root list is part of `TrustAnchors`, the config kind that holds the root list, the CA bundle and the SSH CA key list ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)); `sluis trust sync` fetches it at parity.

### `sluis node unlock`

A board starts locked: the card driver has no PIN ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)). `sluis node unlock NODE` gives it the PIN, and runs on the node itself, as root, because the driver's admin socket is mode `0600` and refuses any other user. An operator reaches it through a shell on the node (SSH, then `sudo`) and pipes the PIN, so the PIN crosses the network only inside that session.

- **The PIN is read from standard input** (one line), or from the descriptor named by `--secret-fd`. It is never a flag or an environment variable, and a terminal is refused because this tool cannot turn the echo off.
- **`NODE` must be the node the driver serves.** The command asks the driver first, and a different name exits 3 with the reason `node` before any PIN is sent.
- **A wrong PIN is tried once.** The driver never retries it, because the card blocks after three wrong attempts. The command exits 3 with the reason `pin` and prints how many attempts the card still allows. With one attempt left the PIN is not sent at all: the command exits 3 with the reason `pin_retries`, because one more wrong PIN would block the card and the PUK procedure is the owners'. A blocked card exits 3 with `pin_blocked`; the PUK is a ceremony of the owners and not a command.
- **`--socket PATH`** names the admin socket; by default it is `/run/sluis-drv-key-yubikey-piv-BOUNDARY/admin.sock`, from `--boundary`.
- **The driver keeps the PIN in locked memory** and nowhere else; a restart of the driver locks it again.

### `sluis node status`

`sluis node status NODE` says whether the card driver of the node it runs on holds the PIN. It is the read-only half of `sluis node unlock`: it asks the same status call on the driver's admin socket, reads no PIN and sends none, and prints two lines: how many PIN attempts the card has left (`node NODE: PIN attempts left: 3`; `unknown while unlocked` while the driver holds the PIN, because the counter cannot be read without ending the login; with one left, `ONE MORE WRONG PIN BLOCKS THE CARD`), and then the last line, `node NODE is locked` or `node NODE is unlocked`, which scripts match whole. With `--output json` it prints `{ "node", "locked", "pin_retries" }`, where `pin_retries` is left out when it is unknown. The counter is read with a `VERIFY` that carries no PIN, so the command never burns an attempt. It prints nothing else of the card. It runs on the node, as root, for the reason `unlock` does.

- **`NODE` must be the node the driver serves.** A different name exits 3 with the reason `node` and prints no state.
- **A driver that cannot be asked is a failure** (exit 1), never `locked` or `unlocked`: a caller that cannot ask does not know. `just boards-status`, `just boards-unlock` and the end of `just boards-deploy` run it on the boards and read the answer ([the end of a deploy](/runtimes/bare-metal/#the-end-of-a-deploy)).
- **`--socket PATH`** names the admin socket, as for `unlock`.

### `sluis key revoke`

An operator revokes keys in two steps and a check, with the publisher's signature between them, because the publisher key lives where the config is signed and never on a node ([0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-declaration)). Neither step needs the token keys or sign-in.

1. **`sluis key revoke --boundary B --kid KID --reason REASON [--out FILE]`** writes the declaration for the keys: `--kid` is an RFC 7638 thumbprint and is repeated for each key, and `REASON` is `compromise`, `suspicion`, `lost-board` or `drill`. It names keys, never a purpose. A key id that is not a thumbprint, a key named twice or another reason exits 2. `--allow-unknown` lets key@ revoke keys it does not know, such as a lost board's own keys; without it such a key refuses the declaration.
2. **The publisher signs it** as a `KeyRevocationDeclaration`, with the key that signs the `KeyPlan` ([Declarations](/reference/signed-config/#declarations)). On the boards it is the harness: `go run ./tools/harness/sign-config -key-dir .cache/boards/publisher -declaration FILE -declaration-out FILE.jws`.
3. **`sluis key revoke --boundary B --declaration FILE.jws`** runs on any node of the boundary, as root, and delivers the signed declaration to key@'s admin socket, `/run/sluis/key/BOUNDARY/admin.sock` (`--socket PATH` names another). It prints each key with `revoked` or `already revoked`. A refusal of key@ exits 3 with its reason and path: `declaration`, `seq`, `schema`, `other-boundary`, `wrapping-key` or `unknown-kid`. A key@ that cannot be reached, or an audit fact that key@ could not make durable, exits 1; in the second case the keys are revoked. A declaration that key@ took in part, because store@ failed, exits 1 and prints each key as `revoked` or `not yet revoked`: deliver the same declaration again to complete it.

**The confirmation.** After the delivery the command checks that the keys have left every key set a verifier can be given ([REQ-KEYS-088](/requirements/keys/#REQ-KEYS-088), [Confirmation](/decisions/0009-export/#confirmation), [#1362](https://github.com/truvity/sluis/issues/1362)). It does not trust a report: it fetches two addresses, the way a relying party does, and needs every revoked key absent from both:

- **The public key set.** The `jwks_uri` that the issuer's OpenID discovery document names, found at `ISSUER/.well-known/openid-configuration` and never at a path the command knows. It is fetched over the network with no credential, and its URL must have the issuer's origin (scheme, host and port): a `jwks_uri` on another origin is `could not tell`. Where a bucket destination exists this is the static document behind the edge; where none exists it is `entry`'s key set behind the forwarder ([Publishing public material](/decisions/0009-export/#the-edge)). The command cannot tell which from outside, and reads what a verifier is given either way. `--issuer URL` names the issuer (no query); by default it is the issuer that `entry` reports in its own discovery document on its socket, which is the issuer of the boundary's `Boundary` document, checked by store@. The issuer is `https`, or `http` on `127.0.0.1` or `[::1]` for development. A `jwks_uri` with a query is fetched as the issuer names it, and the output shows the query. <!-- terms-allow: origin (the web origin of RFC 6454) -->
- **The live key set of `entry`,** read from `entry`'s socket, which is what the edge falls back to. On bare-metal it is `/run/sluis/entry/BOUNDARY.sock`, and `--entry-socket PATH` names another. A socket is reached only on a node that runs `entry`, so the command runs there.

Both are checked by default, because each alone leaves a hole: the public address alone cannot see that `entry` still lists the key, which the edge serves the moment the static document or its copy fails; the socket alone cannot see a stale copy at the edge, which is what relying parties read.

**What a clean result proves, and what it does not.** One round that finds the keys absent is one sample of one address from this host. It does not speak for every node of a CDN: a different point of presence may still serve its old copy until its time to live ends or it is purged. And the socket is the socket of one node: it proves that this node's `entry` has dropped the key, not that the `entry` of another node of the boundary has. On a multi-node boundary, run the check again on each node, or name each node's socket in turn with `--entry-socket`. If the purge failed, the stale window of an edge copy is 65 minutes ([REQ-EXPORT-023](/requirements/export/#REQ-EXPORT-023)) and can outlast `--wait`: check again later with `--check`.

**How the request is made.** Neither request is a cache-buster: a plain `GET` with no query of its own, no `Cache-Control`, `Pragma` or conditional header, no credential and no `Accept` header, so a cache that has not yet dropped the key answers as it answers a verifier (and `entry` refuses a query on these documents). A new connection is opened for each request, over HTTP/1.1, with no proxy from the environment: a connection or a proxy cache of this host must not answer for the edge. The trust roots are the system's, as for `sluis login`. A redirect is not followed. The answer is read up to 1 MiB after decompression.

**What is looked for.** The keys of the declaration that the operator signed, read from its payload, together with any key that key@ reported besides. A reply of key@ that is empty or shorter cannot shorten the list; a key that it reports and the declaration does not name, and one that the declaration names and it does not report, are printed as warnings. With no key to look for the result is `not confirmed`. A key is found by its label (the `kid`) and by its key: the RFC 7638 thumbprint of every listed EC, OKP or RSA key is compared with the revoked kids, which are thumbprints, so a key listed under another `kid`, or none, is `still listed`. A key of another type (a symmetric key, a type this build does not know) cannot be a key of sluis and is matched by its label alone. A key of a type that sluis uses whose members cannot be read is `could not tell`. The answer is read strictly: a duplicate member, or a member in another case (`Keys`, `KID`) that a parser might read in place of the real one, is `could not tell`.

The command reads both addresses again every 2 seconds, for up to `--wait DURATION` (default 2 minutes, which covers the purge target of 60 seconds; `0` checks once; at most 30 minutes), and stops as soon as one round finds every key absent from both addresses in the same round. It prints one line for each address with one of three results, then the warnings and the verdict. Each address line names the issuer, where the command had it (`entry` or `flag`) and how many keys the set listed, so that a person sees that the right document was read:

- `confirmed absent`: the answer was a key set and none of the revoked keys is in it;
- `still listed: KID`: the key set lists the key; a copy that carries an `Age` header shows it (`the copy is 1200 s old`), which points at a stale edge; a key found only by its thumbprint says so;
- `could not tell: REASON`: the address is unreachable, answered other than 200, was too slow (`timed out`), was not a JSON key set, or its discovery document has no `jwks_uri`, names another issuer or sends the check to another origin; with no issuer to discover, the public address is `could not tell` as well. The command never reads a check that did not run as passed ([principle 4](/principles/#4-verify-never-trust-a-claim)). <!-- terms-allow: origin (the web origin of RFC 6454) -->

Warnings do not fail the check. `--issuer` that differs from the issuer `entry` reports is one. So is a public key set that shares no key with a non-empty live key set of `entry`: the edge may lag behind a replacement, or the issuer is not this boundary's.

The last line is `confirmed` and the exit code 0 when every address is `confirmed absent`, otherwise `not confirmed` and exit code 5. The result is the last complete round: an address that is `confirmed absent` in an earlier round and `could not tell` in the last one is `could not tell`, and a request that the end of the wait cut short does not replace what the round before it found. When `exporter@` could not read `KeyRevocation`, the published set stays as it was and the command says `not confirmed` ([REQ-EXPORT-024](/requirements/export/#REQ-EXPORT-024)). An audit fact that key@ could not make durable exits 1 and takes the place of exit 5, with the lines on standard error. The command knows keys, not purposes: a key that was never published, such as a card or audit key, is `confirmed absent`, which is true and says nothing about the purpose.

```text
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 revoked
public key set (https://sluis.example.com/jwks, issuer https://sluis.example.com from entry, 3 keys read): confirmed absent
entry's live key set (/run/sluis/entry/dev.sock, issuer https://sluis.example.com from entry, 3 keys read): confirmed absent
confirmed
```

```text
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 revoked
public key set (https://sluis.example.com/jwks, issuer https://sluis.example.com from entry, 4 keys read): still listed: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8 (the copy is 1200 s old)
entry's live key set (/run/sluis/entry/dev.sock, issuer https://sluis.example.com from entry): could not tell: timed out
not confirmed
```

The second ends with exit code 5 and the line `sluis key revoke: the keys are revoked in key@, but are not confirmed gone from every key set a verifier can be given` on standard error. With `--output json` the `revoke` object has a `confirmation` member ([JSON output](#json-output)). The flags `--issuer`, `--entry-socket` and `--wait` belong to `--declaration` and `--check`; with `--kid` and no `--check` they are a usage error.

**`sluis key revoke --boundary B --check (--declaration FILE | --kid KID ...)`** is the second look. It delivers nothing and asks key@ nothing: it reads the keys from the payload of the declaration file (not verified again: key@ verified it when it was delivered) or from `--kid`, and runs the confirmation. A delivery again with the same declaration is a retry only while that declaration has the highest `seq` key@ took; after a later declaration key@ refuses it, and `--check` is the way to look again. The same flags and exit codes apply: 0, 5, and 2 for a usage error.

:::note[Proposed]
Two points are open. On the serverless and Kubernetes runtimes `entry` has no socket on the node, and the command reaches its live key set as those runtimes are built ([#1014](https://github.com/truvity/sluis/issues/1014)); until then `--entry-socket` is the only way and the address is `could not tell` without it. Where `exporter@` publishes the static document, the command is to name that address apart from `entry`'s key set behind the forwarder, and to read the purge from the report ([#1453](https://github.com/truvity/sluis/issues/1453), [#1454](https://github.com/truvity/sluis/issues/1454)).
:::

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
| 5 | Not confirmed: `sluis key revoke` delivered the declaration, and a key set a verifier can be given still lists a revoked key or could not be checked. The `outcome` is `failed`. |
| 10, 11, 12 | `key status` and `doctor` only: notice, alert and critical. The highest finding wins. |

## JSON output

With `--output json`, a command prints **one JSON object on standard output** when it ends, followed by a newline, whatever its outcome. Only arguments so broken that `--output json` cannot be read print no object; the exit code is then 2.

Every object has these members:

| Member | Meaning |
|---|---|
| `output` | The version of this format, `1`. |
| `command` | The command, such as `key install`. |
| `exit_code` | The exit code the command returns. |
| `outcome` | `done`, `refused`, `usage` or `failed`, matching the exit code; `done` for 10 to 12, and `failed` for 5. |
| `reasons` | When refused: the codes, such as the hand-off contract's or a schema path. |
| `error` | When failed or a usage error: a message for a person. Its wording is not part of the format. |

And these where they apply:

| Member | Commands | Meaning |
|---|---|---|
| `version`, `commit` | `version` | The release version and the commit. |
| `checks` | `config check`, `config explain`, `doctor` | A list of `{ "name", "result", "path" }`; `result` is `ok`, `warn`, `fail` or `not-run`, and `path` names the field a check is about. `doctor` adds `note`, a sentence about what it found; `config check` adds `rule` to a failed line. |
| `fields` | `config explain` | A list of `{ "path", "value", "class", "layer", "version", "source", "checks" }`, with `"secret": true` when the value is a credential's reference and `"digest": true` when it is a digest; `source` names the document the value came from ([`explain`](#sluis-config-check-and-explain)). A secret's `value` is its reference. |
| `keys` | `key request`, `key status` | A list of `{ "purpose", "boundary", "store", "slot", "fingerprint", "certificate", "not_after", "days_left", "level" }`; `certificate` is `installed` or `none` (`key status`); `level` is `none`, `notice`, `alert` or `critical`. |
| `requests` | `key request` | A list of `{ "stem", "kind", "files": [{ "path", "sha256" }] }`. |
| `installed` | `key install` | A list of `{ "stem", "outcome", "reasons" }`. |
| `token` | `token` | `{ "access_token", "expires_at", "audience", "issuer" }`. |
| `login` | `login` | `{ "issuer", "client_id", "subject", "expires_at" }`; no token. |
| `audit` | `audit verify` | `{ "origin", "size", "root_hash", "checkpoints", "entries" }`. | <!-- terms-allow: origin (the C2SP checkpoint origin line) -->
| `node` | `node unlock`, `node status` | `{ "node", "locked", "pin_retries" }`; no PIN. `node unlock` prints it after the PIN was taken, so `locked` is `false` (and has no `pin_retries`); `node status` prints what the driver says, with `pin_retries` left out when the driver cannot read the counter. |
| `revoke` | `key revoke` | `{ "written" }` for the declaration; for the delivery `{ "seq", "keys": [{ "kid", "already" }], "audited", "confirmation" }`. `confirmation`, which `--check` prints alone, is `{ "confirmed", "rounds", "kids", "warnings", "addresses": [{ "name", "address", "state", "issuer", "issuer_source", "keys", "listed", "found_by_key", "age", "reason" }] }`: `name` is `public` or `entry`, `state` is `absent`, `listed` or `unknown`, `issuer_source` is `entry` or `flag`, `keys` is the number of keys the set listed, and `reason` is a short sentence about what went wrong (`timed out`, `it answered 503`, `the answer has no "keys" member, so it is not a key set`), never a value of the answer. |

Members are lower-case words with underscores; times are RFC 3339 in UTC; the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.

## Later commands

These come with the parity milestone and follow the conventions above ([#1097](https://github.com/truvity/sluis/issues/1097)): `sluis trust sync` and `trust enroll` ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)), `sluis restore`, a command of store@ with a plan by default, `--apply` to write and `--overwrite` to replace ([0010](/decisions/0010-backup-and-recovery/#restore)), the rest of `sluis audit` ([0028](/decisions/0028-audit-pieces/#the-audit-front)), `sluis pki` and `sluis ssh`, the commands for integrations, clients and credentials, and the replacements for v1's `sluisctl` sign-in helpers (kubeconfig, cloud profiles, database and vendor wrappers). The backup is a job of exporter@, not a command ([0009](/decisions/0009-export/)). Until then, commands that the integration pages show and this page does not list show the shape, not decided names ([Examples are illustrative](/integrations/#examples-are-illustrative)).
