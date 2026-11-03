---
title: Commands
description: "The sluis command tree of the first working version: conventions, global flags, each command, the JSON output and the exit codes."
status: target
sidebar:
  order: 2
---

sluis has one command-line tool, `sluis`, a Go binary with subcommands for operators and users ([ADR 0013](/decisions/0013-release-train-packaging-and-distribution/#one-version), [ADR 0012](/decisions/0012-the-language-follows-the-executable/#per-actor-table)). This page fixes the commands of the first working version, their flags, their output and their exit codes ([#1097](https://github.com/truvity/sluis/issues/1097)). The rest of the tree belongs to the parity milestone and follows the same conventions ([Later commands](#later-commands)).

The exit codes and the JSON output follow ritueel's [commands](https://ritueel.id/reference/cli/#exit-codes), so an operator who runs both tools learns one scheme.

## Conventions

- **Noun, then verb:** `sluis key request`, `sluis config check`. A command that acts on the whole installation has no noun (`sluis doctor`).
- **Long flags only,** written `--flag value` or `--flag=value`. Positional arguments are used only where this page shows one.
- **Results go to standard output, everything a person reads goes to standard error:** prompts, progress, warnings. A script reads standard output and the exit code.
- **A PIN, a passphrase or a secret is never a flag or an environment variable.** It is typed at the terminal, or read from a file descriptor the caller names (`--secret-fd N`). A command that needs one and has no terminal and no descriptor exits 2.
- **Offline by default.** Only `--live`, `sluis login` and `sluis token` talk to a running sluis; `config check`, `config explain`, `doctor` and the key commands read the host.
- **Colour** is off when standard output is not a terminal, with `--no-color`, or when `NO_COLOR` is set.
- **Errors name a path, never a value** ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)): `clients.example-app.redirects[0]: not an https URL`, not the URL.

## Global flags

| Flag | Meaning |
|---|---|
| `--config FILE` | The install file. Default `/etc/sluis/install.yaml` ([Install file](/reference/install-file/#where-it-lives)). |
| `--boundary NAME` | The boundary a command acts on. Needed when the install file declares more than one and the command is per boundary (the key commands, `token`). |
| `--output text\|json` | `text` by default. `json` prints one object on standard output ([JSON output](#json-output)). |
| `--no-color` | No colour in text output. |
| `--help` | The command's help, on standard output, exit 0. |

## The first working version's commands

| Command | Reads | Writes | Exit codes |
|---|---|---|---|
| `sluis version` | Nothing | The version and the commit it was built from | 0 |
| `sluis config check [FILE] [--live] [--against OLD]` | The install file and the files it names; with `--live`, the operator-set records through the console API; with `--against`, the previous install file and its files | Nothing | 0, 1, 2, 3 |
| `sluis config explain [FILE] [--live] [--field PATH]` | As `check` | Nothing | 0, 1, 2, 3 |
| `sluis doctor` | The host: kernel, randomness, the platform's floor, the keys driver, the intermediates | Nothing | 0, 1, 2, 3, 10, 11, 12 |
| `sluis key request [--purpose PURPOSE] [--out DIR]` | The install file, the root list | A key in its store if it does not exist; the requests and proofs in `DIR` | 0, 1, 2, 3, 4 |
| `sluis key install DIR` | The answers in `DIR`, the root list | The certificate or the binding, into the trust registry | 0, 1, 2, 3, 4 |
| `sluis key status` | The keys and their certificates | Nothing | 0, 1, 2, 10, 11, 12 |
| `sluis login [--issuer URL]` | The group issuer; the boundaries' token endpoints | Tokens in the user's cache | 0, 1, 2, 3 |
| `sluis token --audience CLIENT_ID` | The user's cache; the token endpoint | A refreshed or exchanged token in the cache; the access token on standard output | 0, 1, 2, 3 |

### `sluis config check` and `explain`

`check` validates the install file against the schema embedded in the binary, then the installation against what its drivers declare: runtime, node count, dependencies, the fusion rule, an enabled key purpose with no key ([How `sluis config check` validates an installation](/concepts/drivers/#how-sluis-config-check-validates-an-installation)). It prints one line per check, `ok`, `warn` or `fail`. A `fail` exits 3; warnings, such as an audit log with no witness, exit 0. `FILE` defaults to `--config`.

With `--against OLD`, `check` compares the document with the previous version and prints one `warn` line for each changed path whose reload class is `restart`, with the path and never the value, so a pipeline sees before it publishes that a running installation would refuse the change at reload ([Which keys reload](/reference/install-file/#which-keys-reload)). It also warns about a source that owns a `restart` path. A pipeline that must not publish such a change reads the `warn` lines in the JSON output.

`explain` prints each field's effective value, its origin and the layer that set it. A secret is shown as its reference, never resolved. `--field PATH` limits the output to one subtree. With `--live` both read the operator-set records through the console API with the operator's own token, and `check` lists held objects ([Checking and explaining](/concepts/configuration/#checking-and-explaining)).

### `sluis doctor`

`doctor` checks the platform before a key is created: the kernel is 5.18 or newer, a hardware random generator is present or deliberately absent, the entropy pool is initialised, the systemd floor or its declared exception, and the keys driver ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)). It also prints the expiry warnings of `key status`. It exits 3 on a `fail`, otherwise with the highest finding: a `warn` line is a notice (10), and an expiry warning is its level.

### The key commands

The hand-off is ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/); sluis refuses a version it does not know ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

- **`sluis key request`** creates each enabled key that does not exist, in its store, then writes one request per key that the hand-off covers into `DIR` (default `/var/lib/sluis/keys/request/`), and prints each key's fingerprint. An X.509 intermediate request is `<stem>.csr.pem` and `<stem>.proof.json`; an OpenPGP signing subkey request is `<stem>.subkey.pgp`, with one back-signature for every active primary on the root list sluis holds, and `<stem>.proof.json`. The stem is `<boundary>-<purpose>`, for example `dev-x509-intermediate`. `--purpose` limits the run to one purpose. The first working version requests the boundary's X.509 intermediate; the release-signing subkey joins with the signing API ([#890](https://github.com/truvity/sluis/issues/890)). A key the store cannot attest is still requested, and the proof says which store it is in (`software` on local).
- **`sluis key install DIR`** reads each `<stem>.result.json` and its files, and installs a certificate only after the requester's checks of the contract pass: the certificate verifies to an anchor of the CA bundle, the root list, when sluis holds one, is at least as recent as the answer's `trust_sequence`, the certificate matches the key, and its validity and constraints are as expected. A refusal exits 3 with the contract's code (`issuer`, `malformed` and the others). The token certificate is then issued on the node by the new intermediate ([ADR 0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)).
- **`sluis key status`** lists each enabled key: its purpose, its slot on a card, its store, its fingerprint, its expiry and its warning level. It exits with the highest finding: a notice 60 days before an expiry (10), an alert 30 days before (11) and a critical alert 14 days before (12) ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)).

The root list is the file the install file names ([`trust.root_list`](/reference/install-file/#trust)); `sluis trust sync` takes over that job at parity.

### `sluis login` and `sluis token`

- **`sluis login`** signs a person in at the group issuer with the authorization code flow, PKCE `S256` and a loopback redirect on `127.0.0.1` (RFC 8252), as the public client the install file declares for the CLI (`sluis-cli` in the [example file](/reference/install-file/#the-example-file-for-local)). It then exchanges that token silently (RFC 8693) at each boundary's own token endpoint, so the front never sees a boundary's tokens ([ADR 0017](/decisions/0017-identity-and-sign-in/#step-up)). `--issuer` names the group issuer the first time; afterwards it comes from the cache. A browser opens; with no browser the command prints the URL to standard error.
- **`sluis token --audience CLIENT_ID`** prints an access token for that audience at the boundary given by `--boundary`, from the cache while it is valid, otherwise by a refresh or an exchange. A refusal exits 3 and looks the same for an unknown and a refused audience ([Contracts and errors](/reference/contracts/#oauth-and-openid-connect-endpoints)).
- **The cache** is `$XDG_CONFIG_HOME/sluis/tokens/` (`~/.config/sluis/tokens/` when the variable is unset), one file per issuer, mode `0600`. A file that another user can read is refused, not used.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success; for `key status` and `doctor`, nothing due. |
| 1 | Failure: something that should have worked did not, such as an unreadable file or a store that did not answer. |
| 2 | Usage error: an unknown command or flag, a missing argument, or a secret with no terminal and no descriptor. |
| 3 | Refused by a check or by policy: a schema error, a failed `doctor` or `config check` line, a hand-off answer that fails the requester's checks, a refused sign-in or token. |
| 4 | Refused by the keys driver or the card: a card that is locked or blocked, a PIN not delivered, a store that refuses the key's policy. |
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
| `fields` | `config explain` | A list of `{ "path", "value", "origin", "layer", "source" }`. A secret's `value` is its reference. |
| `keys` | `key request`, `key status` | A list of `{ "purpose", "boundary", "store", "slot", "fingerprint", "not_after", "days_left", "level" }`; `level` is `none`, `notice`, `alert` or `critical`. |
| `requests` | `key request` | A list of `{ "stem", "kind", "files": [{ "path", "sha256" }] }`. |
| `installed` | `key install` | A list of `{ "stem", "outcome", "reasons" }`. |
| `token` | `token` | `{ "access_token", "expires_at", "audience", "issuer" }`. |

Members are lower-case words with underscores; times are RFC 3339 in UTC; the object is not in canonical form. A new member is not a new version, so a reader ignores a member it does not know; a member renamed, removed or changed in meaning is version 2.

## Later commands

These come with the parity milestone and follow the conventions above ([#1097](https://github.com/truvity/sluis/issues/1097)): `sluis trust sync` and `trust enroll` ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)), `sluis node unlock` ([ADR 0006](/decisions/0006-keys-and-sealing/#touch-and-pin)), `sluis secrets`, `sluis backup` and `restore`, `sluis audit`, `sluis pki` and `sluis ssh`, the commands for integrations, clients and credentials, and the replacements for v1's `sluisctl` sign-in helpers (kubeconfig, cloud profiles, database and vendor wrappers). Until then, commands that the integration pages show and this page does not list show the shape, not decided names ([Examples are illustrative](/integrations/#examples-are-illustrative)).
