---
title: Rebuild one board
description: "Runbook for rebuilding one member of a boards installation after a reinstall: what is lost, and the steps with their checks."
status: partial
sidebar:
  order: 6
---

This page is the runbook for one case on the [boards](/runtimes/#boards) installation: one of the three boards was reinstalled from a fresh operating system and has to become a member again, with the other two boards left running. It states the target flow. Part of it is built (the recipes of [Deploy and prove on three boards](/runtimes/bare-metal/#deploy-and-prove-on-three-boards)), part is done by hand with a tool that is not a sluis recipe, and part is planned. Each step says which. **The flow has not been run end to end on a board yet**; the first run is the test of [REQ-DEPLOY-039](/requirements/deploy/#REQ-DEPLOY-039), and this page is fixed to match what that run shows.

Names below are placeholders: `<board>` is the board that was reinstalled, `<peer-a>` and `<peer-b>` are the two healthy boards, `<user>` is the SSH user of the installation, and `<serial>` is the serial of the board's YubiKey. The real values come from the environment (`SLUIS_BOARDS`, `SLUIS_BOARD_SSH_USER`, `SLUIS_BOARD_CARD_SERIALS`) and are never written in the repository.

## What a reinstall loses

| Lost | Why it matters | Where it is made again |
|---|---|---|
| The SSH host keys | The operator's known-hosts entry for the board now names a key the board no longer has, and `ssh` refuses the connection. | Step 3 |
| The local rqlite data | The board's copy of the store is gone. The other two boards hold every item, so nothing is lost for the installation, but the cluster still lists the board's old node. | Steps 1 and 4 |
| The machine-id | The board gets a new one. Nothing in the repository reads it (checked by search, 2026-11-06), so no sluis key or record is tied to it. | Nothing to do |
| The state directories of the units | Keys of the software key driver, the `keyplan.mark` and `boundary.mark` files of key@ and the card driver ([A mark that is ahead of the store](/runtimes/bare-metal/#a-mark-that-is-ahead-of-the-store)), and the audit spool that was not yet sealed. | The marks start empty and rise with the first verified documents; the sealed audit records are in the blob store. |
| The credentials, as encrypted on the board | They were encrypted under the board's own host key, which is new ([Credentials are encrypted on the board](/runtimes/bare-metal/#credentials-are-encrypted-on-the-board)). | Step 5: every deploy encrypts them again. |

What is **not** lost: the YubiKey and everything on it (the PIN, the keys in the slots, the slot `87` key), because the card is a separate device. The reinstall of a board that keeps its card therefore keeps its recipient and its entry in the signed slot map. A board whose card was replaced, or that ran the software key driver, has a new recipient.

## Why trust does not rest on the SSH host keys

The host keys of a board are not what makes it a member. A board is trusted for two reasons only: its **recipient** (the wrapping key in its card, slot `9d`) is listed in the `KeyPlan` that the maintainer's publisher key signed, and its **slot map entry** (the slot `87` key that signs its `PinReleaseRequest`, with the attestation of the card) is listed in the same document. A peer releases the PIN only to a board that the signed `KeyPlan` lists and that `KeyRevocation` does not revoke ([REQ-KEYS-093](/requirements/keys/#REQ-KEYS-093)), and a data key is wrapped only to a recipient that the `KeyPlan` lists ([Who may receive a wrap](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)). The PIN release between boards does not use SSH at all: it crosses the store, over the Raft port ([Touch, PIN and the locked board](/runtimes/bare-metal/#touch-pin-and-the-locked-board)).

SSH is the operator's path to a board: the deploy, the status and `boards-unlock`, which sends the card's PIN through the session with `StrictHostKeyChecking=yes`. A new host key is therefore a change the operator has to confirm by hand (step 3), and the hand-made confirmation is the only place where an SSH host key matters. A reinstalled board that has no listed recipient gets no PIN from a peer and no data key wrap, whatever its host keys say.

If the old card or key may be in someone else's hands (a lost or stolen board), this is not a rebuild but a compromise: declare the board's keys revoked first ([0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/)), and rebuild afterwards.

## Before you start

- The other two boards run, are unlocked, and are both reachable: with one board out of the cluster, rqlite keeps its quorum only while **both** healthy boards stay up. Do not deploy to, restart or unlock-test either of them until step 4 has finished.
- The board comes back at the **same address** it had. rqlite takes its node id from the Raft address, so a different address is a different node and the old one stays in the membership.
- The workstation has the environment of the build (`SLUIS_BOARDS` with all three boards, `SLUIS_BOARD_SSH_USER`), the signed seed from `just boards-prepare`, the executables from `just build-arm64`, and a known-hosts file of its own in `SLUIS_BOARD_SSH_OPTIONS` ([SSH](/runtimes/bare-metal/#deploy-and-prove-on-three-boards)). Prefer that file to `~/.ssh/known_hosts`: step 3 then touches one file, and only for one board.
- Check the healthy boards first. `SLUIS_BOARDS="<peer-a> <peer-b>" devbox run -- just boards-status` must show every unit active and, for each rqlite node, a line like `rqlite: ready; 3 nodes (3 voters), leader ...` under each board's heading. The cluster still counts the dead board as a voter at this point. The status reads each named board only, and notes that a run of fewer boards than the cluster is expected to differ.

## Steps

| # | Step | State |
|---|---|---|
| 1 | Remove the stale node from the rqlite membership | Done by hand with rqlite's own tool; a recipe is planned |
| 2 | Reinstall and prepare the board | Done by hand; the deploy checks the prerequisites |
| 3 | Refresh the known-hosts entry for that board only | Done by hand with OpenSSH; a recipe is planned |
| 4 | Rejoin the cluster under the same Raft address | Existing recipe, `boards-rqlite` |
| 5 | Deploy | Existing recipe, `boards-deploy` |
| 6 | Let the board unlock, or unlock it | Existing: the peer release, and `boards-unlock`; a read-only lock state is planned |
| 7 | Re-enrol its recipient | Existing recipe, `boards-recipients` |
| 8 | Re-sign the `KeyPlan` and put it on the boards | Existing recipes, `boards-prepare` and `boards-deploy`; waiting for each unlock is by hand |
| 9 | Verify | Existing recipes for the cluster and the key; the lock state and the old recipient are planned |

### 1. Remove the stale node from the membership

Do this from a healthy peer, before the reinstalled board starts rqlite. The leader still lists the board's old node as a voter; a node that comes back with no data under the same id would otherwise have to be reconciled with that entry.

State: **existing tool, planned recipe.** There is no sluis recipe that removes a node. rqlite's own tools do it: the `rqlite` shell that the package installs on every board (its `.remove` command, which takes the node id) or the `DELETE /remove` call of the HTTP API with `{"id": "<board>:4002"}` as its body. The node id is the board's Raft address, `<board address>:4002` (port 4002 unless `SLUIS_RQLITE_PORT_RAFT` changed it). The boards have no `curl`, so run the shell on `<peer-a>`, pointed at its own address and port 4001. The exact invocation is checked against the rqlite 10.6.6 shell in the first run of the test, and this step is rewritten with it.

Check: `SLUIS_BOARDS="<peer-a> <peer-b>" devbox run -- just boards-status` shows `rqlite: ready; 2 nodes (2 voters), leader ...` for both. The cluster now has no spare: do not touch either board.

### 2. Reinstall and prepare the board

State: **by hand.** sluis has no installer for the operating system; the supported systems and the image of the boards are in [Supported operating systems](/runtimes/bare-metal/#supported-operating-systems). Install the board with the same address as before, `sudo` with a passwordless account of `<user>`, key-only SSH, and the packages [a board needs before the first deploy](/runtimes/bare-metal/#what-a-board-needs-before-the-first-deploy) (`tar`, and on Rocky 10 `audit`). The YubiKey stays in the board. Open the rqlite ports 4001 and 4002 to the other two boards ([SELinux and the firewall](/runtimes/bare-metal/#selinux-and-the-firewall)).

Check: the deploy checks the prerequisites itself before it sends anything (it refuses a board without `tar`, and the board's checks write nothing), so a missing one shows at step 5. The ssh of step 3 shows the board is up.

### 3. Refresh the known-hosts entry for that board only

State: **by hand, with OpenSSH; a recipe is planned.** Do it before step 4, because `boards-rqlite` connects to the board over ssh. Remove the old entry of this one board from the known-hosts file of the run, fetch the new key, and compare its fingerprint with the one on the board's console before trusting it:

```sh
ssh-keygen -R <board> -f "$PWD/.cache/boards/known_hosts"
ssh-keyscan -t ed25519 <board> >>"$PWD/.cache/boards/known_hosts"
ssh-keygen -lf "$PWD/.cache/boards/known_hosts" | grep <board>
```

Compare the fingerprint on the last line with what the board's console prints (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the board). Do not use `StrictHostKeyChecking=no` or an empty known-hosts file: the scripts refuse them for the unlock, and the host-key check is the only thing between the PIN and a host that answers on the address. If the board's entries in the file are hashed, `ssh-keygen -R` still finds them. The other boards' entries are not touched.

Check: `SLUIS_BOARDS=<board> devbox run -- just boards-status` connects with no host-key warning. It reports the board's units and rqlite as not installed or not running; that is expected before steps 4 and 5. It also reports the rqlite firewall as ABSENT and exits 1 for that reason, which is expected until the board has the firewall again ([the rqlite firewall](/runtimes/bare-metal/#the-rqlite-firewall): apply it to the rebuilt board, one board, after step 9).

### 4. Rejoin under the same Raft address

State: **existing recipe.** Run `boards-rqlite` with **all three** boards in `SLUIS_BOARDS`, because every node starts with `-bootstrap-expect 3` and the Raft addresses of all three in `-join`:

```sh
SLUIS_BOARDS="<peer-a> <peer-b> <board>" devbox run -- just boards-rqlite
```

The recipe is idempotent: on the two healthy boards it installs nothing and does not restart a running node ([rqlite on the boards](/runtimes/bare-metal/#rqlite-on-the-boards)). On the rebuilt board it installs the pinned package and starts a node with no data, which first tries to join the cluster the others are in. It does not form a second cluster, because of the join list. Put the board's own address in the list under the same spelling as before.

Check: the recipe ends with one line per board, `board <b>: rqlite is ready; 3 nodes (3 voters), leader <id>`, and fails if any node sees fewer than three nodes in `/nodes`.

### 5. Deploy

State: **existing recipe.** Deploy to the rebuilt board alone, with the card driver and the serial of its card:

```sh
SLUIS_BOARDS=<board> SLUIS_BOARDS_KEY_DRIVER=yubikey-piv SLUIS_BOARD_CARD_SERIALS=<board>=<serial> devbox run -- just boards-deploy
```

A board with nothing deployed is not a "switch" of the key driver, so the one-board-at-a-time guard of [Switching a board to the card](/runtimes/bare-metal/#switching-a-board-to-the-card-or-back) does not mark it. The deploy installs the signed seed from `just boards-prepare`, encrypts the credentials under the new host key, starts the units, and ends with the AVC check on a board with SELinux enforcing. A card board starts locked, so the wait for its units can end non-zero; that is the next step's work.

Check: the output lists the units as `active`, or as failed only for the units that need an unlocked key@. `SLUIS_BOARDS=<board> devbox run -- just boards-status` shows the same, and rqlite as a ready voter.

### 6. Let the board unlock, or unlock it

State: **existing, with a gap in the check.** There are two ways, and the first is the one to expect.

- **It unlocks itself.** When the `KeyPlan` already lists the board's slot map entry (the board kept its card), key@ asks the peers for the PIN through the store as soon as it runs, and an unlocked peer answers ([REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059)). Give it a few seconds; the polling backs off to 10 seconds ([REQ-KEYS-118](/requirements/keys/#REQ-KEYS-118)). The factory PIN of a test card is the same on all three boards ("a boundary has one PIN").
- **You unlock it.** When the board is not in the signed slot map yet (a new card), no peer will answer. Give it the PIN from the workstation: `SLUIS_BOARDS=<board> devbox run -- just boards-unlock` (the PIN is read from standard input, never an argument), as in [The card driver](/runtimes/bare-metal/#the-card-driver). This needs the host key of step 3.

Check: in the journal of the board, `sudo journalctl -u sluis-key@dev.service` shows `unlocked by a peer's PIN release` after the first way (the audit fact is `key.pin.unlock`), or `sluis node unlock` reports the card driver unlocked after the second. **Planned:** `boards-status` does not show the lock state of a board (read in `boards.sh`, 2026-11-06), and there is no read-only command that does. Until there is, the journal line is the check.

### 7. Re-enrol its recipient

State: **existing recipe.** Read the board's wrapping key id again, and its slot map entry, into the files that `boards-prepare` signs:

```sh
SLUIS_BOARDS=<board> SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 devbox run -- just boards-recipients
```

The variable says that this one board's id may change: the recipe replaces the id it recorded for `<board>` last time (in `recipients.boards`) with the new one, and keeps the ids of the other two. When the board kept its card, the id is the same and nothing changes; the file keeps the same id. Without the variable, and naming only one board, the recipe refuses to write a file that would drop an id. Do not run it for the other boards: their keys are not touched.

Check: the output prints `recipients: 3 ids in .../recipients and 3 slot map entries in .../slot-map`, followed by the reminder to run `boards-prepare` and `boards-deploy`. `SLUIS_BOARDS=<board> devbox run -- just boards-key-check` prints `wrapping key listed: false` until step 8 when the id is new, and `true` when it is the old one.

### 8. Re-sign the KeyPlan

State: **existing recipes; the waiting is by hand.** The maintainer's publisher key signs the new `KeyPlan` with `just boards-prepare`, and `just boards-deploy` puts it on the boards. A deploy stops and starts every unit of a board, the card driver included, and **a restarted card driver is locked again.** So do not deploy to all three boards at once: deploy to **one board at a time**, with `SLUIS_BOARDS_KEY_DRIVER` unset so that each board keeps the driver it runs, and wait until the board has unlocked before the next one. That is the rolling update the PIN release exists for.

```sh
devbox run -- just boards-prepare
SLUIS_BOARDS=<board> devbox run -- just boards-deploy
# wait for the unlock of step 6, then
SLUIS_BOARDS=<peer-a> devbox run -- just boards-deploy
# wait, then
SLUIS_BOARDS=<peer-b> devbox run -- just boards-deploy
```

The other two boards' key@ then wrap the data keys for the new recipient. The recipient that the board had before is no longer in the `KeyPlan`, so no peer releases a PIN to it and no wrap is made for it; the wraps already in the store for it stay unused (nothing here deletes a wrap).

Check: `prepare:` prints `the KeyPlan lists 3 wrap recipients and 3 slot map entries`, and `SLUIS_BOARDS=<board> devbox run -- just boards-key-check` now passes with `wrapping key listed: true` and a complete wrap set.

### 9. Verify

All of these must hold before the rebuild is called done:

1. **The cluster has three voters.** `SLUIS_BOARDS="<peer-a> <peer-b> <board>" devbox run -- just boards-status`: each board prints `rqlite: ready; 3 nodes (3 voters), leader ...`. State: existing.
2. **The board is unlocked.** The journal line or the `sluis node unlock` report of step 6. State: existing by hand; the read-only lock state is planned.
3. **The PIN release works.** Deploy to `<board>` alone once more (`SLUIS_BOARDS=<board> devbox run -- just boards-deploy`): its card driver restarts locked, and with both peers up it unlocks without anyone giving it the PIN, as in step 6. This is the proof of [REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059) on the rebuilt board. State: existing by hand.
4. **The M1 spine passes on the board.** `SLUIS_BOARDS=<board> devbox run -- just boards-smoke`. State: existing.
5. **The old recipient is refused.** A request signed by the board's recipient from before the rebuild is refused with a reason in the audit log. State: **planned**; it is part of the board-flow test of [REQ-DEPLOY-041](/requirements/deploy/#REQ-DEPLOY-041), and there is no command for it yet. When the board kept its card there is no old recipient to refuse, and the test says so.

## The requirements

| Requirement | What it asks | Status |
|---|---|---|
| [REQ-DEPLOY-039](/requirements/deploy/#REQ-DEPLOY-039) | An operator can rebuild one member from a fresh operating system without touching the other members' keys | Planned |
| [REQ-DEPLOY-040](/requirements/deploy/#REQ-DEPLOY-040) | The rebuilt member rejoins under its previous Raft address and the cluster has three voters again | Planned |
| [REQ-DEPLOY-041](/requirements/deploy/#REQ-DEPLOY-041) | The `KeyPlan` lists the rebuilt member's current recipient and no earlier one | Planned |
| [REQ-KEYS-117](/requirements/keys/#REQ-KEYS-117) | A locked board unlocks from any one listed, unlocked, reachable peer | Partial |
| [REQ-KEYS-118](/requirements/keys/#REQ-KEYS-118) | A locked board keeps asking its peers, with a bounded backoff | Partial |

The PIN release itself is [REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059) and [REQ-KEYS-093](/requirements/keys/#REQ-KEYS-093); this page does not restate them.
