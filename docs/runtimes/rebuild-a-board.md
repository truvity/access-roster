---
title: Rebuild one board
description: "Runbook for rebuilding one member of a boards installation after a reinstall: what is lost, and the steps with their checks."
status: partial
sidebar:
  order: 6
---

This page is the runbook for one case on the [boards](/runtimes/#boards) installation: one of the three boards was reinstalled from a fresh operating system and has to become a member again, with the other two boards left running. Part of the flow is built (the recipes of [Deploy and prove on three boards](/runtimes/bare-metal/#deploy-and-prove-on-three-boards)), part is done by hand with a tool that is not a sluis recipe, and part is planned. Each step says which. **The flow has been run end to end once, on 2026-11-07, on three boards, and it passed** ([the first run](#the-first-run)). The page is fixed to what that run showed. It was one run, of a board that kept its card; the cases it did not reach are listed in [the first run](#the-first-run).

Names below are placeholders: `<board>` is the board that was reinstalled, `<peer-a>` and `<peer-b>` are the two healthy boards, `<user>` is the SSH user of the installation, and `<serial>` is the serial of the board's YubiKey. The real values come from the environment (`SLUIS_BOARDS`, `SLUIS_BOARD_SSH_USER`, `SLUIS_BOARD_CARD_SERIALS`) and are never written in the repository.

## What a reinstall loses

| Lost | Why it matters | Where it is made again |
|---|---|---|
| The SSH host keys | The operator's known-hosts entry for the board now names a key the board no longer has, and `ssh` refuses the connection. | Step 3 |
| The local rqlite data | The board's copy of the store is gone. The other two boards hold every item, so nothing is lost for the installation, but the cluster still lists the board's old node. | Steps 1 and 4 |
| The machine-id | The board gets a new one. Nothing in the repository reads it (checked by search, 2026-11-06), so no sluis key or record is tied to it. | Nothing to do |
| The state directories of the units | Keys of the software key driver, the `keyplan.mark` and `boundary.mark` files of key@ and the card driver ([A mark that is ahead of the store](/runtimes/bare-metal/#a-mark-that-is-ahead-of-the-store)), and the audit spool that was not yet sealed. | The marks start empty and rise with the first verified documents. |
| The board's own audit log | On the boards the blob store is the `fs` driver on the board's local disk, so the sealed audit records are on the board and are lost with it unless a copy was made elsewhere. The other boards do not hold them. | Nowhere: the new log starts fresh and verifies (`sluis audit verify`), with none of the old records. See the caution below. |
| The credentials, as encrypted on the board | They were encrypted under the board's own host key, which is new ([Credentials are encrypted on the board](/runtimes/bare-metal/#credentials-are-encrypted-on-the-board)). | Step 5: every deploy encrypts them again. |

What is **not** lost: the YubiKey and everything on it (the PIN, the keys in the slots, the slot `87` key), because the card is a separate device. The reinstall of a board that keeps its card therefore keeps its recipient, its token key and its slot `87` key (MEASURED 2026-11-07: all three unchanged). Its entry in the signed slot map keeps its public keys but not its bytes ([step 8](#8-re-enrol-its-recipient)). A board whose card was replaced, or that ran the software key driver, has a new recipient.

:::caution[The audit log of a board does not survive its reinstall]
This is a risk of the installation, not of the rebuild. With the `fs` blob driver on the board's disk, the audit trail of a board is as durable as that disk. If a board's disk is lost, reinstalled or replaced, its records are gone, and a copy elsewhere is the only way back (the `fs` driver keeps no history, see [a damaged segment](/runtimes/bare-metal/#the-end-of-a-deploy)). Before a planned reinstall, copy the board's blob directory and its log somewhere off the board if the records matter. An installation that has to keep the audit trail across a lost board needs a blob store that is off the board ([One node](/runtimes/bare-metal/#one-node), [Limits and residual risk](/runtimes/bare-metal/#limits-and-residual-risk)).
:::

## Why trust does not rest on the SSH host keys

The host keys of a board are not what makes it a member. A board is trusted for two reasons only: its **recipient** (the wrapping key in its card, slot `9d`) is listed in the `KeyPlan` that the maintainer's publisher key signed, and its **slot map entry** (the slot `87` key that signs its `PinReleaseRequest`, with the attestation of the card) is listed in the same document. A peer releases the PIN only to a board that the signed `KeyPlan` lists and that `KeyRevocation` does not revoke ([REQ-KEYS-093](/requirements/keys/#REQ-KEYS-093)), and a data key is wrapped only to a recipient that the `KeyPlan` lists ([Who may receive a wrap](/decisions/0006-keys-and-sealing/#who-may-receive-a-wrap)). The PIN release between boards does not use SSH at all: it crosses the store, over the Raft port ([Touch, PIN and the locked board](/runtimes/bare-metal/#touch-pin-and-the-locked-board)).

SSH is the operator's path to a board: the deploy, the status and `boards-unlock`, which sends the card's PIN through the session with `StrictHostKeyChecking=yes`. A new host key is therefore a change the operator has to confirm by hand (step 3), and the hand-made confirmation is the only place where an SSH host key matters. A reinstalled board that has no listed recipient gets no PIN from a peer and no data key wrap, whatever its host keys say.

If the old card or key may be in someone else's hands (a lost or stolen board), this is not a rebuild but a compromise: declare the board's keys revoked first ([0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/)), and rebuild afterwards.

## Before you start

- The other two boards run, are unlocked, and are both reachable: with one board out of the cluster, rqlite keeps its quorum only while **both** healthy boards stay up. Do not deploy to, restart or unlock-test either of them until step 4 has finished.
- The board comes back at the **same address** it had. rqlite takes its node id from the Raft address, so a different address is a different node and the old one stays in the membership.
- The workstation has the environment of the build (`SLUIS_BOARDS` with all three boards, `SLUIS_BOARD_SSH_USER`), the signed seed from `just boards-prepare`, the executables from `just build-arm64`, and a known-hosts file of its own in `SLUIS_BOARD_SSH_OPTIONS` ([SSH](/runtimes/bare-metal/#deploy-and-prove-on-three-boards)). Prefer that file to `~/.ssh/known_hosts`: step 3 then touches one file, and only for one board.
- Check the healthy boards first. `SLUIS_BOARDS="<peer-a> <peer-b>" devbox run -- just boards-status` must show every unit active and, for each rqlite node, a line like `rqlite: ready; 3 nodes (3 voters), leader ...` under each board's heading. The cluster still counts the dead board as a voter at this point. The status reads each named board only, and notes that a run of fewer boards than the cluster is expected to differ. It also exits 1 for a run of two boards, because the firewall sets on each board still hold three ([the firewall](/runtimes/bare-metal/#the-rqlite-firewall) compares them with `SLUIS_BOARDS`); read the lines, not the exit status.

## Steps

| # | Step | State |
|---|---|---|
| 1 | Remove the stale node from the rqlite membership | Done by hand with rqlite's own shell; a recipe is planned |
| 2 | Reinstall and prepare the board | Done by hand with a tool that is not a sluis recipe; the deploy checks the prerequisites |
| 3 | Refresh the known-hosts entry for that board only | Done by hand with OpenSSH; a recipe is planned |
| 4 | Rejoin the cluster under the same Raft address | Existing recipe, `boards-rqlite` |
| 5 | Deploy | Existing recipe, `boards-deploy` |
| 6 | Let the board unlock, or unlock it | Existing: the peer release, and `boards-unlock`; the lock state is in `boards-status` |
| 7 | Give the board its firewall | Existing recipes, `boards-firewall` and its checks |
| 8 | Re-enrol its recipient | Existing recipe, `boards-recipients` |
| 9 | Re-sign the `KeyPlan` and put it on the boards | Existing recipes, `boards-prepare` and `boards-deploy`; optional for a board that kept its card; waiting for each unlock is by hand |
| 10 | Verify | Existing recipes; the old recipient's refusal is planned |

### 1. Remove the stale node from the membership

Do this from a healthy peer, before the reinstalled board starts rqlite. The leader still lists the board's old node as a voter; a node that comes back with no data under the same id would otherwise have to be reconciled with that entry.

State: **existing tool, planned recipe.** There is no sluis recipe that removes a node. rqlite's own shell does it, the `rqlite` command that the package installs on every board (MEASURED 2026-11-07, rqlite 10.6.6). Run it **on the leader**, over ssh, because the client port 4001 is behind the [rqlite firewall](/runtimes/bare-metal/#the-rqlite-firewall) and the workstation does not reach it. The node id is the board's Raft address, `<board>:<raft port>` (port 4002 unless `SLUIS_RQLITE_PORT_RAFT` changed it); the leader's address and client port are `<leader>` and `<http port>` (4001 unless `SLUIS_RQLITE_PORT` changed it). The `boards-status` line of the healthy boards names the leader's id.

```sh
printf '.nodes all\n.remove <board>:<raft port>\n' | rqlite -H <leader> -p <http port>
```

`.nodes all` prints the membership first, so the output shows the node before it goes. `.remove` prints **nothing** on success. The boards have no `curl`, so the `DELETE /remove` call of the HTTP API is not an option there.

Check: list the nodes again on the leader (`printf '.nodes all\n' | rqlite -H <leader> -p <http port>`): two nodes remain, both voters and reachable. `SLUIS_BOARDS="<peer-a> <peer-b>" devbox run -- just boards-status` shows `rqlite: ready; 2 nodes (2 voters), leader ...` for both, **and exits 1**: the firewall sets on each board still hold three boards, and the status compares them with `SLUIS_BOARDS`. Read the lines, or use the listing as the check. The cluster now has no spare: do not touch either board.

### 2. Reinstall and prepare the board

State: **by hand, with a tool that is not a sluis recipe.** sluis has no installer for the operating system; the supported systems and the image of the boards are in [Supported operating systems](/runtimes/bare-metal/#supported-operating-systems). The board must come back with the same address as before, `sudo` with a passwordless account of `<user>`, key-only SSH, and the packages [a board needs before the first deploy](/runtimes/bare-metal/#what-a-board-needs-before-the-first-deploy). The YubiKey stays in the board.

The procedure of the first run (MEASURED 2026-11-07, Ubuntu 26.04.1, the board installed from a rescue SD card to its eMMC):

1. **Boot a rescue card** in the board (an SD card with a rescue system on it).
2. **Use a known-hosts file of its own for the rescue system**, apart from the one of the run (`-o UserKnownHostsFile=<rescue known-hosts file>`). The rescue system has host keys of its own; they do not belong in the file of the installed board and are not the keys of step 3.
3. **Stage three things on the board** with `scp`: the operating system image, the firmware, and the install seed that the installer reads (not the signed seed of `boards-prepare`, which carries credentials and is sent at step 5).
4. **Run the installer** on the board: `install-emmc --firmware <firmware> --image <image> --seed <seed> --yes`. It writes the eMMC.
5. **The owner swaps the card.** The tool ends by printing "Remove the SD card"; someone at the board takes the rescue card out, and the board boots from the eMMC. This is a hand action at the board, and the one step the operator cannot do from the workstation.

The install seed holds **public keys and addresses only**. The operator sends **nothing secret** over the rescue session: no PIN, no credential, no private key. The rescue system's host keys are not verified (see the limit in step 3), so the session is trusted with what an eavesdropper could read, and no more.

Install the packages that the deploy needs on the new system: `tar`, **`nftables` on Ubuntu and on Rocky** (`boards-deploy` refuses a board without `/usr/sbin/nft`, and a fresh Ubuntu image of the boards lacked it, MEASURED 2026-11-07), and on Rocky 10 also `audit`. Open the rqlite ports 4001 and 4002 to the other two boards if the image has a firewall of its own ([SELinux and the firewall](/runtimes/bare-metal/#selinux-and-the-firewall)).

Check: the deploy checks the prerequisites itself before it sends anything (it refuses a board without `tar` or `/usr/sbin/nft`, and the board's checks write nothing), so a missing package shows at step 5. The ssh of step 3 shows the board is up.

### 3. Refresh the known-hosts entry for that board only

State: **by hand, with OpenSSH; a recipe is planned.** Do it before step 4, because `boards-rqlite` connects to the board over ssh. Remove the old entry of this one board from the known-hosts file of the run, fetch the new key, and compare its fingerprint with the one the board printed before trusting it:

```sh
ssh-keygen -R <board> -f "$PWD/.cache/boards/known_hosts"
ssh-keyscan -t ed25519 <board> >>"$PWD/.cache/boards/known_hosts"
ssh-keygen -lf "$PWD/.cache/boards/known_hosts" | grep <board>
```

`ssh-keygen -R` leaves a backup, `known_hosts.old`, next to the file. Remove it afterwards if you do not want two copies of the file.

**Where the fingerprint to compare with comes from.** A console cannot run `ssh-keygen -lf` on the board: that needs a login, and the login is what the check is for. What exists is the fingerprint block that cloud-init prints on the console **once**, on the boot that generates the host keys (MEASURED 2026-11-07 on the reinstalled board). So watch the console of the first boot from the eMMC, read the block, and compare its ed25519 line with the last line above. A later boot does not print it again.

**The limit.** A rescue card that is reused, or moved from another board, keeps the host keys it generated the first time, so it prints no new block, and its host key cannot be verified this way. For such a session, and for any session whose key was not checked, send nothing secret: the image, the firmware and the install seed (public keys and addresses only) are all it may receive. The deploy of step 5 sends the credentials in the clear through the ssh session, and encrypts them on the board ([Credentials are encrypted on the board](/runtimes/bare-metal/#credentials-are-encrypted-on-the-board)), and `boards-unlock` sends a PIN, so neither runs against a key that was not verified.

Do not use `StrictHostKeyChecking=no` or an empty known-hosts file: the scripts refuse them for the unlock, and the host-key check is the only thing between the PIN and a host that answers on the address. If the board's entries in the file are hashed, `ssh-keygen -R` still finds them. The other boards' entries are not touched.

Check: `SLUIS_BOARDS=<board> devbox run -- just boards-status` connects with no host-key warning. Its exit status is 1 and is not the check: the units, rqlite and the firewall of a board that has had nothing deployed are not there yet, and what it prints for them is expected until steps 4, 5 and 7. What the step needs is the connection with no host-key warning.

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

A board with nothing deployed is not a "switch" of the key driver, so the one-board-at-a-time guard of [Switching a board to the card](/runtimes/bare-metal/#switching-a-board-to-the-card-or-back) does not mark it. The deploy installs the signed seed from `just boards-prepare`, encrypts the credentials under the new host key, starts the units, and ends with the AVC check on a board with SELinux enforcing.

A card board starts locked, and the deploy has **two expected endings** (MEASURED 2026-11-07); both exit with status 0:

- `SLUIS-BOARD-STATE: ok` and `board <board>: deployed`: a peer released the PIN during the deploy's settle wait, so the board was unlocked by the time the wait ended.
- `board <board>: deployed, LOCKED`: the settle wait ended before a peer answered. Nothing failed; the board unlocks in the next seconds (step 6).

Only `board <board>: deploy FAILED` (exit 1) is a failure.

Check: the output lists the units as `active`, or as waiting for the lock. `SLUIS_BOARDS=<board> devbox run -- just boards-status` shows the same, and rqlite as a ready voter.

### 6. Let the board unlock, or unlock it

State: **existing.** There are two ways, and the first is the one to expect.

- **It unlocks itself.** When the `KeyPlan` already lists the board's slot map entry (the board kept its card), key@ asks the peers for the PIN through the store as soon as it runs, and an unlocked peer answers ([REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059)). Give it a few seconds; the polling backs off to 10 seconds ([REQ-KEYS-118](/requirements/keys/#REQ-KEYS-118)). In the first run four unlocks took 7 to 16 s from request to unlock, with no hand action and no PIN given. The factory PIN of a test card is the same on all three boards ("a boundary has one PIN").
- **You unlock it.** When the board is not in the signed slot map yet (a new card), no peer will answer. Give it the PIN from the workstation: `SLUIS_BOARDS=<board> devbox run -- just boards-unlock` (the PIN is read from standard input, never an argument), as in [The card driver](/runtimes/bare-metal/#the-card-driver). This needs the host key of step 3. Not run yet (see [the first run](#the-first-run)).

Check: `SLUIS_BOARDS=<board> devbox run -- just boards-status` prints `board <board>: unlocked` or `board <board>: locked`, read from the card driver itself. `sudo /opt/sluis/bin/cli/sluis node status <node> --boundary dev` on the board says the same and sends and prints no PIN ([the command](/reference/cli/#sluis-node-status)). The journal shows how it unlocked: `sudo journalctl -u sluis-key@dev.service` has `unlocked by a peer's PIN release` after the first way (the audit fact is `key.pin.unlock`).

### 7. Give the board its firewall

State: **existing recipes.** The reinstall removed the board's [rqlite firewall](/runtimes/bare-metal/#the-rqlite-firewall). Put it back on this one board, in the order of the first rollout ([apply, confirm, remove, and the order of the first rollout](/runtimes/bare-metal/#apply-confirm-remove-and-the-order-of-the-first-rollout)), with all three boards in `SLUIS_BOARDS` and the board in `SLUIS_FIREWALL_BOARDS`:

1. **With an empty administration host:** `boards-firewall`, then `boards-firewall-confirm` within the dead-man time, then `boards-firewall-check`. This workstation is a stranger to the rules, so the check proves the "closed" half with the machine you are on. `SLUIS_FIREWALL_ADMIN_HOST` must be empty for these three. An override in front of a recipe does not clear it when a settings file exports it later: see [clearing the administration host](/runtimes/bare-metal/#clearing-the-administration-host).
2. **With the administration host:** set `SLUIS_FIREWALL_ADMIN_HOST`, run `boards-firewall` again and `boards-firewall-confirm`.
3. **The reboot check:** `boards-firewall-reboot-check`. It reboots the board. **A card board comes back locked and stays locked until a peer unlocks it**; with both peers up that is a matter of seconds (step 6), and without them it is `boards-unlock`.

Check: `boards-firewall-check` passes at point 1, `boards-firewall-confirm` passes at point 2, and the reboot check ends `ok` (with "the stranger half was NOT run" when an administration host is set and there is no outside host, which is expected). `boards-status` for all three boards then prints `rqlite firewall present and kept` and exits 0.

### 8. Re-enrol its recipient

State: **existing recipe.** Read the board's wrapping key id again, and its slot map entry, into the files that `boards-prepare` signs:

```sh
SLUIS_BOARDS=<board> SLUIS_BOARDS_RECIPIENTS_SWITCHED=1 devbox run -- just boards-recipients
```

The variable says that this one board's id may change: the recipe replaces the id it recorded for `<board>` last time (in `recipients.boards`) with the new one, and keeps the ids of the other two. Without the variable, and naming only one board, the recipe refuses to write a file that would drop an id. Do not run it for the other boards: their keys are not touched.

When the board kept its card, the **id and the recipients file are unchanged**. The board's **slot map entry is not unchanged in bytes**: it holds new attestation certificates (the same public keys), and it moves to the end of the slot map file (MEASURED 2026-11-07). So a re-sign (step 9) is optional for a kept card: the signed `KeyPlan` lists the same recipient and the same public keys. Re-sign when you want the signed slot map to carry the current certificates.

Check: the output prints `recipients: 3 ids in .../recipients and 3 slot map entries in .../slot-map`, followed by the reminder to run `boards-prepare` and `boards-deploy`. `SLUIS_BOARDS=<board> devbox run -- just boards-key-check` prints `wrapping key listed: true` for a kept card, and `false` until step 9 when the id is new.

### 9. Re-sign the KeyPlan

State: **existing recipes; the waiting is by hand; optional for a kept card.** The maintainer's publisher key signs the new `KeyPlan` with `just boards-prepare`, and `just boards-deploy` puts it on the boards. A deploy stops and starts every unit of a board, the card driver included, and **a restarted card driver is locked again.** So do not deploy to all three boards at once: deploy to **one board at a time**, with `SLUIS_BOARDS_KEY_DRIVER` unset so that each board keeps the driver it runs, and wait until the board has unlocked before the next one. That is the rolling update the PIN release exists for.

```sh
devbox run -- just boards-prepare
SLUIS_BOARDS=<board> devbox run -- just boards-deploy
# wait for the unlock of step 6, then
SLUIS_BOARDS=<peer-a> devbox run -- just boards-deploy
# wait, then
SLUIS_BOARDS=<peer-b> devbox run -- just boards-deploy
```

The first run deployed the other two boards one at a time like this after the rebuilt board was back, each unlocked by a peer's release.

The other two boards' key@ then wrap the data keys for the new recipient. The recipient that the board had before is no longer in the `KeyPlan`, so no peer releases a PIN to it and no wrap is made for it; the wraps already in the store for it stay unused (nothing here deletes a wrap).

Check: `prepare:` prints `the KeyPlan lists 3 wrap recipients and 3 slot map entries`, and `SLUIS_BOARDS=<board> devbox run -- just boards-key-check` now passes with `wrapping key listed: true` and a complete wrap set.

### 10. Verify

All of these must hold before the rebuild is called done:

1. **The cluster has three voters.** `SLUIS_BOARDS="<peer-a> <peer-b> <board>" devbox run -- just boards-status`: each board prints `rqlite: ready; 3 nodes (3 voters), leader ...`, the lock state `board <b>: unlocked`, and the firewall `present and kept`, and the run exits 0. State: existing.
2. **The board is unlocked.** The `board <board>: unlocked` line of `boards-status`, or `sluis node status` on the board. State: existing.
3. **The PIN release works.** Deploy to `<board>` alone once more (`SLUIS_BOARDS=<board> devbox run -- just boards-deploy`): its card driver restarts locked, and with both peers up it unlocks without anyone giving it the PIN, as in step 6. This is the proof of [REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059) on the rebuilt board. State: existing by hand.
4. **The M1 spine passes on the board.** `devbox run -- just boards-smoke` over all three boards; it ends "M1 passed on 3 boards". State: existing.
5. **The audit log verifies.** `sluis audit verify` on each board, ok. The new log of the rebuilt board starts fresh. State: existing by hand.
6. **No denial.** No AVC with SELinux enforcing (`just boards-avc`), and no AppArmor denial on Ubuntu. State: existing.
7. **The old recipient is refused.** A request signed by the board's recipient from before the rebuild is refused with a reason in the audit log. State: **planned**; it is part of the board-flow test of [REQ-DEPLOY-041](/requirements/deploy/#REQ-DEPLOY-041), and there is no command for it. When the board kept its card there is no old recipient to refuse, and the first run did not run it for that reason.

## The first run

**Result: PASS** (2026-11-07, at `main` `ea228a864a7c1e2ff6c0d969e6887c240c60a2b3`, three boards). One of the three boards was reinstalled from a rescue SD card with Ubuntu 26.04.1 and kept its YubiKey. The other two kept running; then they were deployed one at a time.

| What | Result (MEASURED) |
|---|---|
| The reinstalled board rejoined rqlite | At the same address, as a voter; every node reported 3 nodes, 3 voters, one leader, with equal indices |
| It unlocked | From a peer's PIN release, with no hand action; four unlocks took 7 to 16 s from request to unlock |
| It got the firewall | Steps 7.1 to 7.3, on that one board |
| `boards-status` | Exit 0 on all three boards |
| `boards-smoke` | Passed on all three boards for the first time ("M1 passed on 3 boards") |
| `sluis audit verify` | ok on all three boards; the rebuilt board's new log starts fresh and verifies |
| Denials | No AVC with SELinux enforcing; 0 AppArmor denials |
| An idle check of 10.7 minutes | Checkpoints unchanged, no restarts |
| The card | No PIN was used and nothing was written to a card |
| Time with no spare | 14 min 38 s, from the node removed to the node rejoined |
| Total | About 40 min |

What was lost with the board is the list [above](#what-a-reinstall-loses): the local audit log, the SSH host keys, the machine-id, the rqlite data (re-synced from the peers), the marks and the credentials of the state directories (the deploy encrypted the credentials again). The card kept its keys and its PIN, so the recipient id, the token key and the slot `87` key are unchanged.

**What the run did not show.**

- A board whose **card was replaced**, or that ran the software key driver: its recipient is new, steps 8 and 9 are not optional, the first unlock needs `boards-unlock`, and the request signed by the old recipient is refused ([REQ-DEPLOY-041](/requirements/deploy/#REQ-DEPLOY-041)). None of this has been run.
- The **refusal of the old recipient**: not applicable to a kept card, and no command runs it.
- **Both peers off**, or a peer that is itself locked with nobody to unlock it: not run ([REQ-KEYS-117](/requirements/keys/#REQ-KEYS-117), [REQ-KEYS-118](/requirements/keys/#REQ-KEYS-118)).
- A **compromised** board (revoke first, rebuild after): not a rebuild, and not run.
- A rescue **card that was reused or moved** (step 3's limit).

## The requirements

| Requirement | What it asks | Status |
|---|---|---|
| [REQ-DEPLOY-039](/requirements/deploy/#REQ-DEPLOY-039) | An operator can rebuild one member from a fresh operating system without touching the other members' keys | Partial: run once, 2026-11-07, for a board that kept its card |
| [REQ-DEPLOY-040](/requirements/deploy/#REQ-DEPLOY-040) | The rebuilt member rejoins under its previous Raft address and the cluster has three voters again | Partial: run once, 2026-11-07 |
| [REQ-DEPLOY-041](/requirements/deploy/#REQ-DEPLOY-041) | The `KeyPlan` lists the rebuilt member's current recipient and no earlier one | Partial: the kept card's recipient is listed; a replaced card and the old recipient's refusal are not run |
| [REQ-KEYS-117](/requirements/keys/#REQ-KEYS-117) | A locked board unlocks from any one listed, unlocked, reachable peer | Partial |
| [REQ-KEYS-118](/requirements/keys/#REQ-KEYS-118) | A locked board keeps asking its peers, with a bounded backoff | Partial |

The PIN release itself is [REQ-KEYS-059](/requirements/keys/#REQ-KEYS-059) and [REQ-KEYS-093](/requirements/keys/#REQ-KEYS-093); this page does not restate them.
