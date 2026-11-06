---
title: Incident response for a compromised key
description: "What an operator does when a key is compromised or suspected: the command, the effect, what consumers see and the time a drill measured, for each kind of key."
status: target
sidebar:
  order: 2
---

This page is the operator's runbook for a key that may be in the wrong hands. The rules are in [ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/); this page says what to do, in what order, what stops, what people and relying parties see, and how long it takes. It describes the target state: the commands do not exist yet, and every measured time below is empty until the first drill has run ([REQ-OPS-079](/requirements/ops/#REQ-OPS-079), [REQ-OPS-080](/requirements/ops/#REQ-OPS-080)).

## Before you start

1. **Declare, do not wait.** A suspected compromise is handled as a compromise. A false alarm costs one refresh per client; a wait costs forged tokens ([ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#a-person-declares-and-a-suspicion-counts)).
2. **Only a person declares.** You write a declaration that names the keys, sign it with the publisher key that signs the `KeyPlan`, and deliver it on a node as root ([`sluis key revoke`](/reference/cli/#sluis-key-revoke)). It needs neither sign-in nor the token keys, so it works when both are down. An alert never revokes on its own.
3. **If the compromise is in the key service itself** (a stolen role, a key policy that let someone else sign, a card in someone else's hands), remove that access first, in the key service. Then declare. A replacement key made under the same access is not a transition ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)).
4. **Read the answer.** The command prints "not confirmed" until it has fetched the published key set from its public address and the live key set of `entry`, and found the key gone from both ([principle 4](/principles/#4-verify-never-trust-a-claim)). Treat "not confirmed" as not done.
5. **A revocation is an audit fact and an alert.** It names the keys, the reason and the publisher key that signed the declaration.

A revocation is never undone. A restore, a roll-forward or a write by the key's own node cannot bring a revoked key back ([ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-tighten-only-record)).

## The token-signing key

This is the path with the most at stake, and the one a drill rehearses.

1. **Declare.** `sluis key revoke --boundary B --kid KID --reason compromise --out revoke.yaml` (or `suspicion`), sign `revoke.yaml` with the publisher key, then `sluis key revoke --boundary B --declaration revoke.jws` as root on any node. The command asks `key@` to write a `KeyRevocation` item, and the `key@` of any node can, so a compromised or powered-off node does not block you. `store@` accepts only creates of that kind, so the revocation cannot be undone.
2. **The key leaves the key set at once.** `exporter@` and `entry` omit every revoked `kid` from every key set they publish, and `exporter@` writes the new set, purges the edge copy and reads it back within 60 seconds ([Publishing public material](/decisions/0009-export/#the-order-and-the-time)). `signer` neither promotes nor signs with the revoked `kid`.
3. **The replacement signs at once when no other key is active.** On a multi-node installation the other nodes' keys are already published and cached, so nothing else is needed when the compromise is one node's. On a single-key installation a new key is made, published and purged before its first token.
4. **Wait for "confirmed".** The command checks two addresses and needs the `kid` gone from both: the public key set, through the edge, and the live key set of `entry`. It names the one that still lists the key. If the public address does, the edge copy is stale or `exporter@` could not publish: read its report (`ExportReport`) and purge the address by hand in the edge's own console or API (for Cloudflare, the purge of the URL). If only the live key set does, `entry` has not reread `KeyRevocation`: look at its answer. Then run `sluis key revoke --declaration` again; it is a retry and changes nothing that exists. Treat "not confirmed" as not done.
5. **Find the forgeries.** Every signature is an audit fact, so a token in the window that has no matching fact is forged. A relying party that logs `jti` can do the same; ask the relying parties for their logs.

What people and relying parties see:

| Who | What they see |
|---|---|
| A relying party with a standard verifier | A token signed by the revoked key fails after its copy of the key set expires. A token with an unfamiliar `kid` makes it fetch the key set again. |
| A relying party with a verifier that does not fetch again | Its sign-ins fail until it fetches the set. This verifier breaks the standard; it is fixed, not accommodated, and no workaround exists in this path. |
| A person with a live session | A client holding a token the key signed refreshes once. The session and the refresh token are not affected. |
| A cloud that trusts the workload-issuer key | It forgets the key on its own schedule. See the table of measured times. |

The named exceptions (the per-audience RS256 key, the FAPI keys, the cloud-federation keys and the NATS keys) follow the same steps with their own purpose. For a NATS operator or account key, also reissue the account JWTs on the NATS side after the key is revoked here.

The certificate revocation list is no control for tokens. A standard verifier ignores the `x5c` chain, so the only revocation a token key has is its removal from the key set.

## Data keys

Declare the generation, by its exact name, with `sluis key revoke` and `--reason compromise`. `key@` makes a new generation that every later seal uses and refuses every seal under the compromised one. Whether it also stops opening the compromised generation depends on what the key protects: the integrity keys (`grant`, `cookie`, `chain`) stop opening at once, because a forged value is the threat; the confidentiality keys (`data`, `pseudonym`, `evidence`) keep opening, because the thief already holds the key and refusing opens would only take the data offline. For `data` the re-seal job rewrites every value and then the old wraps are deleted.

| Purpose | What stops | What people see | After the declaration |
|---|---|---|---|
| `grant` | Seals and opens under the old generation are refused | Nothing; a grant lives about 60 seconds | No re-seal |
| `cookie` | Seals and opens under the old generation are refused; every browser session of the boundary ends | People sign in again, silently while the upstream session lives | Refresh-token chains are not affected |
| `chain` | Seals and opens under the old generation are refused; that tenant's session chains end | That tenant's people sign in again | Only that tenant |
| `data` (a tenant's, or the boundary's) | Seals under the old generation are refused; it keeps opening until the re-seal ends, then its wraps are deleted | Nothing, apart from latency during the job | Re-seal runs in pages and can be resumed |
| `pseudonym` | The epoch ends; no new hash under it | Past audit records keep their pseudonyms | A new epoch starts at once |
| `evidence` | Seals under the old generation are refused; it keeps opening for the retention | Nothing; what it already sealed stays exposed (accepted) | New evidence is sealed under a new generation |

On Lambda a warm function keeps its cached keys until their time to live ends, so an integrity key's revoked generation can still open values for that long. This delay is accepted for now and revisited after the first drill ([Accepted risks](#accepted-risks)).

An archive keeps the wraps and the values it held. Re-sealing cannot reach it, and its retention is the bound on that exposure.

## A board

1. **Remove the board.** `sluis key revoke --node NODE --reason compromise` removes its recipient and keys at once. `key@` makes no new wrap for it and deletes its existing wraps; its token-signing key is revoked as above; the other boards go on signing with theirs.
2. **Check that its PIN is not given away.** A peer releases a PIN only to a board that the `KeyPlan` lists and `KeyRevocation` does not revoke, so a stolen board that reconnects gets nothing.
3. **Replace the board.** A new board has a new card and a new key, and the other boards rewrap every data key for it. ritueel revokes the old certificate in the root lists ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)).
4. **Make the removal visible.** A reviewed `KeyPlan` commit drops the board from the signed list. The revocation is permanent: a board comes back only as a new key, listed in the `KeyPlan` by its new thumbprint.
5. **A suspected PIN** is changed with `sluis node pin`, which delivers the new PIN to the board over the unlock channel. Until that command exists, replace the board.

## An audit or issuance log key

Declare the log key with `sluis key revoke --kid KID --reason compromise`, as for a token-signing key. The new key signs a checkpoint that names the last size a witness cosigned before the compromise. Give the verifier both keys, each with the size from which it applies: `sluis audit verify` trusts the old key up to that size and the new key after it.

With no witness, nothing before the compromise can be trusted from the old key alone. A witness key's compromise is handled the same way: revoke it and drop it from the verifiers' witness list.

## An intermediate, an SSH CA and a release subkey

- **An X.509 intermediate.** `sluis key revoke --kid KID --reason compromise`, with the key id of the intermediate's key, makes `ca` stop issuing and removes the certificate from the trust bundle it renders. Hosts take the next bundle. Then ask ritueel to revoke the certificate in the root lists; sluis does not wait for it. **Assumption (not yet checked):** the host sync replaces its anchors with the bundle, and the anchors are the intermediates. If a host anchors a root, leaving the bundle stops nothing for it, and the controls are ritueel's root CRL and the short lifetimes of leaves; leaves carry no revocation address, so most clients never fetch a list. The follow-up in [#1341](https://github.com/truvity/sluis/issues/1341) states what the bundle holds and what the sync removes, and this step is corrected to the result.
- **An SSH user CA or host CA.** A key revocation list cannot name certificates nobody knows exist. Replace the key on ritueel's signed list of SSH CA keys. `sluis-host` fetches the list at the interval the documentation states ([REQ-SSH-009](/requirements/ssh/#REQ-SSH-009)), and alerts when its copy is older than twice that interval ([REQ-SSH-010](/requirements/ssh/#REQ-SSH-010)). The time for a list to reach a host is the last row of the [measured times](#measured-times). For a host CA, also replace the `@cert-authority` line in every client's known-hosts file.
- **An OpenPGP release subkey.** Revoke it under both primaries, as the release signing page describes ([REQ-SUPPLY-012](/requirements/supply/#REQ-SUPPLY-012)).

## A wrapping key, a recipient or an archive key

- **An AWS wrapping key.** Make a new KMS key, rewrap every data key under it, and only then disable the old key. Every data key is also wrapped for the offline recovery recipient, so the old archives stay restorable by ceremony after the disable. KMS automatic rotation is not an answer: it keeps the old key material.
- **A customer-account KMS key.** The customer revokes the grant. sluis fails closed for that tenant and alerts.
- **The recovery recipient.** ritueel replaces it by a ceremony, and every wrap is rewrapped for the new one.
- **The backup archive key.** Replace it and make the archives again. The old archives expire with their retention.
- **The enrolment key of `exchange`.** A bundle change replaces it.

An old archive stays readable by whoever held the old key until it expires. Disabling the key removes the route through the key service and not a copy of the key taken earlier.

## Measured times

Each figure is the time from the declaration to the first refusal by a verifier or a consumer, measured in a drill. They are empty until the first drill, and each gets a date, the versions and the installation.

| Key | Declaration to refusal | Date | Versions | Installation |
|---|---|---|---|---|
| Token-signing key, a standard verifier | | | | |
| Token-signing key, the edge cache purged | | | | |
| exporter@: the revocation seen to the read back completed (target 60 seconds) | | | | |
| Workload-issuer key, AWS | | | | |
| Workload-issuer key, GCP | | | | |
| Workload-issuer key, Entra | | | | |
| `cookie`, boards | | | | |
| `cookie`, Lambda (the cache's time to live) | | | | |
| A board's removal | | | | |
| SSH CA list reaches a host (the stated refresh interval) | | | | |
| X.509 trust bundle sync | | | | |

## Accepted risks

These are written in the [threat model](/security/threat-model/#accepted-risks) and revisited at the stated point.

| Key | What a leak allows | Why it is accepted | Revisited |
|---|---|---|---|
| `pairwise` | The thief links a person's subjects across relying parties | A replacement changes every `sub` and breaks every account link | When CIAM gives subjects their meaning |
| `mac` | The thief confirms guessed e-mail addresses or upstream ids offline against any id seen | A new key changes every link id, and a migration needs sealed inputs | At v1 parity, after a migration is measured |
| `evidence` (what it sealed before the declaration) | The thief reads a tenant's audit and usage evidence from before | Shredding it destroys evidence the law may require | When the first tenant with an evidence retention exits, or at v1 parity |
| Lambda cache | A warm function opens a revoked integrity-key generation until its entry expires | A shorter time to live costs key service calls | After the first drill |

## Drills

- **The token-signing key drill** runs at least once a year and after a change to the key path. It declares a compromise in a test installation, times the path above, lists the verifiers that fail and fills the table of measured times ([REQ-OPS-080](/requirements/ops/#REQ-OPS-080)).
- **The rotation drill** of a healthy key is separate ([REQ-OPS-078](/requirements/ops/#REQ-OPS-078)). The recovery sign-in and the backup restore have drills of their own ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073), [REQ-OPS-040](/requirements/ops/#REQ-OPS-040)).

## Related

- [ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/), the rules and the roads not taken.
- The [threat model](/security/threat-model/), threats [T-8 and T-10](/security/threat-model/#keys-and-signing).
- [Break-glass recovery](/security/break-glass/), the operator's way in when no upstream can vouch.
- [Keys](/reference/keys/), the generated list of purposes, algorithms and slots.
