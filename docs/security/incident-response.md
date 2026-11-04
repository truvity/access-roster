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
2. **Only a person declares.** Sign in with fresh multi-factor authentication, or use the [break-glass](/security/break-glass/) session when normal sign-in is down. An alert never revokes on its own.
3. **If the compromise is in the key service itself** (a stolen role, a key policy that let someone else sign, a card in someone else's hands), remove that access first, in the key service. Then declare. A replacement key made under the same access is not a transition ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)).
4. **Read the answer.** The command prints "not confirmed" until it has fetched the published key set from its public address and found the key gone ([principle 4](/principles/#4-verify-never-trust-a-claim)). Treat "not confirmed" as not done.
5. **A revocation is an audit fact and an alert.** It names the key or the purpose, the reason and you.

A revocation is never undone. A restore, a roll-forward or a write by the key's own node cannot bring a revoked key back ([ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-tighten-only-record)).

## The token-signing key

This is the path with the most at stake, and the one a drill rehearses.

1. **Declare.** `sluis key revoke --purpose token-signing --kid KID --reason compromise` (or `suspected`). Any node's `signer` may revoke any node's key, so a compromised or powered-off node does not block you.
2. **The key leaves the key set at once.** `signer` writes the ring without it, `exporter@` publishes the new set and purges the edge copy.
3. **The replacement signs at once when no other key is active.** On a multi-node installation the other nodes' keys are already published and cached, so nothing else is needed when the compromise is one node's. On a single-key installation a new key is made, published and purged before its first token.
4. **Wait for "confirmed".** If it stays "not confirmed", the edge copy is stale: purge it by hand and run `sluis key status`.
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

Declare with `sluis key revoke --purpose PURPOSE [--tenant TENANT] --reason compromise`. `key@` makes a new generation, stops opening the compromised one at once, and starts the re-seal job. The old wraps are deleted when the job ends.

| Purpose | What stops | What people see | After the declaration |
|---|---|---|---|
| `grant` | The old generation is deleted at once | Nothing; a grant lives about 60 seconds | No re-seal |
| `cookie` | Every browser session of the boundary ends | People sign in again, silently while the upstream session lives | Refresh-token chains are not affected |
| `chain` | That tenant's session chains end | That tenant's people sign in again | Only that tenant |
| `data` (a tenant's, or the boundary's) | The generation stops opening | Nothing, apart from latency during the job | Re-seal runs in pages and can be resumed |
| `pseudonym` | The epoch ends | Past audit records keep their pseudonyms | A new epoch starts at once |

On Lambda a warm function keeps its cached keys until their time to live ends, so a revoked generation can still open values for that long. This delay is accepted for now and revisited after the first drill ([Accepted risks](#accepted-risks)).

An archive keeps the wraps and the values it held. Re-sealing cannot reach it, and its retention is the bound on that exposure.

## A board

1. **Remove the board.** `sluis key revoke --node NODE --reason compromise` removes its recipient and keys at once. `key@` makes no new wrap for it and deletes its existing wraps; its token-signing key is revoked as above; the other boards go on signing with theirs.
2. **Check that its PIN is not given away.** A peer refuses a PIN-release request from a board that the recipient list does not name, so a stolen board that reconnects gets nothing.
3. **Replace the board.** A new board has a new card and a new key, and the other boards rewrap every data key for it. ritueel revokes the old certificate in the root lists ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning)).
4. **Make the removal permanent.** A reviewed `KeyPlan` commit drops the board from the signed list.
5. **A suspected PIN** is changed with `sluis node pin`, which delivers the new PIN to the board over the unlock channel. Until that command exists, replace the board.

## An audit or issuance log key

Declare with `sluis key revoke --purpose audit-log --reason compromise` (or `issuance-log`). The new key signs a checkpoint that names the last size a witness cosigned before the compromise. Give the verifier both keys, each with the size from which it applies: `sluis audit verify` trusts the old key up to that size and the new key after it.

With no witness, nothing before the compromise can be trusted from the old key alone. A witness key's compromise is handled the same way: revoke it and drop it from the verifiers' witness list.

## An intermediate, an SSH CA and a release subkey

- **An X.509 intermediate.** `sluis key revoke --purpose x509 --trust-domain DOMAIN` makes `ca` stop issuing and removes the certificate from the trust bundle it renders. Hosts take the next bundle. Then ask ritueel to revoke the certificate in the root lists; sluis does not wait for it. Leaves carry no revocation address, so the bundle, not the list, is the control.
- **An SSH user CA or host CA.** A key revocation list cannot name certificates nobody knows exist. Replace the key on ritueel's signed list of SSH CA keys. `sluis-host` fetches the list at the interval below, and alerts when its copy is older than twice that interval. For a host CA, also replace the `@cert-authority` line in every client's known-hosts file.
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
| Workload-issuer key, AWS | | | | |
| Workload-issuer key, GCP | | | | |
| Workload-issuer key, Entra | | | | |
| `cookie`, boards | | | | |
| `cookie`, Lambda (the cache's time to live) | | | | |
| A board's removal | | | | |
| SSH CA list refresh (stated interval) | | | | |
| X.509 trust bundle sync | | | | |

## Accepted risks

These are written in the [threat model](/security/threat-model/#accepted-risks) and revisited at the stated point.

| Key | What a leak allows | Why it is accepted | Revisited |
|---|---|---|---|
| `pairwise` | The thief links a person's subjects across relying parties | A replacement changes every `sub` and breaks every account link | When CIAM gives subjects their meaning |
| `mac` | The thief confirms guessed e-mail addresses or upstream ids offline against any id seen | A new key changes every link id, and a migration needs sealed inputs | At v1 parity, after a migration is measured |
| `evidence` | The thief reads a tenant's audit and usage evidence | Shredding it destroys evidence the law may require | When the retention is revisited |
| Lambda cache | A warm function opens a revoked generation until its entry expires | A shorter time to live costs key service calls | After the first drill |

## Drills

- **The token-signing key drill** runs at least once a year and after a change to the key path. It declares a compromise in a test installation, times the path above, lists the verifiers that fail and fills the table of measured times ([REQ-OPS-080](/requirements/ops/#REQ-OPS-080)).
- **The rotation drill** of a healthy key is separate ([REQ-OPS-078](/requirements/ops/#REQ-OPS-078)). The recovery sign-in and the backup restore have drills of their own ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073), [REQ-OPS-040](/requirements/ops/#REQ-OPS-040)).

## Related

- [ADR 0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/), the rules and the roads not taken.
- The [threat model](/security/threat-model/), threats [T-8 and T-10](/security/threat-model/#keys-and-signing).
- [Break-glass recovery](/security/break-glass/), the operator's way in when no upstream can vouch.
- [Keys](/reference/keys/), the generated list of purposes, algorithms and slots.
