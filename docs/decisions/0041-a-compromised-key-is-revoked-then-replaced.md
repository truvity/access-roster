# 0041 — A compromised key is revoked, then replaced: it leaves at once, its replacement signs at once, and only a person declares

**Status:** Accepted
**Date:** 2026-11-04

Proposal: [issue #1341](https://github.com/truvity/sluis/issues/1341).

## Context

The records say that a key is replaced on "a suspected compromise" ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule), [0006](/decisions/0006-keys-and-sealing/#rotation)), and that a compromise is answered by revocation and a transition ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)). They do not say how. Read on 2026-11-04, at `main`:

- **There is no revoke command, no revoked state and no confirmation.** `sluis key` has `request`, `install` and `status` ([CLI](/reference/cli/)). Only a tenant in a customer account has a kill switch ([REQ-KEYS-071](/requirements/keys/#REQ-KEYS-071)).
- **A healthy key's schedule is the only schedule.** A new token-signing key is pre-published for the lead time and an old one stays in the key set for 65 minutes ([0006](/decisions/0006-keys-and-sealing/#rotation)). Applied to a stolen key, the forged tokens verify for the lead time plus 65 minutes after the decision. Only a node's own `signer` may move its key ([REQ-KEYS-077](/requirements/keys/#REQ-KEYS-077)), so a compromised node decides whether its key leaves.
- **A restore could bring a revoked key back.** Roll-forward re-applies revocations of sessions, clients and certificates ([0010](/decisions/0010-backup-and-recovery/#roll-forward)), but nothing says it re-applies the state of a key.
- **Most data keys have no rule at all.** `pseudonym` has a sentence in [0029](/decisions/0029-the-audit-log/#pseudonyms). `mac` and `pairwise` are never replaced in place, which contradicts "replaced on a suspected compromise". No record defines the re-seal job that [REQ-KEYS-011](/requirements/keys/#REQ-KEYS-011) assumes.
- **A stolen board is a PIN away from being useful.** A board that reconnects asks its peers for the PIN, and the records do not say the peer checks that the board is still listed ([0006](/decisions/0006-keys-and-sealing/#touch-and-pin)).
- **The runbook that [0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning) promises does not exist.** The threat model says "until the audit log shows it" ([T-8, T-10](/security/threat-model/#keys-and-signing)) and nothing says what happens next.

The maintainer's rule of 2026-11-04 settles the verifier side: a verifier that breaks a standard is detected and fixed, not accommodated, so the emergency path has no workaround for one. The principles settle the rest of the token-signing case: a tightening takes effect at once and stays ([12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)), redundancy is not a defence against compromise ([2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise)), a person declares and the machine acts ([7](/principles/#7-a-person-only-where-a-person-adds-safety)), a check that cannot run is reported as not run ([4](/principles/#4-verify-never-trust-a-claim)), and a time is measured and dated ([9](/principles/#9-measure-before-deciding-and-date-the-measurement)).

## Decision

### A person declares, and a suspicion counts

- **A compromised key is revoked first and replaced second.** Revoked means it leaves every published set and signs, opens or wraps nothing more. The pre-publication period and the 65 minutes exist so that a healthy key can move without breaking a verifier ([0006](/decisions/0006-keys-and-sealing/#rotation)); they do not apply to a key that is revoked ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)).
- **A suspected compromise is treated as a compromise.** A false alarm costs one refresh per client. A wait costs forged tokens.
- **Only a person declares.** An operator runs `sluis key revoke` with a key or a purpose and a reason, with fresh multi-factor authentication, and the command is reachable in the break-glass session ([principle 7](/principles/#7-a-person-only-where-a-person-adds-safety), [REQ-KEYS-092](/requirements/keys/#REQ-KEYS-092)). A signal raises an alert and never revokes: an alarm that revoked on its own would let an attacker stop sign-in.
- **A revocation is an audit fact and raises an alert,** naming the key or the purpose, the reason and the operator ([REQ-SEC-034](/requirements/sec/#REQ-SEC-034)).
- **Making the replacement is automatic.** The new key is generated in its store, published and, where a board's intermediate certifies it, certified without a ceremony ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)). The declaration is the one human step.

### The token-signing key

- **A token-signing key has four states:** `pre-published`, `active`, `retiring` and `revoked`. `revoked` is reachable from any state and is terminal: it is the presence of the key's item in `KeyRevocation` ([The tighten-only record](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#the-tighten-only-record)). A restore, a roll-forward or a write by the key's own node never moves a key out of it, because `store@` refuses every update or delete of a `KeyRevocation` item ([REQ-KEYS-079](/requirements/keys/#REQ-KEYS-079), [REQ-KEYS-091](/requirements/keys/#REQ-KEYS-091)). `signer` never promotes or signs with a revoked `kid` ([REQ-KEYS-106](/requirements/keys/#REQ-KEYS-106)).
- **Any node's `signer`, and the operator command, may ask `key@` to revoke any node's token key.** Only the owning node moves its own key through the other states. A tightening is open to all and a loosening to the owner, so a compromised owner can neither keep its key nor bring it back ([REQ-KEYS-077](/requirements/keys/#REQ-KEYS-077), [REQ-KEYS-090](/requirements/keys/#REQ-KEYS-090)).
- **The key leaves the key set at once.** `exporter@` and `entry` omit every `kid` listed in `KeyRevocation` from every key set they publish, as a filter at publication, so the omission does not depend on `signer` or on the node that owns the key. `exporter@` publishes the new set and purges the edge copy ([REQ-KEYS-087](/requirements/keys/#REQ-KEYS-087), [REQ-KEYS-107](/requirements/keys/#REQ-KEYS-107)).
- **Forged tokens stop verifying when a verifier's copy of the key set expires:** at most the key set's `max-age` plus the edge time to live after the purge, about 10 minutes (read from [0006](/decisions/0006-keys-and-sealing/#rotation), 2026-11-04; the incident page records the figure a drill measures). Tokens that the key signed legitimately stop verifying too. Their holders refresh, and refresh tokens are opaque rows that a key compromise does not touch ([0018](/decisions/0018-sessions/)).
- **Sessions and sealed data are untouched.** The attacker with a token key cannot mint a refresh token or open a sealed value.
- **The forged tokens can be told from the real ones by sluis,** because every signature is an audit fact ([0006](/decisions/0006-keys-and-sealing/#seal-and-open)) and an access token carries a `jti` ([0020](/decisions/0020-grant-vocabulary-and-token-claims/)). A relying party that logs `jti` can do the same; the incident page says so.
- **The CRL is not a control for tokens.** A standard verifier ignores `x5c`, so a revocation entry for the token certificate protects no one. Removal from the key set is the only revocation a token key has.
- **The named exceptions follow the same path,** each with its own key: the per-audience RS256 key, the FAPI keys, the cloud-federation keys and the NATS nkeys ([0006](/decisions/0006-keys-and-sealing/#named-exceptions)). A NATS operator or account key is also reissued on the NATS side, and the incident page lists that step.
- **The workload-issuer key of `sluis-node` follows it too.** A cloud provider fetches the key set on its own schedule, outside the cache budget of sluis, so the first drill measures how fast each cloud forgets a removed key and the incident page states the figure per cloud ([principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement)).

### The replacement

- **A replacement signs at once when no other key of the issuer is active** (decided 2026-11-04, [REQ-KEYS-089](/requirements/keys/#REQ-KEYS-089)). Its key set is published and its edge copy purged before its first token. A verifier that meets an unfamiliar `kid` fetches the key set again (OpenID Connect Core 1.0, section 10.1.1; the refetch allowance in the lead time is this step), and one that does not is broken against the standard and is fixed, not accommodated.
- **A multi-node installation needs no new key to go on.** The other nodes' active keys are already published and cached, so verifiers see no unfamiliar `kid`. This holds only when the compromise is local to one node.
- **Where the compromise is at `key@`, the key service role, the key policy or the card, another key under the same access is no transition.** The replacement is made in a new store or under a new role first ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise), [principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it)). When the compromise is in the key service itself, the first step is outside sluis: the operator removes the attacker's access there, and the incident page names the order.

### Confirmation

- **`sluis key revoke` prints "not confirmed" until it has fetched the published key set from its public address and found the key absent** ([principle 4](/principles/#4-verify-never-trust-a-claim), [REQ-KEYS-088](/requirements/keys/#REQ-KEYS-088)). A stale edge copy is therefore reported, not assumed away. For a purpose that publishes nothing, the command reports what it could and could not check.
- **A drill measures the time from declaration to a verifier's refusal,** and the incident page states it with its date and versions ([REQ-OPS-080](/requirements/ops/#REQ-OPS-080)). Until the first drill the figure is empty.

### The tighten-only record

- **Every revocation, a token-signing key's included, is an item of a new durable kind, `KeyRevocation`.** `key@` is its one writer: the operator command, and the `signer` of any node, ask `key@` to write it. The item names the revoked target (a purpose, a `kid` or a generation, a recipient) and a reason code from a closed list in plain fields that the publishers and `signer` read. The operator and any free-text reason are in the audit fact ([REQ-SEC-034](/requirements/sec/#REQ-SEC-034)), not in the kind, which is therefore plain: a sealed kind could not be read by the publishers. The kind is backed up, and on a restore the archive's items and the target's are merged by union.
- **`store@` enforces that it only grows.** The kind has a verb rule like `Lease` ([REQ-DATA-097](/requirements/data/#REQ-DATA-097)): create only, no update and no delete ([REQ-KEYS-091](/requirements/keys/#REQ-KEYS-091)). The direction rule of [0004](/decisions/0004-the-data-model/#layers-and-the-direction-rule) alone would permit a delete, so the verb rule is the control. The kind is the run-time layer that the rule permits because it can only tighten ([REQ-KEYS-092](/requirements/keys/#REQ-KEYS-092)).
- **It works while the compromised node is down:** the `key@` of any other node writes it. Making a removal permanent, such as dropping a recipient from the list, goes through the reviewed `KeyPlan` change afterwards. A revocation itself is permanent ([principle 12](/principles/#12-a-loosening-is-temporary-a-tightening-is-durable)).
- **A revocation survives a restore.** The kind is backed up, and the roll-forward re-applies every key revocation that audit records after the archive was taken, also into an empty target ([0010](/decisions/0010-backup-and-recovery/#roll-forward), [REQ-BACKUP-064](/requirements/backup/#REQ-BACKUP-064), [REQ-BACKUP-065](/requirements/backup/#REQ-BACKUP-065)).

### Data keys

- **A data key declared compromised ends its generation, and what happens to its opens depends on what the key protects.** `key@` makes a new generation that every later seal uses and refuses every seal under the compromised one ([REQ-KEYS-101](/requirements/keys/#REQ-KEYS-101), [REQ-KEYS-102](/requirements/keys/#REQ-KEYS-102)). Whether it also stops opening it is decided per purpose:
  - **`grant`, `cookie` and `chain` protect integrity,** because a forged value is the threat. `key@` stops opening the compromised generation at once ([REQ-KEYS-095](/requirements/keys/#REQ-KEYS-095)), so forged values stop working.
  - **`data`, `pseudonym` and `evidence` protect confidentiality,** and the thief already holds the key, so refusing opens protects nothing and only takes the data offline. `key@` keeps opening the compromised generation until nothing sealed under it remains: for `data`, until the re-seal job has rewritten every value ([REQ-KEYS-103](/requirements/keys/#REQ-KEYS-103)), and then it deletes the old wraps ([REQ-KEYS-104](/requirements/keys/#REQ-KEYS-104)); for `evidence`, the log is append-only and cannot be re-sealed, so the generation stays for the retention (an accepted risk, below).
  - The re-seal job is paginated, asynchronous and idempotent, because it runs over a store of any size and is run again after a failure ([REQ-KEYS-096](/requirements/keys/#REQ-KEYS-096)). It is the "planned re-seal" of [REQ-KEYS-011](/requirements/keys/#REQ-KEYS-011).
- **`grant` needs no re-seal.** Nothing durable holds a grant ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)); the old generation is deleted at once and grants are issued again under the new one.
- **`cookie` ends every browser session of the boundary** at the next request ([REQ-KEYS-097](/requirements/keys/#REQ-KEYS-097)). People sign in again, silently while the upstream session lives ([0018](/decisions/0018-sessions/)). Refresh-token chains are not affected.
- **`chain` ends that tenant's chains,** because it is a tenant's key ([0006](/decisions/0006-keys-and-sealing/#data-keys), [REQ-SESS-051](/requirements/sess/#REQ-SESS-051)). The blast radius is one tenant, and its people sign in again.
- **`pseudonym` starts a new epoch at once.** It makes keyed hashes and seals nothing, so there is nothing to re-seal. Past records keep their pseudonyms ([0029](/decisions/0029-the-audit-log/#pseudonyms), [REQ-AUDIT-164](/requirements/audit/#REQ-AUDIT-164)).
- **The tenant's `data` key and the boundary's `data` key are re-sealed,** and keep opening until the job ends. Re-sealing cannot reach a copy that a backup archive holds.
- **An archive keeps the wraps and the values it held.** The archive's retention is the bound on that exposure, and the incident page says so. This is the same limit that erasure has ([0010](/decisions/0010-backup-and-recovery/#roll-forward)).
- **`mac` and `pairwise` are accepted risks,** and so is what `evidence` already sealed; each has a revisit ([Accepted risks](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#accepted-risks)).
- **On Lambda the delay is the cache's time to live,** as it is for erasure ([0006](/decisions/0006-keys-and-sealing/#the-cache)). It matters for the integrity keys, whose opens must stop; for the others the compromised generation goes on opening by design. The delay is stated here and on the incident page, and revisited after the first drill.

### Wrapping keys, recipients and archives

- **A compromised AWS wrapping key is replaced, every wrap is rewrapped under the new one, and then the old key is disabled** ([REQ-KEYS-099](/requirements/keys/#REQ-KEYS-099)). KMS automatic rotation keeps the old key material and so does not answer a compromise.
- **On AWS every data key is also wrapped for the offline recovery recipient** ([REQ-KEYS-100](/requirements/keys/#REQ-KEYS-100)). Disabling the old KMS key would otherwise make every old archive unreadable. The recipient is ritueel's and using it stays a ceremony ([0006](/decisions/0006-keys-and-sealing/#the-recovery-recipient)). The cost is one ritueel step per boundary.
- **An old archive stays readable by whoever held the old key until the archive expires.** After the old key is disabled the thief cannot read it through KMS, but a copy of the unwrapped key from before the disable can. The incident page says so; it is bounded by retention and not removed.
- **A compromised recovery recipient is replaced by a ceremony,** and every wrap is rewrapped for the new one. Its old archives stay openable by the thief until they expire.
- **The backup archive key is replaced and the archives are made again;** the old archives expire.
- **A customer-account KMS key is the customer's lever** ([0006](/decisions/0006-keys-and-sealing/#where-a-tenants-keys-live)): a compromise on the customer's side is the customer's act, and sluis fails closed for that tenant.
- **The enrolment key of `exchange` is replaced by a bundle change** ([0022](/decisions/0022-workload-identity-and-host-enrolment/#host-enrolment)).

### Boards

- **A lost, stolen or suspect board is removed at once.** A `KeyRevocation` item removes its recipient from the wraps and its keys from the slot map, without waiting for a reviewed commit. `key@` makes no new wrap for it ([REQ-KEYS-094](/requirements/keys/#REQ-KEYS-094)) and deletes its existing wraps ([REQ-KEYS-105](/requirements/keys/#REQ-KEYS-105)). The revocation is permanent. A board comes back only with a new key ([principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it)), through a reviewed `KeyPlan` change that lists the new key's thumbprint.
- **A peer releases a PIN only to a board that the `KeyPlan` lists and `KeyRevocation` does not revoke** ([REQ-KEYS-093](/requirements/keys/#REQ-KEYS-093)). The card's PIN policy is not the control while a board can reach its peers: a stolen board that reconnected would otherwise be given its PIN.
- **A suspected PIN is changed with a command,** which delivers the new PIN to the board's `key@` over the unlock channel ([REQ-KEYS-098](/requirements/keys/#REQ-KEYS-098)). Until it exists, the remedy is to replace the board.
- **The board's token-signing key is revoked as above,** and the other boards go on signing with theirs.

### Log keys

- **A log key that is replaced on compromise is replaced by a key-change record.** The new key signs a checkpoint that names the last size a witness cosigned before the compromise. A verifier trusts the old key up to that size and the new key after it ([REQ-AUDIT-163](/requirements/audit/#REQ-AUDIT-163)). The trust anchor is the list of keys that the verifier is given, each with the size from which it applies; the record in the log is evidence for that list, not a replacement for it.
- **With no witness, nothing before the compromise can be trusted from the old key alone.** A deployment that wants more than a replacement for the future runs a witness ([0029](/decisions/0029-the-audit-log/#witnesses)).
- **A witness key's compromise weakens fork detection.** The key is revoked and verifiers drop it from their witness list; a cosignature from it proves nothing from then on.

### Intermediates and SSH CA keys

- **sluis acts first on an intermediate.** `ca` stops issuing under it ([REQ-PKI-052](/requirements/pki/#REQ-PKI-052)) and removes its certificate from the `TrustBundle` it renders ([REQ-PKI-053](/requirements/pki/#REQ-PKI-053)). Hosts take the next bundle, and the root's CRL, which ritueel signs, follows ([0024](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)). sluis does not wait for ritueel.
- **What the bundle controls rests on an assumption.** READ 2026-11-04: `sluis trust sync` writes the certificates of the bundle as the system's anchors and runs `update-ca-trust` or `update-ca-certificates`, and drops a certificate that does not chain to a pinned root ([0022](/decisions/0022-workload-identity-and-host-enrolment/#the-trust-bundle)). The records do not say that a certificate that leaves the bundle also leaves the anchors, and they do not say whether a host anchors the roots or the intermediates. **Assumed:** the sync replaces the anchor set with the bundle, and the anchors are the intermediates. If a host anchors a root, removing an intermediate from the bundle stops nothing for it, and the control is ritueel's root CRL and the short lifetimes of leaves ([0023](/decisions/0023-certificate-authorities/#leaf-profiles)), because leaves carry no CRL distribution point and most TLS and SPIFFE clients never fetch a CRL ([0023](/decisions/0023-certificate-authorities/#revocation)). The follow-up under [#1341](https://github.com/truvity/sluis/issues/1341) states what the bundle holds and what the sync removes, and the incident page is corrected to the result.
- **The CRL of an intermediate's leaves is published, not optional** ([REQ-PKI-007](/requirements/pki/#REQ-PKI-007)), so that a database that configures one can refuse a revoked leaf; it is the control where the bundle is not.
- **A stolen SSH CA key is not answered by a revocation list.** A list cannot name certificates that nobody knows exist. The key is replaced on ritueel's signed list of SSH CA keys, `sluis-host` fetches it at a stated interval and alerts when its copy is older than twice that interval ([REQ-SSH-009](/requirements/ssh/#REQ-SSH-009)), and a host CA also needs a change of the clients' `@cert-authority` lines, which the incident page describes.
- **The release-signing subkey is revoked under both OpenPGP primaries** ([REQ-SUPPLY-012](/requirements/supply/#REQ-SUPPLY-012)); this record changes nothing there.

### What each kind does

| Kind | Declared as | What stops | What is replaced | What consumers see | How fast |
|---|---|---|---|---|---|
| Token-signing key, per node or per boundary | `sluis key revoke`, key id | The key signs nothing and leaves the key set | A new key, active at once when none is | Forged and old tokens fail; clients refresh; an unfamiliar `kid` makes a verifier fetch the set again | The set's `max-age` plus the edge time to live after the purge (about 10 minutes; a drill measures it) |
| Per-audience RS256, FAPI, cloud-federation and NATS keys | The same, with the purpose | The same | The same; NATS also on the NATS side | The same | The same |
| Workload-issuer key (`sluis-node`) | The same | The same | A new key | A cloud provider's cache decides | Measured per cloud in the first drill |
| Audit-log and issuance-log key | The same, purpose and reason | The key signs no checkpoint | A new key, with a key-change record | A verifier given both keys trusts each up to its size | Next checkpoint |
| Witness key | The same | Its cosignatures stop counting | A new witness key | The verifier's witness list drops it | At once |
| X.509 intermediate | The same | `ca` stops issuing; the certificate leaves the bundle (assumed to remove the anchor, see above) | A new intermediate through the hand-off | Hosts that sync the bundle refuse its leaves; otherwise the root's CRL and leaf lifetimes bound it | The next bundle sync; the root's CRL follows |
| SSH user CA, SSH host CA | The same | Hosts stop listing it once the signed list changes | A new CA key on ritueel's list | Hosts take the list at the stated interval; a host CA needs client edits | The stated refresh interval |
| `grant` | `sluis key revoke`, purpose | Seals and opens under the old generation are refused | A new generation | Nothing visible; a grant lives about 60 seconds | About 60 seconds; on Lambda the cache's time to live |
| `cookie` | The same | Seals and opens under the old generation are refused | A new generation | Every browser session ends; sign-in again | The next request; on Lambda the cache's time to live |
| `chain` (a tenant's key) | The same, tenant | Seals and opens under the old generation are refused; the tenant's chains end | A new generation | That tenant's people sign in again | The next open; on Lambda the cache's time to live |
| `data` (tenant, boundary) | The same | Seals under the old generation are refused; it keeps opening until the re-seal ends, then is deleted | A new generation and a re-seal | Nothing, apart from latency during the job | At once for new seals; hours for the re-seal |
| `pseudonym` | The same | The epoch ends; no new hash under it | A new epoch | Past records stay linkable to the thief | At once |
| `evidence` | The same | Seals under the old generation are refused; it keeps opening for the retention | A new generation for new evidence | Nothing; what is already sealed stays exposed (accepted) | At once for new seals |
| `mac`, `pairwise` | Not replaced in place | Nothing | Nothing | Nothing | An accepted risk ([below](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#accepted-risks)) |
| AWS wrapping key | The same | Old key disabled after rewrap | A new KMS key; every wrap rewrapped | Nothing | Hours, with the rewrap |
| Board (its key-agreement key and card) | The same, node | Its recipient and wraps are removed; its PIN release is refused | A new board and card | Other boards rewrap | At once for the removal |
| Recovery recipient, archive key | Ceremony, ritueel | Rewrap for the new recipient | A new recipient or key | Old archives stay openable until they expire | A ceremony |
| Release-signing subkey | Under both OpenPGP primaries | Keyring drops it | A new subkey | The keyring package changes | The release train |

### Accepted risks

Three decisions are accepted as risks and not as solutions. Each is written in the [threat model](/security/threat-model/#accepted-risks) and revisited at the stated point.

- **`pairwise` is never replaced** (decided 2026-11-04). A replacement changes every person's `sub`, so every relying party would lose its account link ([REQ-KEYS-072](/requirements/keys/#REQ-KEYS-072)). The key lives only in `key@`'s memory and its wraps. If it leaks, the thief can link a person's subjects across relying parties, and nothing here takes that back. Revisited when CIAM gives subjects their meaning, before the first customer installation.
- **`mac` is not replaced in place** (decided 2026-11-04). A new key would change every link id, upstream session id and index entry, and a migration needs the sealed inputs ([REQ-KEYS-043](/requirements/keys/#REQ-KEYS-043)). If it leaks, the thief can confirm guessed e-mail addresses or upstream ids offline against any id seen. Revisited at v1 parity, after a migration has been measured.
- **What `evidence` already sealed stays exposed** (decided 2026-11-04). New evidence is sealed under a new generation, but the old one keeps opening for the retention, because shredding it would destroy evidence that the law may require and the log it protects is append-only ([REQ-KEYS-037](/requirements/keys/#REQ-KEYS-037)). If it leaks, the thief reads the tenant's audit and usage evidence from before the declaration. The retention is the bound. Revisited when the first tenant with an evidence retention exits, or at v1 parity, whichever comes first, with a per-epoch evidence key as the option.
- **The Lambda delay is the cache's time to live** (decided 2026-11-04). A revoked data key generation can still open values in a warm function until its entries expire. Revisited after the first drill has measured it: the options then are a shorter time to live, which costs key service calls ([T-32](/security/threat-model/#availability-and-abuse)), and a revocation marker read on every cache hit, which costs a read per request.

### Detection and the drill

- **An alarm is raised when the key service records a signature or an unwrap by a principal other than `key@`, or more signatures for a key than the audit log records** ([REQ-SEC-035](/requirements/sec/#REQ-SEC-035)). Cards have no sign counter, so a board's detection stays audit-based.
- **The incident page states, for each kind, the command, the effect, what consumers see and the measured time** ([REQ-OPS-079](/requirements/ops/#REQ-OPS-079), [Incident response](/security/incident-response/)). A compromise drill of the token-signing key runs at least once a year and after a change to the key path ([REQ-OPS-080](/requirements/ops/#REQ-OPS-080)); the recovery sign-in and the backup restore already have drills ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073), [REQ-OPS-040](/requirements/ops/#REQ-OPS-040)).

## Consequences

- **A compromised token-signing key stops verifying in about 10 minutes, and not after about 1 h 45** (the lead time of 30 minutes, the 65 minutes of retention and 10 minutes of cache, which a healthy rotation would apply). The cost is one refresh per live client in the first minutes, and an unfamiliar-key window on a single-key installation for verifiers that refetch with a throttle.
- **The state machine and the permission rule change.** `revoked` is a fourth state, a node may have another node's key revoked, and `store@` refuses updates and deletes of a `KeyRevocation` item, so the guarantee lives in the store and not in `signer`. ADR 0006 still says, in its rotation section, that a token-signing key moves through three states, and, in its token-signing section, that each node rotates only its own key and removes it from the key set. This record overrides both, and ADR 0006 is amended to link here.
- **A new kind, `KeyRevocation`, and a new command are added.** The kind has one writer, `key@`, holds nothing personal, is backed up, and is merged by union on a restore. Both are small, add-only and tighten-only. The command needs fresh multi-factor authentication and is reachable in the break-glass session.
- **A re-seal job exists.** It is the first background job over sealed data, and it needs a pagination and a resume rule like any job of that size ([REQ-PERF-002](/requirements/perf/#REQ-PERF-002)).
- **AWS gains a wrap.** Every data key on AWS is also wrapped for the recovery recipient, so a boundary needs a ritueel step once, and the wrap count per data key becomes two.
- **A board's removal no longer waits for a reviewed commit, and it is permanent.** The `KeyPlan` change that follows makes it visible in the signed list; a board comes back only as a new key with a new thumbprint.
- **Three risks are written down and not solved,** and one measurement is left to the first drill. A reader of the threat model sees each with its revisit point.
- **The incident page is part of the product.** It is `target` until a drill has filled its figures.

## Roads not taken

- **A standing pre-published spare key per issuer.** It removes the unfamiliar-key window, but it costs a key and a slot per boundary and is useless when the compromise is at the key service or role level, where the spare shares the compromised access ([principle 2](/principles/#2-trust-is-layered-and-redundancy-is-not-a-defence-against-compromise), [principle 8](/principles/#8-nothing-without-a-consumer)).
- **Wait the lead time before the replacement signs.** A single-key installation would refuse every sign-in for 25 to 30 minutes, a self-made outage on top of the compromise.
- **Lengthen the overlap or keep serving the old key for verifiers that cache too long.** A verifier that breaks a standard is detected and fixed, and every minute of overlap is a minute of forged tokens.
- **Revoke automatically on an alert.** An attacker who can trigger the alert could stop sign-in at will ([principle 7](/principles/#7-a-person-only-where-a-person-adds-safety)).
- **Let only the owning node revoke its key.** A compromised node would decide whether its own key leaves.
- **Mark the token certificate in a CRL.** Standard verifiers ignore `x5c`, so the entry protects no one.
- **Migrate pairwise subjects with a mapping for each relying party.** It needs the cooperation of every relying party and changes every `sub`; the risk is accepted until CIAM gives subjects their meaning.
- **Shred the `evidence` wrap on compromise.** It destroys evidence the law may require.
- **A per-epoch `evidence` key now.** It bounds a loss, but it adds a key per epoch before a threat is shown; it returns when the retention is revisited.
- **Keep the old KMS key enabled, scheduled for deletion.** Old archives would stay readable by the thief for as long as the key exists.
- **Start a new log when a log key is compromised.** It is the simplest, but it breaks "one continuous history" and loses the checkpoints a witness already cosigned.
- **Leave the data keys to the same overlap as a healthy rotation.** A generation that opens for hours after a declaration is a generation the thief can open.

## Follow-ups

All are parts of [#1341](https://github.com/truvity/sluis/issues/1341) and are created as issues by the maintainer's script, by milestone.

- **First version, production-blocking: nothing may run in production without these four.** The `revoked` state, the replacement and the any-node revoke (builds on [#774](https://github.com/truvity/sluis/issues/774)); `sluis key revoke` and the `KeyRevocation` kind; the incident page and the first token-key drill; the re-applied revocation after a restore.
- **v1 parity:** board removal and the PIN-release refusal; the generation drop and the re-seal job per data key; the log key-change record; the intermediate and SSH CA procedures, with what the bundle holds; detection from the key service; the replacement of an AWS wrapping key and the recovery wrap on AWS ([REQ-KEYS-099](/requirements/keys/#REQ-KEYS-099), [REQ-KEYS-100](/requirements/keys/#REQ-KEYS-100)); the decision to revisit `mac`, and the revisit of `evidence`.
- **CIAM:** the decision to revisit `pairwise`.
