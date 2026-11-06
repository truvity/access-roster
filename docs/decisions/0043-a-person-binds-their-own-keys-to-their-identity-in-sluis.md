# 0043 — A person binds their own keys to their identity in sluis

**Status:** Accepted
**Date:** 2026-11-06

Proposal: [issue #1494](https://github.com/truvity/sluis/issues/1494), owner decisions SK1 E, BK1 A, BK2 A, BK3 A, 2026-11-06.

## Context

The company issues each staff member a signing key that is born on the person's card. Until now the design left open who binds that key to the person. The first answer was a ceremony of [ritueel](https://ritueel.id) per person, with the company holding each person's primary key. The review of that design on 2026-11-06 found that the card, the attestation and the "person present" check all run on the client of the ceremony, so anyone who can assume the ceremony role can bind a software subkey, and detection is the only real control. It also needs a person at ritueel for every joiner and every lost card.

sluis already knows who a person is, signs the person in with a hardware key, and certifies keys online under a delegated key ([0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification)). On 2026-11-06 the maintainer decided, in these words and answers:

| Label | Decision |
|---|---|
| SK1 E | "key bindings in sluis. A person binds their own key to their identity; sluis checks the proof on the server, records a binding, and acts on it. Staff keys are card-born." |
| BK1 A | "`sluis key bind` does the binding, with ritueel helping the person generate on the card and produce the proof, using standard formats." |
| BK2 A | "software keys can be bound with class `software`. Staff company signing refuses them." |
| BK3 A | "sealed software keys for non-human identities (bots, agents) are a later feature." |
| G1 A | "OpenPGP keys born on cards, with no SSH-signing fallback." |
| G4 A | Staff cards are generated on the card, the PIN and Admin PIN are changed at issue, each person gets a second card, and the attestation is recorded in ritueel's ledger. |
| G5 A | A leaver is removed from the organisation and the GitHub account, the certification lapses, the key leaves the keyring, and a revocation is for compromise only. Old commits stay Verified, by design. |
| P10 A | An `sk-ssh` key gets an SSH certificate, later. |
| PK1 A | A privileged action needs an assertion that the boundary itself verified ([0017](/decisions/0017-identity-and-sign-in/); the classes and the enrolment rule are in [pull request #1484](https://github.com/truvity/sluis/pull/1484)). |

This record replaces the per-person design that G2a, G2b and SK2 to SK5 described. It is the producer of the keys that the GitHub key sync consumes ([pull request #1485](https://github.com/truvity/sluis/pull/1485)).

## Decision

### What a binding is

- **A binding is a record that a person owns a public key.** It holds the person, the key (for OpenPGP its full version 4 fingerprint and the public key), the kind, the class, the attestation as received, the time created, the expiry, and a state: `active`, `ended` or `revoked`. It is the durable kind `KeyBinding`, personal and sealed under the tenant's data key, written only by `exchange`, and erased with the person ([0004](/decisions/0004-the-data-model/)). It is added to the registry with the first build.
- **sluis never holds the private part of a bound key.** The request carries a public key and proofs, and the card keeps the rest ([REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143)).
- **A key is bound to one person.** The same key twice, or the key of another person, is refused ([REQ-KEYS-142](/requirements/keys/#REQ-KEYS-142)).
- **The kinds are OpenPGP and `sk-ssh`.** X.509 and PIV keys come later. Each kind has its own proof format and its own action; the binding, the classes and the gate are the same for all.
- **The classes are the passkey classes:** `hardware-attested`, `hardware` and `software`. Policy decides what each class may do ([REQ-KEYS-128](/requirements/keys/#REQ-KEYS-128)).

| Class | How it is derived |
|---|---|
| `hardware-attested` | The key came with an attestation that verified to a pinned vendor root, and the card's model and firmware are on the installation's allowlist |
| `hardware` | The attestation verified to a pinned vendor root, but the model or the firmware is not on the allowlist |
| `software` | The key came with no attestation |

An attestation that is present and does not verify is refused, not downgraded: a forged statement is an incident, and a person with a card that sluis does not know can ask the operator to extend the allowlist.

**Staff company signing needs `hardware-attested`.** Certifying a key, putting it into the staff keyring and uploading it to a GitHub account are all company signing. A key of class `hardware` or `software` gets none of them ([REQ-KEYS-129](/requirements/keys/#REQ-KEYS-129)). That is G1 A in rule form: staff keys are card-born, and there is no SSH-signing fallback. A `software` binding is still recorded and audited; what it may do is for policy, and by default it does nothing.

### The flow

1. **The person signs in with a fresh hardware step-up that sluis verified itself.** It is a `hardware-attested` assertion checked by the boundary that holds the binding, within the age policy sets; an upstream claim never counts (PK1 A, [REQ-KEYS-123](/requirements/keys/#REQ-KEYS-123)).
2. **The person presents a public key with a proof of possession.** `sluis key bind` asks for a challenge; the person signs it with the key; the request returns the public key, the signature and, for a card, the attestation. For OpenPGP the proof is a detached OpenPGP signature and the attestation is the X.509 statement the card makes. For `sk-ssh` the proof is an SSHSIG signature. ritueel helps the person generate the key on the card and produce these; the formats are standard and sluis does not depend on ritueel's code ([REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122)).
3. **The challenge is sluis's choice, so it is built to be signed safely.** It is 256 random bits, valid for 5 minutes and used once, and the signed bytes start with a fixed label and name the person, the boundary and the key. A card that signs it has signed nothing that parses as a commit, a tag, a checksum file or a certification.
4. **sluis verifies on the server:** the proof; the attestation chain against a vendor root that config pins; and the card's model and firmware against the allowlist, which is installation config that a tenant can narrow and not widen ([REQ-KEYS-125](/requirements/keys/#REQ-KEYS-125), [REQ-KEYS-126](/requirements/keys/#REQ-KEYS-126)). The class follows from the result ([REQ-KEYS-127](/requirements/keys/#REQ-KEYS-127)).
5. **It records the binding** ([REQ-KEYS-124](/requirements/keys/#REQ-KEYS-124)) and **acts on it, per kind:**

| Kind | What sluis does, for a `hardware-attested` binding |
|---|---|
| OpenPGP | Certifies the key (below) |
| OpenPGP | Puts the certified key into the staff keyring, which sluis produces from the bindings and from nothing else ([REQ-KEYS-137](/requirements/keys/#REQ-KEYS-137)) |
| OpenPGP | The GitHub key sync uploads the key to the person's account ([pull request #1485](https://github.com/truvity/sluis/pull/1485)) |
| `sk-ssh` | Later: issues SSH certificates for the key, by the rules of [0023](/decisions/0023-certificate-authorities/#ssh) (P10 A) |

### OpenPGP certification

- **The chain has three links.** The ritueel root makes a trust signature, limited to the company's domain, over one sluis certification key, at a ceremony, as [0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification) says. That intermediate certifies the person's key. The person's card signs the key's own user ID. A verifier that holds only the root's fingerprint accepts a bound key and nothing else under the domain ([REQ-KEYS-130](/requirements/keys/#REQ-KEYS-130)).
- **One intermediate does it, behind key@.** It is a purpose enabled on use ([Key purposes](/decisions/0006-keys-and-sealing/#key-purposes)): a key of the cloud key service (AWS KMS) on a cloud installation and a YubiKey on a board. `signer` makes the certification for a grant that `policy` sealed, in place, and the key is never shown.
- **It certifies only addresses of the person.** The user IDs it certifies are verified addresses of the person in the directory, in the root's domain ([REQ-KEYS-131](/requirements/keys/#REQ-KEYS-131)).
- **The certification ends with the binding.** Its expiry is the binding's, at most 13 months ([REQ-KEYS-132](/requirements/keys/#REQ-KEYS-132)).

### The gate

Attestation proves that a genuine card made a key. It does not prove whose card it is: anyone can buy one and attest a key of their own. Whose it is comes from three things: the fresh hardware sign-in of the person, the approval of the first binding, and the rule for every later one. This applies the enrolment rule of [pull request #1484](https://github.com/truvity/sluis/pull/1484) to bindings.

- **Once a person holds a `hardware-attested` binding, adding any further binding needs a fresh proof from it** (an assertion the boundary checks, signed by the bound key; [REQ-KEYS-133](/requirements/keys/#REQ-KEYS-133)). It covers a binding of every class. A stolen session cannot add a key of its own.
- **The first binding needs approval.** Policy names who may give it: an operator who holds key administration and approves with a fresh hardware-attested assertion of their own, or a directory fact that the person is a live member of the staff group entitled to a company key. A directory approval is enough here, and was refused for the first hardware key of [pull request #1484](https://github.com/truvity/sluis/pull/1484), because the question differs. That record asks whose device a key is; this one asks only whether the person is entitled to a company key, and the person has already passed the device question, because a binding needs a hardware step-up ([REQ-KEYS-134](/requirements/keys/#REQ-KEYS-134)).
- **A person with no usable `hardware-attested` binding** (both cards lost) is bound again by the approval of the first binding.
- **Every bind, every refusal and every end is audited** ([REQ-KEYS-135](/requirements/keys/#REQ-KEYS-135)). **A new `hardware-attested` binding alerts the operators and notifies the person** at their verified address, with the fingerprint ([REQ-KEYS-136](/requirements/keys/#REQ-KEYS-136)).

### Life of a binding

- **Renewal is automatic.** In month 12 sluis re-certifies the same key for another 13 months, with no ceremony and no person present, while the binding is active, the person is live in the directory and the key is not revoked ([REQ-KEYS-138](/requirements/keys/#REQ-KEYS-138)). It warns as [0024](/decisions/0024-root-custody-and-the-signing-api/#lifetimes-and-the-warning) does when a renewal fails. Renewal re-checks the directory and the state, not the card: a card that was lost without anyone saying so stays certified until its binding ends.
- **A second card has its own binding.** Ending one never ends the other ([REQ-KEYS-139](/requirements/keys/#REQ-KEYS-139)).
- **A lost card:** the person (with the second card) or an operator ends that binding, then the person binds a new key. The ended key leaves the next keyring and is no longer renewed.
- **Compromise:** a person declares it, as [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#a-person-declares-and-a-suspicion-counts) says. The binding becomes `revoked` at once, sluis revokes its own certification of the key, and the key goes on the keyring's withdrawn list ([REQ-KEYS-140](/requirements/keys/#REQ-KEYS-140)). Revoking the key itself is the owner's act, with the card.
- **A leaver:** when the directory marks the person `left`, every binding ends ([REQ-KEYS-141](/requirements/keys/#REQ-KEYS-141)). Renewal stops, so the certification lapses; the key leaves the keyring; the GitHub sync removes it from the account. Nothing is revoked, and old commits stay Verified, by design (G5 A).

### The security of the design

- **sluis could certify a rogue key for someone's address.** It holds the intermediate, so a compromised or misused sluis can certify a key that the person never made, and the GitHub sync would then put it on that person's account, where commits signed with it show Verified. Four things stand in the way: policy decides who may bind; a bind needs a fresh hardware sign-in that the boundary checked; the first binding of a person needs approval; and every later one needs a proof from the person's existing card. None of these stops an insider who holds both an operator's hardware key and the policy to change them.
- **A rogue key is visible, and that is the control that remains.** Each bind is audited and alerts the operators, and the person is told at their own address; a certified key appears in the staff keyring as a new fingerprint that anyone can diff; and the card's attestation is stored, so an operator can check a binding against ritueel's ledger of the cards the company issued. The stored attestation carries the card's serial, which the operator sees and which is not an identifier in any token.
- **A compromised intermediate is revoked through ritueel.** sluis acts first: it stops certifying, on the `KeyRevocation` of [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#intermediates-and-ssh-ca-keys). ritueel revokes the root's trust signature over the intermediate and makes a new one at a ceremony. sluis then re-certifies every active binding under the new intermediate from the records, with no card and no person. **Verifiers learn from the keyring.** OpenPGP has no online check, so a verifier that holds the updated keyring package stops trusting the old intermediate at once, and a verifier that holds an old copy trusts it until its certifications expire, at most 13 months, or until it refreshes. GitHub does not read certifications at all: keys already uploaded stay, and the sync removes the ones that are withdrawn.
- **Keys stay on cards.** The private part never reaches sluis and never reaches the company. sluis can certify a key; it cannot make a subkey, a signature or a commit in anyone's name, and it holds no key whose loss lets an attacker sign as a person.
- **A lapse is not a revocation.** A leaver's key is accepted by a verifier that holds the root and a copy of the certified key until the certification expires; a verifier that uses the keyring stops at its next refresh. A leaver who is a risk is a compromise, and is revoked.

### What ritueel owns

- **The roots,** the ceremony that delegates the trust signature to the intermediate, and the ceremonies that renew or replace it.
- **The card-readiness helper and the proof format.** The helper makes the key on the card, sets the PINs, produces the proof and the attestation, and prints them as standard files. ritueel keeps the ledger of the cards it issues. sluis and ritueel share formats and test vectors and no code ([0024](/decisions/0024-root-custody-and-the-signing-api/)). ritueel's ADR 0014 is being rewritten to match this record.
- **Personal keys** that a person keeps outside the company.

### The attestation question

Does the OpenPGP applet's attestation cover a card-born primary used to certify and to sign? **UNVERIFIED.** Read on 2026-11-06 from [Yubico's OpenPGP attestation page](https://developers.yubico.com/PGP/Attestation.html) and [the `ykman openpgp keys attest` reference](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html):

- READ: the signature, decryption and authentication keys can be attested, on firmware 5.2 and later, and only a key generated on the device can be ("imported" is not permitted). Firmware 5.7.4 and later is signed under Yubico's new root.
- READ: the statement carries the key's fingerprint and generation date, and Yubico says not to trust them, because the Admin PIN can overwrite them. The page says to always verify the public key.
- Not found: any statement about a key used for certification. The attested object is the key in a slot. Whether that key is the OpenPGP primary, and its certify flag, are facts of the OpenPGP key (its self-signature), which the statement does not cover. That the signature slot holds the primary is how OpenPGP cards and GnuPG work, and was not read on those pages.

So the design checks the public key of the attestation against the public key of the presented primary, and ignores the fingerprint and date in the statement. The build is gated on the conformance test below. A result that contradicts the design changes this record before anything is built.

**Conformance test, run on a current YubiKey 5 and on one with firmware 5.7.4 or later:**

1. Generate a primary with certify and sign on the card, with `gpg` and with the ritueel helper; export the attestation; verify the chain to the old and the new Yubico root; compare the public key with the primary's.
2. A key imported into the slot has no attestation, and a statement whose public key differs from the primary is refused.
3. The fingerprint and date in the statement are overwritten with the Admin PIN: sluis's result does not change.
4. The card certifies a user ID and signs a commit and a checksum file; `gpgv`, `sqv` and `git verify-commit` accept them.
5. The certified key, with the intermediate's certification and the root's trust signature, is uploaded to a GitHub account (`POST /user/gpg_keys`) and a commit signed on the card shows Verified. This also tests whether GitHub accepts a P-384 key that carries third-party certifications.
6. The model and firmware that sluis reads from the statement select the allowlist entry, and a card outside the list is class `hardware`.

## Consequences

- A joiner binds a key in minutes and a lost card is replaced the same way, with no ceremony and no person at ritueel. The yearly renewal of a person's key stops being work.
- sluis certifies on its own authority, under a trust signature from the root. The root stays offline, and the weight moves to policy, the hardware sign-in and detection. That is a stronger position than a ceremony role that binds software, and a weaker one than a ceremony with a person present; the design chooses automation and says what it costs.
- A card that sluis cannot attest is class `hardware` or `software`, and cannot sign for the company. An installation that wants to accept a new model extends the allowlist.
- The staff keyring is produced by sluis from the bindings. The sync of [pull request #1485](https://github.com/truvity/sluis/pull/1485) was written when ritueel produced it; that source is now sluis, and its two controls (the person-to-certificate rule and sluis's own certification) hold, the second now with its certification in place. The wording of both records is brought in line when they merge.
- New obligations are [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143).

## Roads not taken

- **One KMS key per person.** The company would hold a signing key of everyone and could sign as anyone, a key service per person costs money at every joiner, and nothing proves that a person's key is on a card.
- **Sealed software primaries per person.** sluis would hold a private key that signs as the person, and a software key cannot be attested; it is the BK3 road for bots, and for staff it breaks G1 A.
- **One company primary with everyone's subkeys.** GitHub attribution, user ID churn and revocation churn: one revocation touches every person.
- **ritueel binds each person's subkey in a ceremony (G2a).** The card and the "person present" check run on the client, so a ceremony role can bind a software subkey, and it needs a person at ritueel for every joiner and lost card.
- **Trust an attestation alone.** Anyone can attest a key on a card they bought, so the attestation says what a key is and not whose it is.
- **Directory approval for every further binding.** A directory change needs no hardware proof, so it would let a changed directory entry add a key to a person who has one.
- **An SSH-signing fallback for staff (G1 A).** It cannot be tied to a card the same way, and GitHub treats it as a different key.
- **A new attestation at every renewal.** It brings a person back to the card once a year for a check that the lost-card rule already covers.

## Follow-ups

- Build `sluis key bind`, the kind `KeyBinding`, the certification purpose and the keyring producer: [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143) ([#1494](https://github.com/truvity/sluis/issues/1494)), gated on the conformance test above.
- Run the conformance test and date the result ([#1494](https://github.com/truvity/sluis/issues/1494)).
- Add the certification purpose to the table of [Key purposes](/decisions/0006-keys-and-sealing/#key-purposes) and to the key plan when it is built ([#1494](https://github.com/truvity/sluis/issues/1494)).
- Write the form of the staff keyring, its signature and its list of withdrawn keys, now that sluis produces it, with test vectors shared with ritueel ([#1494](https://github.com/truvity/sluis/issues/1494)).
- Bring the wording of the GitHub key sync into line with sluis as the source of the keyring ([#1494](https://github.com/truvity/sluis/issues/1494)).
- Sealed software keys for non-human identities such as bots and agents (BK3 A): a later feature with its own record when it is designed ([#1494](https://github.com/truvity/sluis/issues/1494)).
- Enforcement of commit signing on GitHub (G3 C) stays a later CI check against the staff keyring ([#1494](https://github.com/truvity/sluis/issues/1494)).
