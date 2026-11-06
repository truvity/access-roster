# 0043 — A person binds their own keys to their identity in sluis

**Status:** Accepted
**Date:** 2026-11-06

Proposal: [issue #1496](https://github.com/truvity/sluis/issues/1496), owner decisions SK1 E, BK1 A, BK2 A, BK3 A, 2026-11-06.

## Context

The company issues each staff member a signing key that is born on the person's card. Until now the design left open who binds that key to the person. The first answer was a ceremony of [ritueel](https://ritueel.id) per person, with the company holding each person's primary key. The review of that design on 2026-11-06 found that the card, the attestation and the "person present" check all run on the client of the ceremony, so anyone who can assume the ceremony role can bind a software subkey, and detection is the only real control. It also needs a person at ritueel for every joiner and every lost card.

sluis already knows who a person is, signs the person in with a hardware key, and certifies keys online under a delegated key ([0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification)). On 2026-11-06 the maintainer decided, in these words and answers:

| Label | Decision |
|---|---|
| SK1 E | "key bindings in sluis. A person binds their own key to their identity; sluis checks the proof on the server, records a binding, and acts on it. Staff keys are card-born." |
| BK1 A | "`sluis key bind` does the binding, with ritueel helping the person generate on the card and produce the proof, using standard formats." |
| BK2 A | "software keys can be bound with class `software`. Staff company signing refuses them." This record names that class `unattested` (see [Classes](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#classes)). |
| BK3 A | "sealed software keys for non-human identities (bots, agents) are a later feature." |
| G1 A | "OpenPGP keys born on cards, with no SSH-signing fallback." |
| G4 A | Staff cards are generated on the card, the PIN and Admin PIN are changed at issue, and each person gets a second card. Here the attestation is recorded in the binding. |
| G5 A | A leaver is removed from the organisation and the GitHub account, the certification lapses, the key leaves the keyring, and a revocation is for compromise only. Old commits stay Verified, by design. |
| FB1 A | "The same rule in both records, operator approval only": the first hardware binding is approved by an operator, and a directory fact is not enough. |
| P10 A | An `sk-ssh` key gets an SSH certificate, later. |
| PX1 | "the card primary expires after about 3 years and is extended at the card." The GitHub App re-uploads the extended key. |
| PK1 A | A privileged action needs an assertion that the boundary itself verified ([0017](/decisions/0017-identity-and-sign-in/); the classes and the enrolment rule are in [pull request #1484](https://github.com/truvity/sluis/pull/1484)). |


This record replaces the per-person design that G2a, G2b and SK2 to SK5 described. It is the producer of the keys that the GitHub key sync consumes ([pull request #1485](https://github.com/truvity/sluis/pull/1485)).

## Decision

### What a binding is

- **A binding is a record that a person owns a public key.** It holds the person; the **key identity**; the kind; the class; the bound set (below); the attestation as received; the time created; the expiry (the key's own, see [The key's own expiry](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-keys-own-expiry)); and a state: `active`, `ended` or `revoked`. It is the durable kind `KeyBinding`, personal and sealed under the tenant's data key, written only by `exchange`, and erased with the person ([0004](/decisions/0004-the-data-model/)). It is added to the registry with the first build.
- **The key identity is the SHA-256 hash of the primary's public key material,** the algorithm, the curve and the public point, and nothing else. It is not the version 4 fingerprint, because the fingerprint covers the creation time, which the holder chooses: the same card key could be given two creation times and bound twice. The fingerprint is kept as a label and is what GitHub and `gpg` show. A key identity is bound to one person at a time ([REQ-KEYS-142](/requirements/keys/#REQ-KEYS-142)).
- **sluis never holds the private part of a bound key.** The request carries public keys and proofs, and the card keeps the rest ([REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143)).
- **The kinds are OpenPGP and `sk-ssh`.** X.509 and PIV keys come later. Each kind has its own proof format and its own action; the binding, the classes and the gate are the same for all.

### Classes

The classes are not the passkey classes of [pull request #1484](https://github.com/truvity/sluis/pull/1484), and they do not reuse their names. A passkey of class `hardware` is unattested and probably device-bound, as the authenticator says; a key whose attestation verified but whose card is not on the list would be the same word with the opposite meaning. A key has no backup flag either. So the names say what sluis verified:

| Class | How it is derived |
|---|---|
| `hardware-attested` | The attestation of the primary and of every subkey verified to the one pinned vendor root, and the card's firmware and form factor are on the installation's allowlist |
| `hardware-unlisted` | The attestation verified to the pinned root, but the firmware or the form factor is not on the allowlist |
| `unattested` | The key came with no attestation. BK2 A calls this class `software`; the name here says what sluis knows, because a card key whose person sent no statement is the same case |

An attestation that is present and does not verify is refused, not downgraded: a forged statement is an incident ([REQ-KEYS-125](/requirements/keys/#REQ-KEYS-125), [REQ-KEYS-126](/requirements/keys/#REQ-KEYS-126), [REQ-KEYS-127](/requirements/keys/#REQ-KEYS-127)). Policy decides what each class may do ([REQ-KEYS-128](/requirements/keys/#REQ-KEYS-128)).

**Staff company signing needs `hardware-attested`.** Certifying a key ([REQ-KEYS-129](/requirements/keys/#REQ-KEYS-129)), putting it into the staff keyring ([REQ-KEYS-137](/requirements/keys/#REQ-KEYS-137)) and handing it to the GitHub key sync ([REQ-KEYS-154](/requirements/keys/#REQ-KEYS-154)) are all company signing. A key of another class gets none of them. That is G1 A in rule form: staff keys are card-born, and there is no SSH-signing fallback. An `unattested` or `hardware-unlisted` binding is still recorded and audited; what it may do is for policy, and by default it does nothing.

**The allowlist is defined on what the statement has.** Yubico's attestation statement carries no model name. READ 2026-11-06 ([Yubico's OpenPGP attestation page](https://developers.yubico.com/PGP/Attestation.html)): it carries the firmware version, the form factor, the serial number, the FIPS and CSPN status, the user-interaction flag and the signature counter, beside a fingerprint, a date and a cardholder name that are not to be trusted. The allowlist therefore names a minimum firmware, a set of form factors and, optionally, a required FIPS flag. It is installation config that a tenant can narrow and not widen. **Firmware floor: 5.7.4,** the first firmware signed under Yubico's new root; sluis pins that one root, "Yubico Attestation Root 1" (the name is to be confirmed against a real statement), and no other. **Older cards are out:** their statements chain to the old root and are refused, and a person with an older card needs a newer one ([REQ-KEYS-152](/requirements/keys/#REQ-KEYS-152)). The fields above are to be confirmed against a real statement before the build (see [The attestation question](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-attestation-question)).

### The flow

1. **The person generates the key on the card first.** The ritueel helper makes the primary and its subkeys on the card, sets the PINs, and writes the **bundle v1**: `<name>.staff.pgp` (the public key: primary, user IDs and subkeys), `<name>.proof.json` (the attestation statement and its certificate chain, one for the primary and one for each subkey) and, in step 4, `<name>.possession.sig`. The formats are standard, ritueel and sluis share test vectors for the bundle and no code ([REQ-KEYS-151](/requirements/keys/#REQ-KEYS-151)).
2. **The person signs in with a fresh hardware step-up that sluis verified itself.** It is a `hardware-attested` assertion checked by the boundary that holds the binding, within the age policy sets; an upstream claim never counts (PK1 A, [REQ-KEYS-123](/requirements/keys/#REQ-KEYS-123)).
3. **`sluis key bind` asks sluis for a challenge that names the person, the boundary and that key.** Each card gets its own challenge ([The challenge](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-challenge)).
4. **The helper signs the challenge with the key on the card** and writes `<name>.possession.sig`. The card needs its PIN and, by the touch policy decided per key (G4 A), a touch.
5. **`sluis key bind` sends the bundle.** sluis verifies on the server: the possession signature; the attestation chain of the primary and of each subkey against the pinned root; the firmware and form factor against the allowlist; that every subkey is attested; and the user IDs against the person's verified addresses ([REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122), [REQ-KEYS-125](/requirements/keys/#REQ-KEYS-125), [REQ-KEYS-131](/requirements/keys/#REQ-KEYS-131)). The class follows from the result.
6. **It records the binding** ([REQ-KEYS-124](/requirements/keys/#REQ-KEYS-124)) and **acts on it, per kind:**

| Kind | What sluis does, for a `hardware-attested` binding |
|---|---|
| OpenPGP | Certifies the key ([OpenPGP certification](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#openpgp-certification)) |
| OpenPGP | Puts the certified key into the staff keyring, which sluis produces from the bindings and from nothing else ([The staff keyring](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-staff-keyring)) |
| OpenPGP | The GitHub key sync uploads the key to the person's account ([pull request #1485](https://github.com/truvity/sluis/pull/1485)) |
| `sk-ssh` | Later: issues SSH certificates for the key, by the rules of [0023](/decisions/0023-certificate-authorities/#ssh) (P10 A) |

### The challenge

The challenge is sluis's choice, so it is built to be signed safely.

- **The bytes are eight lines of UTF-8 text, each ending in a line feed, in this order, with nothing before, between or after:**

```text
sluis-key-bind-v1
action: bind
person: <subject>
boundary: <boundary id>
key: <key identity of the signing key, 64 hex digits>
target: <key identity the action is about, 64 hex digits>
nonce: <256 random bits, 64 hex digits>
expires: <RFC 3339 UTC time, to the second, ending in Z>
```

- **`action` is `bind`, `add`, `end` or `change`.** For a first bind `key` and `target` are the same key. For `add`, `end` and `change` ([The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate), [The key's own expiry](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-keys-own-expiry)), `key` is the existing key that vouches and `target` the key the action is about. A signature for one action cannot be used for another.
- **It lives 600 seconds, long enough for a PIN and a touch, and is used once,** and only by the session that asked for it, the session of the fresh hardware sign-in ([REQ-KEYS-148](/requirements/keys/#REQ-KEYS-148), [REQ-KEYS-149](/requirements/keys/#REQ-KEYS-149)).
- **The signature is an OpenPGP version 4 standalone signature, type 0x02,** made by the key itself. The challenge is the value of a **critical** hashed Notation Data subpacket named `bind-challenge@sluis.id`, flagged human-readable ([REQ-KEYS-150](/requirements/keys/#REQ-KEYS-150)). A type 0x02 signature signs only its own subpacket contents and no document, so it cannot pass as a signature over a file, a commit or a checksum list; a type 0x00 signature over a text would be hashed together with the data it follows, and formats such as a `sha256sum -c` list tolerate extra lines, so a label inside such a text separates nothing. A verifier that does not know a critical notation must reject the signature, which is the separation from every other use.
- **What the label does not protect.** The card signs the digest it is handed and does not see the text. So the protection is on the host: the helper refuses any challenge that lacks the label, has other lines or has a time in the past, shows the challenge before it asks for the PIN, and builds the type 0x02 packet itself. A hostile host or a hostile helper can ask the card to sign any digest at all; nothing in the format stops that, and the PIN and the touch are what stand between a card and an unwanted signature. The label separates this signature from the others that an honest helper produces; it does not make a compromised host safe.
- **The same format is the "fresh proof"** of [The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate): a challenge with `action: add`, `end` or `change`, signed by an existing key of the person.

### OpenPGP certification

- **The chain has three links.** The ritueel root makes a trust signature, limited to the company's domain, over one sluis certification key, at a ceremony, as [0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification) says. That intermediate certifies the person's key. The person's card signs the key's own user IDs.
- **The trust signature's regular expression is anchored and names one domain.** For the domain `example.com` it is `<[^>@]+@example\.com>$`: the whole address, one `@`, the exact domain, and no subdomain. An address at a subdomain needs a trust signature of its own. `sluis key install` refuses an intermediate whose trust signature has another expression, none, or a trust depth above 1 ([REQ-KEYS-153](/requirements/keys/#REQ-KEYS-153)).
- **One intermediate does it, behind key@.** It is a purpose enabled on use ([Key purposes](/decisions/0006-keys-and-sealing/#key-purposes)): a key of the cloud key service (AWS KMS) on a cloud installation and a YubiKey on a board. `signer` makes the certification for a grant that `policy` sealed, in place, and the key is never shown. Like the other OpenPGP keys of 0024 it is ECDSA on P-384 with SHA-384.
- **It certifies only addresses of the person.** The user IDs it certifies are verified addresses of the person in the directory, in the root's domain ([REQ-KEYS-131](/requirements/keys/#REQ-KEYS-131)).
- **Lifetimes, in days.** A certification lasts 395 days (13 months) and no longer than the key's own expiry ([REQ-KEYS-132](/requirements/keys/#REQ-KEYS-132)). Renewal begins 60 days before it ends ([REQ-KEYS-138](/requirements/keys/#REQ-KEYS-138)).
- **What a verifier can check.** A verifier with a web of trust (`gpg` with the root trusted, or `sq-wot`) validates a bound key through the root's trust signature and the intermediate's certification, and rejects an address outside the domain ([REQ-KEYS-130](/requirements/keys/#REQ-KEYS-130)). `gpgv`, `sqv`, apt and rpm do no web of trust. They accept a signature if the signing key is in the keyring they are given and not expired or revoked there; the certification and its 13 months play no part for them. What they rely on is the keyring ([The staff keyring](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-staff-keyring)) and the key's own expiry.

### The bound set

A person's key is more than its primary. The **bound set** is exactly these packets, and sluis stores, certifies, lists in the keyring and syncs to GitHub nothing outside it ([REQ-KEYS-161](/requirements/keys/#REQ-KEYS-161)):

- the primary key packet, with its self-signature and its expiry;
- each user ID that passed the address check, with the person's self-signature on it and sluis's certification;
- each subkey that was attested at bind time, with the primary's binding signature, and any revocation of it.

Every other packet is dropped: a subkey with no attestation of its own, a user ID for another address, a photo, a signature by a third party. **A `hardware-attested` primary with a subkey that has no verified attestation is refused** ([REQ-KEYS-160](/requirements/keys/#REQ-KEYS-160)): the software copy of a subkey could sign as the person and would sit in the company's keyring. An `unattested` binding may carry any subkeys; it is never certified, listed or synced.

### The staff keyring

The G3 check of commit signers and the `gpgv` verification of G6 both need a file, so this record owns it.

- **Form.** sluis publishes three files: `staff.gpg`, a binary OpenPGP keyring of the bound sets of all active `hardware-attested` bindings; `staff.withdrawn`, a list of key identities and fingerprints that left the keyring, each with the reason (`ended`, `lapsed` or `revoked`) and the date; and `staff.manifest`, which names the digest of each, a sequence number that rises with every build, the time built and the time after which a verifier must not use it. A detached OpenPGP signature `staff.manifest.sig` covers the manifest ([REQ-KEYS-165](/requirements/keys/#REQ-KEYS-165)).
- **Produced from the bindings only,** from the active `hardware-attested` bindings and nothing else ([REQ-KEYS-137](/requirements/keys/#REQ-KEYS-137)).
- **Signed by a key of its own.** The manifest is signed by a **keyring-signing key** under the root, a separate purpose behind key@ with a separate key, certified by the root at a ceremony. It is not the certifying intermediate, so one compromise gives an attacker either the power to certify or the power to publish, not both ([REQ-KEYS-164](/requirements/keys/#REQ-KEYS-164)). The root can revoke either key.
- **A verifier checks the manifest signature,** the digests, the sequence number against the last it saw, and the expiry time; a keyring older than that time is unreadable, not empty (the same rule as for the sync's input in [pull request #1485](https://github.com/truvity/sluis/pull/1485)).

### The gate

Attestation proves that a genuine card made a key. It does not prove whose card it is: anyone can buy one and attest a key of their own. Whose it is comes from three things: the fresh hardware sign-in of the person, the approval when the person has no hardware-attested binding, and a proof from an existing card for every other change. This applies the enrolment rule of [pull request #1484](https://github.com/truvity/sluis/pull/1484) to bindings.

- **Once a person holds an active `hardware-attested` binding, adding any further binding needs a fresh proof from it:** a possession signature in the challenge format with `action: add`, by that binding's key, over a challenge issued within the last 600 seconds ([REQ-KEYS-133](/requirements/keys/#REQ-KEYS-133)). It covers a binding of every class. A stolen session cannot add a key of its own.
- **A person with no active `hardware-attested` binding needs an operator's approval** (FB1 A). That is the first binding, and the re-binding of a person whose cards are all lost or ended. The approver holds the key-administration grant, is a different person from the enrollee, and approves with a fresh `hardware-attested` assertion of their own, as for the first hardware key of [pull request #1484](https://github.com/truvity/sluis/pull/1484) (REQ-AUTHN-092 there). A directory fact is not an approval. The config kind `FirstAdmin` names the first operator of an installation, who has no approver ([REQ-KEYS-134](/requirements/keys/#REQ-KEYS-134)).
- **Ending a binding is gated the same way.** It needs a fresh proof (`action: end`) from another active `hardware-attested` binding of the person, or an operator's approval as above ([REQ-KEYS-163](/requirements/keys/#REQ-KEYS-163)). Without this rule a stolen session could end the person's good card and then ask for a re-binding. A person's declaration of compromise is the one exception: it is the safe direction, it takes effect at once, and the person then needs an operator to bind again.
- **Every bind, every refusal and every end is audited** ([REQ-KEYS-135](/requirements/keys/#REQ-KEYS-135)). **A new `hardware-attested` binding alerts the operators**, with the fingerprint, the class and the card's serial ([REQ-KEYS-136](/requirements/keys/#REQ-KEYS-136)), **and notifies the person** at their verified address, with the fingerprint ([REQ-KEYS-155](/requirements/keys/#REQ-KEYS-155)).
- **The card's serial is kept, and it is seen by operators only.** The binding keeps the statement as received, because it must be re-verified when the allowlist or the pinned root changes, and the Yubico statement carries the card's serial. The passkey record keeps none ([pull request #1484](https://github.com/truvity/sluis/pull/1484)), and the reason differs: a passkey is registered at many sites, and a serial would let them follow a person; this statement goes only to the company's own sluis, for a card the company issued, and the serial is what lets an operator compare a new binding with the company's own purchase register. It is never written into an audit record, a token, a log line or the keyring ([REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168)).

### The key's own expiry

Two clocks run, and they are not the same. The **certification** is sluis's, lasts 395 days and is renewed by sluis. The **key** is the person's: the card primary expires after about 3 years, 1095 days (PX1), and only the card can extend it.

- **A key with no expiry is refused,** and so is one that expires beyond the bound policy sets, 1095 days by default. The binding's expiry is the key's own expiry ([REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146)).
- **Same key.** Two presentations are the same key when the primary's key material, the user IDs and the subkeys are the same. Only the expiry may differ.
- **An extension is the same key with a later expiry.** The person extends it at the card, with the ritueel helper or `gpg`, which makes a new self-signature. They present it with a fresh hardware step-up and a challenge with `action: change`. sluis re-verifies the attestation of every subkey, checks that the sets are the same, and keeps the binding ([REQ-KEYS-147](/requirements/keys/#REQ-KEYS-147)).
- **Anything else is a change,** and a change is not an extension. A new or removed user ID, a new or removed subkey: each needs a fresh hardware step-up and a new possession signature by the primary (`action: change`), so the person is present at the card; the attestation of every new subkey; and a verified directory address for every user ID ([REQ-KEYS-162](/requirements/keys/#REQ-KEYS-162)). A change keeps the binding and its key identity, so it is not a second bind of the same key (REQ-KEYS-142); it is allowed because the proof is made by the bound key itself.
- **A key that is not extended lapses with its binding.** sluis warns the person and the operators at 60, 30 and 14 days before the key's expiry ([REQ-KEYS-159](/requirements/keys/#REQ-KEYS-159)). When the key expires, the binding lapses, sluis stops renewing, the key leaves the keyring and the GitHub sync removes it.
- **The GitHub sync re-uploads the extended key.** GitHub's copy changes only when the key is uploaded again, so the sync adds the new copy and removes the old one, by the update rule of [pull request #1485](https://github.com/truvity/sluis/pull/1485) (REQ-OPS-099 there).

### Life of a binding

- **Renewal is automatic.** From 60 days before the certification ends, sluis re-certifies the same key for another 395 days, with no ceremony and no person present, while the binding is active, the person is live in the directory and the key is not revoked ([REQ-KEYS-138](/requirements/keys/#REQ-KEYS-138)). If renewal has not succeeded, sluis alerts at 30 and 14 days before the end ([REQ-KEYS-158](/requirements/keys/#REQ-KEYS-158)). Renewal re-checks the directory and the state, not the card: a card that was lost without anyone saying so stays certified until its binding ends.
- **A second card has its own binding.** Ending one never ends the other ([REQ-KEYS-139](/requirements/keys/#REQ-KEYS-139)).
- **A lost card:** the person (with the second card) or an operator ends that binding ([The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate)), then the person binds a new key. The ended key leaves the next keyring and is no longer renewed.
- **Compromise:** a person declares it, as [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#a-person-declares-and-a-suspicion-counts) says. The binding becomes `revoked` at once ([REQ-KEYS-140](/requirements/keys/#REQ-KEYS-140)), sluis revokes its own certification of the key ([REQ-KEYS-156](/requirements/keys/#REQ-KEYS-156)), and the key goes on the withdrawn list of the next keyring ([REQ-KEYS-157](/requirements/keys/#REQ-KEYS-157)). Revoking the key itself is the owner's act, with the card.
- **A leaver:** when the directory marks the person `left`, every binding ends ([REQ-KEYS-141](/requirements/keys/#REQ-KEYS-141)). Renewal stops, so the certification lapses; the key leaves the keyring; the GitHub sync removes it from the account. Nothing is revoked, and old commits stay Verified, by design (G5 A).

### The security of the design

- **sluis could certify a rogue key for someone's address.** It holds the intermediate, so a compromised or misused sluis can certify a key that the person never made, and the GitHub sync would then put it on that person's account, where commits signed with it show Verified. Four things stand in the way: policy decides who may bind; a bind needs a fresh hardware sign-in that the boundary checked; a person with no hardware-attested binding needs an operator's approval; and every later change needs a proof from the person's existing card. None of these stops an insider who holds both an operator's hardware key and the policy to change them.
- **A rogue key is visible, and that is the control that remains.** Each bind is audited and alerts the operators with the card's serial, so an operator can compare it with the company's own purchase register; the person is told at their own address; and a certified key appears in the keyring as a new key identity that anyone can diff. The data for these checks is in sluis's binding records.
- **A compromised intermediate stops certifying at once, and is replaced through ritueel.** sluis acts first: `signer` refuses to certify once the intermediate is on the `KeyRevocation` of [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#intermediates-and-ssh-ca-keys) ([REQ-KEYS-166](/requirements/keys/#REQ-KEYS-166)). ritueel revokes the root's trust signature over it and makes a new one at a ceremony. sluis then re-certifies every active binding under the new intermediate from the records, with no card and no person ([REQ-KEYS-167](/requirements/keys/#REQ-KEYS-167)). The keyring-signing key is separate, so this compromise does not let an attacker publish a keyring, and the root can revoke that key too.
- **How verifiers learn.** A web-of-trust verifier with an updated copy of the root's revocation stops trusting the old intermediate. `gpgv`, `sqv`, apt and rpm never look at the certification, so for them a compromised intermediate changes nothing: the keyring is what they trust, and a bad key leaves it at the next build. A verifier on an old copy of the keyring trusts every key that was in it until the key's own expiry, up to 1095 days, or until it fetches the new one, which is the reason the manifest has a time after which it must not be used. GitHub does not read certifications at all: keys already uploaded stay, and the sync removes the ones that are withdrawn.
- **Signature times are the signer's.** An OpenPGP signature carries a creation time that the signer chooses. A key that has ended, lapsed or expired can still make a signature that claims an earlier time, and no verifier can tell. Revocation and lapse stop new trust in a key; they do not make an old or backdated signature false.
- **Keys stay on cards.** The private part never reaches sluis and never reaches the company. sluis can certify a key; it cannot make a subkey, a signature or a commit in anyone's name, and it holds no key whose loss lets an attacker sign as a person.
- **A lapse is not a revocation.** A leaver's key is accepted by any verifier that holds an old copy of the keyring until the key's own expiry, and by a web-of-trust verifier that holds the key until the certification ends; a verifier that fetches the new keyring stops at once. A leaver who is a risk is a compromise, and is revoked.

### What ritueel owns

- **The roots,** the ceremony that delegates the trust signature to the intermediate, the certification of the keyring-signing key, and the ceremonies that renew or replace them.
- **The card-readiness helper and the bundle format.** The helper makes the key on the card, sets the PINs, builds and shows the challenge signature, and writes bundle v1 as standard files. sluis and ritueel share formats and test vectors and no code ([0024](/decisions/0024-root-custody-and-the-signing-api/)). ritueel's ADR 0014 is being rewritten to match this record.
- **Personal keys** that a person keeps outside the company.

### The attestation question

Does the OpenPGP applet's attestation cover a card-born primary used to certify and to sign? **UNVERIFIED.** Read on 2026-11-06 from [Yubico's OpenPGP attestation page](https://developers.yubico.com/PGP/Attestation.html) and [the `ykman openpgp keys attest` reference](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html):

- READ: the signature, decryption and authentication keys can be attested, on firmware 5.2 and later, and only a key generated on the device can be ("imported" is not permitted). Firmware 5.7.4 and later is signed under Yubico's new root.
- READ: the statement carries the key's fingerprint and generation date, and Yubico says not to trust them, because the Admin PIN can overwrite them. The page says to always verify the public key.
- Not found: any statement about a key used for certification. The attested object is the key in a slot. Whether that key is the OpenPGP primary, and its certify flag, are facts of the OpenPGP key (its self-signature), which the statement does not cover. That the signature slot holds the primary is how OpenPGP cards and GnuPG work, and was not read on those pages.

So the design checks the public key of each statement against the public key of the primary and of the subkey it attests, and ignores the fingerprint and date in the statement. The build is gated on the conformance test below. A result that contradicts the design changes this record before anything is built.

**Conformance test, run on a YubiKey 5 with firmware 5.7.4 or later, and on one older to see it refused:**

1. Generate a primary with certify and sign on the card, with `gpg` and with the ritueel helper; export the attestation of the signature, decryption and authentication slots; verify each chain to Yubico Attestation Root 1; compare each public key with the primary's and the subkeys'.
2. A key imported into a slot has no attestation, and a statement whose public key differs from the key presented is refused. A card with firmware below 5.7.4 is refused.
3. The fingerprint and date in the statement are overwritten with the Admin PIN: sluis's result does not change.
4. Read a real statement and list its fields. Confirm that it has no model name, and that the firmware, the form factor and the FIPS flag are the fields the allowlist can use, and that the root's name is the one sluis pins.
5. The challenge signature (type 0x02, critical notation): parse it with `gpg --list-packets` and `sq packet dump`; check that `gpg --verify` and `sqv` reject it as a signature over any file (the expectation, UNVERIFIED, is that both refuse it); check that the helper refuses a challenge with a missing label or an extra line.
6. The card certifies a user ID and signs a commit and a checksum file; `gpgv`, `sqv` and `git verify-commit` accept them.
7. Certify the key with the intermediate under the root's trust signature with the anchored expression: `gpg` with the root trusted and `sq-wot` accept an address in the domain and reject one outside it and one at a subdomain.
8. The certified key, with the intermediate's certification and the root's trust signature, is uploaded to a GitHub account (`POST /user/gpg_keys`) and a commit signed on the card shows Verified. This also tests whether GitHub accepts a P-384 key that carries third-party certifications.

## Consequences

- A joiner binds a key in minutes and a lost card is replaced the same way, with no ceremony and no person at ritueel. The yearly renewal of a person's certification stops being work, and the key itself is extended by the person once in three years.
- sluis certifies on its own authority, under a trust signature from the root. The root stays offline, and the weight moves to policy, the hardware sign-in and detection. That is a stronger position than a ceremony role that binds software, and a weaker one than a ceremony with a person present; the design chooses automation and says what it costs.
- A card that sluis cannot attest, or that is not on the allowlist, cannot sign for the company. An installation that wants to accept another form factor extends the allowlist; cards older than firmware 5.7.4 are not accepted.
- The staff keyring is a file that sluis produces, signs with a key of its own and publishes. The sync of [pull request #1485](https://github.com/truvity/sluis/pull/1485) reads the bindings, not the file, and the CI check of G3 C and the `gpgv` check of G6 read the file.
- New obligations are [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143), [REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146) to [REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168).

## Roads not taken

- **One KMS key per person.** The company would hold a signing key of everyone and could sign as anyone, a key service per person costs money at every joiner, and nothing proves that a person's key is on a card.
- **Sealed software primaries per person.** sluis would hold a private key that signs as the person, and a software key cannot be attested; it is the BK3 road for bots, and for staff it breaks G1 A.
- **One company primary with everyone's subkeys.** GitHub attribution, user ID churn and revocation churn: one revocation touches every person.
- **ritueel binds each person's subkey in a ceremony (G2a).** The card and the "person present" check run on the client, so a ceremony role can bind a software subkey, and it needs a person at ritueel for every joiner and lost card.
- **Trust an attestation alone.** Anyone can attest a key on a card they bought, so the attestation says what a key is and not whose it is.
- **Directory approval of the first binding, or of any further one.** The directory cannot say whose device a key is, and a directory change needs no hardware proof, so a changed entry would add a key to a person; FB1 A chose operator approval only, the rule of #1484.
- **An SSH-signing fallback for staff (G1 A).** It cannot be tied to a card the same way, and GitHub treats it as a different key.
- **A new attestation at every renewal.** It brings a person back to the card once a year for a check that the lost-card rule already covers.
- **A key that never expires.** A lost card would leave a key valid for ever, and the yearly certification would be the only limit; an expiry the card extends keeps a person's key in step with their card.
- **A label inside a type 0x00 signature over text.** The text is hashed with its data and lenient formats tolerate extra lines, so a label separates nothing; a type 0x02 signature with a critical notation does.
- **The version 4 fingerprint as the key identity.** It covers a creation time the holder chooses, so one card key could be bound twice.
- **The certifying intermediate also signs the keyring.** One compromise would give an attacker both the power to certify and the power to publish.
- **Keep the old model-name allowlist.** The Yubico statement has no model name, so a list of models would name nothing that sluis can check.

## Follow-ups

- Build `sluis key bind`, the kind `KeyBinding`, the certification and keyring-signing purposes and the keyring producer: [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143), [REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146) to [REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168) ([#1496](https://github.com/truvity/sluis/issues/1496)), gated on the conformance test above.
- Run the conformance test and date the result ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Add the certification and keyring-signing purposes to the table of [Key purposes](/decisions/0006-keys-and-sealing/#key-purposes) and to the key plan when they are built ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Write bundle v1 and the challenge as test vectors shared with ritueel ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Bring the wording of the GitHub key sync into line with this record when both merge ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Sealed software keys for non-human identities such as bots and agents (BK3 A): a later feature with its own record when it is designed ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Enforcement of commit signing on GitHub (G3 C) stays a later CI check against the staff keyring ([#1496](https://github.com/truvity/sluis/issues/1496)).
