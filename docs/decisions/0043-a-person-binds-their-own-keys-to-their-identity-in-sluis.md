# 0043 — A person binds their own keys to their identity in sluis

**Status:** Accepted
**Date:** 2026-11-06

Proposal: [issue #1496](https://github.com/truvity/sluis/issues/1496), owner decisions SK1 E, BK1 A, BK2 A, BK3 A, BD1 B, BD2 B, 2026-11-06.

## Context

The company issues each staff member an OpenPGP identity whose signing keys are born on the person's card. Until now the design left open who binds those keys to the person. The first answer was a ceremony of [ritueel](https://ritueel.id) per person. The review of that design on 2026-11-06 found that the card, the attestation and the "person present" check all run on the client of the ceremony, so anyone who can assume the ceremony role can bind a software subkey, and detection is the only real control. It also needs a person at ritueel for every joiner and every lost card.

sluis already knows who a person is, signs the person in with a hardware key, and certifies keys online under a delegated key ([0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification)). On 2026-11-06 the maintainer decided, in these words and answers:

| Label | Decision |
|---|---|
| SK1 E | "key bindings in sluis. A person binds their own key to their identity; sluis checks the proof on the server, records a binding, and acts on it. Staff keys are card-born." |
| BK1 A | "`sluis key bind` does the binding, with ritueel helping the person generate on the card and produce the proof, using standard formats." |
| BK2 A | "software keys can be bound with class `software`. Staff company signing refuses them." This record names that class `unattested` (see [Classes](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#classes)). |
| BK3 A | "sealed software keys for non-human identities (bots, agents) are a later feature." |
| BD1 B | "because we manage per-company identities (employees) and comporise of company key is much worse then just persons." A person's primary key is made and sealed in sluis, per company; the keys that sign are subkeys born on the person's card. |
| BD2 B | "And even for customers - customers sign/authorize data FOR company to get some service, right?" A customer may bind a key in the company's tenant, for that company only ([Customers](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#customers)). |
| G1 A | "OpenPGP keys born on cards, with no SSH-signing fallback." Under BD1 B the keys that sign are born on cards; the primary is sluis's and never signs data. |
| G4 A | Staff cards are generated on the card, the PIN and Admin PIN are changed at issue, and each person gets a second card. Here the attestation is recorded in the binding. |
| G5 A | A leaver is removed from the organisation and the GitHub account, the certification lapses, the key leaves the keyring, and a revocation is for compromise only. Old commits stay Verified, by design. |
| FB1 A | "The same rule in both records, operator approval only": the first hardware binding is approved by an operator, and a directory fact is not enough. |
| P10 A | An `sk-ssh` key gets an SSH certificate, later. |
| PX1 | "the card primary expires after about 3 years and is extended at the card." Here the card's signing subkey expires after 1095 days, and the card proves the extension. The GitHub App re-uploads the extended key. |
| PK1 A | A privileged action needs an assertion that the boundary itself verified ([0017](/decisions/0017-identity-and-sign-in/); the classes and the enrolment rule are in [pull request #1484](https://github.com/truvity/sluis/pull/1484)). |

This record replaces the per-person design that G2a, G2b and SK2 to SK5 described. It is the producer of the keys that the GitHub key sync consumes ([pull request #1485](https://github.com/truvity/sluis/pull/1485)).

The owner's reason for BD1 B is the size of the loss: sluis manages the identities of a company's employees, and the compromise of one company-wide key is much worse than the compromise of one person. The design therefore keeps every online key per person or per company, never one for all, and says in [The security of the design](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-security-of-the-design) what is still exposed.

## Decision

### What a person has

- **One OpenPGP primary per person per company.** It is generated inside key@ and kept only sealed, as the durable kind `PersonPrimary`, written by key@ and sealed under the **person-key data key of the person's tenant**, one per company ([REQ-KEYS-172](/requirements/keys/#REQ-KEYS-172), [REQ-KEYS-174](/requirements/keys/#REQ-KEYS-174)). It is ECDSA on P-384 with SHA-384, like the other OpenPGP keys of 0024. It is opened only inside key@, the private part is never returned to any caller ([REQ-KEYS-176](/requirements/keys/#REQ-KEYS-176)), and its only use is to make the signatures of that person's own certificate: the user ID self-signature, the bindings and revocations of the person's subkeys, and the renewal of its own expiry ([REQ-KEYS-173](/requirements/keys/#REQ-KEYS-173)). It signs no data. Every use is audited ([REQ-KEYS-175](/requirements/keys/#REQ-KEYS-175)). This is a named exception to the rule that keys sign in place on a card or in a cloud key service ([0006](/decisions/0006-keys-and-sealing/)): it is a key made in key@ and sealed like a data key, and the exception is the maintainer's decision BD1 B.
- **The subkeys are born on the person's card** and bound under that primary. A person has one stable key and one fingerprint for the life of their employment, and a lost card means a new subkey under the same primary: no new identity, no new upload of a new key to every place the key is known.
- **The primary has one user ID: the person's company address,** the verified address in the company's domain that the directory holds as primary. A person with more addresses has one user ID; a change of address is a new user ID certified and the old one revoked, made by sluis from the directory, audited and notified to the person ([REQ-KEYS-131](/requirements/keys/#REQ-KEYS-131), [REQ-KEYS-179](/requirements/keys/#REQ-KEYS-179)).
- **The primary is certified by the company's certification key,** not by the root: one online P-384 key per company, behind key@, under a trust signature from the ritueel root that is limited to that company's domain ([OpenPGP certification](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#openpgp-certification)). No certification key serves two companies ([REQ-KEYS-177](/requirements/keys/#REQ-KEYS-177)).

### What a binding is

- **A binding is a record that a person's card holds the subkeys it names.** One card is one binding. It holds the person; the **key identity**; the kind; the class; the bound set; the attestation as received; the time created; the expiry; and a state: `active`, `ended` or `revoked`. It is the durable kind `KeyBinding`, personal and sealed under the tenant's data key, written only by `exchange`, and erased with the person ([0004](/decisions/0004-the-data-model/)). Both kinds, `PersonPrimary` and `KeyBinding`, are added to the registry with the first build.
- **The key identity is the SHA-256 hash of the public key material of the card's signing subkey,** the algorithm, the curve and the public point, and nothing else. It is not the version 4 fingerprint, because the fingerprint covers the creation time, which the holder chooses: the same card key could be given two creation times and bound twice. No subkey of one binding may be the key material of another ([REQ-KEYS-142](/requirements/keys/#REQ-KEYS-142)).
- **sluis never holds the private part of a card's subkey.** The request carries public keys and proofs, and the card keeps the rest ([REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143)).
- **The kinds are OpenPGP and `sk-ssh`.** X.509 and PIV keys come later. Each kind has its own proof format and its own action; the binding, the classes and the gate are the same for all.

### Classes

The classes are not the passkey classes of [pull request #1484](https://github.com/truvity/sluis/pull/1484), and they do not reuse their names. A passkey of class `hardware` is unattested and probably device-bound, as the authenticator says; a key whose attestation verified but whose card is not on the list would be the same word with the opposite meaning. A key has no backup flag either. So the names say what sluis verified:

| Class | How it is derived |
|---|---|
| `hardware-attested` | The attestation of every subkey verified to the one pinned vendor root, and the card's firmware and form factor are on the installation's allowlist |
| `hardware-unlisted` | The attestation verified to the pinned root, but the firmware or the form factor is not on the allowlist |
| `unattested` | The key came with no attestation. BK2 A calls this class `software`; the name here says what sluis knows, because a card key whose person sent no statement is the same case |

An attestation that is present and does not verify is refused, not downgraded: a forged statement is an incident ([REQ-KEYS-125](/requirements/keys/#REQ-KEYS-125), [REQ-KEYS-126](/requirements/keys/#REQ-KEYS-126), [REQ-KEYS-127](/requirements/keys/#REQ-KEYS-127)). Policy decides what each class may do ([REQ-KEYS-128](/requirements/keys/#REQ-KEYS-128)).

**Staff company signing needs `hardware-attested`.** Binding a subkey under the person's primary ([REQ-KEYS-129](/requirements/keys/#REQ-KEYS-129)), putting it into the staff keyring ([REQ-KEYS-137](/requirements/keys/#REQ-KEYS-137)) and handing it to the GitHub key sync ([REQ-KEYS-154](/requirements/keys/#REQ-KEYS-154)) are all company signing. A key of another class gets none of them. That is G1 A in rule form: staff signing keys are card-born, and there is no SSH-signing fallback. An `unattested` or `hardware-unlisted` binding is still recorded and audited; what it may do is for policy, and by default it does nothing.

**The allowlist is defined on what the statement has.** Yubico's attestation statement carries no model name. READ 2026-11-06 ([Yubico's OpenPGP attestation page](https://developers.yubico.com/PGP/Attestation.html)): it carries the firmware version, the form factor, the serial number, the FIPS and CSPN status, the user-interaction flag and the signature counter, beside a fingerprint, a date and a cardholder name that are not to be trusted. The allowlist therefore names a minimum firmware, a set of form factors and, optionally, a required FIPS flag. It is installation config that a tenant can narrow and not widen. **Firmware floor: 5.7.4,** the first firmware signed under Yubico's new root; sluis pins that one root, "Yubico Attestation Root 1" (the name is to be confirmed against a real statement), and no other. **Older cards are out:** their statements chain to the old root and are refused, and a person with an older card needs a newer one ([REQ-KEYS-152](/requirements/keys/#REQ-KEYS-152)).

### The flow

1. **The person has a primary.** It is made when the person joins and the first binding is approved. The helper reads its public key with `sluis key bind --primary`.
2. **The person generates the subkeys on the card first.** The ritueel helper makes the signing subkey (and, if wanted, the encryption and authentication subkeys) on the card, sets the PINs, and makes the card sign the **back-signature** (type 0x19) over the person's primary and the signing subkey, as OpenPGP requires of a signing subkey ([REQ-KEYS-171](/requirements/keys/#REQ-KEYS-171)). It writes the **bundle v1**: `<name>.subkey.pgp` (the public subkeys, and the back-signature), `<name>.proof.json` (the attestation statement and chain of each subkey) and, in step 4, `<name>.possession.sig`. The formats are standard; ritueel and sluis share test vectors for the bundle and no code ([REQ-KEYS-151](/requirements/keys/#REQ-KEYS-151)).
3. **The person signs in with a fresh hardware step-up that sluis verified itself.** It is a `hardware-attested` assertion checked by the boundary that holds the binding, within the age policy sets; an upstream claim never counts (PK1 A, [REQ-KEYS-123](/requirements/keys/#REQ-KEYS-123)). `sluis key bind` then asks sluis for a challenge that names the person, the boundary and the signing subkey. Each card gets its own challenge ([The challenge](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-challenge)).
4. **The helper signs the challenge with the signing subkey on the card** and writes `<name>.possession.sig`. The card needs its PIN and, by the touch policy decided per key (G4 A), a touch.
5. **`sluis key bind` sends the bundle.** sluis verifies on the server: the possession signature; the back-signature against the person's primary; the attestation chain of every subkey against the pinned root; the firmware and form factor against the allowlist; and that every subkey is attested ([REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122), [REQ-KEYS-125](/requirements/keys/#REQ-KEYS-125), [REQ-KEYS-160](/requirements/keys/#REQ-KEYS-160)). The class follows from the result.
6. **It records the binding** ([REQ-KEYS-124](/requirements/keys/#REQ-KEYS-124)) and **acts on it, per kind:**

| Kind | What sluis does, for a `hardware-attested` binding |
|---|---|
| OpenPGP | key@ signs the binding of each subkey with the person's primary, with the back-signature embedded and the expiry of 1095 days ([The subkey's own expiry](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-subkeys-own-expiry)) |
| OpenPGP | The person's certificate, the primary with its user ID, certification and bound subkeys, goes into the staff keyring ([The staff keyring](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-staff-keyring)) |
| OpenPGP | The GitHub key sync uploads the certificate to the person's account ([pull request #1485](https://github.com/truvity/sluis/pull/1485)) |
| `sk-ssh` | Later: issues SSH certificates for the key, by the rules of [0023](/decisions/0023-certificate-authorities/#ssh) (P10 A) |

**How the two proofs fit.** The back-signature and the challenge signature are both made by the card's signing subkey, and they prove different things. The back-signature says that this subkey agrees to be a subkey of this primary; OpenPGP requires it so that nobody can claim another's signing key. It is made by the card with the signer's own choice of creation time and carries no server nonce, so it could be replayed from an old bundle. The challenge signature has the server's nonce, the person, the boundary and the time, so it proves that the card is present now, for this request. sluis requires both: the back-signature for the OpenPGP packet, the challenge for freshness.

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

- **`action` is `bind`, `add`, `end` or `change`.** For a first bind `key` and `target` are the same key. For `add`, `end` and `change` ([The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate), [The subkey's own expiry](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-subkeys-own-expiry)), `key` is the existing key that vouches and `target` the key the action is about. A signature for one action cannot be used for another.
- **It lives 600 seconds, long enough for a PIN and a touch, and is used once,** and only by the session that asked for it, the session of the fresh hardware sign-in ([REQ-KEYS-148](/requirements/keys/#REQ-KEYS-148), [REQ-KEYS-149](/requirements/keys/#REQ-KEYS-149)).
- **The signature is an OpenPGP version 4 standalone signature, type 0x02,** made by the signing subkey itself. The challenge is the value of a **critical** hashed Notation Data subpacket named `bind-challenge@sluis.id`, flagged human-readable ([REQ-KEYS-150](/requirements/keys/#REQ-KEYS-150)). A type 0x02 signature signs only its own subpacket contents and no document, so it cannot pass as a signature over a file, a commit or a checksum list; a type 0x00 signature over a text would be hashed together with the data it follows, and formats such as a `sha256sum -c` list tolerate extra lines, so a label inside such a text separates nothing. A verifier that does not know a critical notation must reject the signature, which is the separation from every other use.
- **What the label does not protect.** The card signs the digest it is handed and does not see the text. So the protection is on the host: the helper refuses any challenge that lacks the label, has other lines or has a time in the past, shows the challenge before it asks for the PIN, and builds the type 0x02 packet itself. A hostile host or a hostile helper can ask the card to sign any digest at all; nothing in the format stops that, and the PIN and the touch are what stand between a card and an unwanted signature. The label separates this signature from the others that an honest helper produces; it does not make a compromised host safe.
- **The same format is the "fresh proof"** of [The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate): a challenge with `action: add`, `end` or `change`, signed by an existing signing subkey of the person.

### OpenPGP certification

- **The chain has three links.** The ritueel root makes a trust signature, limited to the company's domain, over the company's certification key, at a ceremony, as [0024](/decisions/0024-root-custody-and-the-signing-api/#company-openpgp-certification) says. That key certifies the person's primary. The primary signs its own user ID and binds the card's subkeys.
- **The trust signature's regular expression is anchored and names one domain.** For the domain `example.com` it is `<[^>@]+@example\.com>$`: the whole address, one `@`, the exact domain, and no subdomain. An address at a subdomain needs a trust signature of its own. `sluis key install` refuses a certification key whose trust signature has another expression, none, or a trust depth above 1 ([REQ-KEYS-153](/requirements/keys/#REQ-KEYS-153)).
- **One certification key per company, behind key@.** It is a purpose enabled on use, for a tenant that issues staff keys ([Key purposes](/decisions/0006-keys-and-sealing/#key-purposes)): a key of the cloud key service (AWS KMS) on a cloud installation and a YubiKey on a board. `signer` makes the certification for a grant that `policy` sealed, in place, and the key is never shown. Like the other OpenPGP keys of 0024 it is ECDSA on P-384 with SHA-384.
- **It certifies only the one address of the person** ([REQ-KEYS-131](/requirements/keys/#REQ-KEYS-131)).
- **Lifetimes, in days.** A certification lasts 395 days (13 months) and no longer than the primary's own expiry, which sluis renews with it ([REQ-KEYS-132](/requirements/keys/#REQ-KEYS-132)). Renewal begins 60 days before it ends ([REQ-KEYS-138](/requirements/keys/#REQ-KEYS-138)).
- **What a verifier can check.** A verifier with a web of trust (`gpg` with the root trusted, or `sq-wot`) validates a person's primary through the root's trust signature and the company key's certification, and rejects an address outside the domain ([REQ-KEYS-130](/requirements/keys/#REQ-KEYS-130)). `gpgv`, `sqv`, apt and rpm do no web of trust. They accept a signature if the signing subkey is in the keyring they are given, bound to a primary that has not expired or been revoked there; the certification and its 13 months play no part for them. What they rely on is the keyring ([The staff keyring](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-staff-keyring)) and the expiry of the primary and of the subkey.

### The bound set

A person's certificate has exactly these packets, and sluis stores, lists in the keyring and syncs to GitHub nothing outside them ([REQ-KEYS-161](/requirements/keys/#REQ-KEYS-161)):

- the primary key packet, with its self-signature and its expiry;
- the one user ID, with the primary's self-signature and the company key's certification;
- each subkey that was attested at bind time, with the primary's binding signature (with the card's back-signature embedded) and any revocation of it.

Every other packet is refused or dropped. **A card whose bundle carries a subkey with no verified attestation of its own is refused** ([REQ-KEYS-160](/requirements/keys/#REQ-KEYS-160)): there is no such thing as a software subkey that sluis binds. Subkeys exist by design now, so the question is no longer which subkeys a primary may carry but which ones sluis has bound: only the ones it bound, each attested.

### The staff keyring

The G3 check of commit signers and the `gpgv` verification of G6 both need a file, so this record owns it.

- **Form.** For each company sluis publishes three files: `staff.gpg`, a binary OpenPGP keyring of the certificates of the people who have an active `hardware-attested` binding; `staff.withdrawn`, a list of key identities and fingerprints that left the keyring, each with the reason (`ended`, `lapsed` or `revoked`) and the date; and `staff.manifest`, which names the digest of each, a sequence number that rises with every build, the time built and the time after which a verifier must not use it. A detached OpenPGP signature `staff.manifest.sig` covers the manifest ([REQ-KEYS-165](/requirements/keys/#REQ-KEYS-165)).
- **One certificate per person.** A second card adds a subkey to the same certificate. The sync of [pull request #1485](https://github.com/truvity/sluis/pull/1485) replaces the person's certificate on GitHub when a subkey, the user ID or an expiry changes.
- **Produced from the bindings only,** from the people with an active `hardware-attested` binding, with only their bound sets ([REQ-KEYS-137](/requirements/keys/#REQ-KEYS-137)).
- **Signed by a key of its own.** The manifest is signed by a **keyring-signing key** of the company under the root, a separate purpose behind key@ with a separate key, certified by the root at a ceremony. It is not the company's certification key, so one compromise gives an attacker either the power to certify or the power to publish, not both ([REQ-KEYS-164](/requirements/keys/#REQ-KEYS-164)). The root can revoke either key.
- **A verifier checks the manifest signature,** the digests, the sequence number against the last it saw, and the expiry time; a keyring older than that time is unreadable, not empty (the same rule as for the sync's input in [pull request #1485](https://github.com/truvity/sluis/pull/1485)).

### The gate

Attestation proves that a genuine card made a key. It does not prove whose card it is: anyone can buy one and attest a key of their own. Whose it is comes from three things: the fresh hardware sign-in of the person, the approval when the person has no hardware-attested binding, and a proof from an existing card for every other change. This applies the enrolment rule of [pull request #1484](https://github.com/truvity/sluis/pull/1484) to bindings.

- **Once a person holds an active `hardware-attested` binding, adding any further binding needs a fresh proof from it:** a possession signature in the challenge format with `action: add`, by that binding's signing subkey, over a challenge issued within the last 600 seconds ([REQ-KEYS-133](/requirements/keys/#REQ-KEYS-133)). It covers a binding of every class. A stolen session cannot add a key of its own.
- **A person with no active `hardware-attested` binding needs an operator's approval** (FB1 A). That is the first binding, and the re-binding of a person whose cards are all lost or ended. The approver holds the key-administration grant, is a different person from the enrollee, and approves with a fresh `hardware-attested` assertion of their own, as for the first hardware key of [pull request #1484](https://github.com/truvity/sluis/pull/1484) (REQ-AUTHN-092 there). A directory fact is not an approval. The config kind `FirstAdmin` names the first operator of an installation, who has no approver ([REQ-KEYS-134](/requirements/keys/#REQ-KEYS-134)).
- **Ending a binding is gated the same way.** It needs a fresh proof (`action: end`) from another active `hardware-attested` binding of the person, or an operator's approval as above ([REQ-KEYS-163](/requirements/keys/#REQ-KEYS-163)). Without this rule a stolen session could end the person's good card and then ask for a re-binding. A person's declaration of compromise is the one exception: it is the safe direction, it takes effect at once, and the person then needs an operator to bind again.
- **Every bind, every refusal and every end is audited** ([REQ-KEYS-135](/requirements/keys/#REQ-KEYS-135)). **A new `hardware-attested` binding alerts the operators**, with the fingerprint, the class and the card's serial ([REQ-KEYS-136](/requirements/keys/#REQ-KEYS-136)), **and notifies the person** at their verified address, with the fingerprint ([REQ-KEYS-155](/requirements/keys/#REQ-KEYS-155)).
- **The card's serial is kept for staff cards, and it is seen by operators only.** The binding keeps the statement as received, because it must be re-verified when the allowlist or the pinned root changes, and the Yubico statement carries the card's serial. The passkey record keeps none ([pull request #1484](https://github.com/truvity/sluis/pull/1484)), and the reason differs: a passkey is registered at many sites, and a serial would let them follow a person; this statement goes only to the company's own sluis, for a card the company issued, and the serial is what lets an operator compare a new binding with the company's own purchase register. It is never written into an audit record, a token, a log line or the keyring ([REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168)).

### The subkey's own expiry

Two clocks run, and they are not the same. The **certification** and the primary's expiry are sluis's, last 395 days and are renewed by sluis. The **card's subkeys** are the person's: the binding of each expires after 1095 days (PX1), and only the card can prove an extension.

- **The binding has an expiry** at most 1095 days after it is made, or the bound that policy sets ([REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146)). The binding signature that sluis makes carries it as the subkey's key expiration time.
- **The same bound set.** Two presentations are the same bound set when the signing subkey and the other subkeys, by key material, are the same. Only the expiry may differ.
- **An extension is the same bound set with a later expiry, proved by the card.** The person signs in with a fresh hardware step-up and the helper signs a challenge with `action: change` by the signing subkey. sluis re-verifies the attestation of every subkey, checks that the set is the same, and makes the new binding signature with the primary ([REQ-KEYS-147](/requirements/keys/#REQ-KEYS-147)). The card does not make the signature; the primary does, and the card's proof is what permits it.
- **Anything else is a change.** A subkey added to or removed from the card's bound set needs a fresh hardware step-up, a new possession signature by the signing subkey, the back-signature and the attestation of each new subkey ([REQ-KEYS-162](/requirements/keys/#REQ-KEYS-162)). A change keeps the binding and its key identity.
- **A subkey that is not extended lapses with its binding.** sluis warns the person and the operators at 60, 30 and 14 days before the expiry ([REQ-KEYS-159](/requirements/keys/#REQ-KEYS-159)). When it expires, the binding lapses, the subkey leaves the keyring and the GitHub sync replaces the person's certificate.
- **The GitHub sync re-uploads the extended certificate.** GitHub's copy changes only when the key is uploaded again, so the sync adds the new copy and removes the old one, by the update rule of [pull request #1485](https://github.com/truvity/sluis/pull/1485) (REQ-OPS-099 there).

### Life of a binding

- **Renewal is automatic.** From 60 days before the certification ends, sluis re-certifies the person's primary for another 395 days and renews its expiry, with no ceremony and no person present, while the person has an active binding, is live in the directory and the primary is not revoked ([REQ-KEYS-138](/requirements/keys/#REQ-KEYS-138)). If renewal has not succeeded, sluis alerts at 30 and 14 days before the end ([REQ-KEYS-158](/requirements/keys/#REQ-KEYS-158)). Renewal re-checks the directory and the state, not the card: a card that was lost without anyone saying so stays bound until its binding ends.
- **A second card has its own binding,** and its own subkeys under the same primary. Ending one never ends the other ([REQ-KEYS-139](/requirements/keys/#REQ-KEYS-139)).
- **A lost card:** the person (with the second card) or an operator ends that binding ([The gate](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-gate)), then the person binds a new card. sluis revokes the lost card's subkeys under the same primary; the fingerprint of the person does not change.
- **Compromise:** a person declares it, as [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#a-person-declares-and-a-suspicion-counts) says. The binding becomes `revoked` at once ([REQ-KEYS-140](/requirements/keys/#REQ-KEYS-140)), sluis revokes the subkeys with a subkey revocation signature of the primary ([REQ-KEYS-156](/requirements/keys/#REQ-KEYS-156)), and the keys go on the withdrawn list of the next keyring ([REQ-KEYS-157](/requirements/keys/#REQ-KEYS-157)). A compromised primary is a compromise of sluis's key@ and follows [The security of the design](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-security-of-the-design).
- **A leaver:** when the directory marks the person `left`, every binding ends ([REQ-KEYS-141](/requirements/keys/#REQ-KEYS-141)). Renewal stops, so the certification and the primary's expiry lapse within 395 days; the certificate leaves the keyring; the GitHub sync removes it from the account. Nothing is revoked, and old commits stay Verified, by design (G5 A).

### The security of the design

- **Blast radius was the owner's reason for BD1 B, and the design is cut to it.** The sealed primaries of a company are sealed under that company's own person-key data key, so the ciphertext of one company opens with no other company's key. The certification key and the keyring-signing key are per company. No online key serves two companies, and none serves everyone. A compromise of one person's card gives a few subkeys that are bound for one person, and a compromised company costs that company only.
- **What remains, plainly.** Anyone who controls key@ for a company can make a subkey of their own and bind it under any of that company's people, because key@ opens the sealed primaries. If the attacker takes the wrapping key and the ciphertext, they can do it quietly and offline, with no call to sluis and no audit record. The per-company seal protects one company from another's compromise; it does not protect a company from the compromise of its own boundary's wrapping key, and on a boundary shared by several companies that key wraps all their data keys. A company that wants a harder wall puts itself on a boundary of its own, or in the arrangement of [0006](/decisions/0006-keys-and-sealing/) where the tenant keeps its wrapping keys in its own account.
- **The control against that is detection,** and it is the only one. A binding made through sluis is audited, alerts the operators, notifies the person and shows up in the published keyring as a new subkey that anyone can diff. A subkey bound offline shows up in none of those, but a commit signed with it fails the later CI check of G3 C, which compares each commit's signing key with the published keyring. The wrapping key's use shows in the cloud key service's own logs. Until G3 C exists, "cards only" is written policy and a rogue subkey is found only by someone who reads those logs.
- **sluis could still bind a rogue subkey through its own path,** and the GitHub sync would put it on that person's account, where commits signed with it show Verified. Four things stand in the way: policy decides who may bind; a bind needs a fresh hardware sign-in that the boundary checked; a person with no hardware-attested binding needs an operator's approval; and every later change needs a proof from the person's existing card. None of these stops an insider who holds both an operator's hardware key and the policy to change them.
- **A compromised certification key stops certifying at once, and is replaced through ritueel.** sluis acts first: `signer` refuses to certify once the key is on the `KeyRevocation` of [0041](/decisions/0041-a-compromised-key-is-revoked-then-replaced/#intermediates-and-ssh-ca-keys) ([REQ-KEYS-166](/requirements/keys/#REQ-KEYS-166)). ritueel revokes the root's trust signature over it and makes a new one at a ceremony. sluis then re-certifies the primary of every person of that company under the new key from the records, with no card and no person ([REQ-KEYS-167](/requirements/keys/#REQ-KEYS-167)). The keyring-signing key is separate, so this compromise does not let an attacker publish a keyring, and the root can revoke that key too.
- **How verifiers learn.** A web-of-trust verifier with an updated copy of the root's revocation stops trusting the old certification key. `gpgv`, `sqv`, apt and rpm never look at the certification, so for them a compromised certification key changes nothing: the keyring is what they trust, and a bad key leaves it at the next build. A verifier on an old copy of the keyring trusts every key that was in it until the expiry of the subkey or of the primary, at most 395 days for a leaver's primary, or until it fetches the new one, which is the reason the manifest has a time after which it must not be used. GitHub does not read certifications at all: keys already uploaded stay, and the sync replaces or removes them.
- **Signature times are the signer's.** An OpenPGP signature carries a creation time that the signer chooses. A key that has ended, lapsed or expired can still make a signature that claims an earlier time, and no verifier can tell. Revocation and lapse stop new trust in a key; they do not make an old or backdated signature false.
- **The card's keys stay on the card.** The private part of a signing subkey never reaches sluis. A compromise of sluis lets an attacker bind a key of their own; it does not let them make a signature with a card's key.
- **A lapse is not a revocation.** A leaver's keys are accepted by any verifier that holds an old copy of the keyring until the expiry, and by a web-of-trust verifier until the certification ends; a verifier that fetches the new keyring stops at once. A leaver who is a risk is a compromise, and is revoked.

### Customers

BD2 B: a customer may bind a key inside the company's tenant, for that company only, to sign or authorise data for the company's service. At design level that means:

- **A customer's key is a binding like any other, in the customer's tenant.** It has a key identity, a class, an expiry and a state, and a signature by it is accepted only for that tenant ([REQ-KEYS-180](/requirements/keys/#REQ-KEYS-180)). A signature "authorises data" when the company's service defines a document, a customer signs it with the bound key, and sluis verifies the signature against the customer's active binding and records the verification as evidence in the audit log. sluis does not decide what the data means.
- **A customer's key never certifies anything and never signs for the company.** It is never certified by the company's key, never placed in the staff keyring and never synced to GitHub ([REQ-KEYS-181](/requirements/keys/#REQ-KEYS-181)). A customer has no primary in sluis.
- **It is optional.** A customer is never required to hold a key unless the policy of the tenant demands one for an action ([REQ-KEYS-183](/requirements/keys/#REQ-KEYS-183)). This agrees with [REQ-SESS-037](/requirements/sess/#REQ-SESS-037), which forbids enrolling a factor for, or asking for a passkey of, a person who signs in through a customer upstream: a bound key is a signing key and never a sign-in factor ([REQ-KEYS-184](/requirements/keys/#REQ-KEYS-184)). If the owner wants a bound key to serve as a step-up for customers, REQ-SESS-037 has to be amended first.
- **Binding needs a fresh sign-in at the customer's upstream,** with the `acr` and `max_age` that policy asks for ([REQ-SESS-036](/requirements/sess/#REQ-SESS-036), [REQ-KEYS-185](/requirements/keys/#REQ-KEYS-185)). A customer has no hardware step-up to give, so PK1 A does not apply to them.
- **The tenant's admin approves a customer's first binding.** The approver is a person of that tenant who holds its key-administration grant, is never the customer, and approves with a fresh `hardware-attested` assertion of their own ([REQ-KEYS-182](/requirements/keys/#REQ-KEYS-182)). A tenant admin sees only their own customers.
- **The class rules are the same.** Policy decides what `hardware-attested`, `hardware-unlisted` and `unattested` customer keys may do; most customer keys will be `unattested`.

What is left open about customers is in the follow-ups, with a recommendation each: the format of what a customer signs, who verifies and where the evidence goes, and whether a tenant may waive approval.

### What ritueel owns

- **The roots,** the ceremony that delegates the trust signature to each company's certification key, the certification of each company's keyring-signing key, and the ceremonies that renew or replace them.
- **The card-readiness helper and the bundle format.** The helper makes the subkeys on the card, sets the PINs, makes the back-signature, builds and shows the challenge signature, and writes bundle v1 as standard files. sluis and ritueel share formats and test vectors and no code ([0024](/decisions/0024-root-custody-and-the-signing-api/)). ritueel's ADR 0014 is being rewritten to match this record.
- **Personal keys** that a person keeps outside the company.

### The attestation question

The first question was whether the OpenPGP applet's attestation covers a card-born primary that certifies and signs. Under BD1 B the card holds no primary, so the question becomes narrower: does it cover the card's signing subkey, and can the card make the back-signature a signing subkey needs? Read on 2026-11-06 from [Yubico's OpenPGP attestation page](https://developers.yubico.com/PGP/Attestation.html) and [the `ykman openpgp keys attest` reference](https://docs.yubico.com/software/yubikey/tools/ykman/OpenPGP_Commands.html):

- READ: the signature, decryption and authentication keys can be attested, on firmware 5.2 and later, and only a key generated on the device can be ("imported" is not permitted). Firmware 5.7.4 and later is signed under Yubico's new root. So the three card slots, which are now the signing, encryption and authentication subkeys, are covered.
- READ: the statement carries the key's fingerprint and generation date, and Yubico says not to trust them, because the Admin PIN can overwrite them. The page says to always verify the public key.
- **UNVERIFIED:** that a card can make the type 0x19 back-signature and the type 0x02 challenge signature with the signature-slot key through the helper's library and through `gpg`; that `gpg`, `sqv` and GitHub accept a certificate whose signing subkey was bound this way; and that GitHub accepts a P-384 certificate with third-party certifications.

So the design checks the public key of each statement against the public key of the subkey it attests, and ignores the fingerprint and date in the statement. The build is gated on the conformance test below. A result that contradicts the design changes this record before anything is built.

**Conformance test, run on a YubiKey 5 with firmware 5.7.4 or later, and on one older to see it refused:**

1. Generate the signature, decryption and authentication keys on the card with `gpg` and with the ritueel helper; export the attestation of each slot; verify each chain to Yubico Attestation Root 1; compare each public key with the subkey presented.
2. A key imported into a slot has no attestation, and a statement whose public key differs from the subkey presented is refused. A card with firmware below 5.7.4 is refused.
3. The fingerprint and date in the statement are overwritten with the Admin PIN: sluis's result does not change.
4. Read a real statement and list its fields. Confirm that it has no model name, that the firmware, the form factor and the FIPS flag are the fields the allowlist can use, and that the root's name is the one sluis pins.
5. The card makes the back-signature (type 0x19) over a test primary and the signing subkey; a primary binds the subkey with it embedded; `gpg --list-packets`, `sq packet dump`, `gpg --check-sigs` and `sq inspect` accept the result.
6. The challenge signature (type 0x02, critical notation): parse it with `gpg --list-packets` and `sq packet dump`; check that `gpg --verify` and `sqv` reject it as a signature over any file (the expectation, UNVERIFIED, is that both refuse it); check that the helper refuses a challenge with a missing label or an extra line.
7. The card signs a commit and a checksum file as the signing subkey; `gpgv`, `sqv` and `git verify-commit` accept them, using a certificate whose subkey the test primary bound.
8. Certify the test primary with the company key under the root's trust signature with the anchored expression: `gpg` with the root trusted and `sq-wot` accept an address in the domain and reject one outside it and one at a subdomain.
9. The certificate, with the certification, the root's trust signature and the bound subkey, is uploaded to a GitHub account (`POST /user/gpg_keys`) and a commit signed on the card shows Verified. This also tests whether GitHub accepts a P-384 certificate with third-party certifications and a subkey that carries an embedded back-signature.

## Consequences

- A joiner binds a card in minutes and a lost card is replaced the same way, with no ceremony and no person at ritueel. A person keeps one fingerprint for as long as they work for the company. The yearly renewal of the certification stops being work, and the card's keys are extended by the person once in three years.
- sluis holds a sealed private key per employee, and key@ can act as that employee's primary. That is the price of one stable key, and [The security of the design](/decisions/0043-a-person-binds-their-own-keys-to-their-identity-in-sluis/#the-security-of-the-design) states what it exposes and what stands against it. Every key that signs data stays on a card.
- sluis certifies on its own authority, under a trust signature from the root that is limited to one company's domain. The root stays offline, and the weight moves to policy, the hardware sign-in and detection.
- A card that sluis cannot attest, or that is not on the allowlist, cannot sign for the company. An installation that wants to accept another form factor extends the allowlist; cards older than firmware 5.7.4 are not accepted.
- The staff keyring is a file that sluis produces, signs with a key of its own and publishes. The sync of [pull request #1485](https://github.com/truvity/sluis/pull/1485) reads the bindings, not the file, and the CI check of G3 C and the `gpgv` check of G6 read the file.
- The tenant gains a sixth data key purpose, `person-key`, and a company that issues staff keys gains a certification key and a keyring-signing key. Both are added to the tables of 0006 when they are built.
- New obligations are [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143), [REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146) to [REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168) and [REQ-KEYS-171](/requirements/keys/#REQ-KEYS-171) to [REQ-KEYS-185](/requirements/keys/#REQ-KEYS-185).

## Roads not taken

- **Card-born primaries (the earlier SK1 E shape).** Each card would have its own primary and so its own fingerprint: a lost card is a new identity, every upload and every trust decision is redone, and the company has no one stable key per person.
- **One KMS key per person.** It works on AWS only, the company would hold a signing key of everyone in a service that signs on request, and each key needs a yearly ceremony to certify; a sealed primary in key@ is cheaper and the same on a board.
- **One company-wide online key that certifies or binds for everyone.** Its compromise is every employee at once, which is the loss BD1 B exists to avoid; the keys are per person and per company.
- **One company primary with everyone's subkeys.** GitHub attribution, user ID churn and revocation churn: one revocation touches every person.
- **ritueel binds each person's subkey in a ceremony (G2a).** The card and the "person present" check run on the client, so a ceremony role can bind a software subkey, and it needs a person at ritueel for every joiner and lost card.
- **Trust an attestation alone.** Anyone can attest a key on a card they bought, so the attestation says what a key is and not whose it is.
- **Directory approval of the first binding, or of any further one.** The directory cannot say whose device a key is, and a directory change needs no hardware proof, so a changed entry would add a key to a person; FB1 A chose operator approval only, the rule of #1484.
- **An SSH-signing fallback for staff (G1 A).** It cannot be tied to a card the same way, and GitHub treats it as a different key.
- **A new attestation at every renewal.** It brings a person back to the card once a year for a check that the lost-card rule already covers.
- **A subkey binding that never expires.** A lost card would leave a key valid for ever; an expiry that the card's proof extends keeps the binding in step with the card.
- **A label inside a type 0x00 signature over text.** The text is hashed with its data and lenient formats tolerate extra lines, so a label separates nothing; a type 0x02 signature with a critical notation does.
- **The version 4 fingerprint as the key identity.** It covers a creation time the holder chooses, so one card key could be bound twice.
- **The certification key also signs the keyring.** One compromise would give an attacker both the power to certify and the power to publish.
- **Keep a model-name allowlist.** The Yubico statement has no model name, so a list of models would name nothing that sluis can check.
- **Software subkeys bound under the primary.** The point of the card is that the private part never reaches a host; a bound software subkey would put a copy of the person's signing power in the company's keyring.

## Follow-ups

- Build `sluis key bind`, the kinds `PersonPrimary` and `KeyBinding`, the `person-key` data key, the certification and keyring-signing purposes, and the keyring producer: [REQ-KEYS-122](/requirements/keys/#REQ-KEYS-122) to [REQ-KEYS-143](/requirements/keys/#REQ-KEYS-143), [REQ-KEYS-146](/requirements/keys/#REQ-KEYS-146) to [REQ-KEYS-168](/requirements/keys/#REQ-KEYS-168) and [REQ-KEYS-171](/requirements/keys/#REQ-KEYS-171) to [REQ-KEYS-185](/requirements/keys/#REQ-KEYS-185) ([#1496](https://github.com/truvity/sluis/issues/1496)), gated on the conformance test above.
- Run the conformance test and date the result ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Add the sixth tenant data key and the named exception for the sealed primary to [0006](/decisions/0006-keys-and-sealing/), and the purposes to its key plan, when they are built ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Write bundle v1 (`.subkey.pgp`, `.proof.json`, `.possession.sig`) and the challenge as test vectors shared with ritueel ([#1496](https://github.com/truvity/sluis/issues/1496)).
- **Open, customers: the format of what a customer signs.** Options: a JWS (RFC 7515) over the JSON document the service defines, with the bound key as a JWK; HTTP Message Signatures (RFC 9421) over the request; an OpenPGP signature; a W3C data-integrity proof. The owner has not specified one. Recommendation: JWS, because tokens in sluis are already JOSE, the customer's key is then a JWK, and verification needs no new library ([#1496](https://github.com/truvity/sluis/issues/1496)).
- **Open, customers: who verifies and where the evidence goes.** Options: sluis verifies on the service's request and returns a result; the service verifies with the key set sluis publishes; both. Recommendation: sluis verifies and writes the audit evidence, because the binding state (active, ended, revoked) lives in sluis ([#1496](https://github.com/truvity/sluis/issues/1496)).
- **Open, customers: may a tenant waive the admin's approval?** Options: never; for the class `unattested` only; per policy. Recommendation: never in the first version, because the approval is what ties a key to the customer ([#1496](https://github.com/truvity/sluis/issues/1496)).
- **Open, customers: which kinds a customer may bind.** Options: OpenPGP only; JWK keys only; both. Recommendation: JWK keys first, to match the recommended format, with OpenPGP later ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Bring the wording of the GitHub key sync into line with this record when both merge: one certificate per person, replaced when a subkey, the user ID or an expiry changes ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Sealed software keys for non-human identities such as bots and agents (BK3 A): a later feature with its own record when it is designed ([#1496](https://github.com/truvity/sluis/issues/1496)).
- Enforcement of commit signing on GitHub (G3 C) stays a later CI check against the staff keyring ([#1496](https://github.com/truvity/sluis/issues/1496)).
