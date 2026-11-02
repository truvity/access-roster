# 0012 — Cryptography uses P-384 by default, and authority keys are born in their store, sign in place and rotate by rule

**Status:** Accepted
**Date:** 2026-11-01

Proposal: [issue #909](https://github.com/truvity/sluis/issues/909).

## Context

Every token, certificate and signed log head that sluis makes is signed, and every secret it keeps is sealed. Three groups of readers constrain the algorithms: verifiers that do not belong to sluis (many OIDC libraries were written for RS256), standards that fix a set (the FAPI 2.0 Security Profile, section 5.4.1, names PS256, ES256 and EdDSA; checked 2026-10-29), and drivers (a cloud key service, a hardware key and a software key support different algorithms at very different speeds).

The keys themselves are worth more than anything they sign. sluis holds the token-signing keys, the keys of its certificate authorities, the log key and the sealing key, and it publishes a key for each workload identity it issues. The volume is low: a production installation of v1 saw about 25,000 tokens in 7 days, a peak of 0.8 a second, 95 % of them token exchange. Hardware fails, is lost and is stolen, and installations differ: AWS with a key service, small boards with a YubiKey in each node, a workstation with software keys for development.

v1 ADR 0005 made ES384 the default, and v1 ADR 0009 added a per-audience RS256 exception with a separate key; this record keeps both. sluis holds no root: roots are [ritueel](https://ritueel.id)'s, and the hand-off is [0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/). The `keys` port is in [0002](/decisions/0002-the-design-model-actors-ports-drivers-and-contracts/#ports-and-drivers).

## Decision

### Algorithms

- **EC P-384 with ES384 is the default** and what sluis chooses for itself, including the checkpoints of the audit log and of the issuance log (C2SP signed notes with P-384 keys). One curve means one key type in the key set, one verifier path and one sealing scheme.
- **sluis supports the FAPI 2.0 set: PS256, ES256 and EdDSA (Ed25519).** ES384 stays the default.
- **Everything sluis signs, seals, hashes, derives or encrypts stays within the FIPS-approved set:** P-384 ECDSA, AES-256-GCM, HKDF-SHA384, HMAC-SHA384 (for audit pseudonyms, [0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/)) and SHA-384, plus the named exceptions below. There is no FIPS mode and no certified build in 2.0: Go keeps the standard library's defaults (`GOFIPS140` and `fips140` unset), and Rust uses current crates and rustls with no FIPS pin. Keeping to the approved set means a FIPS build can be added later as a build option without changing a format or a stored value. The Rust build facts are in [0014](/decisions/0014-the-language-follows-the-executable/).
- **AES-256-GCM takes its nonce from the cryptographic library**, never from the caller (in Rust, `RandomizedNonceKey` of `aws-lc-rs`).
- **TLS follows the libraries' defaults**, which may negotiate X25519 or ChaCha20-Poly1305. Nothing sluis stores or publishes depends on them.
- **The only source of randomness is the operating system's CSPRNG**, through Go's `crypto/rand` (tests use `testing/cryptotest.SetGlobalRandom`) or, in Rust, the generator of the cryptographic library. Nothing is mixed in from a key service or a card. `sluis doctor` checks the platform: kernel 5.18 or newer (a cloned virtual machine reseeds), a hardware generator present or deliberately absent, and the entropy pool initialised before the first key.
- **Driver support is checked per algorithm** when the installation is checked, not at the first token. PS256 on a YubiKey takes about 2.3 seconds per signature, so it suits a low-volume audience only; Ed25519 in PIV needs firmware 5.7 or newer.
- **Tokens are standard JWS and JWT**, verified with any language's standard libraries against the published key set. The algorithms sluis accepts from others, such as passkey assertions, are set with those features ([0006](/decisions/0006-identity-issuers-audiences-and-sign-in/#passkeys)). How a client or audience selects a non-default algorithm is client-profile configuration.

### Named exceptions

"No RSA" and "P-384 only" have exactly these exceptions. Each has its own key, which serves no other purpose.

1. **FAPI 2.0:** PS256, ES256 and EdDSA, as above.
2. **Cloud federation:** a key that signs a workload token for a cloud uses the algorithm that cloud requires: ES384 for AWS, ES256 for GCP, RS256 (RSA-2048) for Azure Entra.
3. **Per-audience RS256:** for an audience configured to need RS256, sluis signs that audience's tokens with a separate RSA key, published beside the EC keys. The audience, not the caller, decides.
4. **NATS decentralized authentication.** NATS fixes Ed25519 for its operator, account and user keys (nkeys), and its JWTs are signed with them. sluis follows that:
   - **one Ed25519 key per purpose:** the operator identity, an operator signing key per environment, a scoped signing key per role and account, and the callout account's key. None of them serves another purpose;
   - **the keys live in the cloud key service, or behind `key-holder`** with an access list that names only the NATS credential minter. A user's own nkey is generated by the workload and never leaves it;
   - **no xkey.** The X25519 key that NATS can use to seal callout requests is not used, because X25519 alone is not an approved algorithm under FIPS 140-3. TLS on the client port protects the request instead;
   - Ed25519 is approved (FIPS 186-5) and is in Go's FIPS 140-3 module, so this exception stays within the approved set.
5. **Formats that fix their own algorithm are followed:** the C2SP tlog-cosignature witness keys use Ed25519 or ML-DSA-44 as that specification requires ([0016](/decisions/0016-the-audit-log/#witnesses)); a witness key authorises nothing and serves no other purpose.
6. **age** for backup archives and export drops, because the recipients' tools read it. Its X25519 and ChaCha20-Poly1305 are outside the approved set; age is kept in 2.0 as a named exception and is revisited, with OpenPGP or CMS, if a FIPS build is added.

### Keys sign in place

- **An authority key is born in its store, signs in place and cannot be exported.** The store signs each digest itself. There are no derived signing keys, no burst key and no short-lived online key certified by an intermediate.
- **One key for each signing purpose.** X.509 intermediates are separate per trust domain; the SSH user CA and SSH host CA are separate; the token-signing key and the log key are separate, and a key that issues certificates never signs tokens.
- **Every key whose public half is trusted through the PKI chain is a hardware-held child key**, attested where the hardware can attest and certified through a root that ritueel holds: the CA intermediates and the OpenPGP signing subkeys. Hardware-held means a key service such as AWS KMS or a card such as a YubiKey. KMS cannot attest where a key was born, so for it the checks are the key's description, its policy, the record of its creation and a match between the public key and the request.
- **SSH CA keys are anchors, not a chain.** The `ssh-user` and `ssh-host` keys are held in `key-holder`; hosts trust a list of SSH CA keys that ritueel publishes, signed by a root ([0008](/decisions/0008-certificate-authorities-for-x509-ssh-and-databases/#ssh)).
- **Ephemeral keys are outside the rule:** session keys, ECDH keys, wrapped data keys and derived keys are neither hardware-held nor certified.
- **The `keys` port has `wrap` and `unwrap` beside `sign` and `public-key`.** On AWS a wrap is an encrypt call with a context that names the purpose; on a YubiKey it is ECDH and HKDF in the style of HPKE with the P-384 sealing key, which needs no hardware to seal and the card to open.
- **CA serial numbers are random and 128 bits long.** No serial ledger is kept.
- **The first version supports three key stores:** YubiKey PIV through `key-holder`, AWS KMS, and software keys for development and CI. PKCS#11 drivers for devices such as YubiHSM 2 and Nitrokey HSM 2, more drivers and post-quantum keys come later ([#1029](https://github.com/truvity/sluis/issues/1029)).
- **Two main topologies:** a KMS intermediate per environment on AWS, and a YubiKey intermediate on each node of the boards, born on its card, attested, certified for about 13 months and re-signed every year over the same key. In both the root is ritueel's.
- **A lost or stolen board is replaced, not restored:** a new key on a new card, a new certificate, and ritueel revokes the old one. The card's PIN policy limits the exposure until then.
- **On AWS, KMS protects a signing key by its key policy:** one P-384 key per enabled authority purpose, whose key policy names exactly one actor. `kms:Sign` takes no encryption context, so the condition on an encryption context protects symmetric keys only. The key that wraps a backup archive is not the sealing key; it may live in another account, and only the restore role may decrypt with it.

### When keys are shared and when separate

A key is shared between two uses only when all of these are equal: **the audience** (who verifies or decrypts), **the required lifetime**, **revocation coupling** (one use would never be disabled without the other), **the callers** (the blast radius of a misuse), and **the store itself separates the uses** (an encryption context with key-policy conditions). If any one differs, the uses get separate keys.

- **Symmetric KMS keys are shared** per account or environment, with one alias per use and its own encryption context, enforced by `kms:EncryptionContext:` conditions in the key policy.
- **Asymmetric signing keys are never shared** across purposes, environments or installations.
- **Tenants get no keys of their own.** A tenant's data key is wrapped under the sealing key with the tenant in the encryption context, and shredding a tenant deletes its data key. An audit tenant is the same: its data key is wrapped under the sealing key. A per-tenant signing key is a possible later bring-your-own-key feature.
- **Environments never share keys.**
- **Sealing in other actors uses the sealing key with its own purpose:** the session cookie-sealing key of `session` is a data key wrapped under the sealing key with `purpose=cookie`. The HPKE enrolment key of `exchange` is an ECDH key that hosts encrypt to, so its audience differs and it is a key of its own.

### Rotation

- **The yearly cycle re-signs.** An X.509 intermediate gets a new certificate over the same key at the yearly ceremony; an OpenPGP subkey gets a new binding that extends its expiry. A renewal makes no new key.
- **Key material rotates by the rule of [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule).** A software key is replaced every three years, within the one to three years that NIST SP 800-57 gives for a signing key, which also keeps the rotation path exercised. A key on a card or in a cloud KMS is replaced on events, with a review of advisories at the yearly ceremony: an advisory affecting the device or firmware, deprecation of its algorithm, loss or end of life, and also a suspected compromise, a change of store and a change of custody. The rule for roots is ritueel's, and the principle links it.
- **Log keys are the one exception to the rule above: they rotate only on compromise.** This covers the log key of the audit writer and the issuance-log key of `ca`. A log is one continuous history, and its signatures must verify for the life of the log.
- **Symmetric KMS keys use KMS automatic rotation.**
- **A rotation makes the new key first and retires the old one after.** On a card the new key goes into a free spare slot while the old one finishes; in KMS it is a new key under the same alias. A new intermediate is requested like the first one ([0013](/decisions/0013-the-hand-off-to-root-custody-and-the-signing-api/#the-hand-off)).

### Grants are sealed, not signed

A mint grant is read only by sluis itself, so no outside verifier needs a signature. `policy` seals the grant with authenticated encryption under the sealing key, with `purpose=grant` in the encryption context, and the actor that carries it out opens it under the same context. On AWS the key policy lets `policy` encrypt and the minters and `signer` decrypt under that context only; on a YubiKey the sealing slot serves grants too. A grant to `signer` authorises one artifact signature ([0029](/decisions/0029-the-signing-api-signs-sent-content-for-an-authorised-proof-and-returns-an-armoured-detached-signature/)). `policy` holds no signing key, and there is no grant-signing key. A grant sealed in one environment cannot be opened in another.

### The token-signing key

- **Token-signing and workload-issuer keys are hardware-held, separate from the CA key and from each other, one of each per node.** `signer` uses the token-signing key and `sluis-node` the workload-issuer key, each in a slot of its own; the two are never shared, because their callers and their blast radius differ. The node's own intermediate certifies each with a **non-CA certificate that allows digital signatures only**, issued on the node without a ceremony under the profile of [0021](/decisions/0021-leaf-certificate-profiles-lifetimes-and-revocation/#leaf-profiles), so a key that signs tokens cannot issue a certificate.
- **Each key-set entry carries an `x5c` chain:** the token certificate, the node intermediate, then up to the root. A standard client ignores it and fetches the key over TLS; a verifier that wants to can check custody down to a root it trusts. The chain is in the key set, not in each token.
- **The key set carries every active token key, and a next key only while an event rotation is in progress.**

### The card slot map

A documented, versioned map says which card slot serves which purpose: one slot per purpose and a shared spare range. This is the default map, version 1 (2026-11-01). It covers PIV slots `9a`, `9c`, `9d`, `9e` and the retired slots `82` to `95`.

| Slot | Purpose |
|---|---|
| `9c` | X.509 intermediate |
| `9a` | Token signing |
| `9d` | Sealing (ECDH and wrap), also for grants |
| `82` | `ssh-user` CA |
| `83` | `ssh-host` CA |
| `84` | Log key (audit and usage) |
| `85` | OpenPGP release-signing subkey |
| `86` | Workload issuer, for `sluis-node` |
| `87` to `95` | Spare (fifteen slots, hex), shared by every purpose |
| `9e` | Not used: the card-authentication slot signs without a PIN by default |

- **The spare range holds the new key of an event rotation** while the old one finishes, and older sealing keys until their data keys are re-wrapped.
- **Purposes outside the default map take a spare slot when enabled.** The issuance-log key of `ca`, the keys of the named exceptions (PS256, RS256, cloud federation, NATS) and the HPKE enrolment key ([0007](/decisions/0007-workload-identity-and-host-enrolment/#host-enrolment)) are each a key of their own. The trust bundle has no signing key: its certificates verify themselves ([0007](/decisions/0007-workload-identity-and-host-enrolment/#the-trust-bundle)). On KMS each is a separate key; on a card an installation that enables one names its slot from the spare range in its declared map.
- **A purpose an installation does not enable gets no slot and no key.** `sluis config check`, `sluis key request` and node initialisation refuse a collision, and an enabled purpose with no slot.
- **Keys are per environment boundary, not per tenant.** A card belongs to one boundary.
- **The map ships as a default in code; an installation may override it in declared configuration.** The map records each slot's attestation in the registry. The slot map of root cards is ritueel's. The keys page shows the map.
- **The release subkey lives in a PIV slot reached through `key-holder`,** which also makes the subkey's back-signature on the card. The OpenPGP applet is not used on a node.

### Touch and PIN

- **Node cards are touch never and PIN once.** A node signs unattended, including the back-signature of its subkey. The policies are fixed at key generation and visible in the attestation.
- **A node starts locked.** `key-holder` does not have the PIN when it starts:
  - `sluis node unlock <node>` delivers the PIN over an authenticated channel: an SSH certificate from sluis's own CA, or the admin API;
  - a peer that is already unlocked releases the node's encrypted PIN automatically, which covers a reboot of one node and a rolling update;
  - after a full power loss one manual unlock is needed, and the first node then unlocks the others;
  - the PIN is never stored in plaintext on disk, and `key-holder` never retries a wrong PIN, because the card blocks after three attempts and then needs the PUK.

### Exclusive card access

`key-holder` has exclusive access to its card. It runs as a dedicated user, the card service accepts only that user, and no other software that talks to cards runs on the node. Measured 2026-10-31 on a YubiKey 5 Nano: the PIN state belongs to the powered card and not to the connection, so while it is unlocked any local process can sign, any client's default disconnect resets the card, and wrong PINs from any local user block it. Exclusive access is a requirement of the node. How `key-holder` mediates its callers is in [0004](/decisions/0004-drivers-listeners-and-boundary-enforcement/#key-holder-is-the-one-mediator).

### Floors in code

- **The software `keys` driver refuses to start when the environment is `production`.** It is allowed in development and staging, with a warning in staging. Configuration chooses only among the modes the floor allows, so a development configuration loaded on the wrong node cannot make a software key a production authority key.

## Consequences

- **Signing speed is set by the store.** A YubiKey 5 Nano signs P-384 in about 147 ms, about 7 signatures a second per card, and three boards give about 21 a second (measured 2026-10-31, firmware 5.8.0), against a measured peak of 0.8 tokens a second in v1. A key service is faster. A software key is for development and CI only.
- A client that needs RS256 or PS256 is served without moving the installation off ES384, at the cost of an RSA key to hold, rotate and publish for each exception and a larger token for that audience. PS256 on a card costs seconds per signature.
- No FIPS mode means no FIPS claim: v2.0 does not say it uses a validated module, and the standards register says so. The approved-set rule is kept by review: a new algorithm, a crate that brings its own primitive or a caller-supplied GCM nonce is a regression even when every test passes.
- NATS keys add Ed25519 to the key types that the cloud key service and `key-holder` must offer. Each connection costs a few signatures, far below the key service's quotas at the volumes measured. Without the xkey, a callout request is protected by TLS only, so TLS on every client connection is a requirement, not an option.
- No key can be exported, so a backup never holds one. A restore on new hardware means new keys and new certificates; secrets that are not keys are archived sealed ([0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#backup-and-restore-by-origin)).
- Every enabled signing purpose adds a key and a policy; in return a key policy names one actor and one use. Sharing symmetric keys per environment and sealing grants, cookies and tenant data keys under the sealing key keep the number of keys small.
- A node card uses eight slots in the default map and keeps fifteen spare slots (`87` to `95` in hex), shared by event rotations, older sealing keys and purposes outside the default map; `9e` stays empty.
- The token-signing key adds a certificate under each new intermediate and one more certificate to the key set's chain, refreshed at each yearly re-signing.
- A full power loss needs a person for one unlock. A wrong PIN is never retried, so a bad unlock cannot lock the card.
- `sluis config check` has to know the key modes, the floor and the slot map. Tests need a virtual card or a software stand-in, and rehearsals on a real card.
- Platforms with a weak generator are caught by `sluis doctor`, not compensated for.

## Roads not taken

- **RSA as the default.** It taxes every relying party for the least capable one; the per-audience exception serves that verifier and costs the others nothing.
- **P-256 (ES256) as the default.** A 128-bit security level for a speed that low volume does not need; ES256 stays supported where required.
- **Ed25519 as the default.** Not every key mode offers it (PIV needs firmware 5.7 or newer) and fewer verifiers accept it than ES384.
- **FIPS mode and a certified build now, in Go or in both languages.** The cost lands on every build before any installation needs it, and a Go-only mode would be a half claim; the approved set keeps a later variant possible.
- **NATS keys under the format rule, without a named exception.** That rule is written for witness keys, which authorise nothing; NATS keys authorise access to accounts and subjects, so they get the scrutiny of a named exception with one key per purpose.
- **Keep the NATS xkey.** X25519 alone is not approved under FIPS 140-3, and NATS creates no xkey in its own FIPS mode; TLS on the client port carries the request.
- **Mix randomness from a key service or a card into the system's.** More code in the path that makes every key, for a failure that a startup check catches.
- **Derived signing keys, a burst key, or a short-lived online key certified by the intermediate.** Three boards sign about 21 signatures a second and a key service more, far above the load; a key in memory can be copied.
- **The intermediate signs the tokens itself.** One key would both issue certificates and sign every token, so a flaw in token handling would reach the CA.
- **A pair of slots per signing purpose, used in turn.** The yearly cycle re-signs the same key, so most pairs would stay empty for years; one shared spare range serves the rare event rotation.
- **Yearly rotation of key material.** A new key and a ceremony per node every year adds exposure and work and exercises the path no better than the rotation rule of principle 3.
- **A separate usage-log key, a grant-signing key, or a key per tenant.** Each adds keys, policies and slots for uses that share an audience and writer (usage), have no outside verifier (grants), or are covered by a wrapped data key (tenants).
- **A key set with no `x5c`.** Custody could then be checked only in the audit log; standard clients ignore the member anyway.
- **The PIN on disk, automatic PIN retries, or touch always on node cards.** A PIN on disk is open to anyone who reads the disk, three wrong attempts block the card, and touch would stop a node from signing unattended.

## Follow-ups

- More `keys` drivers (PKCS#11 for YubiHSM 2 and Nitrokey HSM 2) and post-quantum tokens and certificates: Later, [#1029](https://github.com/truvity/sluis/issues/1029).
