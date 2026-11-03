---
title: Keys
description: "Which store backs each sluis key: key modes, the AWS KMS and card layouts, the card slot map, key-holder, the token-signing key and the hand-off."
status: target
sidebar:
  order: 4
---

sluis signs tokens, X.509 and SSH certificates, the checkpoints of its logs and, when it is enabled, release artifacts, and it seals data at rest. Each of these purposes has a key of its own, and each [environment boundary](/concepts/boundaries/) has its own set: no key is shared between development, staging and production. This page says which store backs each key in each installation and how a caller reaches it. The rules behind it, the algorithms, when keys are shared, rotation and why keys sign in place, are [ADR 0006](/decisions/0006-keys-and-sealing/). The threats to the keys are on the [threat model](/security/threat-model/).

## Key modes

The key mode is the choice of the `keys` driver. There are three:

| Mode | Driver | Where it is used |
|---|---|---|
| **AWS KMS** | `aws-kms` | [lambda](/runtimes/installations/#lambda), [kubernetes](/runtimes/installations/#kubernetes) and other AWS installations |
| **YubiKey PIV, through `key-holder`** | `yubikey-piv` | [boards](/runtimes/installations/#boards) and other installations on single-board computers: one card per node |
| **Software** | `software` | [local](/runtimes/installations/#local), CI, and the `kubernetes-dev` preset of the chart |

The local installation uses software keys and needs no hardware. A dedicated development card is opt-in: only the `key-holder` container reaches it, through the host's smart-card service, and `key-holder` has the card to itself ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). A card shared with gpg, or a person's daily card, is not a mode the installation sets up.

The floor is in code: the `software` driver refuses to start when the environment is `production` and warns in staging, and configuration chooses only among the modes the floor allows, so a development configuration loaded on the wrong node cannot make a software key a production authority key ([ADR 0006](/decisions/0006-keys-and-sealing/#floors-in-code)). On Kubernetes the keys are AWS KMS keys only ([ADR 0011](/decisions/0011-runtimes-and-installations/#kubernetes)); a production cluster outside AWS has no key mode in 2.0. The workload tokens a pod presents there are the cluster's projected ServiceAccount tokens, signed by the cluster: sluis neither holds nor signs them.

PKCS#11 drivers (YubiHSM 2, Nitrokey HSM 2), more drivers and post-quantum keys come later ([#1029](https://github.com/truvity/sluis/issues/1029)). TPM 2.0 is a backlog feature, and an addition to the card, not a replacement.

## Topologies

| Topology | Intermediates | Where it applies |
|---|---|---|
| **A KMS intermediate per environment** | One KMS intermediate for each environment, certified through a KMS root that [ritueel](https://ritueel.id) holds | AWS installations |
| **A card intermediate on each node** | One intermediate on each node's own YubiKey, born on it, attested, certified by a ritueel root for about 13 months and re-signed every year over the same key | The boards and other single-board installations |

In both, the root is ritueel's and sluis holds intermediates only ([Roots and certification](#roots-and-certification)).

## Algorithms

ES384 (ECDSA on P-384) is the default for everything sluis signs, including the checkpoints of the audit log and of the issuance log. sluis adds ES256 first, as the signing algorithm of the FAPI 2.0 profile; PS256 and EdDSA follow when a client needs them and the key store offers them ([ADR 0038](/decisions/0038-fapi-2-profile/)). It has a short list of named exceptions, each with a key of its own that serves nothing else: cloud federation (ES256 for GCP, RS256 for Azure Entra), a per-audience RS256 key, NATS Ed25519 keys, the C2SP witness keys, and age for backups and export drops ([ADR 0006](/decisions/0006-keys-and-sealing/#named-exceptions)). Everything else stays within the FIPS-approved set, with no FIPS mode or certified build in 2.0 ([ADR 0006](/decisions/0006-keys-and-sealing/#algorithms)). Support depends on the driver: PS256 on a YubiKey takes about 2.3 seconds a signature, and Ed25519 in PIV needs firmware 5.7 or newer.

In Go, JOSE is `go-jose/v4` behind sluis's own `jose` package, so the library can be replaced without touching the actors; Rust and TypeScript only verify, with `jsonwebtoken` and `jose` ([Approved libraries](/reference/approved-libraries/#jose)). There is no Rust JOSE driver. Tokens are standard JWS and JWT that any language verifies against the published key set; small verification demos in a few languages come with the package ([#869](https://github.com/truvity/sluis/issues/869)).

## The token-signing key

Tokens are signed directly by the store: a KMS key or the card signs each token itself, and there is no derived, burst or short-lived online key ([ADR 0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)). The volume allows it. A YubiKey 5 Nano signs P-384 in about 147 ms, about 7 signatures a second per card and about 21 a second for three boards (measured 2026-10-31, firmware 5.8.0), against a v1 peak of 0.8 tokens a second. A key service is faster.

The token-signing key is a key of its own, not the intermediate, so a key that signs tokens can never issue a certificate. The node's own intermediate certifies it with a **non-CA certificate that allows digital signatures only**, issued on the node without a ceremony, under the token-signing profile of [ADR 0042](/decisions/0042-leaf-certificate-profiles-lifetimes-and-revocation/#leaf-profiles). Each entry of the published key set carries an **`x5c`** chain: the token certificate, the node intermediate, then up to the root. A standard verifier ignores it and fetches the key over TLS; a verifier that wants to can check custody down to a root it trusts. The chain is in the key set, not in each token ([ADR 0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)). The workload-issuer key of `sluis-node` is made the same way, in its own slot, and is published in the key set beside the token keys; it is never the token-signing key, because its callers and its blast radius differ.

Grants are sealed, not signed: `policy` seals a mint grant under the sealing key with `purpose=grant`, and there is no grant-signing key ([ADR 0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).

## Wrap and unwrap

The `keys` port has `wrap` and `unwrap` beside `sign` and `public-key`, so a data key is protected without the key that protects it leaving its store. On AWS a wrap is KMS `Encrypt` with an encryption context that names the purpose; on a card it is ECDH and HKDF against the public key in the sealing slot ([Sealing on a card](#sealing-on-a-card)). The state values and the sealed secrets of [Data and secrets](/concepts/data/#every-value-is-encrypted) are protected this way. The key that wraps a backup archive is not the sealing key ([Backup](/concepts/backup/#encryption)).

## AWS KMS layout

On the AWS installations each installation and environment has these keys. Aliases follow the actor that uses the key, `alias/sluis/<boundary>/<actor>/<purpose>` ([Actors](/concepts/actors/)):

| Key | Spec | Purpose |
|---|---|---|
| Sealing and wrapping | One symmetric key, `ENCRYPT_DECRYPT` | Every sealing and wrapping need: the data keys of the state, the cookie key of `session`, sealed secrets and mint grants, each with its own encryption context |
| Token signing | `ECC_NIST_P384`, `SIGN_VERIFY` | Tokens and the key set, used by `signer` |
| X.509 intermediate | `ECC_NIST_P384`, `SIGN_VERIFY` | The CA key of each trust domain, used by `ca`. Only if the installation issues certificates |
| SSH CA | `ECC_NIST_P384`, `SIGN_VERIFY` | `ssh-user` and `ssh-host`, one key each, used by `ssh-ca`. Only if enabled |
| Log key | `ECC_NIST_P384`, `SIGN_VERIFY` | The checkpoints of the audit log and of the usage log, used only by the writer |
| OpenPGP release-signing subkey | Asymmetric, `ECC_NIST_P384`, `SIGN_VERIFY` | Release artifacts, through the signing API: a key of its own with its own key policy, bound as a subkey by a ritueel primary, and used by `signer` only ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/)). Only if release signing is enabled |
| Per tenant | None | A tenant's data keys are wrapped under the sealing key |

A purpose that an installation does not enable has no key. Each signing key's policy names exactly one actor, because `kms:Sign` takes no encryption context; the one symmetric key serves every sealing need, with `kms:EncryptionContext:` conditions that let each actor decrypt only under its own contexts ([ADR 0006](/decisions/0006-keys-and-sealing/#key-purposes)). A signing key that ritueel certifies has one more principal, which cannot sign: a read-only role in its account (`DescribeKey`, `GetPublicKey` and `GetKeyPolicy`) that ritueel's certifier assumes to read the key and its policy ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)).

The purposes outside this table are each a separate key when enabled: the issuance-log key of `ca`, the keys of the named exceptions (PS256, RS256, cloud federation, NATS) and the HPKE enrolment key that only `exchange` uses ([Identity](/concepts/identity/)).

**The sealing key.** In production it is a new multi-Region symmetric key plus a replica, because losing it loses every sealed value and a single-Region key cannot be made multi-Region later. Elsewhere, and in an audit or quota installation, which holds only its own log key, it may be the account's existing symmetric key under its own alias and context.

## YubiKey layout

A YubiKey in PIV mode has 24 slots (the four named slots `9a`, `9c`, `9d`, `9e` and the retired slots `82` to `95`) and no symmetric keys. There is one card per node, it belongs to one boundary, and keys are per boundary, not per tenant: the data keys of tenants and companies are wrapped by the sealing key and need no slots. EUCLEAK, a side-channel flaw of older firmware, is fixed from firmware 5.7. The root cards are ritueel's and never sit in a node.

### The card slot map

A node card uses a documented, versioned slot map: one slot per purpose and a shared spare range. This is the **default map, version 1**; the slot numbers are confirmed when `key-holder` is built ([#914](https://github.com/truvity/sluis/issues/914)). A purpose that an installation does not enable gets no slot and no key.

| Slot | Purpose |
|---|---|
| `9c` | X.509 intermediate |
| `9a` | Token signing |
| `9d` | Sealing (ECDH and wrap), also for grants |
| `82` | `ssh-user` CA, for `ssh-ca` |
| `83` | `ssh-host` CA, for `ssh-ca` |
| `84` | Log key (audit and usage) |
| `85` | OpenPGP release-signing subkey, through `key-holder` |
| `86` | Workload issuer, for `sluis-node`: its own key, never shared with `9a` |
| `87` to `95` | Spare, fifteen slots shared by every purpose: the new key of an event rotation while the old one finishes, older sealing keys until their data keys are re-wrapped, and purposes outside the default map |
| `9e` | Not used: the card-authentication slot signs without a PIN by default |

The map ships as a default in code, and an installation may override it in declared configuration. An installation that enables a purpose outside the default map, such as the issuance-log key or a named exception, names its slot from the spare range. `sluis config check`, `sluis key request` and node initialisation refuse a collision, and an enabled purpose with no slot. The yearly renewal needs no second slot, because it re-signs the same key ([ADR 0006](/decisions/0006-keys-and-sealing/#rotation)). The release subkey lives in a PIV slot like every other node key; the OpenPGP applet is not used on a node.

### Sealing on a card

The card has no symmetric key, so sealing uses ECDH and HKDF in the style of HPKE with the P-384 key in slot `9d`. The sealer makes an ephemeral P-384 key, performs ECDH against the slot's **public** key, derives an AEAD key and stores the ephemeral public key beside the ciphertext, so sealing needs no hardware. To open, the card performs ECDH with the private key in `9d` and the same HKDF yields the same key. Older sealing keys stay in spare slots, so what they sealed can still be opened.

## key-holder

Every actor reaches a node card only through **`key-holder`**, the one process that opens it. It is written in Go with `piv-go` ([ADR 0012](/decisions/0012-the-language-follows-the-executable/)) and serves one socket per caller, checks the peer uid on every call, and signs only content it understands for each purpose: the `ca` purpose only a certificate within its constraints, the `ssh-ca` purposes only an OpenSSH certificate body, a token purpose only a JWS signing input. How it mediates is on [Ports and drivers](/concepts/drivers/#the-mediating-driver).

**Exclusive card access.** `key-holder` runs as a dedicated user, the card service accepts only that user, and no other software that talks to cards runs on the node. The reason was measured on 2026-10-31 on a YubiKey 5 Nano (firmware 5.8.0): the PIN state belongs to the powered card, not to a connection, so while it is unlocked any local process can sign; any client's default disconnect resets the card; and wrong PINs from any local user block it ([ADR 0006](/decisions/0006-keys-and-sealing/#exclusive-card-access)).

**Touch and PIN.** Node cards are touch never and PIN once, so a node signs unattended. The policies are fixed at key generation and visible in the attestation, which chains to Yubico Attestation Root 1, the anchor sluis ships.

**Unlock.** `key-holder` starts locked and never stores the PIN in plaintext on disk:

- `sluis node unlock <node>` delivers the PIN over an authenticated channel, an SSH certificate from sluis's own CA or the admin API;
- an unlocked peer releases the node's encrypted PIN automatically, which covers a reboot of one node and a rolling update;
- after a full power loss one manual unlock is needed, and the first node then unlocks the others;
- a wrong PIN is never retried, because the card blocks after three attempts and then needs the PUK.

## Roots and certification

sluis holds **no root**. The roots, their ceremonies and every transition between root stores belong to [ritueel](https://ritueel.id); sluis holds intermediates and signs with them every day. The two exchange standard formats, which are fixed by ritueel's [hand-off contract, version 1](https://ritueel.id/reference/hand-off-contract/) and not repeated here ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)):

1. **Request.** `sluis key request` creates the key if it does not exist, on the node's card or in the key service, and writes a PKCS#10 request with a proof of where the key lives: the card's attestation chain (store `piv`), or the KMS key's full ARN (store `aws-kms`), which ritueel reads through a read-only role that sluis creates in the key's account. For an OpenPGP signing subkey it writes the public subkey and one back-signature for every active primary on the root list it holds, which `key-holder` makes on the card.
2. **Certify.** At ritueel's ceremony a root checks the proof and signs. This is the only step that touches a root. The answer is one certificate, or the bound subkey, and a result file; the root is not in it.
3. **Install.** `sluis key install` checks that the certificate verifies to an anchor of the CA bundle, that a root list, when sluis holds one, is at least as recent as the answer's trust sequence, and that the certificate matches the key and its request, then starts using it. The root list is optional: any CA that signs a PKCS#10 request in the profile can certify sluis, with anchors from the bundle alone and no rollback protection ([ADR 0024](/decisions/0024-root-custody-and-the-signing-api/#the-floor)).
4. **Watch.** `sluis key status` shows each key, its store and its expiry. An intermediate certificate or an OpenPGP subkey lasts about 13 months and is re-signed over the same key in month 12. With a card root that needs a person on ritueel's side once a year, and sluis warns 60, 30 and 14 days before the end; with a KMS root `ritueel renew` does it unattended under a declared policy ([what may run unattended](https://ritueel.id/learn/re-sign/#what-may-run-unattended)).

Key material is replaced by the rule of [principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule), on an event and, for a software key, also at most every three years; the log keys, the audit log key and the issuance-log key of `ca`, change only on compromise ([ADR 0006](/decisions/0006-keys-and-sealing/#rotation)). The token certificate is not part of the hand-off: the node's intermediate issues it. The tests get their root from a plain CA tool or, when it exists, from ritueel's software-root mode, run by the harness or a setup script; sluis never generates a root.

Hosts pin the public keys (SPKI hashes) of the roots, verify the root list that ritueel signs when they hold one, and refuse a list with a lower trust sequence than the one they hold (`sluis trust sync`). The list is re-signed at least once a year and lasts 13 months; a host whose list has expired keeps it, goes on trusting its roots and warns. How roots are made, held and replaced, and the accepted limits of root custody, are taught at [ritueel.id](https://ritueel.id).
