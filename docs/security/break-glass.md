---
title: Break-glass recovery
description: "The operator's way back in: passkeys held in config, in three credential classes, with recovery scope only, audited and drilled."
status: target
sidebar:
  order: 1
---

**Break-glass recovery** is the operator's way back in when normal sign-in cannot work: the upstream directory is down, a federation is misconfigured, or no upstream can vouch for anyone. It is the one sign-in that no upstream vouches for, and it still holds no account and no password, only public keys in config ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017), [Design principles](/principles/)). Its decision record is [ADR 0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery).

## Passkeys only

Recovery accepts a passkey assertion and nothing else ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066)). There is no password, no recovery code and no Kubernetes ServiceAccount token checked by a cluster: each of those is a reusable secret to guard or a dependency on the system that may be the one that failed. sluis stores only public material, the credential ids and the public keys.

## The credentials are config

The recovery credentials are the config kind `BreakGlassPasskey`, which `session` reads from the snapshot ([Kinds](/reference/kinds/#breakglasspasskey)). They are not durable data, so a damaged or restored store cannot lose them, roll them back or hold them back. A credential is added, replaced or removed only by a reviewed, signed commit, like any other config ([0005](/decisions/0005-the-store/#configuration-loading), [Signed config](/reference/signed-config/)). Recovery itself cannot change them.

## Three credentials in three classes

A `BreakGlassPasskey` has one of three credential classes: `hardware-fido`, `hardware-piv` or `synced` ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)). Enabling recovery requires three registered credentials ([REQ-AUTHN-067](/requirements/authn/#REQ-AUTHN-067)):

| Credential | Rule | Why |
|---|---|---|
| Two hardware keys, each of class `hardware-fido` or `hardware-piv` | Each accepted only when its enrolment carried an attestation that was verified against the authenticator vendor's attestation roots ([REQ-AUTHN-068](/requirements/authn/#REQ-AUTHN-068)) | Attestation shows the key is a hardware authenticator, not a software copy; two survive the loss of one |
| One synced passkey, class `synced` | Accepted only by its pinned credential id ([REQ-AUTHN-069](/requirements/authn/#REQ-AUTHN-069)), kept in a vault of its own, apart from the hardware keys; its attestation is `none`, so the pin is the only proof | It survives the loss of both hardware keys, and the pin keeps any other passkey of the same account out |

A `hardware-fido` credential is a FIDO security key, which makes a WebAuthn credential with an attestation statement. A `hardware-piv` credential is a key in a PIV slot of a card, whose public key and chain come from the slot's attestation. Each credential is registered by its credential id and public key, so an assertion from any other authenticator is refused even if it belongs to the same person.

## Enrolment

**The enrolment tools only show the JSON to commit** ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)). Nothing is stored by the tools, and the person commits what they show:

- **A command-line tool enrols a FIDO hardware key.** It asks the key for a credential with direct attestation, verifies the chain to a pinned vendor root, and prints the entry.
- **A command-line tool reads a PIV key from its attestation.** The slot's attestation certificate gives the public key, the slot, and the PIN and touch policies, and the chain runs to the same kind of pinned vendor root. A card issues a new attestation certificate for the same key on every request, so an entry is compared by its public key and chain, never by the certificate's bytes.
- **A page enrols the synced passkey.** It creates the passkey in the browser, shows the JSON, and sends nothing and stores nothing. A passkey belongs to a relying-party ID, so the production page is served over https from the shared sign-in domain, the `FrontHost`, with that domain as the relying-party ID, the one that staff passkeys and the ceremonies use ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).

The enrolment spike ([#1178](https://github.com/truvity/sluis/issues/1178)) passed on 2026-11-03: one credential of each class was enrolled with its tool, and one recovery assertion from each verified. It ran on one machine, with Linux, Chrome and one hardware key model, and with `localhost` as the relying-party ID; the page's network log stayed empty and its storage stayed empty while it created the passkey and signed a challenge. Safari, Firefox, macOS, Windows, other authenticators and the https origin under a real sign-in domain are not covered yet. The command names of the tools are planned and not yet in the [command reference](/reference/cli/).

## Verifying a recovery sign-in

`session` verifies a recovery assertion against its own challenge, like any passkey, on every runtime ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)):

1. `session` issues a fresh challenge.
2. The person signs it with one of the registered credentials.
3. `session` finds the entry by its pinned credential id in the snapshot; a hardware entry must carry a verified attestation.
4. It checks the client data (the type, its own challenge, a web origin on the verifier's allow-list) and the relying-party ID ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).
5. It checks the signature with the entry's public key.
6. On success it opens a recovery session; every outcome, success or refusal, is an audit record.

The checks are the same for every class, with these differences ([0017](/decisions/0017-identity-and-sign-in/#break-glass-recovery)). A PIV key cannot make a WebAuthn assertion, so a `hardware-piv` credential signs `authenticatorData || SHA-256(clientDataJSON)` with the slot key, and user presence and verification follow from the slot's attested policy. A hardware assertion must not be backup-eligible. The signature counter is checked for `hardware-fido`, ignored for `hardware-piv`, and not used as a clone signal for `synced`.

## What a recovery session may do

A session opened by recovery carries the **recovery scope only** ([REQ-AUTHN-070](/requirements/authn/#REQ-AUTHN-070)), and gets no refresh token. The scope is the built-in break-glass policy, which grants beyond config, so linking it is a loosening: it is a `PredefinedPolicyLinkTemporary` that `exchange` writes and that expires, after 1 hour by default and 24 hours at most ([0007](/decisions/0007-policy-and-sealed-grants/#template-links)). It restores access: an operator repairs a connection, a federation or a tenant setting. Config, the recovery credentials among it, changes only by a commit, so recovery cannot change it. A wider session would turn the emergency door into a standing back door.

## Audited, alerted and drilled

- **Every use is audited,** successful or refused ([REQ-AUTHN-071](/requirements/authn/#REQ-AUTHN-071)). Recovery does not wait for the audit path: it spools its record locally and delivers it when the path is back, so a down audit installation cannot shut the emergency door ([Audit](/concepts/audit/)).
- **Every successful use raises an alert** to the operators ([REQ-AUTHN-072](/requirements/authn/#REQ-AUTHN-072)). A recovery that nobody expected is an incident until proven otherwise.
- **The runbook requires a drill every quarter** ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)): each credential is used once in a test of the full path, and the drill is itself audited and alerted. A recovery path that is never exercised fails when it is needed.
- **`sluis config check` warns** when recovery is enabled without all three credentials.

## Where it runs

Recovery needs no cloud account and no cluster, so it works on every [runtime](/runtimes/). Do not run the installation that signs people in to a cluster on that same cluster without it ([Kubernetes](/runtimes/kubernetes/#limits-and-residual-risk)).

Recovery is for sign-in to sluis. Emergency SSH access to hosts is a different path, the break-glass SSH CA that ritueel holds offline ([SSH](/integrations/infrastructure-access/#the-break-glass-ssh-ca)).

## Residual risk

Whoever holds a registered hardware key and can unlock it, or controls the vault of the synced passkey, can open a recovery session. The recovery scope and its expiry bound what that session can do, and the alert and the audit record make each use visible. An operator who has not committed the three credentials before they are needed has no way back in but a restore. The wider model is the [threat model](/security/threat-model/) (T-41).
