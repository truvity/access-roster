---
title: Break-glass recovery
description: "The operator's emergency way back in: passkeys only, two attested hardware keys and one pinned synced passkey, recovery scope, audited and drilled."
status: target
sidebar:
  order: 1
---

**Break-glass recovery** is the operator's way back in when normal sign-in cannot work: the upstream directory is down, a federation is misconfigured, or no upstream can vouch for anyone. It is the one exception to the rule that sluis hosts no accounts and stores no passwords ([REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017), [Design principles](/principles/)). Its decision record is [ADR 0043](/decisions/0043-break-glass-recovery-uses-passkeys-only/).

## Passkeys only

Recovery accepts a passkey assertion and nothing else ([REQ-AUTHN-066](/requirements/authn/#REQ-AUTHN-066)). There is no password, no recovery code and no Kubernetes ServiceAccount token checked by a cluster: each of those is a reusable secret to guard or a dependency on the system that may be the one that failed. sluis stores only public material, the credential ids and the public keys.

Enabling recovery requires three registered credentials ([REQ-AUTHN-067](/requirements/authn/#REQ-AUTHN-067)):

| Credential | Rule | Why |
|---|---|---|
| Two hardware keys | Accepted only when their registration carried an attestation statement that sluis verified ([REQ-AUTHN-068](/requirements/authn/#REQ-AUTHN-068)) | Attestation shows the key is a hardware authenticator, not a software copy; two survive the loss of one |
| One synced passkey | Accepted only by its pinned credential id ([REQ-AUTHN-069](/requirements/authn/#REQ-AUTHN-069)), kept in a dedicated vault apart from the hardware keys | It survives the loss of both hardware keys, and the pin keeps any other passkey of the same account out |

Each credential is registered by its credential id, so an assertion from any other authenticator is refused even if it belongs to the same person.

## What a recovery session may do

A session opened by recovery carries the **recovery scope only** ([REQ-AUTHN-070](/requirements/authn/#REQ-AUTHN-070)). It restores access and can ask for no other scope. A wider session would turn the emergency door into a standing back door.

## Audited, alerted and drilled

- **Every use is audited,** successful or refused ([REQ-AUTHN-071](/requirements/authn/#REQ-AUTHN-071)). Recovery does not wait for the audit path: it spools its record locally and delivers it when the path is back, so a down audit installation cannot shut the emergency door ([Audit](/concepts/audit/)).
- **Every successful use raises an alert** to the operators ([REQ-AUTHN-072](/requirements/authn/#REQ-AUTHN-072)). A recovery that nobody expected is an incident until proven otherwise.
- **The runbook requires a drill every quarter** ([REQ-AUTHN-073](/requirements/authn/#REQ-AUTHN-073)). A recovery path that is never exercised fails when it is needed.

## Where it runs

Recovery needs no cloud and no Kubernetes, so it works on every [runtime](/runtimes/). Do not run the installation that signs people in to a cluster on that same cluster without it ([Kubernetes](/runtimes/kubernetes/#limits-and-residual-risk)).

Recovery is for sign-in to sluis. Emergency SSH access to hosts is a different path, the break-glass SSH CA that ritueel holds offline ([SSH](/integrations/ssh/)).

## Residual risk

Whoever holds a registered hardware key and can unlock it, or controls the vault of the synced passkey, can open a recovery session. The recovery scope bounds what that session can do, and the alert and the audit record make each use visible. The wider model is the [threat model](/security/threat-model/).
