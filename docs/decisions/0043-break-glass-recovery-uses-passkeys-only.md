# 0043 — Break-glass recovery uses passkeys only: two attested hardware keys and one pinned synced passkey, a recovery scope, an alert on every use and a quarterly drill

**Status:** Superseded by 0017
**Date:** 2026-11-03

Proposal: [issue #1000](https://github.com/truvity/sluis/issues/1000).

## Context

Operators sign in through an upstream directory, and sluis hosts no accounts and stores no passwords ([0017](/decisions/0017-identity-and-sign-in/#passkeys), [REQ-CIAM-017](/requirements/ciam/#REQ-CIAM-017)). When the directory is down, a federation is misconfigured or no upstream can vouch for anyone, the operators still need a way back in to repair it. That way in is the one exception to "no accounts", so it has to be narrow, visible and proven to work.

v1 offered two recovery proofs: a Kubernetes ServiceAccount token checked by the API server, and an SRP-6a password that never crossed the wire ([#795](https://github.com/truvity/sluis/issues/795)). Both are reusable secrets or depend on a system that may be the one that failed: a cluster API server, or a password someone must store and rotate. WebAuthn gives a phishing-resistant proof whose private half never leaves its authenticator, and an attestation statement can show that an authenticator is hardware.

The maintainer decided on 2026-11-01 that recovery uses passkeys only; the requirements already state it (REQ-AUTHN-066 to REQ-AUTHN-073). This record writes the decision down.

## Decision

- **Recovery accepts a passkey assertion and nothing else** (REQ-AUTHN-066): no password, no recovery code, no ServiceAccount token. sluis stores only the credential ids and the public keys.
- **Enabling recovery requires three registered credentials** (REQ-AUTHN-067):
  - **two hardware keys,** each accepted only if its registration carried an attestation statement that sluis verified against the authenticator vendor's attestation roots (REQ-AUTHN-068), so a software copy cannot be registered and the loss of one key is survived;
  - **one synced passkey,** accepted only by its pinned credential id (REQ-AUTHN-069) and kept in a vault of its own, apart from the hardware keys, so the loss of both hardware keys is survived and no other passkey of the same account gets in.
- **A recovery session carries the recovery scope only** (REQ-AUTHN-070). It can restore access: repair an upstream, a federation or a policy, and register or revoke recovery credentials. It can ask for no other scope and gets no refresh token; it ends at the human absolute limit ([0018](/decisions/0018-sessions/#human-sessions)).
- **Every use is audited, successful or refused** (REQ-AUTHN-071). Recovery never waits for the audit path: the record is spooled locally and delivered when the path is back ([0029](/decisions/0029-the-audit-log/#retention)).
- **Every successful use raises an alert to the operators** (REQ-AUTHN-072). An unexpected recovery is an incident until proven otherwise.
- **The runbook requires a drill every quarter** (REQ-AUTHN-073): each credential is used once in a test of the full path, and the drill is itself audited and alerted.
- **Recovery runs on every runtime** and needs no cloud account and no cluster: `session` verifies the assertion against its own challenge, like any passkey ([0017](/decisions/0017-identity-and-sign-in/#passkeys)).
- **Recovery is for sign-in to sluis only.** Emergency SSH access to hosts is the break-glass SSH CA that ritueel holds offline ([0023](/decisions/0023-certificate-authorities/#ssh)).

## Consequences

- No reusable secret exists for recovery: nothing to rotate, leak or phish, and nothing that depends on the system being recovered.
- Recovery needs three credentials registered before it is needed, and an operator who skipped that has no way back in but a restore. `sluis config check` warns when recovery is enabled without all three.
- Whoever holds a registered hardware key and can unlock it, or controls the synced passkey's vault, can open a recovery session. The recovery scope bounds what it can do, and the alert and the audit record make every use visible.
- The quarterly drill costs an operator's time four times a year; a recovery path that is never exercised fails when it is needed.
- The page [Break-glass recovery](/security/break-glass/) describes this record.

## Roads not taken

- **A recovery password, as v1's SRP-6a.** A reusable secret that must be stored, rotated and guarded, and the one password in a product that stores none.
- **Recovery codes.** Printed reusable secrets with the same problems, and no proof that a person holds them at the moment of use.
- **A ServiceAccount token checked by a cluster's API server.** Recovery would depend on the cluster, which may be the thing that failed, and would not exist on the other runtimes.
- **Hardware keys without attestation.** A software authenticator could then be registered as a hardware key.
- **Only hardware keys.** Losing both, or the place where both are kept, would leave no way back in; the pinned synced passkey covers that.
- **A recovery session with the operator's full scope.** It would turn the emergency door into a standing back door.

## Follow-ups

- The recovery sign-in, built in the parity milestone: [#795](https://github.com/truvity/sluis/issues/795).
