# 0045 — The signing API signs the content it is sent for a proof that policy authorised, and its first stage returns an armoured OpenPGP detached signature

**Status:** Superseded by 0024
**Date:** 2026-11-03

Proposal: [issue #890](https://github.com/truvity/sluis/issues/890).

## Context

[0024](/decisions/0024-root-custody-and-the-signing-api/#the-signing-api) says that sluis signs artifacts for a caller that proves its identity with an OIDC token, that policy decides which repository, branch or workflow may use which key, and that the first stage is a detached, ASCII-armoured `.asc` signature. It leaves the request and the response, the way a caller names a key, the packet details of the signature and the policy and audit names to this record. The project's own releases are the first user.

Three facts about the formats shape the contract:

- **An OpenPGP signature cannot be made from a digest alone.** The signature hashes the data, then its own version, type, algorithm and hashed subpackets, then a trailer (RFC 9580, section 5.2.4). The signer has to see the data. A release signs the checksum file, which is small; the large files are covered by the checksums in it.
- **A key signs only what it is for.** A second signature format under the same key would let a chosen input for one format pass as a signature in the other, which is why signing keys are never shared across purposes ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)).
- **`signer` must not be a signing oracle for whoever reaches it** ([0002](/decisions/0002-families-of-actors/#the-four-families)). The caller is a CI job on the internet's side of `entry`, so the decision to sign has to come from `policy` and reach `signer` in a form that only `policy` can make.

## Decision

### Who does what

- **The signing API is a public Connect service of `exchange`,** reached through `entry`. `exchange` already verifies proofs (the `github-oidc` verifier driver is in the first working version, [0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)), asks `policy`, and calls `signer`; no new edge is needed.
- **The release-signing key belongs to `signer`,** the actor that signs, as a purpose of its own beside the token-signing key ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)). The two keys are never shared and have one user actor each.
- **The flow is four steps:**
  1. The caller sends the content with its proof, a GitHub Actions identity token, in the `Authorization` header.
  2. `exchange` verifies the proof and asks `policy` to decide the action `artifact.sign` on the resource `SigningKey` `release-signing`, with the verified attributes of the job (repository, ref, workflow, environment) and the digest and length of the content as context.
  3. `policy` seals a **signing grant**: the decision, the policy digest, the key purpose, the SHA-384 of the content, the caller, and an expiry 60 seconds ahead, under the sealing key with `purpose=grant` ([0007](/decisions/0007-policy-and-sealed-grants/#sealed-grants)).
  4. `exchange` passes the grant and the content to `signer`. `signer` opens the grant, refuses unless the key purpose, the content hash and the expiry match, builds the signature and signs in place through the keys port.

### The request and the response

```proto
service SigningService {
  rpc SignDetached(SignDetachedRequest) returns (SignDetachedResponse);
}

message SignDetachedRequest {
  string request_id = 1; // the caller's idempotency key
  bytes content = 2;     // 1 byte to 4 MiB
}

message SignDetachedResponse {
  string armored_signature = 1; // the .asc text
  string key_fingerprint = 2;   // the signing subkey, 40 upper-case hex characters
  string audit_id = 3;          // the id of the audit record of this signature
}
```

- **The caller names no key.** An installation has one release-signing key per environment boundary, and the request is for that key. A second signing key adds a field, which is a compatible change ([Contracts and errors](/reference/contracts/#versions)).
- **The caller sends the content, not a digest,** up to 4 MiB, the limit of a Connect message. The signed files of apt and rpm repositories and a release's checksum file are far below it. An empty or larger body is `invalid_argument`.
- **The request id follows the rule for public methods:** a repeat within 24 hours returns the first outcome, signature included, and a reused id with other content is `failed_precondition` ([Every call](/reference/contracts/#every-call)).

### The signature

- **It is an OpenPGP version 4 signature of type `0x00` (binary document),** with the public-key algorithm ECDSA (19) on P-384, the hash SHA-384 (10), made by the release subkey.
- **The hashed subpackets are the signature creation time and the issuer fingerprint (subpacket 33);** the one unhashed subpacket is the issuer key id (16). No other subpacket is written, and the signature does not expire. This is the packet rule of ritueel's ADR 0006, which its tools check.
- **The output is armoured** as RFC 9580, section 6 says, with the checksum line so that older readers accept it, and with no `Version` or `Comment` header. The creation time is `signer`'s clock, in UTC seconds.
- **The subkey signs; the primary does not.** The signature verifies against the release keyring that ritueel's tools build, which carries the primaries and every current subkey binding ([Release signing](/distribution/release-signing/#the-openpgp-release-key)).
- **`signer` builds the packets itself,** and the keys port signs the signature input (the content, then the hashed fields and the trailer); the driver hashes it with SHA-384. `key-holder` parses that structure before it signs, as it does for a certificate body ([Storage](/reference/storage/#keys)).

### When the API refuses to sign

- **The key's binding must be installed and unexpired.** `signer` signs only while it holds the OpenPGP binding that `sluis key install` stored, the primary's certification of the subkey, and the binding has not expired. Otherwise the answer is `failed_precondition`. In a development installation the binding is made by ritueel's software-root mode, so its signatures are for tests only ([0024](/decisions/0024-root-custody-and-the-signing-api/#sluis-holds-no-root)).
- **A caller without a valid proof is `unauthenticated`;** one that `policy` does not permit is `permission_denied`, with the uniform refusal of the edge ([Uniform refusals at the edge](/reference/contracts/#uniform-refusals-at-the-edge)). A repository, ref or workflow outside the policy looks the same as one that does not exist.
- **Every signature is audited,** as a key use: OCSF class 6003 API Activity, activity 99 "Sign", the key in `resources[]`, the caller as the acting party and the policy decision in the `security_control` profile ([0030](/decisions/0030-audit-records-and-the-usage-stream/#the-class-mapping)). `unmapped.sluis` carries the SHA-384 and the length of the content, never the content. The record is written before the response, and a signature whose record could not be written is not returned.

### The first stage and the next

- **The first working version has this one method, `SignDetached`,** for a GitHub Actions proof. The parity stage adds the signing of `Release.gpg`, `InRelease` and `repomd.xml.asc` as uses of the same method ([#1074](https://github.com/truvity/sluis/issues/1074)); later stages are the rpm package header and a stand-in for `gpg` that git can call ([#1075](https://github.com/truvity/sluis/issues/1075)).
- **A raw ECDSA signature is not in this stage.** It would be made by a key of its own, because the same key under two formats is the cross-use that principle 3 rules out, and nothing in the first working version consumes one ([#1117](https://github.com/truvity/sluis/issues/1117)). A Sigstore bundle follows the same rule.

## Consequences

- A flaw in the parser of `entry` or in `exchange` can ask `signer` only for a signature that `policy` sealed for exactly that content, within a minute. To sign something else an attacker needs `policy` to agree, as for a credential.
- The policy sees the job's repository, ref and workflow, which is what a release key needs: "this workflow, on this ref, may sign" is a Cedar permit, not code.
- The cost is a second key in `signer`, a slot on a node card ([0006](/decisions/0006-keys-and-sealing/#the-slot-plan)) and a key policy that lets `signer` open grants. The OpenPGP packet code exists in `signer` and in ritueel's tools, and the two share a test matrix of `gpg`, `gpgv`, `sqv`, apt and rpm ([0024](/decisions/0024-root-custody-and-the-signing-api/#consequences)).
- A caller that must sign a large file signs its checksum file. That is how the packaging tools work already.
- Requirements: REQ-SUPPLY-016 is reworded for content, and [REQ-SUPPLY-019](/requirements/supply/#REQ-SUPPLY-019) to [REQ-SUPPLY-024](/requirements/supply/#REQ-SUPPLY-024) are added.

## Roads not taken

- **A request that carries a digest.** It cannot produce an OpenPGP signature, because the signature hashes its own trailer after the data.
- **A `key` field naming the purpose.** With one signing key it carries nothing, and a field a caller can set invites a request for a key it should not name.
- **The signing API on `signer`.** `signer` would parse a caller's request and need an edge to `policy`; serving it from `exchange` reuses the edges that exist and keeps the signer free of internet parsing.
- **A decision that `signer` takes itself.** It would make the actor that holds the key also the one that decides.
- **A signature without a grant.** It would rest on the word of `exchange` alone: a flaw in `exchange` could sign anything with the release key.
- **A raw signature from the OpenPGP subkey.** Two formats under one key allow one to be passed off as the other.
- **A Sigstore bundle in the first stage.** More to build before the first user, and apt and rpm do not read it ([0024](/decisions/0024-root-custody-and-the-signing-api/)).
- **A token exchanged first, then a second call.** It adds a step and drops the job's attributes from the second decision; the first decision is the one with the facts.
- **A signature that does not wait for its audit record.** A signing service is found out by its records, so a signature without one is the failure to avoid.

## Follow-ups

- The signing API's later stages: [#1074](https://github.com/truvity/sluis/issues/1074), [#1075](https://github.com/truvity/sluis/issues/1075); release use and CI credentials: [#874](https://github.com/truvity/sluis/issues/874).
- A raw signature and a Sigstore bundle, each with a key of its own: [#1117](https://github.com/truvity/sluis/issues/1117).
