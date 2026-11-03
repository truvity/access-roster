# 0042 — Every leaf certificate has a fixed profile and a short lifetime, intermediates are name-constrained per environment, and one static CRL per intermediate is re-signed daily

**Status:** Superseded by 0023
**Date:** 2026-11-03

Proposal: [issue #1073](https://github.com/truvity/sluis/issues/1073).

## Context

`ca@<boundary>` issues every X.509 leaf from the boundary's intermediate, and keeps uses apart by profiles rather than by an intermediate per use ([0023](/decisions/0023-certificate-authorities/#x509)). The token-signing key has its own non-CA certificate from the node's intermediate ([0006](/decisions/0006-keys-and-sealing/#the-token-signing-key)). Both records name the profiles but leave out their fields, the lifetimes and how often revocation is published. The first working version needs them: the key set carries an `x5c` chain from its first build, and the local installation's actors talk mutual TLS with certificates from `ca`.

Forces:

- **Relying parties read certificates as they implement the standards.** An X.509-SVID has exactly one URI SAN, the SPIFFE ID ([SPIFFE X509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)). PostgreSQL maps the whole subject with `clientname=DN`. TLS clients check a DNS or IP SAN. A certificate with no extended key usage is accepted for any use by many clients.
- **Revocation reaches few relying parties.** Most TLS and SPIFFE clients never fetch a CRL, and sluis runs no OCSP responder (REQ-PKI-008). A short lifetime is the control that works everywhere; a CRL helps only the relying parties that configure it, such as a database.
- **Name constraints are checked by verifiers, not by the issuer.** RFC 5280 constrains each name type separately: a type with no permitted subtree is unconstrained. ritueel's hand-off contract requires at least one permitted subtree, marked critical, in an intermediate request, and its certifier checks them against its policy. That policy lists URI hosts today; the DNS subtrees below are checked by ritueel when its policy lists them (waiting on a change in ritueel, [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70)), and verifiers enforce them from the first certificate either way.
- **Principle 2** asks for short leaves; **principle 5** for profiles that the consumers implement.

## Decision

### The intermediate's name constraints

- **Each environment's intermediate is name-constrained to that environment.** `sluis key request` writes critical name constraints into the request ([0024](/decisions/0024-root-custody-and-the-signing-api/#the-hand-off)), built from the boundary's declared names:
  - permitted URI: the boundary's SPIFFE trust domain ([0022](/decisions/0022-workload-identity-and-host-enrolment/#trust-domains));
  - permitted DNS: the boundary's public hosts (`sluis.<env>.example.com`), the environment's private zone under the reserved `.internal` top-level domain (for example `prod.example.internal`), and any further host zones the boundary declares;
  - permitted IP: only ranges the boundary declares; with none declared, the request excludes `0.0.0.0/0` and `::/0`, so no leaf of that intermediate can carry an IP address that verifies.
- **A development intermediate cannot vouch for a production name.** Each environment declares its own zone, and the intermediates of two environments permit disjoint names.
- **`ca` refuses a leaf outside its intermediate's permitted subtrees** before it asks `key-holder` to sign, so a mistake is a refusal at the issuer and not a certificate that verifiers reject.
- **The intermediate's other fields** (path length, extended key usage, validity of about 13 months) are ritueel's hand-off contract and are not repeated here.

### Leaf profiles

Every leaf has a random 128-bit serial, `basicConstraints` critical with CA false, a critical `keyUsage` of `digitalSignature` only, and its subject key's algorithm as [0006](/decisions/0006-keys-and-sealing/#algorithms) allows. A profile fixes the rest, and no two profiles can produce the same certificate shape:

| Profile | Extended key usage | Names | Default lifetime | Maximum |
|---|---|---|---|---|
| Token signing (non-CA) | none | Subject `CN=token-signing, OU=<actor>@<boundary>`; no SAN | To the issuing intermediate's `notAfter` | The intermediate's `notAfter` |
| Workload X.509-SVID | `serverAuth`, `clientAuth` | Exactly one URI SAN, the workload's SPIFFE ID; empty subject | 1 hour | 24 hours |
| Host X.509-SVID | `serverAuth`, `clientAuth` | The host's URI SAN, plus its declared or derived DNS names ([0023](/decisions/0023-certificate-authorities/#ssh)) | 24 hours | 7 days |
| sluis mutual TLS | `serverAuth`, `clientAuth` | Exactly one URI SAN, the actor's SPIFFE ID ([Names](/decisions/0002-families-of-actors/#names)) | 24 hours | 24 hours |
| Database client | `clientAuth` only | Subject `CN=<role>, OU=<requester>, O=sluis-database`; no SAN | Set by policy | 12 hours |
| cert-manager | `serverAuth`, and `clientAuth` when requested | DNS and URI names taken from the requester's identity, never from the request alone | The requested duration | 90 days |

- **The token certificate cannot serve TLS or issue.** It has no SAN and no CA flag, so a TLS client's name check fails and a path validator refuses it as an issuer. It is re-issued over the same key whenever its intermediate is renewed, so its `x5c` chain is never older than the intermediate.
- **Policy may shorten any lifetime, never lengthen it past the maximum.** The maxima are floors in code ([0006](/decisions/0006-keys-and-sealing/#floors-in-code)); `sluis config check` refuses a declared lifetime above one.
- **SSH certificate lifetimes** are in [0023](/decisions/0023-certificate-authorities/#ssh).

### Databases on CloudNativePG

- **CNPG keeps a CA of its own for replication between its instances,** and `ca` never issues for the replication role (as [0023](/decisions/0023-certificate-authorities/#database-client-certificates) reserves it).
- **The server certificates come from cert-manager, through the sluis-backed issuer,** under the cert-manager profile.
- **Client certificates for application roles come from the database client profile;** the server trusts sluis's chain for them beside the replication CA. How one cluster is wired stays in that cluster's own repository.

### Revocation

- **Each intermediate has one static CRL of its leaves**, a full list with no delta, signed by the intermediate and published in the boundary's bucket beside the key set, so it is served while the issuer's compute is down.
- **The CRL is re-signed every 24 hours with a `nextUpdate` of 7 days,** and at once after a revocation. A relying party that misses a day of fetches keeps a valid list.
- **A revoked serial stays on the list until its certificate expires.** In practice that matters only for profiles longer than a day: the host X.509-SVID, the database client at its maximum, and cert-manager certificates.
- **Leaves carry no CRL distribution point and no OCSP address.** A relying party that checks revocation configures the CRL's URL, as PostgreSQL does with `ssl_crl_file`.
- **The intermediate itself is revoked by a root's CRL, which ritueel signs** (valid 25 months), not by this one ([0024](/decisions/0024-root-custody-and-the-signing-api/#root-pins-and-the-root-list)).

## Consequences

- A workload or actor certificate stolen from memory is useless within a day, usually within an hour, with no revocation needed. The cost is issuance load: every workload renews about every 40 minutes and every actor daily, which `ca` and its card or key service must carry ([0006](/decisions/0006-keys-and-sealing/#consequences)).
- A misconfigured `ca` in one environment cannot produce a certificate that a verifier in another environment accepts for its names, provided the verifier enforces name constraints, which current TLS libraries do.
- Excluding all IP ranges by default means a host reached by address needs a declared range before it can get a certificate for it.
- The fixed database subject form and the `O=sluis-database` marker are what the fixed regular-expression map in each database matches; they are tested as security controls.
- CRL publication is one small signature per intermediate per day, and the list stays short because leaves are short.
- The defaults are numbers, and the maintainer may change them in review; a change that lengthens a maximum needs a record.
- Requirements: [REQ-PKI-043](/requirements/pki/#REQ-PKI-043) to [REQ-PKI-049](/requirements/pki/#REQ-PKI-049).

## Roads not taken

- **An intermediate per use (databases, workloads, cert-manager).** Each costs a request, a certification and a yearly renewal at ritueel; the profiles and the subject maps give the same separation ([0023](/decisions/0023-certificate-authorities/#x509)).
- **Intermediates without name constraints.** Any intermediate of any environment could then vouch for production names, and ritueel's contract requires a permitted subtree.
- **An OCSP responder.** An online service on the trust path for a control that short lifetimes already give; REQ-PKI-008 keeps it out until a record decides it.
- **A CRL distribution point in every leaf.** Few clients fetch it, and a client that does would make sluis's bucket a dependency of every TLS handshake.
- **Day-long workload certificates.** Simpler renewal, but a stolen workload key would stay useful for a day where an hour suffices for SPIFFE practice.
- **An extended key usage for the token certificate.** No registered EKU means "signs JWTs"; the missing SAN and CA flag already keep it out of TLS and issuance.

## Follow-ups

- The X.509 CA actor that implements the profiles: [#913](https://github.com/truvity/sluis/issues/913).
- ACME for host certificates, after the first release: [#978](https://github.com/truvity/sluis/issues/978).
- DNS name constraints in ritueel's policy, so that ritueel checks the DNS part of an intermediate's constraints: [truvity/ritueel#70](https://github.com/truvity/ritueel/issues/70).
