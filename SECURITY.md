# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/access-roster/security/advisories/new).

Do NOT open a public issue for security vulnerabilities.

## Supported Versions

Only the latest release is supported with security updates.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Design notes relevant to a reviewer

- The service **holds directory credentials so that its consumers hold
  none**. Credentials — OAuth refresh tokens, service-account keys, the
  private keys of the GitHub Apps an owner created from the console,
  people's GitHub link tokens — live only in Kubernetes Secrets in its
  own namespace; the ServiceAccount holds a namespaced Role, never a
  cluster-wide one. The console never returns secret material and the
  logs never print it. An operator may copy four of those Secrets out as
  a backup; the copy's custody is the operator's.
- The service is **read-only against the directory**: every scope it
  asks for is a read-only Admin SDK scope. A compromised service can
  enumerate accounts and groups; it cannot change them. Its one write
  surface is **GitHub**: the controller invites, adds, promotes and
  removes members of the organisations listed in `githubRoster.actsIn`,
  with a key that lives only in its namespace, and it removes only on an
  answer the directory vouches for, never an owner, and never more than
  half an organisation without an operator's confirmation.
- The safety-critical output is the per-domain **authoritative** flag.
  Consumers that remove access act only on authoritative answers; a failed
  probe, a partial read, a stale snapshot or a domain conflict all read as
  "not authoritative", never as "gone".
- Every service here trusts **exactly two anchors** and never a third
  ([docs/design/trust.md](docs/design/trust.md)): the cluster (a
  ServiceAccount token checked by TokenReview, audience-bound,
  allow-listed) for workloads in the same cluster, and the issuer (its
  JWKS, an audience) for everything else. A workload calling the
  console's API presents its ServiceAccount token, verified against its
  cluster's published key set, so the service holds access to no
  cluster; a person presents the issuer's own session. NetworkPolicy
  gates both as the second layer, never the only one. Break-glass is the cluster anchor used as the floor: a
  ServiceAccount token a person mints with cluster RBAC, no stored
  credential in a cluster; outside one, a generated password held only
  as an Argon2id digest.
- The service **authenticates nobody.** Sign-in is always delegated to
  an identity provider; the service verifies the result and applies the
  policy. As a security token service it verifies proofs produced
  elsewhere — a corporate sign-in, a GitHub job's token, a cluster's
  ServiceAccount token — and holds no passwords, no users and no MFA. Of
  its own tokens, only the access token of a CLI sign-in at a public
  client declaring `sign_in_exchange` is a proof for exchange; an ID
  token is not (1.5.5).
- The **audit trail** is kept by an audit installation connected as a
  plugin, which access-roster reaches as its own workload (a projected
  service-account token) and holds no bucket or key for. Ordinary records
  never wait on it; a recovery sign-in does, and is refused when its record
  cannot be kept. The console's Audit page reads the installation with a
  short-lived token minted for the person signed in, never passed to the
  browser. The client
  address in a record is read from `X-Forwarded-For` only as far as
  `audit.forwardedForTrustedHops` says, so set it to the deployment's
  own proxies and no more.
