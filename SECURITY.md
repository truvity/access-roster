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

- The hub **holds directory credentials so that its consumers hold none**.
  Credentials (OAuth refresh tokens, service-account keys) live only in
  Kubernetes Secrets in the hub's own namespace; the ServiceAccount holds a
  namespaced Role, never a cluster-wide one. The console never returns
  secret material and the logs never print it.
- The hub is **read-only against the directory**: every scope it asks for
  is a read-only Admin SDK scope. A compromised hub can enumerate accounts
  and groups; it cannot change them.
- The safety-critical output is the per-domain **authoritative** flag.
  Consumers that remove access act only on authoritative answers; a failed
  probe, a partial read, a stale snapshot or a domain conflict all read as
  "not authoritative", never as "gone".
- The consumer API authenticates callers by Kubernetes ServiceAccount
  token (TokenReview, audience-bound, allow-listed) on a ClusterIP Service
  gated by NetworkPolicy. The operator API and console sit on a separate
  listener with its own session, established by a corporate sign-in, an
  external issuer, a bearer forwarded by an authenticating gateway, or —
  for day one and break-glass — a local admin account whose password is
  generated into a Secret and shown nowhere else.
- The hub **authenticates nobody and issues nothing.** Sign-in is always
  delegated to an identity provider; the hub verifies the result and
  applies the policy. access-issuer, the second service designed for this
  repository, is a security token service under the same rule: it
  verifies proofs produced elsewhere and holds no passwords, no users
  and no MFA.
