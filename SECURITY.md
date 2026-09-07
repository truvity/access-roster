# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it privately via
[GitHub Security Advisories](https://github.com/truvity/directory-roster/security/advisories/new).

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
- The consumer API listens on a ClusterIP Service gated by NetworkPolicy;
  the operator API and console sit on a separate listener that is only
  reachable through the gateway's authentication.
