# Changelog

One line per release; full detail lives in the release notes and the
git history.

## Unreleased
- Policy model settled (2026-09-07): five tables — groups, claims,
  lifetimes, clients, memberships — one schema for both services, deep
  merge with a scalar-conflict check, shortest lifetime, layered loading
  (declared + console), memberships the only console-writable table,
  clients declared or self-registered and never created in a console.
  Replaces the flat rules list; `docs/reference/policy.md`.
- Documentation rewritten for the self-contained repository: why it
  exists, the ten concepts, one architecture, a design per battery
  (hub, access-issuer, access-proxy, libraries, accessctl and the
  action), reference pages including the rules language, connect guides
  per kind of relying party, migration from an identity provider,
  extension points.
- Repository renamed to access-roster: one repository for the directory
  hub and the later token service, which share verifiers, rules and
  backends. The hub keeps its name: `directory-roster` binary, chart and
  namespace.
- Access model for the hub itself: own login with a connected directory
  or an external issuer, a forwarded bearer behind a gateway, a generated
  break-glass admin, rules with four subject kinds (`AccessService`);
  consumers authenticate with ServiceAccount tokens verified by
  TokenReview.
- The token service designed (`docs/design/token-service.md`) and the
  family drawn end to end in one architecture page (`docs/architecture.md`).
- Repository scaffolding, the hub design (`docs/design/hub.md`), the
  architecture with C4 diagrams, the contracts and the connect runbook —
  documentation first, for review before the prototype.
