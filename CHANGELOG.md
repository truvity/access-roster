# Changelog

One line per release; full detail lives in the release notes and the
git history.

## Unreleased
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
  family drawn end to end (`docs/architecture/access-roster.md`).
- Repository scaffolding, the hub design (`docs/design/hub.md`), the
  architecture with C4 diagrams, the contracts and the connect runbook —
  documentation first, for review before the prototype.
