# Doctrine

The design rules: what this repository owns and what the installation
that consumes it owns, and the reasons for the shape. The test for
whether something belongs here: *why is it like this, and would a change
fit.* This page is an index; the pages below hold the argument.

- [why.md](why.md) — the situation it starts from, the problems it
  solves, and the principles every design question is decided by
- [concepts.md](concepts.md) — the words used precisely
- [architecture.md](architecture.md) — every piece and how it connects,
  and [who owns what](architecture.md#who-owns-what): access-roster, the
  directories, the relying parties
- [design/trust.md](design/trust.md) — two anchors and one vocabulary of
  internal groups: the rule under everything
- [design/access-roster.md](design/access-roster.md) — one process, the
  directory model, freshness, sessions, the console, the GitHub
  controller, the audit trail
- [design/access-proxy.md](design/access-proxy.md) — why the proxy is
  upstream oauth2-proxy in a chart and no code of ours
- [design/accessctl.md](design/accessctl.md) — why a CLI at all, the
  GitHub Action, and the credential broker's list of decisions it does
  not make
- [design/libraries.md](design/libraries.md) — the Go module and the
  TypeScript package, and the whoami contract between them
- [integrations.md](integrations.md) — every integration, case by case
- [development/extending.md](development/extending.md) — where something
  new plugs in, and what it must ship with
