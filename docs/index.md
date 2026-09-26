# Documentation

One entry point. Four other pages here are themselves indexes —
[doctrine.md](doctrine.md), [reference.md](reference.md),
[adoption.md](adoption.md), [safety.md](safety.md) — each the table of
contents for its own pages; this page is where you start when you do not
yet know which of those you want.

## Where to start

- [adoption.md](adoption.md) — prerequisites, install order, connecting
  things, migrating, and the zero-diff gate
- [safety.md](safety.md) — what is refused and why, the failure
  semantics, and the traps
- [reference.md](reference.md) — every value, flag, input and output
- [doctrine.md](doctrine.md) — the design rules, and who owns what
- [CHANGELOG.md](../CHANGELOG.md) — what changed for a consumer, per
  version

## Read next

| You want to | Read |
|---|---|
| understand the ideas behind it | [why.md](why.md), then [design/trust.md](design/trust.md) |
| see every piece and how they connect | [architecture.md](architecture.md) |
| learn the words this repository uses precisely | [concepts.md](concepts.md) |
| see every integration point at a glance | [integrations.md](integrations.md) |
| write the policy | [reference/policy.md](reference/policy.md) |
| connect the corporate directory people sign in with | [connect/corporate-directory.md](connect/corporate-directory.md), and [operations/connect-runbook.md](operations/connect-runbook.md) |
| give a CI job an identity with no stored secret | [connect/github-actions.md](connect/github-actions.md) |
| deploy it | [operations/adoption-plain-helm.md](operations/adoption-plain-helm.md), [reference/configuration.md](reference/configuration.md), then [operations/connect-runbook.md](operations/connect-runbook.md) |
| run it: what to check, what to back up, how to restore | [operations/runbook.md](operations/runbook.md), [configuration.md — restoring from the Secrets alone](reference/configuration.md#restoring-from-the-secrets-alone) |
| use it from a laptop or a CI job | [reference/accessctl.md](reference/accessctl.md) |
| put a console behind the gateway | [connect/console-app.md](connect/console-app.md) |
| keep a GitHub organisation's teams in step with the policy | [connect/github-organisation.md](connect/github-organisation.md) |
| declare GitHub Apps as data and create them from the console | [connect/github-apps-catalogue.md](connect/github-apps-catalogue.md) |
| give a Pulumi or Terraform program that manages the organisation an identity of its own | [connect/infrastructure-as-code.md](connect/infrastructure-as-code.md) |
| connect a cluster, an AWS account, ArgoCD, Kargo, a workflow | [connect/](connect/) |
| mint a short-lived SSH, database or client certificate | [connect/openbao.md](connect/openbao.md) |
| see what the conformance suite said, and why | [conformance.md](conformance.md) |
| run the conformance suite | [operations/conformance.md](operations/conformance.md) |
| build a service that accepts both people and workloads | [connect/service-to-service.md](connect/service-to-service.md) |
| see why a decision was made, and what it forecloses | [decisions/](decisions/README.md) |
| extend it — a new directory backend, a new kind of client | [development/extending.md](development/extending.md) |
| change the console or run it locally | [CONTRIBUTING.md](../CONTRIBUTING.md) |
