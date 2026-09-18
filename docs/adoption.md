# Adoption

What a platform needs to take access-roster into use: the prerequisites,
the order to install in, the first sign-in, connecting a directory and
then each cluster, account and console, adopting objects or an identity
provider that already exist, and moving between releases. The test for
whether something belongs here: *I am about to change what runs.* This
page is an index; the pages below hold the substance.

## The zero-diff gate

**A consumer adopts a release only when the render it produces is
byte-identical to what runs, or differs exactly by the change the release
announces.** Render both charts with your values at the pinned version
and at the new one, and compare; a difference you cannot explain from
[CHANGELOG.md](../CHANGELOG.md) is a reason to stop. Moving from
hand-written objects, or from another installation method, to these
charts is one change whose render diff is empty; tightening a default is
a separate release, adopted separately. The policy is part of the
values, so a policy change is a render diff too, and is reviewed as one.
[operations/adoption-plain-helm.md](operations/adoption-plain-helm.md#without-argocd-or-kargo)
shows the comparison with nothing but `helm template` and `diff`.

## Where it is written down

- [operations/adoption-plain-helm.md](operations/adoption-plain-helm.md) —
  prerequisites, install order for both charts with neutral values, the
  first sign-in, and taking releases without a GitOps controller
- [reference/configuration.md](reference/configuration.md) — what the
  issuer's chart renders and expects, and the objects the service writes
- [operations/runbook.md](operations/runbook.md#day-one) — day one: the
  recovery sign-in and the console's Overview
- [operations/connect-runbook.md](operations/connect-runbook.md) — the
  one-time OAuth client and connecting each Google Workspace
- [connect/](connect/) — one guide per thing that trusts the issuer: a
  [Kubernetes cluster](connect/kubernetes-cluster.md), an
  [AWS account](connect/aws-account.md), [ArgoCD](connect/argocd.md),
  [Kargo](connect/kargo.md), [a console](connect/console-app.md),
  [GitHub Actions](connect/github-actions.md),
  [a GitHub organisation](connect/github-organisation.md),
  [catalogue GitHub Apps](connect/github-apps-catalogue.md),
  [registries and artifacts](connect/registries-and-artifacts.md),
  [a service called by workloads](connect/service-to-service.md),
  [a secret manager that mints certificates](connect/openbao.md),
  [the corporate directory](connect/corporate-directory.md)
- [operations/migration-from-an-idp.md](operations/migration-from-an-idp.md)
  — retiring an identity provider run for infrastructure without a day of
  broken logins
- [operations/migration-from-google-group-sync.md](operations/migration-from-google-group-sync.md)
  — moving from a per-workspace directory reader
- [reference/accessctl.md](reference/accessctl.md#installing-it) — putting
  `accessctl` on laptops and into CI toolchains
- [CHANGELOG.md](../CHANGELOG.md) — every release, and for a breaking
  one what to do first
