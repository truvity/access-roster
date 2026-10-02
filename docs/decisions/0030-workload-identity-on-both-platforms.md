# 0030 — Workload identity: both mechanisms on both platforms

**Status:** Accepted; applies [0002](0002-mission-boundary-tokens-and-memberships.md)
**Date:** 2026-10-02

## Context

A workload proves who it is to the issuer in one of two ways. A Kubernetes
ServiceAccount token, projected for an audience, is verified against its
cluster. An AWS role's identity token, minted by outbound identity federation
(`sts:GetWebIdentityToken`), is verified against the account's issuer
([connect/aws-workloads.md](../connect/aws-workloads.md)). Which of them a
workload has follows from where it runs, and a workload can run on one platform
and call a service on the other: a Lambda function reaching an issuer in a
cluster, or a pod reaching one on Lambda.

## Decision

**Both mechanisms are accepted on both platforms.** The verifier is the same
code whichever way the issuer is hosted; the matcher a policy writes names the
identity (a service-account subject, an assumed role), not the host. An
installation declares which clusters and which accounts it trusts, and
everything else is refused.

A workload on Kubernetes that wants an AWS identity gets one the way EKS
provides it (Pod Identity or a role annotation on its ServiceAccount, see
`serviceAccount.annotations` in [reference/configuration.md](../reference/configuration.md)),
and the **Identity port** hands both kinds of credential to the adapters that
need one: the Sealing and Blob adapters use the AWS identity, and the audit sink
uses the projected token.

## Consequences

The Lambda platform needs no stored credential to reach anything it is allowed
to reach, and a pod on any cluster needs none to reach an issuer on Lambda.
Trusting a second kind of identity is an explicit entry in the installation's
configuration and appears in the audit trail the same way as the first.

## Alternatives considered

**A single mechanism per platform.** Rejected: it makes the cross-platform case
(the one that justifies two platforms) need a stored secret.

**A static API key for the cross-platform case.** Rejected for the reason in
0002: a bearer secret with no identity to revoke.
