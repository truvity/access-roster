# 0026 — Two platforms, permanently: Kubernetes and AWS Lambda

**Status:** Accepted
**Date:** 2026-10-02

## Context

access-roster runs today as Kubernetes workloads: the issuer and console as one
service, the GitHub and Slack controllers beside it, state in Kubernetes
objects and Valkey. Part of an installation's own sign-in path (the cluster's
API server, its dashboards and its metrics gateway) depends on the issuer,
while the issuer itself runs on that cluster. A second platform that does not
share the cluster's fate removes that circle. The AWS side already exists in
part: the issuer verifies AWS outbound-federation tokens, and an extension
layer sends a function's telemetry with the function role's identity
([integrations/aws-lambda.md](../integrations/aws-lambda.md)).

The constraint is that a second platform must not become a second product. A
platform-specific code path that only one installation exercises rots.

## Decision

access-roster supports **two platforms, both maintained and both tested**:

- **Kubernetes**, installed by the Helm chart.
- **AWS Lambda**: an HTTP function (the issuer, console and Connect services,
  run unchanged behind the Lambda Web Adapter) and a tick function (the
  reconcilers, invoked by EventBridge Scheduler and by the trigger port), behind
  an API Gateway HTTP API.

Neither is a stepping stone to the other. What differs between them is chosen
by **ports and adapters** ([0027](0027-the-state-port-nats-jetstream-and-dynamodb.md),
[0028](0028-nothing-writes-configmaps-or-secrets.md),
[0029](0029-ticks-per-target-under-a-lease.md); the specification is
[design/ports.md](../design/ports.md)): the same business code runs on both, and
an adapter is the only place a platform's name appears. **Go remains the
language** for services, command-line tools and infrastructure libraries.

A CDN or proxy in front of the HTTP API is an installation's choice and is not
part of the platform. No platform-specific compute beyond Lambda and Kubernetes
is adopted.

## Consequences

Every adapter ships with a conformance suite that runs against all of its
siblings, so a platform that nobody currently runs is still covered by CI.
Feature work lands through the ports; a feature that needs a platform primitive
no port offers is a port change first.

Lambda constrains the service: unary RPCs only on the function, a request must
finish within the platform's timeout, and nothing can hold a long poll or a
background goroutine between invocations. Work that needs time moves into a
tick.

This record does not decide self-hosted packaging without Kubernetes, nor a
runtime in another language. Both are parked.

## Alternatives considered

**Kubernetes only.** Rejected: it leaves the sign-in circle in place.

**Lambda only.** Rejected: an installation that has a cluster and no AWS account
would have nowhere to run it, and a lease-holding replica pair is the simplest
thing that gives the controllers high availability there.

**A second implementation per platform** (a Lambda-native rewrite). Rejected: two
implementations of one policy engine will disagree, and a disagreement in an
access decision is the failure this product exists to prevent.
