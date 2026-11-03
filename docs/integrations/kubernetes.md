---
title: Kubernetes API server
description: How sluis verifies Kubernetes ServiceAccount tokens against a cluster's published keys, and how an API server trusts sluis as its OIDC issuer.
status: target
sidebar:
  order: 7
---

Kubernetes appears twice here. A **workload** in a cluster proves itself to sluis with its ServiceAccount token, and a cluster's **API server** trusts sluis to say who a person or a CI job is. Only the first is an integration; the second is a client profile. Running sluis itself in pods is a runtime, on [Kubernetes](/runtimes/kubernetes/).

## What it's for

- **A service in one cluster calls a service in another.** The caller's ServiceAccount token goes to sluis, which returns a token for the callee's audience with the groups policy gives that ServiceAccount. The callee verifies one token format whatever cluster the caller is in.
- **An engineer uses `kubectl` with their own identity.** Their directory group is the `groups` claim, and RBAC binds that group. No kubeconfig holds a long-lived credential.
- **A CI job deploys to a cluster.** It exchanges its CI identity for the cluster's audience; policy matchers on repository and branch decide which jobs may.
- **A controller reads sluis's data as itself**, proving who it is with its ServiceAccount token.
- **Many clusters, no credentials for them.** sluis checks a token against the cluster's published key set; it needs no kubeconfig and calls no cluster API.

## Integration kinds

| Kind | What it does for Kubernetes |
|---|---|
| `WorkloadVerifier` | The `k8s-sa-token` verifier driver of `exchange` checks a projected ServiceAccount token against the issuing cluster's published key set and returns `cluster`, `namespace` and `name` as attributes. It holds no secret ([ADR 0022](/decisions/0022-workload-identity-and-host-enrolment/#proofs-and-the-exchange)). |

Signing in to the API server is a client profile: each cluster is one OIDC client (`k8s:<cluster>`) that reads the `groups` claim, and sluis lists those clusters for the person.

sluis does **not** call `TokenReview`, which would need a kubeconfig per cluster; a published key set needs none. Nothing in sluis depends on a cluster checking a token: break-glass recovery is passkeys only ([Break-glass recovery](/security/break-glass/)). sluis also writes no Kubernetes objects; clusters pull what they need.

## What sluis asks the vendor for

**For the verifier:** the cluster's issuer URL and the address of its public key set. A cluster is declared once; a bad row stops the verifier at start.

**For the API server sign-in:** nothing from the cluster. The cluster's owner points the API server at sluis's issuer URL, the client id, the username claim and the `groups` claim, and binds RBAC to the group names.

The signing algorithm has to match. sluis signs with ES384 by default, and some API servers accept only RS256; the per-audience RS256 exception covers them with its own RSA key ([ADR 0006](/decisions/0006-keys-and-sealing/#named-exceptions)).

## What policy controls

- **Which ServiceAccounts count as which group**, by cluster, namespace and name.
- **Which groups may sign in to which cluster.** Each cluster's client has `requires`, and `sluis kubeconfig` lists only the clusters a person is granted.
- **Group names.** RBAC binds the names as policy spells them, so a typo is a silent denial. Render the policy and read the names before binding.
- **Lifetime.** A revocation reaches the API server when the token expires, so keep the client's cap short and tell the cluster's owners.

## What is audited

- Each token exchange for a workload (cluster, ServiceAccount, audience) and each refusal.
- Each sign-in to a cluster's client.
- Declaring or removing a cluster.

## Setup

Names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Declare the cluster for the verifier.
2. Point the API server at sluis: an EKS identity-provider configuration, the `--oidc-*` flags, or an `AuthenticationConfiguration` file.
3. Write the groups and the client in the policy.
4. A person runs `sluis kubeconfig`; a CI job uses the exchange action with `audiences: k8s:<cluster>`.

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  kubernetes:
    prod:
      actors: [verifier]
      issuer: https://oidc.cluster.example.org/id/EXAMPLE
      jwks_uri: https://oidc.cluster.example.org/id/EXAMPLE/keys
      api_server_client:
        id: k8s:prod
        groups_claim: groups
        signing_alg: ES384        # or RS256 for an API server that accepts nothing else
```

Keep the cloud's own cluster access as the cluster's break-glass path until a policy-granted admin has used the cluster, and test it on a schedule.
