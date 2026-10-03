# 0028 — Nothing writes ConfigMaps or Secrets; written secrets are sealed

**Status:** Accepted; extended by [0034](0034-exports-go-to-openbao-directly.md)
**Date:** 2026-10-02

## Context

Today the service writes Kubernetes objects: workspace credentials, GitHub App
private keys, links and the catalogue Apps' tokens are Secrets it updates, and
its reports are ConfigMaps. That needs RBAC to write them, makes a GitOps sync
the enemy of a ConfigMap whose data a controller rewrites, and has no
counterpart on Lambda. It also means a compromise of the process is a write
into its namespace.

## Decision

**ConfigMaps and Secrets are inputs only:** the mounted policy, the
configuration file, and secrets an operator or an operator-managed system puts
in place. The service holds no permission to create or update either.

A secret the **console** writes (a connected workspace's credential, a GitHub
App's key, a link's tokens, a catalogue App's bot token) is **sealed**: encrypted
with AES-GCM under a data key, and stored in the State store
([0027](0027-the-state-port-nats-jetstream-and-dynamodb.md)) with its
record. The data key is wrapped by a **key-encryption key** the **Sealing port**
holds:

- **KMS** on AWS, which an EKS workload can also use through Pod Identity;
- **OpenBao Transit**, or a **mounted key-encryption key**, where KMS is not
  available.

The store holds only ciphertext and the wrapped data key, so a copy of the store
is not a copy of the secrets, and a rotation of the key-encryption key rewraps
without touching the plaintext. The signing-key schedule is sealed the same
way.

No parameter store (SSM) and no OpenBao key-value mount holds a secret this
service writes.

## Consequences

The backup of a deployment is the State store and the key-encryption key, both
named, instead of five named Secrets. Losing the key-encryption key loses every
sealed secret, and an operator is told so in the runbook; the recovery for a lost
workspace credential stays **Reconnect**.

A secret an installation declares as data (for example in a catalogue) is still
an input and is read, not written. Pushing a catalogue App's token to a secret
store for a consumer is a separate output and is unchanged.

## Alternatives considered

**SSM Parameter Store for written secrets.** Rejected: AWS-only, a second
store with its own limits and throttling, and a second place a backup must
cover.

**OpenBao key-value for written secrets.** Rejected: it makes the service's
availability depend on the secret store's on the sign-in path.

**Store plaintext in the State store and rely on its encryption at rest.**
Rejected: it puts every secret in the clear for anyone allowed to read the table
or the stream.
