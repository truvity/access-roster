---
title: AWS and Cloudflare
description: How accounts trust sluis as an OIDC provider, how AWS roles prove themselves to sluis, and how sluis mints short-lived Cloudflare API tokens and R2 credentials.
status: target
sidebar:
  order: 5
---

Two clouds, two shapes. **AWS** federates: it trusts sluis as an OpenID Connect issuer and takes its tokens, so sluis stores nothing of AWS and mints nothing for it. **Cloudflare** cannot accept an external issuer for API tokens, so sluis mints for it, from a tenant's own connection, for declared targets only ([0025](/decisions/0025-integrations/#credential-minters)).

| | AWS | Cloudflare |
|---|---|---|
| Kind | `WorkloadVerifier`, plus accounts that trust sluis | `CredentialMinter` |
| Stored in sluis | Nothing | A `MinterConnection` of the tenant (the minting credential, sealed) and its `MinterTarget` items |
| Bounded by | The roles each account's trust policy allows | `MinterBounds` (config) and the grant that `policy` sealed |

## AWS

AWS appears in three directions, and it helps to keep them apart.

| Direction | Who proves what to whom | Mechanism |
|---|---|---|
| **Accounts trust sluis** | A person or a CI job proves its identity to sluis, then to an AWS account. | An IAM OIDC provider for sluis's issuer; `AssumeRoleWithWebIdentity` at STS. |
| **AWS roles prove themselves to sluis** | A Lambda function, container task or instance running as an IAM role calls a service that trusts sluis. | AWS outbound identity federation; a workload verifier in `exchange` checks the token. |
| **sluis's own actors reach AWS** | A sluis actor writes to its bucket or uses its key. | The boundary's workload issuer and `AssumeRoleWithWebIdentity` ([Identity](/concepts/identity/)). |

### What AWS is for

- **An engineer assumes a role in an account** with their normal sign-in, without an identity-centre product. `aws --profile deployer@123456789012 s3 ls` works because the profile asks sluis for a token and STS accepts it.
- **A CI job deploys** with a role limited to that job. It exchanges its CI identity token for a sluis token for one role's audience and assumes the role. No access key is stored in CI.
- **A Lambda function calls an internal service.** It asks AWS for an identity token for the service's audience; sluis verifies it and returns a token for the function's role and groups.
- **A sluis actor writes its audit archive to a bucket** with credentials from `AssumeRoleWithWebIdentity`, so a compromised node reaches only what the actors it runs may reach ([#870](https://github.com/truvity/sluis/issues/870)).

### Kinds of AWS integration

| Kind | What it does for AWS |
|---|---|
| `WorkloadVerifier` | The verifier driver of `exchange` verifies an AWS outbound-federation token: the issuer is a declared account's, the audience matches, the signature checks against the account's key set, the token is fresh, the account in the role ARN matches, and the subject is a role ARN. It refuses assumed-role sessions, users and the account root. |

The other two directions need no adapter: the account trusts sluis's issuer (a client profile), and a cloud driver exchanges a workload token. AWS has no minter: STS mints the credentials, and sluis only issues the token STS accepts. A vendor that can federate gets no standing credential from sluis.

### What sluis asks AWS for

Nothing long-lived: sluis holds no AWS access key for any direction. In each account the operator creates:

- an **IAM OIDC provider** for sluis's issuer URL (HTTPS, no port, no query);
- **one role per purpose**, whose trust policy names the audience, plus a `sub` condition when the role is for one workload.

For the verifier, sluis reads each account's public key set over outbound access to the AWS token hosts. Each account turns on outbound identity federation, and the role's policy allows it to ask for a token, limited to one audience, the ES384 algorithm and a short duration. AWS accepts ES384, sluis's default, so no RSA key is needed.

### What policy controls for AWS

- **Who may assume which role.** Each role is a client, and its `requires` names the groups that may ask for it. The decision rides in the token's `aud`, which the role's trust policy reads, so AWS holds no per-user statements.
- **For a workload:** matchers on account, role name and path.
- **Lifetime.** The shorter of the group lifetime and the client's cap, with no refresh token. A revocation reaches AWS when the token expires, so give the client a short cap.
- **Trusted accounts** for the verifier, as a declared list in the config kind `ExchangeTrust`. An empty list verifies no AWS token.

### What is audited for AWS

- Every exchange: the proof (person, CI or workload), the audience, the outcome and the groups.
- Each refusal: a role in no group, an unknown audience, a token from an undeclared account. The caller sees one fixed answer for all of them.
- For sluis's own actors, CloudTrail records each `AssumeRoleWithWebIdentity`.

### AWS setup

See [the AWS pattern](/integrations/connecting/#aws-oidc-provider-and-role-trust); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Run `sluis integrations render aws --account acme-prod`. It writes the IAM OIDC provider and one trust policy per declared role, as a template for your infrastructure-as-code tool, so trust comes from the same configuration as the clients.
2. Apply it in the account, and declare the roles as clients with `requires`.
3. A person runs `sluis login`, then `sluis aws-config`, which writes a profile `<role>@<account>` per role they are granted.
4. A CI job uses the exchange action with `audiences: aws:<account>:<role>`, where `<account>` is the account's declared name (`acme-prod` below), never its number ([0017](/decisions/0017-identity-and-sign-in/#audiences)).

```yaml
# ExchangeTrust and InstallationClient, config kinds (example)
accounts:
  acme-prod:
    account: "123456789012"
    verifier:                      # accept AWS roles as workloads
      issuer: https://<id>.tokens.sts.global.api.aws
      algs: [ES384]
clients:
  aws:acme-prod:deployer: { requires: [ci-platform] }
  aws:acme-prod:power:    { requires: [sre] }
```

```ini
# ~/.aws/config written by the command (example)
[profile deployer@acme-prod]
credential_process = sluis aws --audience aws:acme-prod:deployer
region = eu-example-1
```

## Cloudflare

Cloudflare is a credential minter. A tenant's Cloudflare account is a connection that holds one account-level token able to create other tokens, sealed. The Cloudflare adapter opens it at key@ for a mint, and hands out expiring tokens, each cloned from a **prototype** token that a person reviewed. What it hands out is never recorded.

### What Cloudflare is for

- **A release job updates DNS for one zone.** It exchanges its CI identity for a token that can edit DNS on that zone only and expires within the hour.
- **A job writes to an object-store bucket.** It receives R2 credentials scoped to one bucket and, if you want, one prefix, in the form an S3 client expects.
- **An engineer makes an ad hoc change.** They sign in, ask for a target, and get a token that is gone by the end of the day, instead of a long-lived token in a password manager.
- **Infrastructure-as-code runs mint on demand.** Each run asks for its own token; nothing is kept. The adapter sweeps the tokens it minted by listing them at Cloudflare: those under the name prefix that sluis gives its tokens and past their expiry are removed, so no record of a token is needed.

### Kinds of Cloudflare integration

| Kind | What it does for Cloudflare |
|---|---|
| `CredentialMinter` | Opens a mint grant sealed by `policy`, checks the target, creates a token by cloning the prototype with an expiry, and sweeps expired tokens by their name prefix and expiry at the vendor. |

That is the only kind. The Cloudflare adapter is separate from the `cloud-cloudflare` driver, which mints R2 temporary credentials for sluis's own buckets with the boundary's parent token; the two share a library but not a credential ([0013](/decisions/0013-release-train-packaging-and-distribution/#packaging-per-runtime)).

### Connections and targets

| Kind | Class | Holds |
|---|---|---|
| `MinterBounds` | Config | The target types an installation allows a minter to mint (a cloud role, a prototype token, a DNS zone) and the longest lifetime of each |
| `MinterConnection` | Durable, per tenant, sealed | The tenant's Cloudflare account and the minting token |
| `MinterTarget` | Durable, Tenant-adjustable, plain | One thing the tenant may mint: a prototype token or a DNS zone, with the lifetime asked for |

- **A tenant declares its targets inside the bounds.** The store refuses a target outside `MinterBounds`, and a request for a target that is not declared is refused with `NOT_FOUND`.
- **An IaC tool that creates a target through the API** makes durable data of the tenant, not config.
- **A minter whose "tenant" is not a sluis tenant,** such as the NATS operator, keeps its credential as the secret kind `MinterSecret`, bounded by `MinterBounds` ([0025](/decisions/0025-integrations/#credential-minters)).

### What sluis asks Cloudflare for

| Token | Held by | Permissions |
|---|---|---|
| **The minter token** | The tenant's `MinterConnection`, sealed | The account's API-token management permission, read and write, nothing else. |
| **A prototype token, one per target** | Cloudflare only; its value is never read | The rights a minted token should have, such as *DNS write* on one zone or *Bucket item write* on one bucket. Created, then **disabled**, so it is a template. |

**The minter is the sharpest credential in the integration.** A token that can create tokens can create anything the account owner can, and Cloudflare does not let you cap that on the token (checked against the live API in October 2026). The protection is on sluis's side:

- The adapter refuses a prototype that is active, missing, or grants token administration, billing, account settings, memberships or access-identity rights. This refusal list is a floor in code: configuration can add names, not remove them.
- A target can list the permission groups its prototype may hold (`allowed_permission_groups`); anything else is refused. Prefer setting it.
- The minter credential is sealed at rest, opened only by the adapter for one call, and never leaves it.

Cloudflare's own limits apply: about 1,200 API requests per five minutes per user, and 500 tokens per account.

### What policy controls for Cloudflare

- **Who may mint which target.** A grant maps a group to targets. Pin a CI job by the verified attributes of its identity (repository, ref, workflow file), not by a workflow name.
- **How much.** Live tokens per caller and per target, and mints per caller per hour, are enforced by `policy` and `quota` **before** the adapter is called. The adapter enforces only Cloudflare's limits.
- **The lifetime** per target, under the longest lifetime that `MinterBounds` allows.

A token request is a standard token exchange with `audience=cloudflare:<target>`.

### What is audited for Cloudflare

- Each mint: the target, the caller, the grant and the expiry. **The token value is never recorded.**
- Each refusal and its reason: not granted, target refused, cap exceeded, rate limited.
- Each connection made, changed or disconnected, without its credential.

### Cloudflare setup

See [the setup pattern](/integrations/connecting/#cloudflare-the-minting-token); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Create the minter token with token-management permission only. Enter it through the console or the API, or from standard input: `sluis integrations connect cloudflare --account main`.
2. Create each prototype token with the rights a minted token should have, then disable it.
3. Declare the targets, and write the grants in the policy.

```yaml
# MinterTarget items of a tenant, written through the API (example)
targets:
  - id: dns-example
    prototype: <prototype-token-id>
    allowed_permission_groups: ["DNS Write"]
    lifetime: 1h
  - id: r2-archive
    prototype: <r2-prototype-token-id>
    endpoint: https://<account-id>.r2.cloudflarestorage.com
    lifetime: 1h
```

```text
$ sluis cloudflare token dns-example
CLOUDFLARE_API_TOKEN=...
```
