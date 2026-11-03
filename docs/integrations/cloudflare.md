---
title: Cloudflare
description: How sluis mints short-lived Cloudflare API tokens and R2 credentials by cloning a disabled prototype token, and why the minting token is the sharpest edge.
status: target
sidebar:
  order: 5
---

Cloudflare is a credential minter. sluis holds one account-level token that can create other tokens, and uses it to hand out expiring tokens, each cloned from a **prototype** token that an operator reviewed.

## What it's for

- **A release job updates DNS for one zone.** It exchanges its CI identity for a token that can edit DNS on that zone only and expires within the hour.
- **A job writes to an object-store bucket.** It receives R2 credentials scoped to one bucket and, if you want, one prefix, in the form an S3 client expects.
- **An engineer makes an ad hoc change.** They sign in, ask for a preset, and get a token that is gone by the end of the day, instead of a long-lived token in a password manager.
- **Infrastructure-as-code runs mint on demand.** An on-demand preset stores nothing; each run mints its own token, and the token is swept after it expires.

## Integration kinds

| Kind | What it does for Cloudflare |
|---|---|
| `CredentialMinter` | Opens a mint grant sealed by `policy`, checks the prototype, creates a token by cloning the prototype with an expiry, and sweeps expired tokens it created. |

That is the only kind, as `cloudflare@<company>`. It is separate from the **`cloud-cloudflare@<boundary>` driver**, which mints R2 temporary credentials for sluis's own buckets with the boundary's parent token; the two share a library but not a credential ([ADR 0003](/decisions/0003-units-transports-and-fusion/#per-driver-checks)).

## What sluis asks the vendor for

| Token | Held by | Permissions |
|---|---|---|
| **The minter token** | The Cloudflare integration, as a credential | The account's API-token management permission, read and write, nothing else. |
| **A prototype token, one per preset** | Cloudflare only; its value is never read | The rights a minted token should have, such as *DNS write* on one zone or *Bucket item write* on one bucket. Created, then **disabled**, so it is a template. |

**The minter is the sharpest credential in the integration.** A token that can create tokens can create anything the account owner can, and Cloudflare does not let you cap that on the token (checked against the live API in October 2026). The protection is on sluis's side:

- sluis refuses a prototype that is active, missing, or grants token administration, billing, account settings, memberships or access-identity rights. This refusal list is a floor in code: configuration can add names, not remove them.
- A preset can list the permission groups its prototype may hold (`allowed_permission_groups`); anything else is refused. Prefer setting it.
- The minter credential is sealed at rest, readable only by the integration's own process, and never leaves it.

Cloudflare's own limits apply: about 1,200 API requests per five minutes per user, and 500 tokens per account.

## What policy controls

- **Who may mint which preset.** A grant maps a group to presets. Pin a CI job by the verified attributes of its identity (repository, ref, workflow file), not by a workflow name.
- **How much.** Live tokens per caller and per preset, and mints per caller per hour, are enforced by `policy` and `quota` **before** the minter is called. The minter enforces only Cloudflare's limits.
- **The lifetime** per preset, and whether the token is stored and rotated or minted on demand.

A token request is a standard token exchange with `audience=cloudflare:<preset>`.

## What is audited

- Each mint: the preset, the caller, the grant and the expiry. The token value is never recorded.
- Each refusal and its reason: not granted, prototype refused, cap exceeded, rate limited.
- Each sweep, and drift: a token under sluis's prefix that is not in its record, or the reverse.

## Setup

See [the setup pattern](/integrations/connecting/#cloudflare-the-minting-token); names and keys are [illustrative](/integrations/#examples-are-illustrative).

1. Create the minter token with token-management permission only, and store it with `sluis credentials put cloudflare.main.minter`, which reads standard input.
2. Create each prototype token with the rights a minted token should have, then disable it.
3. Run `sluis integrations connect cloudflare --account main`, declare the presets, and write the grants in the policy.

```yaml
# /etc/sluis/install.yaml (example)
integrations:
  cloudflare:
    main:
      actors: [minter]
      account_id: <account-id>
      minter: cred:sluis-int-cloudflare.main.minter
      presets:
        dns-example:
          prototype: <prototype-token-id>
          allowed_permission_groups: ["DNS Write"]
          lifetime: 1h
          mode: on-demand
        r2-archive:
          prototype: <r2-prototype-token-id>
          endpoint: https://<account-id>.r2.cloudflarestorage.com
          lifetime: 1h
          mode: stored
          rotation: 20m
```

```text
$ sluis cloudflare token dns-example
CLOUDFLARE_API_TOKEN=...
```
