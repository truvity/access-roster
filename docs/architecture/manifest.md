---
title: Permission manifest
description: "The format of the permission manifest, one per actor: its fields, how kinds, keys, sockets, calls and hosts are named, the uid table and the generators."
status: target
sidebar:
  order: 5
---

Every actor has one **permission manifest**. It states what the actor may read and write, which keys and secrets it may use, which sockets it listens on, which actors it calls and which may call it, and which hosts it may reach; nothing that enforces least privilege is written by hand, because the manifest generates it ([ADR 0002](/decisions/0002-families-of-actors/#registries-generate-the-enforcement), [Architecture](/architecture/#the-permission-manifest-is-the-spine)). This page fixes the manifest's format and its generators ([#863](https://github.com/truvity/sluis/issues/863)).

## Files

```text
manifest/
  Actor.pkl            the base module: the fields below and their checks
  uids.pkl             the pinned uid of every actor and driver
  actors/<actor>.pkl   one manifest per actor, amending Actor.pkl
  generated/           the JSON of every manifest and the JSON Schema of the format
```

- **One Pkl module per actor**, named as in the [actor registry](/reference/actors/). Pkl runs at build time only; the build writes each manifest as JSON and the format's JSON Schema under `manifest/generated/`, and the generators read only that JSON ([ADR 0004](/decisions/0004-the-data-model/#schemas-are-protobuf)). Generated files are committed, and CI fails on a stale one.
- **The registry and the manifests agree.** Every actor of the registry that has an executable has a manifest, and the generator refuses a manifest of an actor the registry lacks.
- **An integration kind has one manifest per kind**; an integration instance (`github@<org>`) adds its declared egress hosts and its secrets from the install file, within what the kind's manifest allows.

## Fields

| Field | Meaning |
|---|---|
| `actor` | The actor's name |
| `instances` | `any`, or `exactly 1`, which needs a lease with more than one node ([ADR 0003](/decisions/0003-units-transports-and-fusion/#units)) |
| `ports` | For each port it uses: `required` or `optional`, and the capability flags it needs (`compare-and-set` on state, a lock mode on blob) |
| `records` | The record kinds it reads or writes: `kind`, `access` (`write` or `read`), and for a written kind its `origin`, `durability` and whether it `accepts_operator_set` ([ADR 0004](/decisions/0004-the-data-model/#storage-classes)) |
| `keys` | The key purposes it uses: `purpose`, the operations (`sign`, `public-key`, `wrap`, `unwrap`) and, for a wrap or an unwrap, the encryption `context` |
| `secrets` | The secret names it reads or writes behind the `secrets` port |
| `listens` | Its sockets: `api` for every actor, and `public` for `entry` only |
| `calls` | The services it calls: the actor and the Connect service, such as `{ actor: signer, service: sluis.signer.v2alpha1.SignerService }` |
| `called_by` | The actors that may call each service it serves |
| `egress` | The hosts and ports it may reach outside the node: none for a core actor; an integration's vendor hosts |

### How things are named

| Thing | Name | Defined on |
|---|---|---|
| A record kind | singular kebab-case, unique per boundary | [Storage](/reference/storage/#record-keys) |
| A key purpose | the purposes of ADR 0006 (`token-signing`, `sealing`, …) | [Storage](/reference/storage/#keys) |
| A service | `sluis.<actor>.v2alpha1.<Name>Service` | [Contracts and errors](/reference/contracts/#packages-and-files) |
| A socket | `/run/sluis/<actor>/<boundary>.sock` for `api`; `/run/sluis/entry/<boundary>-public.sock` for `public` | [ADR 0003](/decisions/0003-units-transports-and-fusion/#listeners) |
| An instance | `<actor>@<boundary>`, the same in every layer | [ADR 0002](/decisions/0002-families-of-actors/#names) |

### Rules the generator enforces

- **One writer per kind:** two manifests that both write one kind are refused ([ADR 0004](/decisions/0004-the-data-model/#one-writer-per-kind)).
- **Both ends of every edge:** a call is allowed only when the caller's `calls` and the callee's `called_by` both name it, so neither side can grant itself a caller or a callee.
- **Only `entry` listens publicly,** and a manifest that uses an authority key never has a `public` socket ([ADR 0003](/decisions/0003-units-transports-and-fusion/#fusion)).
- **`policy` has no `records`, no `egress` and no `calls`** ([ADR 0007](/decisions/0007-policy-and-sealed-grants/)).
- **A purpose used to sign has exactly one user actor**; a purpose used to wrap and unwrap, such as `sealing`, may have several, each with its own context ([ADR 0006](/decisions/0006-keys-and-sealing/#key-purposes)).
- **A fused unit's manifest is the union of its actors'**, and it is refused when it holds a key and a `public` socket together ([The fusion rule](/decisions/0003-units-transports-and-fusion/#fusion)).

## An example: `signer`

```pkl
amends "../Actor.pkl"

actor = "signer"
instances = "any"
ports {
  ["keys"] { use = "required" }
  ["state"] { use = "required"; flags { "compare-and-set" } }
  ["transport"] { use = "required" }
}
records {
  new { kind = "signing-ring"; access = "write"; origin = "issued"; durability = "durable" }
  new { kind = "data-key"; access = "write"; origin = "issued"; durability = "durable" }
}
keys {
  new { purpose = "token-signing"; ops { "sign"; "public-key" } }
  new { purpose = "sealing"; ops { "wrap"; "unwrap" }; context = "data-key" }
}
listens { "api" }
called_by {
  ["sluis.signer.v2alpha1.SignerService"] { "session"; "exchange" }
}
```

`signer` calls no actor and reaches no host; its key set reaches the blob through the issuer documents ([Storage](/reference/storage/#fs)).

## The uid table

- **`manifest/uids.pkl` pins one uid per actor and per driver,** the same in the Compose file and in the chart ([ADR 0011](/decisions/0011-runtimes-and-installations/#the-local-installation)). A uid is never reused, even for a retired actor.
- **On bare-metal the packages make named system users,** `sluis-<actor>-<boundary>`, so the uid table applies to images only ([ADR 0002](/decisions/0002-families-of-actors/#names)).

- **A uid for each boundary's instance in containers.** An instance of each boundary has its own uid on bare-metal (L2, [The isolation ladder](/decisions/0008-boundaries-and-tenants/#the-ladder)), and so it has in containers: the uid of `<actor>@<boundary>` is the actor's pinned base uid plus 1000 times the number that the install file declares for the boundary (`boundaries.<name>.uid_block`, an integer from 0 to 54, unique in the file). The base uids are in the range 10000 to 10999, so no two instances of any actors share a uid and the peer-uid check on a shared socket tells `ca@dev` from `ca@prod`. The number is stable when a boundary is added and is never reused after a boundary is removed. A one-boundary installation, such as the local installation of the first working version, declares block 0 and so runs on the base uids. Callers differ between boundaries, so the instances are kept apart ([principle 3](/principles/#3-keys-are-shared-rotated-and-given-to-tenants-by-rule)).

## Generators

Every generator reads the JSON manifests and the install file, writes its output, and has a golden test and a place in the deny matrix ([Integration invariants](/architecture/components/#integration-invariants)).

| Generator | Output | First needed by |
|---|---|---|
| Compose | The local installation's Compose project: one service per actor instance and per driver, its `user:`, the socket volumes it may mount, `network_mode: none` except for integrations and the edge forwarder, a read-only root file system, no capabilities | The first working version |
| Library scopes | The `<boundary>/<kind>` scopes and key purposes each port library allows | The first working version |
| `key-holder` access list | `(caller actor, purpose, operation)` and the socket per caller | The first working version |
| Call graph | The table the interceptor of every process enforces | The first working version |
| Deny matrix and blast radius | The tests that every other actor is denied each actor's records, keys, secrets and sockets, and the checked-in report of what each actor can reach | The first working version |
| systemd | Template units, sockets and sandbox drop-ins | Boards |
| Store users | One rqlite cluster per (boundary, owning actor), with its `execute` and `query` users | Boards |
| Cloud policies | IAM roles and policies, KMS key policies, queue and bucket policies, as documents for the infrastructure code | Lambda, Kubernetes |
| Kubernetes | ServiceAccounts, NetworkPolicies, the chart's per-actor values | Kubernetes |
| Explorer data | The actors, drivers and edges of the architecture explorer ([#882](https://github.com/truvity/sluis/issues/882)) | When the manifests exist |
