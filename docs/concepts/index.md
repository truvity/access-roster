---
title: Concepts
description: "The vocabulary of sluis v2: the terms the concept pages use, each with a one-line meaning and a link to the page that explains it."
status: target
sidebar:
  order: 0
---

The concept pages explain the model the rest of the documentation relies on. This is their vocabulary, one line per term. For the same system drawn as boxes, see [Architecture](/architecture/).

| Term | Meaning | Page |
|---|---|---|
| **Actor** | A process with one responsibility that declares the ports it requires | [Actors](/concepts/actors/) |
| **Actor instance** | An actor in one boundary, named `<actor>@<boundary>`, such as `ca@prod` | [Actors](/concepts/actors/#naming) |
| **Fusion rule** | When two actors may share one unit on a small machine | [Actors](/concepts/actors/#the-fusion-rule) |
| **Grant** | The decision of `policy`, sealed under the sealing key; a minter acts only on a grant it can open | [Actors](/concepts/actors/#why-the-signer-and-the-policy-are-separate) |
| **Integration actor** | A process for one vendor tenant and one credential; it never decides | [Integrations](/integrations/) |
| **Permission manifest** | What one actor may touch, generated into every enforcement layer | [Architecture](/architecture/) |
| **Port** | An abstract interface: keys, state, lease, blob, transport, index, witness, cloud, secrets, export, config-source | [Ports and drivers](/concepts/drivers/) |
| **Capability flag** | A property of a port a consumer can require, such as compare-and-set on `state` | [Ports and drivers](/concepts/drivers/) |
| **Driver** | An implementation of a port, started by the platform beside its actor | [Ports and drivers](/concepts/drivers/) |
| **`key-holder`** | The one mediating driver, fronting a node's card | [Ports and drivers](/concepts/drivers/) |
| **Runtime** | Bare-metal, serverless or kubernetes | [Runtimes](/runtimes/) |
| **Installation** | A runtime, its nodes, its dependencies and one driver per port; four are tested | [Installations](/runtimes/installations/) |
| **Boundary** | A unit of isolation: an environment, a company or a product | [Boundaries](/concepts/boundaries/) |
| **Isolation ladder** | The levels a boundary can take, from L0 (tenant) to L4 (its own runtime) | [Boundaries](/concepts/boundaries/#the-isolation-ladder) |
| **Authority key** | A key that signs for others: a CA intermediate, the token-signing key, an SSH CA key | [Keys](/concepts/keys/) |
| **Sealing key** | The key per environment that wraps data keys and seals grants | [Keys](/concepts/keys/) |
| **Subject** | The opaque id of a person, the same at every issuer | [Identity](/concepts/identity/#a-persons-subject) |
| **Trust domain** | The SPIFFE name of a boundary | [Identity](/concepts/identity/#trust-domains) |
| **Proof** | What a machine presents to get a credential | [Identity](/concepts/identity/#proof-kinds-are-verifier-drivers) |
| **Trust bundle, root list** | The certificates a host trusts, and the root-signed list they chain to | [Identity](/concepts/identity/#the-trust-bundle) |
| **Audit log** | The tamper-evident log sealed in batches by its one writer | [Audit](/concepts/audit/) |
| **Usage stream** | Usage events built from the same call as the audit record | [Audit](/concepts/audit/) |
| **Record kind** | A kind of stored record, which only its owning actor may write | [Data and secrets](/concepts/data/) |
| **Backup** | A copy of authoritative state; derived data is rebuilt | [Backup](/concepts/backup/) |
| **Install file** | The declared configuration of one installation | [Configuration](/concepts/configuration/) |
