---
title: Reference
description: "The specs the first working version is built against: the registries, commands, bootstrap file, signed config, contracts, store API, policy and libraries."
status: target
sidebar:
  order: 0
---

These pages fix the shapes a developer needs before writing code for the [first working version](/roadmap/): the names, fields, formats and codes that the decision records leave to a spec. A decision record says why; a page here says exactly what. When a page and a [decision record](/decisions/) disagree, the record is the reasoning and the page is fixed.

The three registries that generate the enforcement have a generated page each ([The registries are the spine](/architecture/#the-registries-are-the-spine)). The other pages are written by hand.

| Page | What it fixes |
|---|---|
| [Actor registry](/reference/actors/) | Every actor: family, language, placement, key purposes, ports, the actors it calls, egress, governing records, requirement areas, standards, issue label |
| [Kinds](/reference/kinds/) | Every kind: its storage class, scope, treatment, profile, layer, writer, readers, lifetime, indexes, and whether it is exportable and backed up |
| [Rules](/reference/rules/) | The actor × kind × verb matrix, the writer of every kind, and the deny matrix |
| [Keys](/reference/keys/) | Every key purpose and data key: algorithm, key type on AWS, board slot, the actor that uses it, and the slot plan |
| [Commands](/reference/cli/) | The `sluis` command tree of the first working version, its flags, its JSON output and its exit codes |
| [Bootstrap file](/reference/bootstrap-file/) | The file store@ reads at start: its keys, its checks, and the example for the local installation |
| [Signed config](/reference/signed-config/) | The signed config document, its sequence, the snapshot rules and the test vectors |
| [Contracts and errors](/reference/contracts/) | How `proto/` is written and versioned, which services are public, and the error model |
| [Store API](/reference/store-api/) | The store service on the wire, the typed clients, the item contract of the drivers, the address encoding and the sealed envelope |
| [Policy](/reference/policy/) | The Cedar schema, its entity types and actions, template links, the grant vocabulary file, and a worked example with test vectors |
| [Approved libraries](/reference/approved-libraries/) | The cryptography and parser libraries each language may use, and the choices made for each |

Each page marks a point that still needs the maintainer as a proposed note that links its issue. Everything else on these pages is decided.
