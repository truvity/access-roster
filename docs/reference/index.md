---
title: Reference
description: "The specs the first working version is built against: commands, install file, vocabulary, contracts, storage, policy, approved libraries and actors."
status: target
sidebar:
  order: 0
---

These pages fix the shapes a developer needs before writing code for the [first working version](/roadmap/): the names, fields, formats and codes that the decision records leave to a spec. A decision record says why; a page here says exactly what. When a page and a [decision record](/decisions/) disagree, the record is the reasoning and the page is fixed.

| Page | What it fixes |
|---|---|
| [Actor registry](/reference/actors/) | Every actor: language, placement, keys and slots, ports, governing ADRs, requirement areas, standards, issue label |
| [Commands](/reference/cli/) | The `sluis` command tree of the first working version, its flags, its JSON output and its exit codes |
| [Install file](/reference/install-file/) | The install-file schema v1, and the example file of the local installation |
| [Configuration sources](/reference/config-sources/) | The `sources` list, the composition rule with its refusals and vectors, the signed document and what a source driver returns |
| [Contracts and errors](/reference/contracts/) | How `proto/` is written and versioned, which services are public, and the error model |
| [Storage](/reference/storage/) | The port contracts, the record kinds of the first working version, the state envelope and the on-disk layout of the local drivers |
| [Policy](/reference/policy/) | The Cedar schema, its entity types and actions, template links, and a worked example with test vectors |
| [Vocabulary](/reference/vocabulary/) | The grant vocabulary file, schema v1: scopes, things, roles, the role ladder and sensitive scopes |
| [Approved libraries](/reference/approved-libraries/) | The cryptography and parser libraries each language may use, and the choices made for each |

The permission manifest, which generates the enforcement, is on [Architecture](/architecture/manifest/).

Each page marks a point that still needs the maintainer as a proposed note that links its issue. Everything else on these pages is decided.
