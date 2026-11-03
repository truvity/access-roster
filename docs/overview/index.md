---
title: Overview
description: Start here. What sluis is, who it is for, what it does and what it leaves out, how v2 relates to v1, and a map of the documentation.
status: target
sidebar:
  order: 1
---

sluis is an open-source identity and access broker for people, robots and external systems. It sits between the identity providers that already know who someone is and the systems that need a credential before they let that someone in.

## Who it is for

sluis is for engineers who run the identity layer of a small organisation, a platform team or a self-hosted lab, and want it small, auditable and cheap to run. The mission is on the [home page](/).

An installation is one of two kinds, and the two are distinct installations of the same product ([roadmap](/roadmap/#a-core-and-two-later-modules)):

- A **workforce installation** signs in the people of an organisation and reconciles its systems. It runs the core.
- A **customer installation** adds the CIAM layer ([0032](/decisions/0032-customer-identity-installations/)) and brokers an external customer-identity product for the end users of several products. The core is the same in both; the CIAM layer and the quota module are later layers.

Every installation runs the same **foundation**: store@ for data, exporter@ for export and key@ for keys. Identity, audit and quota are **modules** on top of it, and an installation runs the modules it needs, such as the audit module alone ([Families](/concepts/families/#the-foundation-and-the-modules)).

The people who work with either kind are these.

- **Operators** install it on a workstation, on three single-board computers, as AWS Lambda functions or on Kubernetes. The same actors and configuration run on each; these four are the [tested installations](/runtimes/).
- **Platform and security engineers** write the policy that says who may get which credential, and read the audit trail that says who did.
- **Integrators** add sign-in providers, directory sources and credential minters as adapters: work actors that implement one of the ConnectRPC contracts of [Integrations](/integrations/).

## What it does

- It **federates sign-in** from upstream identity providers, so people use the accounts they already have.
- It **issues OIDC tokens** and **exchanges tokens** (RFC 8693): a robot or a CI job presents a token from the system it runs on and receives a sluis token for the system it wants to reach.
- It **mints short-lived downstream credentials**, such as cloud credentials, GitHub installation tokens and certificates. Nothing it hands out is meant to outlive the task.
- It **reconciles directory facts** from workspace directories and GitHub teams, so that policy can say "members of this team" without sluis owning the team.
- It **writes a tamper-evident audit trail** of every flow, refusals included ([Audit](/concepts/audit/)).

The part that holds a key is small and parses no internet input, and the part that decides is separate from the part that signs. Work actors hold no storage, key or audit credential at rest; only the data, keys and audit families do ([Families](/concepts/families/)).

## What it leaves out

- **It is not a general secrets engine.** It keeps the secrets it generates or receives as sealed or hashed data, reads the secrets an operator gives it from a secret source, and publishes a small typed set of values, but has no general key-value store, transit engine or lease system for others. Use a secrets manager for those ([Data](/concepts/data/)).
- **It has no users of its own and holds no roots.** It writes no Kubernetes object, except a Secret that exporter@ writes when an installation chooses the direct path. Roots belong to the sister product [ritueel](https://ritueel.id). The reasons are in [what sluis is, and is not](/principles/#what-sluis-is-and-is-not).

## v1 and v2

v1 is the sluis that runs today, a set of AWS Lambda functions on the `master` branch. v2 is a rewrite on `main` that shares no history with v1. v2 first reaches parity with v1 (the [features page](/features/) lists what that means); after parity it adds FAPI 2.0, and later CIBA, once a real consumer exists, in poll mode with a passkey on the approving device ([#980](https://github.com/truvity/sluis/issues/980)). The two lines coexist until the maintainer's own deployments run v2 ([ADR 0001](/decisions/0001-v1-and-v2-lines/)). The order of delivery is on the [roadmap](/roadmap/); the v1 documentation is at [/v1/](/v1/).

## Map of the documentation

| Section | What you find there |
|---|---|
| [Design principles](/principles/) | The yardstick the decision records follow. |
| [Concepts](/concepts/) | The model and its vocabulary: [families of actors](/concepts/families/), [data](/concepts/data/), [keys](/concepts/keys/), [boundaries](/concepts/boundaries/), [identity](/concepts/identity/) and [audit](/concepts/audit/). |
| [Integrations](/integrations/) | Every system sluis connects to, and how to set it up. |
| [Architecture](/architecture/) | The three zoom levels, the components and the deployment, and the registries behind them ([Kinds](/reference/kinds/), [Rules](/reference/rules/), [Actors](/reference/actors/)). |
| [Security](/security/threat-model/) | The threat model and break-glass recovery. |
| [Runtimes](/runtimes/) | Bare-metal, serverless and Kubernetes, and the four tested installations. |
| [Reference](/reference/) | The specifications the first working version is built against. |
| [Tutorial](/tutorials/single-node-install/) | A step-by-step install on a single node. |
| [Distribution](/distribution/packages/) | Packages, platforms and release signing. |
| [Standards](/standards/) | The specifications sluis follows and how conformance is proved. |
| [Decisions](/decisions/), [Roadmap](/roadmap/), [Project status](/status/) | The reasoning, the milestones and where the work stands. |

A badge beside each title says whether the page describes a design not built yet, something partly built or something shipped. Plain prose is the design; a **Proposed** note names the open issue that will settle it. The rules are in [Target-state pages](/contributing/pages/).
