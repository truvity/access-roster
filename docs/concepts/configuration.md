---
title: Configuration
description: "How sluis is configured: the install file, a schema defined in Pkl and checked as JSON Schema, layers, operator-set records, live reload and explain."
status: target
sidebar:
  order: 9
---

sluis is configured by files that an operator reads and edits, and by the records an operator sets on the console. The design makes four promises about them: a file that is wrong is refused before anything takes effect; a field that does not exist is an error, not silently ignored; any value can be traced to the origin and the layer that set it; and an operational switch can never change who may do what. The rules are [ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/).

## Pkl at build time, JSON Schema at run time

The shape of the configuration is defined once, in **Pkl**, and Pkl runs at build time only ([ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#pkl-and-json-schema)). The build generates a **JSON Schema** (draft 2020-12), which is part of the public API, the Helm values schemas and the reference documentation; where Pkl has no generator, a separate open-source tool fills the gap. Generated artifacts are committed, and CI fails on a stale one. **There is no Pkl at run time**: the Pkl tool is about 95 MiB and pkl-go spawns it as a child process, too heavy for a small board or a Lambda function.

- **The schema is embedded in each binary** that loads configuration, and has a stable `$id` with its version in the path. An incompatible change is a new version under a new path, beside the old one.
- **Go and Rust types are hand-written** behind the JSON Schema check; a small generator comes later, when it pays for itself.
- **One validator per language, with shared conformance vectors:** `santhosh-tekuri/jsonschema/v6` in Go, the `jsonschema` crate in Rust, `ajv` in TypeScript. Each vector is a document with the expected verdict and error path, and a validator that disagrees fails the build.
- **Strictness comes from the schema.** `unevaluatedProperties: false` makes an unknown key an error that names the path, and format assertions are on, so a field declared as a URL or a duration is checked as one. Errors never show the value.
- **Retired fields:** a retired option set in a declared file is refused. A retired field in a record that sluis wrote itself is read, ignored and never written again.
- **Telemetry is not configured in the file**: it is the standard `OTEL_*` environment variables only.

The schema also carries each record kind's **origin** and each field's **sensitivity** ([Data and secrets](/concepts/data/#origins-and-sensitivity)); CI checks them, and the backup list, the telemetry allowlist and the audit redaction are generated from them.

## What is configured: an installation

The thing an operator configures is an **installation**: one concrete deployment, made of a **runtime** (bare-metal, serverless or Kubernetes, see [Runtimes](/runtimes/)), the **nodes** (1, N, or elastic on serverless), the available **dependencies** (an AWS account, a Cloudflare account, a YubiKey, a NATS service) and one **driver** per port ([Ports and drivers](/concepts/drivers/)). "Installation" is not a configuration key: the install file *is* the installation ([ADR 0018](/decisions/0018-runtimes-installations-and-delivery-order/#runtime-kinds)). The four tested installations ([local, boards, lambda and kubernetes](/runtimes/installations/)) ship as example install files used by the documentation, the tutorials and the test matrix; an operator copies one as a starting point. The word **environment** is kept for development, staging and production.

**One install file per installation, also in a federation.** A sluis that spans several [boundaries](/concepts/boundaries/) is a front installation plus one boundary installation for each L4 boundary, each with its own install file, joined by declared trust. A boundary below L4 is declared in the install file of the installation that holds it, and every actor instance it gets is named `<actor>@<boundary>` ([Actors](/concepts/actors/)). On bare-metal a systemd generator reads `/etc/sluis/install.yaml` and creates those instances from the template units; on Kubernetes the chart's presets do the same. Nothing generates packages per installation.

## Layers

Declared values come from layers, and a later layer overrides an earlier one ([ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#origins)):

1. **defaults**, built into the schema;
2. **runtime**, the defaults of the runtime kind;
3. **install**, the file the operator edits;
4. **environment overrides**, for the values that differ between development, staging and production, including the few fields marked as tunable that a process environment variable may set.

Layers apply inside declared configuration only; operator-set is an origin, not a layer.

## Declared and operator-set

Two of the five origins are configuration, because they are an operator's intent:

| Origin | What it is | Written by |
|---|---|---|
| **declared** | Reviewed files or infrastructure as code, delivered read-only | Nobody at run time; the operator, through review and deployment |
| **operator-set** | A lasting choice a person makes on the console, the CLI or the API, such as the chat channels an integration manages or a runtime switch, for the record kinds that accept it | The actor that owns the record kind, which validates the write; every change is audited under the person's name |

The **effective configuration** is declared overlaid with operator-set. Learned facts and issued records are data that the configuration refers to, not configuration.

- **Declared locks.** A field that declared sets cannot be changed on the console, which shows it as locked. Otherwise the order is declared, then operator-set, then the schema default.
- **Tighten-only switches** (recovery off, a reconciler paused, a lower quota limit) may be moved by an operator in their safe direction even when declared sets them. Moving one back is a declared change that names a new generation, so a stale document cannot undo a tightening.
- **An object defined in both places is held**: nothing changes on it until one side is removed, or a declared fragment adopts the operator-set record with `adopts: <kind>/<id>@<revision>`.
- **Authority is declared.** Two things are issued under it at run time, inside a declared delegation policy and a declared template: Cedar policies linked from templates ([ADR 0009](/decisions/0009-policy-is-cedar-in-a-rust-actor/#template-links)) and instance records such as tenants, accounts, upstream connections and a tenant's clients ([Issued instances](#issued-instances)).

**Switches never reach authority.** Authority says who may do what: policy, grants, the clients that may ask for tokens. Tunables (a log level, a timeout, the choice of a driver) are declared and may come from an environment override; runtime switches (recovery off, a paused reconciler, an acknowledged breaker) are operator-set, read live and tighten-only where they touch safety.

A secret in configuration is a reference such as `{ credential: idp-client-secret }`, resolved at run time from a read-only source, and later also through the `secrets` port ([Install file](/reference/install-file/#format), [Secrets and export](/concepts/data/#secrets-and-export)). The value never appears in a file, in `explain` output, in logs or in a crash dump.

## Sources

Declared configuration can come from more than the install file. A **source** is a file, a Lambda layer, a mounted ConfigMap or AWS AppConfig, read through the `config-source` port ([ADR 0057](/decisions/0057-configuration-sources-are-a-port-sources-own-disjoint-paths-authority-is-signed-and-a-failing-source-keeps-the-version-in-force/)). The install file is the base and lists the others in `sources`. Each source owns paths that no other owns, so the merged document is a union and nothing overrides anything; each document is checked before it is merged, and the result once after. Authority delivered through a service is a signed document, verified before it is parsed. The rules and the vectors are [Configuration sources](/reference/config-sources/); which drivers an installation offers is on [Installations](/runtimes/installations/#configuration-sources).

## Issued instances

Authority says who may do what, and it is written once, in git, and reviewed. What a tenant or a customer creates is an **instance**: an issued record made at run time by a declared client or an operator under a declared template, bounded by a declared delegation policy, and audited with the template, the slot values and the delegation that permitted it ([ADR 0031](/decisions/0031-declared-and-issued-configuration-authority-is-declared-and-instances-are-issued/)). An instance holds no authority its template did not carry.

- **A workforce installation** declares its authority in git and has it delivered through a configuration service, which is AWS AppConfig on serverless or the equivalent for the runtime, with live reload.
- **A customer-identity installation** declares its own authority the same way. Its per-customer defaults, values for the slots of a template within the template's bounds, live in project configuration of the configuration service and not in git. Per-tenant changes and the organisation of users belong to a customer-identity module outside the core of sluis.

## Live reload

Declared configuration may **live-reload as whole versioned snapshots**, from a file, a ConfigMap, a Lambda layer or AWS AppConfig. A new snapshot is validated as `sluis config check` validates it, swapped atomically and audited with its digest; a snapshot that fails is refused and the version in force stays. A snapshot is the whole composition of the sources, never one source alone, and each driver signals a change in its own way: a file by notify, AppConfig by poll ([Configuration sources](/reference/config-sources/#what-a-driver-returns)). Not every path can change in a running instance. Every path of declared configuration is `live` (applied on reload) or `restart` (a change is refused at reload and applied by a restart), marked in the schema; keys, stores, drivers, listeners and trust are `restart`, and clients, policy, grants and roles are `live`. A snapshot that changes a `restart` path is refused as a whole, and `sluis config check --against` lists those paths beforehand. The rule is [ADR 0010](/decisions/0010-configuration-and-data-pkl-schema-origins-and-sensitivities/#reload-classes) and the classes by area are [Which keys reload](/reference/install-file/#which-keys-reload). Operator-set values are read live through the `state` port, with a short cache whose lifetime is part of the field's schema.

## Checking and explaining

`sluis config check` validates the configuration against the schema, then validates the installation against the requirements its drivers declare and refuses a combination that cannot work ([How `sluis config check` validates an installation](/concepts/drivers/#how-sluis-config-check-validates-an-installation)). `sluis config explain` prints each field's effective value, its origin and the layer that set it.

Both are **offline by default**, so CI runs them with no call to sluis. With `--live` they also read the operator-set records through the console API, with an operator's credentials: `check --live` lists held objects and the records a new declared fragment would lock or hold, and `explain --live` shows, for an operator-set value, the record id, its revision, who set it and when.

An excerpt of an install file, `/etc/sluis/install.yaml`, in the keys of [install-file schema v1](/reference/install-file/), which lists every key. It is not a valid file on its own: v1 also requires `boundaries`, `clients`, `policy` and `trust`, and `org` on an upstream, and it accepts only `software` as the `keys` driver; `yubikey-piv` arrives with the boards installation.

```yaml
runtime: bare-metal
environment: production
nodes: 1
front:
  host: sluis.example.com
  rp_id: example.com
drivers:
  keys: yubikey-piv
  state: embedded
upstreams:
  workforce:
    kind: oidc
    org: example                                       # a company boundary, omitted here
    issuer: https://idp.example.org
    client_id: sluis-example
    client_secret: { credential: idp-client-secret }   # a reference, never the secret
```

What `sluis config explain` prints for it:

```text
runtime                                = bare-metal                  install   /etc/sluis/install.yaml:1
front.host                             = sluis.example.com           install   /etc/sluis/install.yaml:5
drivers.keys                           = yubikey-piv                 install   /etc/sluis/install.yaml:8
actors.session.log_level               = debug                       environment override   (tunable)
upstreams.workforce.client_secret      = credential:idp-client-secret  install   (reference, not resolved)
```
