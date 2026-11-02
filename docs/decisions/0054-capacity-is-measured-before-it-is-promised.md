# 0054 — Capacity is measured before it is promised: a dated spike of the signing path, the state drivers and the audit writer, and tokens stay signed in place meanwhile

**Status:** Proposed
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #878](https://github.com/truvity/sluis/issues/878).

## Context

[Principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement) says a design that depends on a number rests on a measurement. For the customer-identity installation on Kubernetes there is none.

- **What exists.** The boards have a recorded budget: about 7 P-384 signatures a second per card and about 21 a second for three boards (measured 2026-10-31, [Board capacity](/runtimes/bare-metal/#board-capacity)). v1's workforce load was about 25,000 tokens in seven days with a peak of 0.8 a second ([0012](/decisions/0012-cryptography-and-authority-keys/)). The key service was measured from Lambda on 2026-11-02 ([below](/decisions/0054-capacity-is-measured-before-it-is-promised/#measured-so-far), [#878](https://github.com/truvity/sluis/issues/878)).
- **What is missing for customers.** No sign-in or refresh rate, no key-service measurement from pods of the installation, no access-pattern or hot-key analysis of the state table, no limit of the single audit writer, no index size. [REQ-PERF-001](/requirements/perf/#REQ-PERF-001) asks only that budgets be recorded when a path changes.
- **Why signing is the first worry.** Every token is signed in place by the store ([0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place)): a sign-in signs an ID token and an access token, every refresh signs again, and every exchange into a customer boundary signs a token for it. With tokens of at most one hour ([0028](/decisions/0028-grants-come-from-a-declared-vocabulary-and-a-token-carries-fixed-claims-for-one-audience/#lifetimes)) a population of customers refreshes all day. The key service has one request quota per account and Region for ECC operations, shared by every ECC key and caller in them ([below](/decisions/0054-capacity-is-measured-before-it-is-promised/#measured-so-far)).

The rule of [0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place) is not in question: there are no derived, burst or short-lived online signing keys, because a key in memory can be copied ([principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it)). The question is whether the number of signatures that customers need fits what the store allows, and what to do if it does not.

## Decision

### The baseline

- **Tokens stay signed in place by the key store.** Nothing in this record changes [0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place) before the measurement says it must.
- **No capacity figure enters a record, a page or a promise until the spike's result is recorded.** A figure from the workforce, or from a card, is not a customer figure.

### Measured so far

MEASURED on 2026-11-02, 00:00 to 00:20 UTC, in AWS `eu-central-1`, from AWS Lambda (arm64, 1769 MB, Go) to one `ECC_NIST_P384` key with `ECDSA_SHA_384` over a digest, in the same Region as the key; about 125,000 Sign calls in total. This is part of [#878](https://github.com/truvity/sluis/issues/878); EC2 and pods of the installation are not measured yet.

| What | Result |
|---|---|
| Warm Sign, 1, 8 and 32 concurrent execution environments | p50 5.8 ms; p99 10.8, 14.4 and 19.8 ms |
| A software P-384 signature on the same Lambda | p50 0.25 ms, so a key-service signature costs about 23 times as much time |
| The first Sign in a new execution environment (292 samples) | p50 about 76 ms (the connection set-up), 20% over 300 ms and 13% over 900 ms, up to 2.0 s; the cause was not investigated, and the second to twentieth Sign in the same environments were normal |
| Request quota for ECC cryptographic operations, READ from the account's quota service | 1000 a second, the default, adjustable; shared by every ECC operation of the account in the Region |
| Offered 300 to 1500 Sign calls a second with retries off | 0.1 to 0.3% of calls throttled, so a caller retries throttling even far under the quota |
| Offered 2000 a second with retries off | about 1290 a second served and 35.6% refused at once with `ThrottlingException`; latency of the served calls did not change, so throttling refuses and does not queue |

What it means:

- **The quota, not latency, bounds an installation.** At the default, token and ID-token signing through the key service caps one account and Region at about 1000 signatures a second, divided by the signatures per token, unless the quota is raised. One execution environment signing in sequence reaches about 170 a second.
- **Headroom over the workforce load is large:** about 1250 times the v1 peak of 0.8 a second at the nominal quota.
- **A cold start has a long tail.** A latency target for a cold sign-in on Lambda is stated with the 75 ms median and the 2 s tail of the first Sign, on top of about 113 ms of initialisation.
- **The shared bucket is one more reason for the limits of [0053](/decisions/0053-volumetric-abuse-is-stopped-at-the-edge-and-sluis-bounds-what-one-source-can-cost/#inside-sluis):** one tenant's loop spends everyone's signatures.

Whether the customers' load fits the quota depends on the products' sessions and clients, which are inputs the spike still needs; the decision lines that depend on the target load stay Proposed.

### The model to fill in

The signing rate is `sign-ins × signatures per sign-in + refreshes × signatures per refresh + exchanges × signatures per exchange`. With `S` concurrent sessions, `C` clients per session and tokens of one hour, refreshes run at about `S × C / 3600` a second. For illustration only, and not a forecast, `S = 100,000` and `C = 2` give about 55 refreshes a second and so more than 100 signatures a second, two orders above the workforce peak. The real inputs (the products, their users, their clients per session) come from the products before the spike runs.

### The spike

It follows the shape of a result in [Decisions, requirements and research](/contributing/decisions/#the-shape-of-a-result). Its question is: what sign-in and refresh rate can the Kubernetes installation sustain in one AWS Region, and which part limits it first?

1. **Token signing, the rest.** What is not yet measured: P-384 `Sign` from EC2 and from pods of the installation in its Region, the rate reached with 64 and 256 concurrent callers, on several keys, and whether a second key raises the ceiling or only the shared quota counts. The price per request, read from the provider's price list on the day.
2. **State on DynamoDB.** The records one sign-in, one code exchange, one refresh and one exchange read and write, with consistent reads and the conditional writes and transactions of the atomic batch counted; the partition keys and whether any one is hot (the limiter's buckets of [0053](/decisions/0053-volumetric-abuse-is-stopped-at-the-edge-and-sluis-bounds-what-one-source-can-cost/#inside-sluis) and a product's `person` records are the likely ones); capacity mode against on-demand throttling; item sizes; expiry.
3. **The audit writer.** The sustained events a second that the one writer of one log seals into batches on the blob store, the backlog on the queue at that rate, the time from emit to sealed, the index's ingest rate, and the cost of unwrapping pseudonym keys per event ([0025](/decisions/0025-audit-pseudonyms-are-keyed-per-company-and-epoch/)).
4. **End to end.** Sign-in and refresh rate against p99 latency with three replicas of the core pod, a pool replica pair ([0048](/decisions/0048-customer-connections-run-in-a-pool-per-customer-boundary/)) and the audit installation, with the first bottleneck named.

The result states when and where it ran (UTC, Region, cluster size), the versions of every component, what the setup over- and under-counts (a fake upstream is faster than a real one; one Region has no cross-zone failure), the numbers in tables with units, and the raw logs' place.

### If the store's quota binds

In this order, each only if the one before it cannot meet the measured need:

1. **Ask for a higher quota.** The ECC quota is adjustable; it is a request to the provider and changes nothing in the design.
2. **Sign fewer tokens.** Do not sign an ID token that the client did not ask for, and let a resource server that can introspect take a reference token ([REQ-TOKEN-014](/requirements/token/#REQ-TOKEN-014)), which signs nothing.
3. **Spread across accounts.** A customer boundary in its own account (L4, [0047](/decisions/0047-a-customer-identity-installation-is-a-front-a-few-customer-boundaries-and-key-less-tenants/#moving)) has its own quota.
4. **Change [0012](/decisions/0012-cryptography-and-authority-keys/#keys-sign-in-place).** A new record that weighs a short-lived online key against principle 1. It is the last road and needs its own measurement.

## Consequences

- Nobody promises a number to a product before the result exists, and the result is dated, because a quota and a price rot. The signing figures above are measured and dated; the rest of the path is not.
- The spike needs a cluster in a development account and a load generator that plays a real upstream's latency; it costs engineer time and a small bill.
- The record stays Proposed until the result is linked. Then it is amended into an Accepted record that states the measured figures and the road taken.
- Requirements: [REQ-PERF-003](/requirements/perf/#REQ-PERF-003), [REQ-PERF-004](/requirements/perf/#REQ-PERF-004) are added.

## Roads not taken

- **Decide a design now from the workforce numbers.** A peak of 0.8 tokens a second says nothing about a population of customers.
- **A short-lived online signing key to avoid the quota.** It breaks principle 1 and 0012 before anyone knows the quota binds.
- **Longer tokens to reduce signatures.** The maximum of an hour is a floor of the token rules, and a stolen bearer token is useful for its whole life.
- **Provision for the largest imaginable load.** It buys capacity for nobody, against principle 8.
- **Measure on a developer's laptop.** The key service, the table and the writer's queue are in the cloud; a local number measures none of them.

## Follow-ups

- The spike, its result and the amendment: [#878](https://github.com/truvity/sluis/issues/878), widened to the whole path.
