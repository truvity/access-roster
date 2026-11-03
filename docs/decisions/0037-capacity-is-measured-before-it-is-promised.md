# 0037 — Capacity is measured before it is promised: a dated spike of the signing path, the hops to store@ and key@, the engines and the audit writer, and tokens stay signed in place meanwhile

**Status:** Proposed
**Layer:** CIAM module
**Date:** 2026-11-02

Proposal: [issue #878](https://github.com/truvity/sluis/issues/878).

## Context

[Principle 9](/principles/#9-measure-before-deciding-and-date-the-measurement) says a design that depends on a number rests on a measurement. For the customer-identity installation on Kubernetes there is none, and the model adds two hops to every request that no figure covers yet.

- **What exists.** The boards have a recorded budget ([Board capacity](/runtimes/bare-metal/#board-capacity)): about 7 P-384 signatures a second per card and about 21 a second for three boards (measured 2026-10-31); a data key opened on a card takes a median of 143 ms, about 7 a second per card, and is cached afterwards (measured on two boards' cards, 2026-11-03); and three boards deliver 400 replicated commits a second with a p99 of 118 to 127 ms (measured 2026-11-02). v1's workforce load was about 25,000 tokens in seven days with a peak of 0.8 a second ([0006](/decisions/0006-keys-and-sealing/)). The key service was measured from Lambda on 2026-11-02 ([below](/decisions/0037-capacity-is-measured-before-it-is-promised/#measured-so-far), [#878](https://github.com/truvity/sluis/issues/878)).
- **What is missing for customers.** No sign-in or refresh rate; no key service measurement from the pods of the installation; no latency of a call from a work actor to store@ or to key@ on Kubernetes or on Lambda; no access-pattern or hot-item analysis of the engine; no limit of the audit writer; no index size; and, on boards, no memory per unit once `ca` and `ssh-ca` are separate units and no cost of a directory re-sync. [REQ-PERF-001](/requirements/perf/#REQ-PERF-001) asks only that budgets be recorded when a path changes.
- **Why the hops are a worry.** Every work actor calls store@ on its data port and key@ on its keys port, so a request crosses at least one hop to each ([0003](/decisions/0003-units-transports-and-fusion/#transports)). A hop is a Unix socket call on boards, an invoke on Lambda and an in-cluster call on Kubernetes. Opening a sealed value costs a hop to key@, which the cache of opened data keys makes a memory operation after the first use ([0006](/decisions/0006-keys-and-sealing/#the-cache)). The cost of opening the session cookie at key@ on every request is unmeasured.
- **Why signing is the first worry.** Every token is signed in place by key@ ([0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place)): a sign-in signs an ID token and an access token, every refresh signs again, and every exchange into a customer boundary signs a token for it. With tokens of at most one hour ([0020](/decisions/0020-grant-vocabulary-and-token-claims/#lifetimes)) a population of customers refreshes all day. The key service has one request quota per account and Region for ECC operations, shared by every ECC key and caller in them ([below](/decisions/0037-capacity-is-measured-before-it-is-promised/#measured-so-far)).

The rule of [0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place) is not in question: there are no derived, burst or short-lived online signing keys, because a key in memory can be copied ([principle 1](/principles/#1-a-key-is-born-in-its-store-and-never-leaves-it)). The question is whether the number of signatures and hops that customers need fits what key@ and store@ allow, and what to do if it does not.

## Decision

### The baseline

- **Tokens stay signed in place by key@.** Nothing in this record changes [0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place) before the measurement says it must.
- **A warm sign-in, without the upstream, completes in under 500 ms at p99** (two authorizes and one token). A step issues its store reads concurrently, and every function on the sign-in path has at least 1024 MB; 128 MB is not workable (a cold authorize took 4.2 s). Measured on 2026-11-03 ([#1179](https://github.com/truvity/sluis/issues/1179)).
- **Every request keeps its hops.** A request takes the same steps on every installation ([principle 19](/principles/#19-one-model-many-transports)). The spike measures the hops and does not remove one; a step that one platform skips is a design change for all of them ([0003](/decisions/0003-units-transports-and-fusion/#transports)).
- **No capacity figure enters a record, a page or a promise until the spike's result is recorded.** A figure from the workforce, or from a card, is not a customer figure.

### Measured so far

#### The warm sign-in on Lambda

MEASURED on 2026-11-03, from AWS Lambda with one function per actor ([#1179](https://github.com/truvity/sluis/issues/1179)): a whole warm sign-in takes about 0.40 s at p50 and 0.49 s at p99, and about 0.29 s and 0.36 s with concurrent reads. The sign-in is two authorizes and one token, without the upstream. A step that issues its store reads concurrently gains the difference between the two figures. A function with 128 MB is not workable: a cold authorize took 4.2 s.

#### The key service from Lambda

MEASURED on 2026-11-02, 00:00 to 00:20 UTC, in one EU region of AWS, from AWS Lambda (arm64, 1769 MB, Go) to one `ECC_NIST_P384` key with `ECDSA_SHA_384` over a digest, in the same Region as the key; about 125,000 Sign calls in total. This is the call that key@ makes to the key service. The invoke from the work actor to key@ is not in it. This is part of [#878](https://github.com/truvity/sluis/issues/878); EC2 and pods of the installation are not measured yet.

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
- **The shared bucket is one more reason for the limits of [0036](/decisions/0036-volumetric-abuse/#inside-sluis):** one tenant's loop spends everyone's signatures.

#### The boards

MEASURED on boards with a card each, on the dates in the first column ([Board capacity](/runtimes/bare-metal/#board-capacity)).

| Date | What | Result |
|---|---|---|
| 2026-10-31 | One P-384 signature on a card | About 147 ms, about 7 a second per card, about 21 a second for three boards |
| 2026-11-03 | Opening a data key on a card (ECDH) | Median 143 ms, about 7 a second per card; a cached key costs a memory operation |
| 2026-11-02 | Replicated commits, three boards, 10 clusters of three nodes | 400 a second delivered in full with a p99 of 118 to 127 ms; saturated at about 600 a second with the CPU 95% busy |
| 2026-11-02 | One replicated commit | p50 21 to 41 ms and p99 62 to 123 ms |

What it means:

- **The cards, not the state, limit a board installation.** The design needs about 7 commits a second at the v1 peak and about 73 at the signing ceiling (estimated 2026-10-31 from the flows), against a budget of 400.
- **A cache miss on a card is a 143 ms wait.** The seven a second per card serve misses and not requests, so the hit rate of the cache decides how many requests a card supports.
- **Every limiter admit and every session write is a Raft commit.** Their rate is an input to the budget of 400.

Whether the customers' load fits the quota and the budgets depends on the products' sessions and clients, which are inputs the spike still needs; the decision lines that depend on the target load stay Proposed.

### The model to fill in

The signing rate is `sign-ins × signatures per sign-in + refreshes × signatures per refresh + exchanges × signatures per exchange`. With `S` concurrent sessions, `C` clients per session and tokens of one hour, refreshes run at about `S × C / 3600` a second. For illustration only, and not a forecast, `S = 100,000` and `C = 2` give about 55 refreshes a second and so more than 100 signatures a second, two orders above the workforce peak.

The hop rate is the request rate times the hops per request. The hops per action are read from the flows: the calls to store@ for the records one sign-in, one code exchange, one refresh and one exchange read and write, the calls to key@ to seal, open or make a keyed hash, and the call to key@ to sign. The real inputs (the products, their users, their clients per session) come from the products before the spike runs.

### The spike

It follows the shape of a result in [Decisions, requirements and research](/contributing/decisions/#the-shape-of-a-result). Its question is: what sign-in and refresh rate can an installation sustain, and which part limits it first?

1. **Token signing, the rest.** What is not yet measured: P-384 `Sign` from EC2 and from the pods of the installation in its Region, the rate reached with 64 and 256 concurrent callers, on several keys, and whether a second key raises the ceiling or only the shared quota counts. The price per request, read from the provider's price list on the day.
2. **The hops to store@ and key@.** The latency and the rate of a call from a work actor to store@ and to key@ on each transport: an invoke on Lambda, an in-cluster call on Kubernetes, and a Unix socket on boards. The per-request cost of opening the session cookie at key@ with batching, the hit rate of the data key cache and the cost of a miss (a KMS request on AWS, an ECDH on a card). Whether an invoke is fast enough for one function per actor was the Lambda latency spike ([#1179](https://github.com/truvity/sluis/issues/1179)): it is, and no in-process store exception is needed ([0003](/decisions/0003-units-transports-and-fusion/)). Its result is in [The warm sign-in on Lambda](/decisions/0037-capacity-is-measured-before-it-is-promised/#the-warm-sign-in-on-lambda).
3. **The engines.** On DynamoDB: the items one sign-in, one code exchange, one refresh and one exchange read and write, with consistent reads and the conditional writes and transactions counted; the partition keys and whether any one is hot (the `RateWindow` buckets of [0036](/decisions/0036-volumetric-abuse/#inside-sluis) and a product's `Person` items are the likely ones); capacity mode against on-demand throttling; item sizes; expiry. On rqlite: the commits per action, with every `RateWindow` write counted.
4. **The audit writer.** The sustained events a second that the one writer of one log seals into batches on the blob store, the backlog on the transport at that rate, the time from emit to sealed, the index's ingest rate, and the cost per event of the keyed hash that makes a pseudonym ([0029](/decisions/0029-the-audit-log/#pseudonyms)).
5. **Boards: memory and re-sync.** The memory per unit on 2 GB boards when `ca` and `ssh-ca` are separate units and every holder is a unit of its own, and the cost of a directory re-sync, where every write is a commit. This is the board capacity spike ([#1180](https://github.com/truvity/sluis/issues/1180)).
6. **End to end.** Sign-in and refresh rate against p99 latency with three cells ([0003](/decisions/0003-units-transports-and-fusion/#cells)), a connection pool replica pair ([0033](/decisions/0033-customer-connections/#a-pool-per-customer-boundary)) and the audit installation, with the first bottleneck named.

The result states when and where it ran (UTC, Region, cluster size), the versions of every component, what the setup over- and under-counts (a fake upstream is faster than a real one; one Region has no cross-zone failure), the numbers in tables with units, and the raw logs' place.

### If the key service's quota binds

In this order, each only if the one before it cannot meet the measured need:

1. **Ask for a higher quota.** The ECC quota is adjustable; it is a request to the provider and changes nothing in the design.
2. **Sign fewer tokens.** Do not sign an ID token that the client did not ask for, and let a resource server that can introspect take a reference token ([REQ-TOKEN-014](/requirements/token/#REQ-TOKEN-014)), which signs nothing.
3. **Spread across accounts.** A customer boundary at level L4 of the ladder runs in its own account and has its own quota ([0008](/decisions/0008-boundaries-and-tenants/#the-ladder), [0032](/decisions/0032-customer-identity-installations/#moving)).
4. **Change [0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place).** A new record that weighs a short-lived online key against principle 1. It is the last road and needs its own measurement.

## Consequences

- Nobody promises a number to a product before the result exists, and the result is dated, because a quota and a price rot. The signing figures above are measured and dated; the hops and the rest of the path are not.
- The spike needs a cluster in a development account, a Lambda installation and a load generator that plays a real upstream's latency; it costs engineer time and a small bill.
- The record stays Proposed until the result is linked. Then it is amended into an Accepted record that states the measured figures and the road taken.
- The hops of the model are accepted for the isolation they buy ([0002](/decisions/0002-families-of-actors/#credential-holders)). The spike prices them; a price that is too high changes a transport or the cache, never a check.
- Requirements: [REQ-PERF-003](/requirements/perf/#REQ-PERF-003) and [REQ-PERF-004](/requirements/perf/#REQ-PERF-004) state the rule for the result.

## Roads not taken

- **Decide a design now from the workforce numbers.** A peak of 0.8 tokens a second says nothing about a population of customers.
- **A short-lived online signing key to avoid the quota.** It breaks principle 1 and [0006](/decisions/0006-keys-and-sealing/#keys-sign-in-place) before anyone knows the quota binds.
- **Skip a hop to save latency.** Opening a sealed value in the store, or linking the store into a work actor, would give the work actor a credential and drop one of the two independent checks ([0007](/decisions/0007-policy-and-sealed-grants/#two-independent-checks)); the transport may change after the measurement, the steps do not.
- **Longer tokens to reduce signatures.** The maximum of an hour is a floor of the token rules, and a stolen bearer token is useful for its whole life.
- **Provision for the largest imaginable load.** It buys capacity for nobody, against principle 8.
- **Measure on a developer's laptop.** The key service, the engine and the writer's transport are in the cloud or on the boards; a local number measures none of them.

## Follow-ups

- The spike, its result and the amendment: [#878](https://github.com/truvity/sluis/issues/878), widened to the whole path.
- The board capacity spike: memory per unit on 2 GB boards with `ca` and `ssh-ca` separate, and the directory re-sync cost: [#1180](https://github.com/truvity/sluis/issues/1180).
