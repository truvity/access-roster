# 0046 — Usage records are a class that is never dropped, and plans and balances live in the product

**Status:** Accepted
**Date:** 2026-11-12

Proposal: [issue #841](https://github.com/truvity/sluis/issues/841), maintainer decisions D4 A and D7 A, 2026-11-12.

## Context

[0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream) makes usage a separate log kind that the writer takes from the same call as the audit record, and [0039](/decisions/0039-quota-allowance/) put a balance per tenant inside sluis: the product pushes an allowance, `quota` counts it down and refuses at zero. [0029](/decisions/0029-the-audit-log/#facts-that-are-lost-are-counted) lets a security fact be lost when the spool is full, and counts the loss.

The maintainer's update of 2026-11-12 is that audit serves the product too, and covers consumption limits and usage logs for billing. Billing needs exactly-once counting: a lost record under-bills, a duplicate over-bills. The counted loss that is acceptable for security facts is not acceptable for usage. A limit needs a fast check on the request path, not only a log. And money, plans and balances are the product's, as [0039](/decisions/0039-quota-allowance/#context) already said.

| Label | Decision |
|---|---|
| D4 A | Usage is its own record class and is never dropped. Each record has an idempotency key, and the write fails if the record cannot be stored. Security audit keeps counted loss. sluis does a fast limit check against counters; plans and balances stay on the product side. |
| D7 A | The cancel list is approved as it stands: the allowance and balance engine of 0039 is superseded. |

## Decision

### Two classes of record

- **Security audit keeps counted loss.** [0029](/decisions/0029-the-audit-log/#facts-that-are-lost-are-counted) stands for every audit fact, unchanged.
- **A usage record is a class of its own and is never best effort.** The usage part of a message is never dropped, never buffered in memory and never counted as lost. The operation that produces it uses a blocking emit and fails when the transport does not accept the record durably: it returns an error, and the operation did not happen. The emitter's `EmitRequired` is that call.
- **Every usage record carries an idempotency key.** It is the key of [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream), `source` plus `id`. The writer stores a repeat once, so a retry after an uncertain answer neither loses nor doubles a record.
- **The write fails if the record cannot be stored.** A full spool, an absent transport and a writer that refuses are errors of the operation, not notes on the next record.
- **Aggregation is per customer, organisation and product,** the claims of the sluis token ([0045](/decisions/0045-customers-sign-in-upstream-and-the-sluis-token-carries-customer-org-and-product/)). A usage record names them as identifiers and carries no personal data ([REQ-AUDIT-132](/requirements/audit/#REQ-AUDIT-132)).
- **The shape of [0030](/decisions/0030-audit-records-and-the-usage-stream/#usage-is-derived-from-the-same-event-once) stays:** one call builds the audit part and the usage part, with their own log kinds. The guarantee differs by class; the pipeline does not split.

### Limits and balances

- **sluis checks a limit on the request path.** A limit check compares a counter of usage for a customer, organisation and product in the current period with a limit, and answers allow or refuse, next to the policy decision. The product writes the limit; sluis holds the counter.
- **sluis holds no plan, price, money or balance.** The allowance, its modes, the push and the write-off of [0039](/decisions/0039-quota-allowance/) are not built. The product keeps its plans and balances and builds its billing from the usage log, as [0030](/decisions/0030-audit-records-and-the-usage-stream/#the-usage-stream) says.
- **The meters of [0040](/decisions/0040-meters-and-usage-evidence/) stand:** a meter has a name, a unit and a kind, and only declared outcomes become usage evidence.

## Consequences

- A full spool now stops some operations that it used to let through: the ones that produce usage. This is the price of exactly-once counting, and the operator sees an error, not a silent gap.
- Usage and security audit have different failure behaviour in one transport, so the emitter's API separates them, and a test shows that a security fact is lost and counted while a usage record is refused.
- The writer already removes repeats by `metadata.uid`; the idempotency key is the same promise made for usage.
- The counters of the limit check are a hot item: [0039](/decisions/0039-quota-allowance/) measured how one conditional update on one item behaves under load, and that measurement is the starting point for them.
- Requirements: [REQ-AUDIT-189](/requirements/audit/#REQ-AUDIT-189), [REQ-AUDIT-190](/requirements/audit/#REQ-AUDIT-190) and [REQ-QUOTA-097](/requirements/quota/#REQ-QUOTA-097) are added; the rows of the allowance engine are withdrawn.

## Roads not taken

- **Counted loss for usage too.** A bill would be wrong by an amount nobody can reconstruct.
- **A buffer in memory for usage.** A restart would lose it, and [0028](/decisions/0028-audit-pieces/#transport) rejects a buffer in memory.
- **Keep the balance in sluis (0039).** Money-adjacent state would sit in an identity product, and billing correctness would still depend on the product's own log.
- **A separate usage pipeline.** A second path could emit twice or without an audit record, as [0030](/decisions/0030-audit-records-and-the-usage-stream/#roads-not-taken) found.
- **No limit check, usage only.** A limit would be enforced after the fact, by the product, and a burst would pass.

## Follow-ups

- The emitter's separation of the two classes and the usage stream: [#841](https://github.com/truvity/sluis/issues/841).
- The shape of the limit counters, their period and the limit's configuration are written with the first caller of the check, in P2 of the [roadmap](/roadmap/#phases): [#841](https://github.com/truvity/sluis/issues/841).
