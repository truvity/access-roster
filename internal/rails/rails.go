// Package rails is what reconcilers share. A reconciler here is a loop
// that, every pass and for every target its policy binds, reads what a
// system holds, asks the console who should hold it, decides, acts where
// the target is enabled, and reports. GitHub organisations were the first;
// Slack workspaces are the second. The pieces in this package are the ones
// both call with the same meaning and only the nouns different:
//
//   - [Run] and [Pacing]: the pass loop and its backoff while a rollout
//     leaves the console on another policy.
//   - [Directory], [Holders], [Vouch] and [Removal]: the two questions put to
//     the console (who holds a group, what is true of one address), each
//     answer gated by [PolicyGuard], and the rule that a removal rests on a
//     vouched answer or does not happen. [Confirm] is the ask-one-at-a-time
//     loop under it.
//   - [Ledger]: which held rows were already recorded, so each is recorded
//     once and not again after a restart.
//   - [Journal]: the last good report per target, in memory and in the
//     store, so a failed pass keeps what was known.
//   - [CheckBreaker] and its [Fingerprint]: the removal circuit breaker.
//   - [Switch]: the dry-run gate a target is born behind.
//
// It is still not a framework. There is no Reconciler interface, no shared
// row, action or report type, and no pass skeleton: deriving and deciding,
// the change calls, credentials, status documents and audit events differ
// in kind between systems, and a shape guessed to cover them would bend
// the first to fit the second. Those stay in each system's own package
// (internal/githubroster). Nothing here imports generated clients; a
// reconciler adapts its own to the funcs and interfaces taken. Metrics
// are deliberately not here: the instruments are exported telemetry with a
// system's own names, and a second copy of forty lines is cheaper than a
// shared one that has to stay identical to both.
package rails
