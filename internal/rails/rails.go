// Package rails is the small set of reconciler mechanics that turned out,
// while writing the GitHub controller, to have nothing to do with GitHub:
// asking about one removal candidate at a time before acting on it,
// refusing to act on an answer computed under a different policy, tripping
// a circuit breaker before a pass changes too much of a target at once,
// and gating whether a pass acts on what it decided or only reports what
// it would have.
//
// It is not a reconciler framework. internal/githubroster is still the
// only implementation, and everything GitHub-shaped in it — teams,
// logins, invitations, deriving and deciding what an organisation should
// look like — stays there entirely. This package holds only the four
// pieces that were already generic in that code, so a second reconciler
// does not have to duplicate them; see docs/design/access-roster.md for
// what would turn this into a framework worth the name, and why that is
// not this change.
package rails
