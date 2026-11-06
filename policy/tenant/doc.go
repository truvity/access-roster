// Package tenant checks the access rows a company states for itself before
// an installation merges them into its own access model.
//
// An installation that serves several companies owns the access matrix: the
// rungs, the scopes and the level each rung holds on each scope. A company
// owns its people, its projects and its bindings. It states them as a
// [Fragment], a deliberately narrow value that cannot carry the matrix, the
// vocabulary, the lifetimes, the claims or the clients, so widening the
// matrix is not representable. The installation states the owner's reach as
// a [Ceiling]: the directories its people live in, the groups it may mint or
// be granted, the rungs it may extend, and the organisations, workspaces and
// places it holds.
//
// [Check] refuses a fragment that reaches outside its ceiling and returns a
// list of [Violation] values with stable codes. The zero ceiling refuses
// every fragment that declares anything, so a missing ceiling never reads as
// no limit. [Check] reads the rows themselves. It needs no model of the
// installation, which lets a company run it in its own repository; a base
// model, when given, adds the keys the owner may not redeclare.
//
// [CheckEffect] is the guard. It derives the installation's roster
// ([compile.Roster]) before and after the fragment is merged and refuses what
// the difference reaches outside the ceiling: a company that joins a rung
// inherits that rung's cells, and a name it wrote cannot say that. [MergeAll]
// runs both checks for every owner, leaves out an owner with any violation,
// refuses two owners that declare or mint the same thing, and merges the rest
// in an order that does not matter, so one invalid company changes nothing for
// another.
//
// The package adds no concept to the policy. A group is still
// `<scope>:<thing>:<role>` ([policy.SplitGroup]), and a ceiling pattern is
// that shape with `*` for one segment. Examples use the neutral owners acme
// and globex.
package tenant
