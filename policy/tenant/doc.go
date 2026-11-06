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
// no limit. The checks here read the rows themselves. They need no model of
// the installation, which lets a company run them in its own repository; a
// base model, when given, adds the keys the owner may not redeclare.
//
// The package adds no concept to the policy. A group is still
// `<scope>:<thing>:<role>` ([policy.SplitGroup]), and a ceiling pattern is
// that shape with `*` for one segment. Examples use the neutral owners acme
// and globex.
package tenant
