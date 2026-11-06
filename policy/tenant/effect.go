package tenant

import "github.com/truvity/sluis/policy/compile"

type (
	// Owned is an owner with the fragment it states.
	Owned struct {
		Owner    Owner
		Fragment Fragment
	}

	// Result is what [MergeAll] decided for one owner.
	Result struct {
		// Owner is the owner's name.
		Owner string
		// Violations are why the owner was left out, sorted by path and
		// code. None means the owner's fragment is in the merged model.
		Violations []Violation
	}
)

// Accepted reports whether the owner's fragment is in the merged model.
func (r Result) Accepted() bool { return len(r.Violations) == 0 }

// rosterFunc derives the roster of a model. It is a parameter of effect so
// that a test can hand in a derivation with a bug.
type rosterFunc func(compile.Model, compile.Conventions) *compile.Policy

// effect is not implemented yet.
func effect(rosterFunc, compile.Model, compile.Conventions, Owner, Fragment) ([]Violation, []string) {
	return nil, nil
}

// CheckEffect is not implemented yet.
func CheckEffect(base compile.Model, c compile.Conventions, o Owner, f Fragment) []Violation {
	vs, _ := effect(compile.Roster, base, c, o, f)

	return vs
}

// MergeAll is not implemented yet: it merges every fragment unchecked.
func MergeAll(base compile.Model, _ compile.Conventions, owned ...Owned) (compile.Model, []Result) {
	fragments := make([]Fragment, 0, len(owned))
	results := make([]Result, 0, len(owned))

	for _, o := range owned {
		fragments = append(fragments, o.Fragment)
		results = append(results, Result{Owner: o.Owner.Name})
	}

	return merged(base, fragments...), results
}
