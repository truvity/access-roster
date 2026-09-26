package policy

import (
	"fmt"
	"maps"
	"slices"
)

// Vocabulary is an installation's OPTIONAL declaration of what a grant
// name is allowed to mean: which scopes and things exist, which roles
// each thing has, and which role implies which other one.
//
// It is opt-in on purpose. Every rule below fires only once a `vocabulary`
// table is present at all: an installation that declares none keeps
// today's behaviour exactly — any three-segment name is a grant, and
// nothing checks whether its segments mean anything. Declaring one is a
// deliberate move from "the schema believes whatever spelling shows up in
// `groups`" to "the schema can tell a typo, an undeclared role or a stray
// scope from a real grant, at load."
type Vocabulary struct {
	// Scopes are the environments and tenant shapes an installation
	// recognises: `kernel`, `prod`, `devel`, `stage`, or `all` for a thing
	// that exists once per installation rather than once per environment.
	Scopes map[string]ScopeSpec `yaml:"scopes,omitempty"`
	// Things are the subsystems, projects and applications a role is held
	// ON: `k8s`, `argocd`, `grafana`. Each names the scopes it exists in
	// and the roles its ladder has, with their implies edges.
	Things map[string]ThingSpec `yaml:"things,omitempty"`
}

// ScopeSpec is one declared scope.
type ScopeSpec struct {
	// Sensitive marks a scope a mapping wildcard must never reach —
	// `kernel` and `prod`, typically. A wildcard key still expands freely
	// across every OTHER scope a thing declares; see [Vocabulary.expand].
	// It has no effect on a concrete grant, which names its scope outright
	// and is checked like any other.
	Sensitive bool `yaml:"sensitive,omitempty"`
}

// ThingSpec is one declared thing: the scopes it exists in, and its
// roles, each with the roles it implies.
type ThingSpec struct {
	// Scopes are the declared scopes this thing exists in. A concrete
	// grant naming a scope this thing does not list is refused at load.
	Scopes []string `yaml:"scopes,omitempty"`
	// Roles is the thing's ladder: role name to the roles it directly
	// implies. `admin: [operator]` means holding admin also holds
	// operator; it says nothing about what operator itself implies —
	// that is operator's own entry, and evaluation walks the chain. Empty
	// implies nothing (a leaf role, most often `viewer`).
	Roles map[string][]string `yaml:"roles,omitempty"`
}

// validate checks the vocabulary on its own: every thing's scopes are
// declared, every thing has at least one role, every implies edge names a
// declared role of the SAME thing, and no thing's implies graph has a
// cycle. A nil vocabulary — no `vocabulary` table at all — validates as
// nothing, which is the opt-in.
func (v *Vocabulary) validate() error {
	if v == nil {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(v.Things)) {
		spec := v.Things[name]
		if len(spec.Scopes) == 0 {
			return fmt.Errorf("vocabulary: thing %q declares no scopes", name)
		}
		for _, scope := range spec.Scopes {
			if _, ok := v.Scopes[scope]; !ok {
				return fmt.Errorf("vocabulary: thing %q names scope %q, which is not declared under vocabulary.scopes", name, scope)
			}
		}
		if len(spec.Roles) == 0 {
			return fmt.Errorf("vocabulary: thing %q declares no roles", name)
		}
		for _, role := range slices.Sorted(maps.Keys(spec.Roles)) {
			for _, implied := range spec.Roles[role] {
				if _, ok := spec.Roles[implied]; !ok {
					return fmt.Errorf("vocabulary: thing %q: role %q implies %q, which is not a declared role of %q",
						name, role, implied, name)
				}
			}
		}
		if cycle := cycleInRoles(spec.Roles); cycle != "" {
			return fmt.Errorf("vocabulary: thing %q: the implies graph has a cycle at role %q", name, cycle)
		}
	}
	return nil
}

// cycleInRoles reports one role name on a cycle of the implies graph, or
// "" if the graph is acyclic. Iteration is over sorted keys so that a
// policy which fails this check fails it the same way on every run.
func cycleInRoles(roles map[string][]string) string {
	const (
		white = iota
		gray
		black
	)
	color := make(map[string]int, len(roles))
	var found string
	var visit func(string) bool
	visit = func(role string) bool {
		color[role] = gray
		for _, next := range roles[role] {
			switch color[next] {
			case gray:
				found = next
				return true
			case white:
				if visit(next) {
					return true
				}
			}
		}
		color[role] = black
		return false
	}
	for _, role := range slices.Sorted(maps.Keys(roles)) {
		if color[role] == white && visit(role) {
			return found
		}
	}
	return ""
}

// fits reports why a CONCRETE grant (no wildcard segment) does not belong
// to this vocabulary, or nil when it does. Checked in the order the
// design settled on: an undeclared scope is reported before an undeclared
// thing, which is reported before a scope the thing does not have, which
// is reported before an undeclared role — each check assumes everything
// before it already held.
func (v *Vocabulary) fits(scope, thing, role string) error {
	if _, ok := v.Scopes[scope]; !ok {
		return fmt.Errorf("scope %q is not declared under vocabulary.scopes", scope)
	}
	spec, ok := v.Things[thing]
	if !ok {
		return fmt.Errorf("thing %q is not declared under vocabulary.things", thing)
	}
	if !slices.Contains(spec.Scopes, scope) {
		return fmt.Errorf("thing %q does not name scope %q among its scopes %v", thing, scope, spec.Scopes)
	}
	if _, ok := spec.Roles[role]; !ok {
		return fmt.Errorf("role %q is not declared for thing %q", role, thing)
	}
	return nil
}

// checkWildcard validates a mapping wildcard's CONCRETE segment, if it has
// one. A wildcard always has a concrete role (a role wildcard is refused
// before this is reached) and at least one of scope or thing as `*`; the
// segment that is not `*` is checked the same way [Vocabulary.fits] would,
// except that when THING is the wildcard, the role is not required to
// exist on any particular thing — [Vocabulary.expand] simply skips a thing
// that lacks it, because different things legitimately have different
// ladders.
func (v *Vocabulary) checkWildcard(scope, thing, role string) error {
	if scope != "*" {
		if _, ok := v.Scopes[scope]; !ok {
			return fmt.Errorf("scope %q is not declared under vocabulary.scopes", scope)
		}
	}
	if thing != "*" {
		spec, ok := v.Things[thing]
		if !ok {
			return fmt.Errorf("thing %q is not declared under vocabulary.things", thing)
		}
		if scope != "*" && !slices.Contains(spec.Scopes, scope) {
			return fmt.Errorf("thing %q does not name scope %q among its scopes %v", thing, scope, spec.Scopes)
		}
		if _, ok := spec.Roles[role]; !ok {
			return fmt.Errorf("role %q is not declared for thing %q", role, thing)
		}
	}
	return nil
}

// expand computes the concrete grants a mapping wildcard names: every
// (scope, thing) pair where the thing declares both that scope and that
// role, EXCLUDING any scope marked [ScopeSpec.Sensitive] — whether the
// scope came from the wildcard's own concrete segment or from sweeping
// every scope a swept-in thing declares. scope or thing (never both
// concrete, and never both `*` and role `*` at once — refused earlier) may
// each be "*" to mean "every one this role fits."
//
// A thing, or a (thing, scope) pair, that does not have the role is
// skipped rather than refused: `devel:*:viewer` reaching a thing with no
// `viewer` role is exactly what "expands across things that declare devel
// and viewer" means, not an error about the things that do not.
func (v *Vocabulary) expand(scope, thing, role string) []string {
	things := []string{thing}
	if thing == "*" {
		things = slices.Sorted(maps.Keys(v.Things))
	}
	var out []string
	for _, t := range things {
		spec, ok := v.Things[t]
		if !ok {
			continue
		}
		if _, ok := spec.Roles[role]; !ok {
			continue
		}
		scopes := spec.Scopes
		if scope != "*" {
			if !slices.Contains(spec.Scopes, scope) {
				continue
			}
			scopes = []string{scope}
		}
		for _, s := range scopes {
			if v.Scopes[s].Sensitive {
				continue
			}
			out = append(out, s+Separator+t+Separator+role)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// checkGrantName validates one name wherever a grant is named in the
// policy, other than as a Groups-table key. `where` says which table and
// entry it came from, for the refusal. rung:/emp: names and anything else
// that does not parse as a three-segment grant ([SplitGroup] returns
// false) are exempt: the vocabulary governs grants, and those are not
// grants.
//
// A mapping wildcard is refused here unconditionally — rule 4 restricts
// wildcards to Groups-table keys, never to Claims, Lifetimes, `requires`
// or a GitHub binding, whatever the vocabulary allows there.
func (p Policy) checkGrantName(where, name string) error {
	scope, thing, role, ok := SplitGroup(name)
	if !ok {
		return nil
	}
	if scope == "*" || thing == "*" || role == "*" {
		return fmt.Errorf("%s: %q is a mapping wildcard, which may only appear as a groups key", where, name)
	}
	if p.Vocabulary == nil {
		return nil
	}
	if err := p.Vocabulary.fits(scope, thing, role); err != nil {
		return fmt.Errorf("%s: %q: %w", where, name, err)
	}
	return nil
}

// checkGroupKey validates one Groups-table key, where a mapping wildcard
// IS allowed, and returns the concrete grants it stands for: itself, for
// an ordinary key or a non-grant (`rung:`, `emp:`); its wildcard
// expansion, for a mapping wildcard.
func (p Policy) checkGroupKey(name string) ([]string, error) {
	scope, thing, role, ok := SplitGroup(name)
	if !ok {
		return []string{name}, nil
	}
	if role == "*" {
		return nil, fmt.Errorf("groups: %q wildcards the role, which is always refused: a role must be named", name)
	}
	wildcard := scope == "*" || thing == "*"
	if !wildcard {
		if p.Vocabulary != nil {
			if err := p.Vocabulary.fits(scope, thing, role); err != nil {
				return nil, fmt.Errorf("groups: %q: %w", name, err)
			}
		}
		return []string{name}, nil
	}
	if p.Vocabulary == nil {
		return nil, fmt.Errorf("groups: %q uses a mapping wildcard, which needs a declared vocabulary", name)
	}
	if err := p.Vocabulary.checkWildcard(scope, thing, role); err != nil {
		return nil, fmt.Errorf("groups: %q: %w", name, err)
	}
	return p.Vocabulary.expand(scope, thing, role), nil
}

// groupKeyTargets is [Policy.checkGroupKey] without the error: every
// caller past [Policy.Validate] already knows the key is good, and
// [Policy.Evaluate] and [Policy.Unconsumed] both need only the mapping,
// on every request or lint pass, not the validation.
func (p Policy) groupKeyTargets(name string) []string {
	targets, err := p.checkGroupKey(name)
	if err != nil {
		// Reached only for a policy nobody validated — evaluating it is
		// already a misuse. A key that cannot be mapped grants nothing,
		// which is the safe direction to fail in.
		return nil
	}
	return targets
}
