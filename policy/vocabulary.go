package policy

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
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
// roles, each with the roles it implies and, optionally, the scopes it is
// itself restricted to.
type ThingSpec struct {
	// Scopes are the declared scopes this thing exists in. A concrete
	// grant naming a scope this thing does not list is refused at load.
	Scopes []string `yaml:"scopes,omitempty"`
	// Roles is the thing's ladder: role name to [RoleSpec] — the roles it
	// directly implies and, optionally, the scopes it is valid on. Empty
	// Implies means it implies nothing (a leaf role, most often `viewer`);
	// empty Scopes means it is valid on every scope the thing declares,
	// which is what every role meant before per-role scoping existed.
	Roles map[string]RoleSpec `yaml:"roles,omitempty"`
}

// RoleSpec is one declared role: the roles it directly implies, and,
// optionally, the subset of its thing's scopes it is itself valid on.
//
// Its YAML value may be EITHER the plain list of implied roles this
// schema has always accepted (`admin: [operator]`, `viewer: []`), OR an
// object naming `implies` and/or `scopes` explicitly (`user: {scopes:
// [devel]}`), for a role that belongs to only some of its thing's
// declared scopes rather than all of them. Every policy written before
// per-role scoping existed used the first form, and [RoleSpec.UnmarshalYAML]
// keeps reading it exactly the same way.
type RoleSpec struct {
	// Implies are the roles this role directly implies — see
	// [ThingSpec.Roles].
	Implies []string `yaml:"implies,omitempty"`
	// Scopes restricts this role to some of its thing's declared scopes.
	// Empty (the default, and the only thing the plain-list form can
	// mean) means the role is valid on every scope the thing declares. A
	// non-empty Scopes must be a subset of the thing's own — see
	// [Vocabulary.validate] — and a concrete grant naming a scope this
	// role does not list is refused, exactly like a scope the THING does
	// not list; see [Vocabulary.fits].
	Scopes []string `yaml:"scopes,omitempty"`
}

// UnmarshalYAML implements yaml.Unmarshaler. A sequence node is the
// existing implies-only shorthand; a mapping node is the object form,
// decoded through a plain struct so a stray key is refused by strict
// decoding the same way the rest of this schema refuses one.
func (r *RoleSpec) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		var implies []string
		if err := node.Decode(&implies); err != nil {
			return fmt.Errorf("role: %w", err)
		}
		*r = RoleSpec{Implies: implies}
		return nil
	case yaml.MappingNode:
		var obj struct {
			Implies []string `yaml:"implies,omitempty"`
			Scopes  []string `yaml:"scopes,omitempty"`
		}
		if err := node.Decode(&obj); err != nil {
			return fmt.Errorf("role: %w", err)
		}
		*r = RoleSpec{Implies: obj.Implies, Scopes: obj.Scopes}
		return nil
	default:
		return fmt.Errorf("role must be a list of implied roles, or an object with implies/scopes")
	}
}

// MarshalYAML implements yaml.Marshaler, the inverse of
// [RoleSpec.UnmarshalYAML]: a role restricted to no particular scope
// marshals back to the plain list, exactly the shape every role had
// before this field existed, so [Policy.Digest] does not change for a
// policy that declares no per-role scoping. Only a role that DOES
// restrict its scopes marshals as the object form.
func (r RoleSpec) MarshalYAML() (any, error) {
	if len(r.Scopes) == 0 {
		return r.Implies, nil
	}
	return struct {
		Implies []string `yaml:"implies,omitempty"`
		Scopes  []string `yaml:"scopes,omitempty"`
	}{r.Implies, r.Scopes}, nil
}

// allowsScope reports whether this role may be exercised on scope: every
// scope its thing declares, when it restricts itself to none; only its
// own listed scopes otherwise.
func (r RoleSpec) allowsScope(scope string) bool {
	return len(r.Scopes) == 0 || slices.Contains(r.Scopes, scope)
}

// effectiveScopes is the role's own Scopes when it declares any, or
// thing's full Scopes otherwise — "every scope this role actually
// covers," used to check an implies edge covers as much ground as the
// role naming it (see [Vocabulary.validate]).
func (r RoleSpec) effectiveScopes(thing ThingSpec) []string {
	if len(r.Scopes) > 0 {
		return r.Scopes
	}
	return thing.Scopes
}

// validate checks the vocabulary on its own: every thing's scopes are
// declared, every thing has at least one role, every role's own `scopes`
// (if declared) is a non-empty subset of its thing's, every implies edge
// names a declared role of the SAME thing whose own scopes cover
// everything the source role covers, and no thing's implies graph has a
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
			rspec := spec.Roles[role]
			// A role MAY declare `scopes`, restricting itself to some of
			// its thing's — never none (a role valid nowhere is pointless
			// to declare at all, and almost certainly a stray empty list
			// rather than an intentional one) and never a scope its thing
			// does not itself have.
			if rspec.Scopes != nil && len(rspec.Scopes) == 0 {
				return fmt.Errorf("vocabulary: thing %q: role %q declares an empty scopes list", name, role)
			}
			for _, scope := range rspec.Scopes {
				if _, ok := v.Scopes[scope]; !ok {
					return fmt.Errorf("vocabulary: thing %q: role %q names scope %q, which is not declared under vocabulary.scopes",
						name, role, scope)
				}
				if !slices.Contains(spec.Scopes, scope) {
					return fmt.Errorf("vocabulary: thing %q: role %q names scope %q, which is not among its own scopes %v",
						name, role, scope, spec.Scopes)
				}
			}
			for _, implied := range rspec.Implies {
				impliedSpec, ok := spec.Roles[implied]
				if !ok {
					return fmt.Errorf("vocabulary: thing %q: role %q implies %q, which is not a declared role of %q",
						name, role, implied, name)
				}
				// Inheritance rule: an implied role must be allowed on
				// every scope its source is — refused at load rather than
				// silently skipped at evaluation, because a mismatch here
				// is a policy mistake (a role restricted to fewer scopes
				// than something it implies), not a legitimate shape
				// evaluation should quietly work around. See
				// docs/decisions/0012-per-role-scopes-in-the-vocabulary.md.
				for _, scope := range rspec.effectiveScopes(spec) {
					if !impliedSpec.allowsScope(scope) {
						return fmt.Errorf(
							"vocabulary: thing %q: role %q implies %q, but %q is not valid on scope %q, which %q is",
							name, role, implied, implied, scope, role)
					}
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
func cycleInRoles(roles map[string]RoleSpec) string {
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
		for _, next := range roles[role].Implies {
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
// is reported before an undeclared role, which is reported before a
// scope the ROLE itself does not cover — each check assumes everything
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
	rspec, ok := spec.Roles[role]
	if !ok {
		return fmt.Errorf("role %q is not declared for thing %q", role, thing)
	}
	if !rspec.allowsScope(scope) {
		return fmt.Errorf("role %q of thing %q is valid only on scopes %v", role, thing, rspec.Scopes)
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
// (scope, thing) pair where the thing declares that scope, the thing has
// that role, AND the role itself allows that scope (see
// [RoleSpec.allowsScope]) — EXCLUDING any scope marked
// [ScopeSpec.Sensitive] — whether the scope came from the wildcard's own
// concrete segment or from sweeping every scope a swept-in thing
// declares. scope or thing (never both concrete, and never both `*` and
// role `*` at once — refused earlier) may each be "*" to mean "every one
// this role fits."
//
// A thing, a (thing, scope) pair, or a (thing, scope) pair the ROLE
// itself does not cover, that does not have the role is skipped rather
// than refused: `devel:*:viewer` reaching a thing with no `viewer` role,
// or `kernel:*:user` skipping a thing whose `user` role names `scopes:
// [devel]`, is exactly what "expands across everything that fits" means,
// not an error about the things that do not.
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
		rspec, ok := spec.Roles[role]
		if !ok {
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
			if !rspec.allowsScope(s) {
				continue
			}
			out = append(out, s+Separator+t+Separator+role)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// expandIgnoringSensitivity is [Vocabulary.expand] without the sensitive
// exclusion — it still respects a role's own [RoleSpec.allowsScope]
// restriction, because that restriction is not what the message this
// composes is about. It exists only to compose a refusal: it says what a
// wildcard WOULD have reached, so the message naming a sensitive scope
// can offer a real concrete example rather than an abstract one.
func (v *Vocabulary) expandIgnoringSensitivity(scope, thing, role string) []string {
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
		rspec, ok := spec.Roles[role]
		if !ok {
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
			if !rspec.allowsScope(s) {
				continue
			}
			out = append(out, s+Separator+t+Separator+role)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// emptyWhy explains why [Vocabulary.expand] came back with nothing, for a
// wildcard key whose only refusal reason is not simply "its own scope is
// sensitive" (that case gets its own, more specific message — see
// [Policy.checkGroupKey]). Called only once [Vocabulary.checkWildcard] has
// already passed, so a CONCRETE thing is guaranteed to have the role;
// what remains to explain is a thing wildcard sweeping in nothing, the
// role's own scope restriction ruling out every candidate, or every
// candidate scope turning out sensitive.
func (v *Vocabulary) emptyWhy(scope, thing, role string) string {
	things := []string{thing}
	if thing == "*" {
		things = slices.Sorted(maps.Keys(v.Things))
	}
	roleFound, scopeFound, roleScopeFound := false, false, false
	var sensitiveScopes []string
	for _, t := range things {
		spec, ok := v.Things[t]
		if !ok {
			continue
		}
		rspec, ok := spec.Roles[role]
		if !ok {
			continue
		}
		roleFound = true
		candidates := spec.Scopes
		if scope != "*" {
			if !slices.Contains(spec.Scopes, scope) {
				continue
			}
			candidates = []string{scope}
		}
		for _, s := range candidates {
			scopeFound = true
			if !rspec.allowsScope(s) {
				continue
			}
			roleScopeFound = true
			if v.Scopes[s].Sensitive {
				sensitiveScopes = append(sensitiveScopes, s)
			}
		}
	}
	switch {
	case !roleFound:
		return fmt.Sprintf("no declared thing has role %q", role)
	case !scopeFound:
		return fmt.Sprintf("no thing with role %q declares scope %q", role, scope)
	case !roleScopeFound:
		return fmt.Sprintf("role %q is not valid on scope %q for any thing that declares it", role, scope)
	default:
		slices.Sort(sensitiveScopes)
		sensitiveScopes = slices.Compact(sensitiveScopes)
		return fmt.Sprintf("every matching scope (%s) is sensitive", strings.Join(sensitiveScopes, ", "))
	}
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
	targets := p.Vocabulary.expand(scope, thing, role)
	if len(targets) == 0 {
		// An empty expansion is a grant that never takes effect — exactly
		// the failure this vocabulary exists to catch, so it is refused
		// here rather than silently accepted as a key nobody is ever in.
		if scope != "*" && p.Vocabulary.Scopes[scope].Sensitive {
			if example := p.Vocabulary.expandIgnoringSensitivity(scope, thing, role); len(example) > 0 {
				return nil, fmt.Errorf(
					"groups: %q: scope %q is sensitive and is never reached by a wildcard; "+
						"name the concrete groups (e.g. %q) instead", name, scope, example[0])
			}
		}
		return nil, fmt.Errorf("groups: %q expands to no group: %s", name, p.Vocabulary.emptyWhy(scope, thing, role))
	}
	return targets, nil
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
