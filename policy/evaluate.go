package policy

import (
	"maps"
	"slices"
	"strings"
	"time"
)

// Input is one verified proof, as far as the policy is concerned.
// Everything in it has already been checked by the caller: the policy
// decides only what a verified identity is entitled to.
type Input struct {
	// Email of the signed-in account, when the proof is a sign-in.
	Email string
	// DirectoryGroups the hub reports for that account.
	DirectoryGroups []string
	// Authoritative reports whether the hub's answer may be acted on.
	// Membership never grants anything without it.
	Authoritative bool
	// GitHub carries a CI identity token's verified claims.
	GitHub *GitHubClaims
	// ServiceAccount carries a verified Kubernetes ServiceAccount.
	ServiceAccount *ServiceAccountRef
}

// GitHubClaims are a CI identity token's verified claims.
type GitHubClaims struct {
	Repository  string
	Owner       string
	Ref         string
	Workflow    string
	Environment string
	// Visibility is the repository's visibility: public, private or
	// internal.
	Visibility string
	// WorkflowRef is the workflow file the run was started from, at the
	// ref it was read at: `org/repo/.github/workflows/release.yml@refs/heads/main`.
	WorkflowRef string
	// JobWorkflowRef is the workflow file the JOB is defined in. It
	// differs from WorkflowRef in a reusable workflow, and it is the one
	// that says which code holds the token.
	JobWorkflowRef string
	// SHA is the commit the run is for.
	SHA string
	// EventName is what started the run: push, pull_request,
	// workflow_dispatch...
	EventName string
	// RefType is branch or tag.
	RefType string
}

// ServiceAccountRef is a verified Kubernetes ServiceAccount.
type ServiceAccountRef struct {
	// Cluster names which cluster's API server vouched for it. The same
	// namespace and name exist on every cluster, so without it two
	// different machines are one subject — which is the collision `sub`
	// exists to prevent. Empty where a deployment has not named its
	// cluster, and empty in a matcher means any.
	Cluster   string
	Namespace string
	Name      string
}

// Subject is how a ServiceAccount is spelled as a token's `sub`:
// `<cluster>:k8s:<namespace>:<name>`, scope first like every group name.
//
// A ref with no cluster renders the older three-part form, so an
// installation that has not named its cluster keeps the subjects it
// already mints.
func (r ServiceAccountRef) Subject() string {
	if r.Cluster == "" {
		return "k8s:" + r.Namespace + ":" + r.Name
	}

	return r.Cluster + ":k8s:" + r.Namespace + ":" + r.Name
}

// ParseServiceAccountSubject reads every spelling this estate has minted
// for a ServiceAccount, and is the only place that knows there is more
// than one.
//
// Three exist because they arrived from different directions: the API
// server's own `system:serviceaccount:<ns>:<name>`, which a recovery
// sign-in completed as; this issuer's older `k8s:<ns>:<name>`, from a
// token exchange; and the cluster-qualified form above. A reader that
// knows one of them refuses a token minted by a release either side of
// its own, so they are all read here and only the last is written.
func ParseServiceAccountSubject(subject string) (ServiceAccountRef, bool) {
	if rest, found := strings.CutPrefix(subject, "system:serviceaccount:"); found {
		namespace, name, ok := strings.Cut(rest, ":")
		if !ok || namespace == "" || name == "" {
			return ServiceAccountRef{}, false
		}

		return ServiceAccountRef{Namespace: namespace, Name: name}, true
	}

	parts := strings.Split(subject, ":")
	switch {
	case len(parts) == 3 && parts[0] == "k8s" && parts[1] != "" && parts[2] != "":
		return ServiceAccountRef{Namespace: parts[1], Name: parts[2]}, true
	case len(parts) == 4 && parts[1] == "k8s" && parts[0] != "" && parts[2] != "" && parts[3] != "":
		return ServiceAccountRef{Cluster: parts[0], Namespace: parts[2], Name: parts[3]}, true
	default:
		return ServiceAccountRef{}, false
	}
}

// Held is one internal group a caller is in, and why.
//
// A caller may hold one [Held.Group] for more than one reason at once — a
// concrete Groups-table key AND a mapping wildcard that also reaches it,
// or a direct hold AND an implied one — and every reason is its own
// [Held] entry rather than one entry picking a winner: explainability
// means showing all of them, not the first one found.
type Held struct {
	// Group is the internal group's name — always concrete, even when it
	// was reached through a mapping wildcard or through inheritance.
	Group string
	// Via names what put the caller in it: the directory groups matched,
	// or the matcher, rendered for a person to read. Empty when Group was
	// reached only through inheritance (Implies is set instead).
	Via []string
	// Key is the Groups-table key that matched directly — equal to Group
	// for an ordinary key, and different for a mapping wildcard: matching
	// `*:k8s:admin` for `devel:k8s:admin` records Key="*:k8s:admin". Empty
	// when Group was reached only through inheritance.
	Key string
	// Implies is the concrete group whose role implied this one, one hop
	// at a time, per [Vocabulary]'s declared implies graph: holding
	// `devel:k8s:admin` where admin implies operator implies viewer
	// produces a `devel:k8s:viewer` [Held] with Implies="devel:k8s:operator",
	// not "…admin" — the direct parent, so a reader (the console,
	// eventually) walks the chain one link at a time rather than being
	// handed a root it has to trust. Empty when Group was held directly.
	Implies string
}

// Result is what the policy grants a proof.
type Result struct {
	// Groups are the internal groups held, sorted.
	Groups []string
	// Held carries the same, with the reason for each.
	Held []Held
	// Claims is the deep merge of the held groups' fragments, with the
	// group names themselves added under "groups".
	Claims map[string]any
	// Lifetime is the shortest across the held groups, or the default.
	Lifetime time.Duration
}

// Has reports whether an internal group is held.
func (r Result) Has(group string) bool { return slices.Contains(r.Groups, group) }

// Evaluate resolves a proof into groups, claims and a lifetime.
//
// Membership through the directory needs an authoritative answer:
// membership the hub cannot vouch for must not grant anything new.
// Matchers do not, because a CI token or a signed-in address is verified
// on its own.
//
// Two things happen here, and only here, so that every reader downstream —
// a client's or resource's `requires`, a token's `groups` claim, GitHub
// team reconciliation reading who holds a bound group — sees the result
// without knowing either exists:
//
//  1. A Groups-table key that is a mapping wildcard ([Policy.Vocabulary])
//     stands for every concrete grant its expansion names; a caller
//     matched by the key holds all of them, unioned with whatever
//     concrete keys separately match.
//  2. A concrete grant `S:T:R` held by either route also holds every role
//     `R` implies, transitively, on the SAME `S:T` — never across scopes.
func (p Policy) Evaluate(in Input) Result {
	confirmed := make(map[string]struct{}, len(in.DirectoryGroups))
	for _, g := range in.DirectoryGroups {
		confirmed[strings.ToLower(g)] = struct{}{}
	}

	// held accumulates every reason a concrete grant is held, by name.
	// Seeded from the Groups table below (direct membership or a matcher,
	// through a key's own name or a wildcard's expansion), then grown by
	// the inheritance walk that follows.
	held := map[string][]Held{}
	// frontier is every concrete grant reached DIRECTLY — the seed for the
	// inheritance walk, which starts from held roles and adds implied
	// ones, never the reverse.
	var frontier []string

	for _, name := range slices.Sorted(maps.Keys(p.Groups)) {
		group := p.Groups[name]
		var via []string

		if in.Authoritative {
			for _, address := range p.effectiveMembers(name) {
				if _, ok := confirmed[strings.ToLower(address)]; ok {
					via = append(via, address)
				}
			}
		}
		for i := range group.Matchers {
			if group.Matchers[i].matches(in) {
				via = append(via, group.Matchers[i].Describe())
			}
		}
		if len(via) == 0 {
			continue
		}

		for _, concrete := range p.groupKeyTargets(name) {
			if _, seen := held[concrete]; !seen {
				frontier = append(frontier, concrete)
			}
			held[concrete] = append(held[concrete], Held{Group: concrete, Key: name, Via: via})
		}
	}

	// Inheritance: breadth-first over the implies graph, one hop at a
	// time, so a branching ladder (admin implying both deployer and
	// operator) and a chained one (admin -> operator -> viewer) both
	// close correctly. reached stops a role from being re-queued once its
	// own implied roles have been added, but a later, DIFFERENT source
	// reaching an already-reached role still records its own [Held] entry
	// — two paths to the same grant are two reasons, not one.
	if p.Vocabulary != nil {
		queue := slices.Clone(frontier)
		reached := make(map[string]bool, len(frontier))
		for _, g := range frontier {
			reached[g] = true
		}
		for len(queue) > 0 {
			g := queue[0]
			queue = queue[1:]

			scope, thing, role, ok := SplitGroup(g)
			if !ok {
				continue
			}
			spec, ok := p.Vocabulary.Things[thing]
			if !ok {
				continue
			}
			for _, impliedRole := range spec.Roles[role].Implies {
				implied := scope + Separator + thing + Separator + impliedRole
				held[implied] = append(held[implied], Held{Group: implied, Implies: g})
				if !reached[implied] {
					reached[implied] = true
					queue = append(queue, implied)
				}
			}
		}
	}

	var out Result
	claims := map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(held)) {
		out.Groups = append(out.Groups, name)
		out.Held = append(out.Held, held[name]...)
		if fragment, ok := p.Claims[name]; ok {
			// A conflict is refused at load; ignoring one here would hide
			// a bug, so the fragment that cannot merge is simply skipped
			// and the rest of the token is still correct.
			_ = mergeFragment(claims, fragment, "")
		}
	}

	if len(out.Groups) > 0 {
		asAny := make([]any, 0, len(out.Groups))
		for _, name := range out.Groups {
			asAny = append(asAny, name)
		}
		if existing, ok := claims["groups"].([]any); ok {
			claims["groups"] = union(existing, asAny)
		} else {
			claims["groups"] = asAny
		}
	}
	if len(claims) > 0 {
		out.Claims = claims
	}
	out.Lifetime = p.lifetimeOf(out.Groups)
	return out
}

// effectiveMembers is a group's declared directory groups.
//
// It survives the removal of the memberships table because
// every caller reads a group's members through one function, and one
// function is where a future second source would have to announce
// itself.
func (p Policy) effectiveMembers(name string) []string {
	return slices.Clone(p.Groups[name].Members)
}

// lifetimeOf is the shortest lifetime across the held groups, falling
// back to the default. Privilege shortens a session; it never lengthens
// one.
func (p Policy) lifetimeOf(groups []string) time.Duration {
	shortest := time.Duration(0)
	for _, name := range groups {
		if d, ok := p.Lifetimes[name]; ok {
			if shortest == 0 || d.Duration() < shortest {
				shortest = d.Duration()
			}
		}
	}
	if shortest == 0 {
		shortest = p.Lifetimes[LifetimeDefault].Duration()
	}
	return shortest
}

// Title is what a person is shown this client as, given its id: the
// declared `display_name`, or for a cluster's client that declares none,
// "Kubernetes — <cluster>", or else the id itself.
//
// Never a generic "the application": a page that cannot name where a
// person is going has told them nothing they can check, and the id,
// however machine-shaped, is at least the same word on every page and in
// every log.
func (c Client) Title(id string) string {
	if name := strings.TrimSpace(c.DisplayName); name != "" {
		return name
	}
	if cluster, ok := strings.CutPrefix(id, "k8s:"); ok && cluster != "" {
		return "Kubernetes — " + cluster
	}
	return id
}

// Cap applies a client's ttl_cap to a lifetime.
func (c Client) Cap(lifetime time.Duration) time.Duration {
	capped := c.TTLCap.Duration()
	if capped > 0 && (lifetime == 0 || capped < lifetime) {
		return capped
	}
	return lifetime
}

// Admits reports whether a result holds any group the client requires.
func (c Client) Admits(r Result) bool {
	for _, name := range c.Requires {
		if r.Has(name) {
			return true
		}
	}
	return false
}
