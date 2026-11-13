package tenant

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/truvity/sluis/policy/compile"
)

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
		// AppGrants are the accepted owner's App grants, by App id, for
		// the installation to add to those Apps' grants. Nil when the
		// owner was left out.
		AppGrants map[string][]AppGrant
		// Gates are the accepted owner's gates, by client id, for the
		// installation to add to its clients ([Gate.Client]). Nil when the
		// owner was left out.
		Gates map[string]Gate
	}
)

// Accepted reports whether the owner's fragment is in the merged model.
func (r Result) Accepted() bool { return len(r.Violations) == 0 }

// rosterFunc derives the roster of a model. It is a parameter of effect so
// that a test can hand in a derivation with a bug.
type rosterFunc func(compile.Model, compile.Conventions) *compile.Policy

// CheckEffect refuses a fragment by what it does to the installation's
// roster, not by what it says. It derives [compile.Roster] for the base and
// for the base with the fragment merged, and compares them:
//
//   - a group that is new, or gained a member or a matcher, must match a
//     pattern of the ceiling (a rung's own group, `rung:<name>`, matches
//     when the ceiling lists the rung), and every matcher it gained must be
//     on an organisation, cluster or account the owner holds;
//   - a member a group gained must be in the owner's directories, unless
//     the base roster already holds that member somewhere: the people of
//     the installation reach a company's new group through the rungs, and
//     the pattern bounds where, while a fragment cannot name one;
//   - anything the fragment may not change is refused: a member or matcher
//     a group loses, a group that disappears, a lifetime that changes, the
//     default lifetime, a deferred grant, a binding of an organisation or
//     workspace the owner does not hold, the people registry.
//
// A company that joins a rung inherits the rung's cells, so what it reaches
// is bounded by the groups those cells derive and not by the names it
// wrote. A new rule in the derivation cannot widen a company either: it
// shows up as a change here. The check is conservative; a change it cannot
// tell is harmless is refused.
//
// A base with no scopes matrix has no roster, and an effect that cannot be
// seen is refused. CheckEffect does not read the fragment's rows; [Check]
// does, and [MergeAll] runs both. It assumes that no key of the fragment is
// already in the base.
func CheckEffect(base compile.Model, c compile.Conventions, o Owner, f Fragment) []Violation {
	vs, _ := effect(compile.Roster, base, c, o, f)

	return vs
}

// effect is [CheckEffect] with the derivation as a parameter. It also
// returns the groups the fragment mints: new, and not fed by a rung.
func effect(roster rosterFunc, base compile.Model, conv compile.Conventions, o Owner, f Fragment) ([]Violation, []string) {
	if f.IsEmpty() {
		return nil, nil
	}

	c := newChecker(nil, o)

	if o.Ceiling.IsZero() {
		c.add(OwnerEmptyCeiling, "ceiling", "the owner has no ceiling, so the fragment may declare nothing")

		return c.sorted(), nil
	}

	before := roster(base, conv)
	after := roster(merged(base, f), conv)

	if before == nil || after == nil {
		c.add(OwnerEffect, "base", "the installation's model has no scopes matrix, so what the fragment changes cannot be derived")

		return c.sorted(), nil
	}

	minted := c.groupEffects(before, after)
	c.lifetimeEffects(before, after)
	c.deferredEffects(before, after)
	c.githubEffects(before, after)
	c.slackEffects(before, after)

	if !reflect.DeepEqual(before.People, after.People) {
		c.add(OwnerEffect, "people", "the people registry would change")
	}

	return c.sorted(), minted
}

func index[V any](list []V, name func(V) string) map[string]V {
	out := make(map[string]V, len(list))
	for _, v := range list {
		out[name(v)] = v
	}

	return out
}

// groupAllowed reports whether the ceiling allows the group to be minted or
// to gain members.
func (c *checker) groupAllowed(name string) bool {
	if rung, ok := strings.CutPrefix(name, compile.RungPrefix); ok {
		_, listed := c.rungs[rung]

		return listed
	}

	return matchesAny(c.ceiling.Groups, name)
}

func (c *checker) inDirectories(address string) bool {
	_, domain, ok := strings.Cut(address, "@")
	if !ok {
		return false
	}

	_, in := c.directories[strings.ToLower(domain)]

	return in
}

// gained is what is in now and was not in before.
func gained[T comparable](before, now []T) []T {
	var out []T

	for _, v := range now {
		if !slices.Contains(before, v) {
			out = append(out, v)
		}
	}

	return out
}

func (c *checker) groupEffects(before, after *compile.Policy) []string {
	held := map[string]struct{}{}
	for i := range before.Groups {
		for _, m := range slices.Concat(before.Groups[i].Members, before.Groups[i].Emails) {
			held[m] = struct{}{}
		}
	}

	was := index(before.Groups, func(g compile.Group) string { return g.Name })
	is := index(after.Groups, func(g compile.Group) string { return g.Name })

	for _, name := range sortedKeys(was) {
		if _, ok := is[name]; !ok {
			c.add(OwnerEffect, key("groups", name), "group %q would disappear", name)
		}
	}

	var minted []string

	for i := range after.Groups {
		g := &after.Groups[i]
		prev, existed := was[g.Name]
		path := key("groups", g.Name)

		for _, m := range slices.Concat(gained(g.Members, prev.Members), gained(g.Emails, prev.Emails)) {
			c.add(OwnerEffect, path, "group %q would lose %q", g.Name, m)
		}

		if lost := c.lostMatchers(prev, g); lost != "" {
			c.add(OwnerEffect, path, "group %q would lose %s", g.Name, lost)
		}

		members, emails := gained(prev.Members, g.Members), gained(prev.Emails, g.Emails)
		matchers := gained(prev.GitHub, g.GitHub)
		accounts := gained(prev.ServiceAccounts, g.ServiceAccounts)
		roles := gained(prev.AWS, g.AWS)

		if len(members)+len(emails)+len(matchers)+len(accounts)+len(roles) == 0 {
			continue
		}

		if !c.groupAllowed(g.Name) {
			verb := "gain members or matchers"
			if !existed {
				verb = "be created"
			}

			c.add(OwnerEffect, path, "group %q would %s and matches no pattern of the owner's ceiling", g.Name, verb)
		}

		for _, m := range slices.Concat(members, emails) {
			if _, in := held[m]; !in && !c.inDirectories(m) {
				c.add(OwnerEffect, path, "group %q would gain %q, outside the owner's directories and not held by the installation", g.Name, m)
			}
		}

		c.matcherEffects(path, g.Name, matchers, accounts, roles)

		if !existed && len(g.Rungs) == 0 {
			minted = append(minted, g.Name)
		}
	}

	return minted
}

// lostMatchers names the matchers the group had and no longer has.
func (c *checker) lostMatchers(prev compile.Group, now *compile.Group) string {
	var out []string

	lost := gained(now.GitHub, prev.GitHub)
	for i := range lost {
		out = append(out, fmt.Sprintf("a GitHub matcher on %q", lost[i].Repository+lost[i].Owner))
	}

	for _, m := range gained(now.ServiceAccounts, prev.ServiceAccounts) {
		out = append(out, fmt.Sprintf("the ServiceAccount matcher %s/%s", m.Namespace, m.Name))
	}

	for _, m := range gained(now.AWS, prev.AWS) {
		out = append(out, fmt.Sprintf("the AWS matcher %s/%s", m.Account, m.Role))
	}

	return strings.Join(out, ", ")
}

// matcherEffects checks that every matcher a group gained is on something
// the owner holds.
func (c *checker) matcherEffects(
	path, group string, github []compile.GitHubMatcher, accounts []compile.ServiceAccountMatcher, roles []compile.AWSMatcher,
) {
	for i := range github {
		m := &github[i]
		owners := []string{}

		if m.Owner != "" {
			owners = append(owners, m.Owner)
		}

		if owner, _, ok := strings.Cut(m.Repository, "/"); m.Repository != "" && ok {
			owners = append(owners, owner)
		}

		if len(owners) == 0 {
			c.add(OwnerEffect, path, "group %q would gain a GitHub matcher that names no organisation", group)
		}

		for _, owner := range owners {
			if _, ok := c.githubOrgs[strings.ToLower(owner)]; !ok {
				c.add(OwnerEffect, path, "group %q would gain a GitHub matcher on organisation %q, which the owner does not hold", group, owner)
			}
		}
	}

	for _, m := range accounts {
		if _, ok := c.clusters[m.Cluster]; !ok {
			c.add(OwnerEffect, path, "group %q would gain a ServiceAccount matcher in cluster %q, which the owner may not run in", group, m.Cluster)
		}
	}

	for _, m := range roles {
		if _, ok := c.accounts[m.Account]; !ok {
			c.add(OwnerEffect, path, "group %q would gain an AWS matcher in account %q, which the owner may not run in", group, m.Account)
		}
	}
}

func (c *checker) lifetimeEffects(before, after *compile.Policy) {
	was := index(before.Lifetimes, func(l compile.Lifetime) string { return l.Group })
	is := index(after.Lifetimes, func(l compile.Lifetime) string { return l.Group })
	groups := index(after.Groups, func(g compile.Group) string { return g.Name })

	for _, name := range sortedKeys(is) {
		path := key("lifetimes", name)
		prev, had := was[name]
		now := is[name]

		switch {
		case had && prev.Duration != now.Duration:
			c.add(OwnerEffect, path, "the lifetime of %q would change from %s to %s", name, prev.Duration, now.Duration)
		case had:
		case name == "default":
			c.add(OwnerEffect, path, "the default lifetime would be set to %s", now.Duration)
		case !strings.HasPrefix(name, compile.RungPrefix):
			c.add(OwnerEffect, path, "a lifetime would be set for %q, which is not a rung", name)
		}
	}

	for _, name := range sortedKeys(was) {
		if _, kept := is[name]; kept {
			continue
		}

		if _, alive := groups[name]; alive || name == "default" {
			c.add(OwnerEffect, key("lifetimes", name), "the lifetime of %q would disappear", name)
		}
	}
}

func (c *checker) deferredEffects(before, after *compile.Policy) {
	for _, d := range gained(before.Deferred, after.Deferred) {
		c.add(OwnerEffect, key("deferred", d.Group), "the grant of %q to %q would be deferred: %s", d.Group, d.Subject, d.Reason)
	}

	for _, d := range gained(after.Deferred, before.Deferred) {
		c.add(OwnerEffect, key("deferred", d.Group), "the deferred grant of %q to %q would disappear", d.Group, d.Subject)
	}
}

func (c *checker) githubEffects(before, after *compile.Policy) {
	was := index(before.GitHub, func(b compile.GitHubBinding) string { return b.Org })
	is := index(after.GitHub, func(b compile.GitHubBinding) string { return b.Org })

	for _, org := range sortedKeys(was) {
		switch now, ok := is[org]; {
		case !ok:
			c.add(OwnerEffect, key("github", org), "the binding of organisation %q would disappear", org)
		case !reflect.DeepEqual(was[org], now):
			c.add(OwnerEffect, key("github", org), "the binding of organisation %q would change", org)
		}
	}

	for _, org := range sortedKeys(is) {
		if _, had := was[org]; had {
			continue
		}

		if _, ok := c.githubOrgs[strings.ToLower(org)]; !ok {
			c.add(OwnerEffect, key("github", org), "organisation %q would be bound, and the owner does not hold it", org)
		}
	}
}

func (c *checker) slackEffects(before, after *compile.Policy) {
	was := index(before.Slack, func(b compile.SlackBinding) string { return b.Workspace })
	is := index(after.Slack, func(b compile.SlackBinding) string { return b.Workspace })

	for _, ws := range sortedKeys(was) {
		switch now, ok := is[ws]; {
		case !ok:
			c.add(OwnerEffect, key("slack", ws), "the binding of workspace %q would disappear", ws)
		case !reflect.DeepEqual(was[ws], now):
			c.add(OwnerEffect, key("slack", ws), "the binding of workspace %q would change", ws)
		}
	}

	for _, ws := range sortedKeys(is) {
		if _, had := was[ws]; had {
			continue
		}

		if _, ok := c.slackWorkspaces[strings.ToLower(ws)]; !ok {
			c.add(OwnerEffect, key("slack", ws), "workspace %q would be bound, and the owner does not hold it", ws)
		}
	}
}

// MergeAll merges the owners' fragments into the base and says, per owner,
// whether it was accepted.
//
// An owner is accepted as a whole or not at all. It is refused when [Check]
// finds a violation, when [CheckEffect] does, when another owner declares
// the same key, when another owner mints the same group, or when its name
// is empty or shared. A refused owner is left out and the others are merged
// as if it had not been there: one invalid company never changes what
// another contributes. Collisions are decided on what the owners declare,
// not on whether the other owner is otherwise valid, so the same set of
// fragments is refused the same way whoever else is in the list.
//
// App grants and gates are not part of the model: an accepted owner's are
// in its [Result], for the installation to add to its Apps and clients. Two
// owners that declare the same gate are both refused; a gate whose id is
// already one of the installation's own clients is the installation's to
// refuse, since its clients are not in the model.
//
// The result does not depend on the order of the owners. Results are sorted
// by owner name. The base is never written to. With no owners the model
// returned is the base, and [compile.Roster] of the base and fragments
// merged equals [compile.Roster] of the model written whole.
func MergeAll(base compile.Model, conv compile.Conventions, owned ...Owned) (compile.Model, []Result) {
	owners := slices.Clone(owned)
	slices.SortStableFunc(owners, func(a, b Owned) int { return strings.Compare(a.Owner.Name, b.Owner.Name) })

	problems := make([][]Violation, len(owners))
	minted := make([][]string, len(owners))

	for i := range owners {
		o := &owners[i]
		problems[i] = Check(&base, o.Owner, o.Fragment)

		vs, groups := effect(compile.Roster, base, conv, o.Owner, o.Fragment)
		minted[i] = groups

		// What the fragment would do is only worth saying once what it
		// says is in order.
		if len(problems[i]) == 0 {
			problems[i] = vs
		}
	}

	declared := map[string][]int{}
	named := map[string][]int{}

	for i := range owners {
		o := &owners[i]

		if o.Owner.Name != "" {
			named[o.Owner.Name] = append(named[o.Owner.Name], i)
		}

		for _, k := range declaredKeys(o.Fragment) {
			declared[k] = append(declared[k], i)
		}

		for _, g := range minted[i] {
			declared[key("groups", g)] = append(declared[key("groups", g)], i)
		}
	}

	for _, name := range sortedKeys(named) {
		if who := named[name]; len(who) > 1 {
			for _, i := range who {
				problems[i] = append(problems[i], Violation{
					Owner: name, Code: OwnerCollision, Path: "owner",
					Detail: fmt.Sprintf("the owner name %q is used by %d fragments", name, len(who)),
				})
			}
		}
	}

	for _, path := range sortedKeys(declared) {
		who := declared[path]
		if len(who) < 2 {
			continue
		}

		names := make([]string, 0, len(who))
		for _, i := range who {
			names = append(names, owners[i].Owner.Name)
		}

		for _, i := range who {
			problems[i] = append(problems[i], Violation{
				Owner: owners[i].Owner.Name, Code: OwnerCollision, Path: path,
				Detail: fmt.Sprintf("%s is declared by %s", path, strings.Join(names, " and ")),
			})
		}
	}

	results := make([]Result, len(owners))

	var accepted []Fragment

	for i := range owners {
		o := &owners[i]
		results[i] = Result{Owner: o.Owner.Name}

		if len(problems[i]) == 0 {
			accepted = append(accepted, o.Fragment)
			results[i].AppGrants = o.Fragment.AppGrants
			results[i].Gates = o.Fragment.Gates

			continue
		}

		results[i].Violations = sortViolations(problems[i])
	}

	return merged(base, accepted...), results
}

// declaredKeys are the keys of a fragment that name one thing for the whole
// installation, as paths. A rung is not one: owners add people to it.
func declaredKeys(f Fragment) []string {
	var out []string

	add := func(kind string, names []string) {
		for _, n := range names {
			out = append(out, key(kind, n))
		}
	}

	add("projects", sortedKeys(f.Projects))
	add("applications", sortedKeys(f.Applications))
	add("github", sortedKeys(f.GitHub))
	add("slack", sortedKeys(f.Slack))
	add("jobs", sortedKeys(f.Jobs))
	add("workloads", sortedKeys(f.Workloads))
	add("gates", sortedKeys(f.Gates))

	return out
}
