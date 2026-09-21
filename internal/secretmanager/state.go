package secretmanager

import (
	"slices"
	"sort"
	"strings"
)

// State is what one group is, in a namespace, once what the deployment
// declares is laid beside what the store holds.
//
// Four, not three: a reader that could not look must not be drawn as a
// store that holds nothing. That distinction is the reason this page
// exists at all — an empty namespace and a namespace nobody may read
// look identical to everything except the status of the call.
type State string

const (
	// StateBound is declared, present, and carrying a policy of its own
	// name. The ordinary state: nothing to do.
	StateBound State = "bound"
	// StateAbsent is declared and not in the store. The apply has not
	// run, or it refused. It is not drift: the estate's answer is
	// already right, and the store has yet to hear it.
	StateAbsent State = "absent"
	// StateUnexpected is in the store and not declared. This is the
	// interesting one — something granted access that no reviewed file
	// asks for — and it is what a page like this is worth reading for.
	StateUnexpected State = "unexpected"
	// StateUnreadable is what the reader could not look at. Never
	// inferred from an empty answer: only from a refusal.
	StateUnreadable State = "unreadable"
)

// GroupView is one group as the page draws it: its state, what the store
// says it carries, and which doors admit it.
type GroupView struct {
	// Name is the group's name, which is also the name of the policy it
	// is expected to carry. One name, three things — the internal group,
	// the policy and the identity group — is the whole convention, and a
	// page that shows them separately is showing that it held.
	Name string
	// State is the four-way answer above.
	State State
	// Declared is whether the deployment's own policy names this group
	// for this namespace.
	Declared bool
	// Policies is what the store's identity group carries, which is
	// usually the group's own name and is worth showing when it is not.
	Policies []string
	// HasPolicy is whether a policy of the group's own name exists in
	// the namespace. A group bound to a policy that is not there grants
	// nothing, and the store reports neither as an error.
	HasPolicy bool
	// Members is how many entities the store has put in the group. It is
	// not membership — that is the roster's answer, and the console has
	// it — but a group nobody has ever logged in as reads differently
	// from one with fifty.
	Members int
	// Aliases are the doors this group is bound at.
	Aliases []GroupAlias
	// Doors are the alias mounts, sorted, for a page that wants to say
	// "CLI and web" without walking the aliases.
	Doors []string
}

// Live is what one namespace's reads returned, with a flag for each read
// the reader was refused — because a refusal is a state to draw and not
// an error to return.
type Live struct {
	// Groups are the identity groups the store holds, by name.
	Groups map[string]Group
	// Policies are the names of the ACL policies in the namespace.
	Policies []string
	// GroupsUnreadable is whether the groups could not be listed.
	GroupsUnreadable bool
	// PoliciesUnreadable is whether the policies could not be listed.
	PoliciesUnreadable bool
}

// Compare lays the groups a deployment declares for one namespace beside
// what the store holds, and returns one view per group, sorted by name.
//
// Declared groups come from the installation's own policy — the same
// file that decides who is in them — so "declared" here means "the
// estate asks for this", never "somebody typed it into the console".
func Compare(declared []string, live Live) []GroupView {
	views := map[string]*GroupView{}

	policies := map[string]bool{}
	for _, name := range live.Policies {
		policies[name] = true
	}

	for _, name := range declared {
		views[name] = &GroupView{Name: name, Declared: true, State: StateAbsent}
	}
	for name, group := range live.Groups {
		view, ok := views[name]
		if !ok {
			view = &GroupView{Name: name}
			views[name] = view
		}
		view.Policies = slices.Clone(group.Policies)
		view.Members = group.Members
		view.Aliases = slices.Clone(group.Aliases)
		for _, alias := range group.Aliases {
			if door := or(alias.Mount, alias.MountAccessor); door != "" && !slices.Contains(view.Doors, door) {
				view.Doors = append(view.Doors, door)
			}
		}
		sort.Strings(view.Doors)
		view.HasPolicy = policies[name]
		if view.Declared {
			view.State = StateBound
		} else {
			view.State = StateUnexpected
		}
	}

	// A refusal wins over everything derived from the reads it denied.
	// The page must not say "absent" — which reads as "the apply has not
	// run" and sends somebody to look at a pipeline — when the honest
	// answer is that this service may not look.
	for _, view := range views {
		switch {
		case live.GroupsUnreadable:
			view.State = StateUnreadable
		case live.PoliciesUnreadable && view.State == StateBound:
			// The group is there; whether its policy is, is unknown.
			view.HasPolicy = false
		}
	}

	out := make([]GroupView, 0, len(views))
	for _, view := range views {
		out = append(out, *view)
	}
	slices.SortFunc(out, func(a, b GroupView) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// DeclaredFor is the groups of one environment, out of every internal
// group the installation declares: the ones whose first segment is the
// environment's name.
//
// The convention this reads is the whole naming scheme —
// `{environment}:{project}:{role}` — and a group that does not follow it
// belongs to no namespace, which is why `all:` groups (the ones that
// span environments) are not shown under any one of them.
func DeclaredFor(environment string, groups []string) []string {
	prefix := environment + ":"
	out := make([]string, 0, len(groups))
	for _, name := range groups {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Counts is how many groups are in each state, for a namespace's summary
// line: the page says "42 bound, 1 unexpected" before it says anything
// else, because that sentence is what somebody opened it to read.
type Counts struct {
	Bound      int
	Absent     int
	Unexpected int
	Unreadable int
}

// Count summarises a namespace's groups.
func Count(views []GroupView) Counts {
	var c Counts
	for i := range views {
		switch views[i].State {
		case StateBound:
			c.Bound++
		case StateAbsent:
			c.Absent++
		case StateUnexpected:
			c.Unexpected++
		case StateUnreadable:
			c.Unreadable++
		}
	}
	return c
}
