package main

import (
	"fmt"
	"sort"
)

// compat lists what the table `cur` changes in `unmapped.sluis` against the table `old` of the last release in a way
// that a release of the same major version must not (ADR 0030, "The sluis fields"; REQ-AUDIT-119): a member that is
// gone, a member of another type or shape, an action that is gone, a member that was optional and is required now, a
// bound that is tighter. A member that is new, or a bound that is looser, is fine.
func compat(old, cur *tableFile) []string {
	var out []string
	now := map[string]action{}
	for _, a := range cur.Actions {
		now[a.Name] = a
	}
	for _, o := range old.Actions {
		n, ok := now[o.Name]
		if !ok {
			out = append(out, fmt.Sprintf("%s: the action is gone", o.Name))
			continue
		}
		out = append(out, compatFields(o.Name, old, cur, o.Fields, n.Fields)...)
	}
	sort.Strings(out)
	return out
}

func compatFields(where string, old, cur *tableFile, o, n map[string]fieldSpec) []string {
	var out []string
	for _, name := range sortedNames(o) {
		w := where + "." + name
		nf, ok := n[name]
		if !ok {
			out = append(out, w+": the member is gone")
			continue
		}
		of := o[name]
		if !of.Required && nf.Required {
			out = append(out, w+": the member was optional and is required now")
		}
		out = append(out, compatField(w, old, cur, of, nf)...)
	}
	return out
}

func kind(f fieldSpec) string {
	switch {
	case f.Type != "":
		return "scalar"
	case f.Items != "":
		return "list"
	case f.Map != nil:
		return "map"
	}
	return "object"
}

func compatField(w string, old, cur *tableFile, o, n fieldSpec) []string {
	if kind(o) != kind(n) {
		return []string{w + ": the member changed from a " + kind(o) + " to a " + kind(n)}
	}
	switch kind(o) {
	case "scalar":
		return compatType(w, old.Types[o.Type], cur.Types[n.Type])
	case "list":
		out := compatType(w+"[]", old.Types[o.Items], cur.Types[n.Items])
		if n.Max < o.Max {
			out = append(out, fmt.Sprintf("%s: the bound of the list went from %d to %d", w, o.Max, n.Max))
		}
		return out
	case "map":
		out := compatType(w+"{key}", old.Types[o.Key.Type], cur.Types[n.Key.Type])
		if n.Max < o.Max {
			out = append(out, fmt.Sprintf("%s: the bound of the map went from %d to %d", w, o.Max, n.Max))
		}
		return append(out, compatFields(w, old, cur, o.Map.Fields, n.Map.Fields)...)
	}
	return compatFields(w, old, cur, o.Fields, n.Fields)
}

// compatType compares a type of a member: the JSON type and the pattern stay, a length or a range may only widen.
func compatType(w string, o, n typeDef) []string {
	var out []string
	if o.Type != n.Type {
		out = append(out, fmt.Sprintf("%s: the type changed from %s to %s", w, o.Type, n.Type))
	}
	if o.Pattern != n.Pattern {
		out = append(out, w+": the pattern changed")
	}
	if tighter(o.MaxLength, n.MaxLength, false) {
		out = append(out, w+": maxLength is tighter")
	}
	if tighter(o.Maximum, n.Maximum, false) {
		out = append(out, w+": maximum is tighter")
	}
	if tighter(o.Minimum, n.Minimum, true) {
		out = append(out, w+": minimum is tighter")
	}
	return out
}

// tighter reports whether the new bound admits less than the old one. A missing bound admits everything. For a lower
// bound (low) a larger value admits less; for an upper bound a smaller one does.
func tighter(o, n *int64, low bool) bool {
	switch {
	case n == nil:
		return false
	case o == nil:
		return true
	case low:
		return *n > *o
	}
	return *n < *o
}
