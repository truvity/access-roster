package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// compat lists what the table `cur` changes against the table `old` of the last release in a way that a release of the same
// major version must not (ADR 0030, "The sluis fields"; REQ-AUDIT-119), so that the newest table still validates every
// record the old one did: an action that is gone, the class, an activity, an outcome or the actor that changed or went,
// a person, a tenant or a policy decision that the row no longer allows or now requires, a member that is gone, of another
// type or shape, or optional and required now, a member that is new and required, a type that is tighter. A member that is
// new and optional, an action that is new, or a bound that is looser, is fine.
func compat(old, cur *tableFile) []string {
	var out []string
	if old.OCSF != cur.OCSF {
		out = append(out, fmt.Sprintf("the OCSF version changed from %s to %s (metadata.version is a constant of every schema, so the records of the old release fail the newest)", old.OCSF, cur.OCSF))
	}
	if old.Product != cur.Product {
		out = append(out, fmt.Sprintf("the product changed from %s to %s (metadata.product.name is a constant of every schema)", old.Product, cur.Product))
	}
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
		out = append(out, compatRow(o, n)...)
		out = append(out, compatFields(o.Name, old, cur, o.Fields, n.Fields)...)
	}
	// Every type the old table names is still there and no tighter: the shared types (the status code, the version, the
	// time) are members of every record, though no row lists them.
	for _, name := range sortedNames(old.Types) {
		nt, ok := cur.Types[name]
		if !ok {
			out = append(out, "type "+name+": the type is gone")
			continue
		}
		out = append(out, compatType("type "+name, old.Types[name], nt)...)
	}
	sort.Strings(out)
	return out
}

// level orders what a row says of a part of the record that it may carry: none, optional, required.
func level(s string) int {
	switch s {
	case "optional":
		return 1
	case "required":
		return 2
	}
	return 0
}

// compatRow compares the top-level shape of two rows of one action.
func compatRow(o, n action) []string {
	var out []string
	if o.Class != n.Class {
		out = append(out, fmt.Sprintf("%s: the class changed from %d to %d", o.Name, o.Class, n.Class))
	}
	if o.Actor != n.Actor {
		out = append(out, fmt.Sprintf("%s: the actor changed from %s to %s", o.Name, o.Actor, n.Actor))
	}
	for _, oa := range o.activities() {
		if !slices.Contains(n.activities(), oa) {
			out = append(out, fmt.Sprintf("%s: the activity %d %q is gone", o.Name, oa.ID, oa.Name))
		}
	}
	for _, oo := range o.Outcomes {
		if !slices.Contains(n.Outcomes, oo) {
			out = append(out, fmt.Sprintf("%s: the outcome %s is gone", o.Name, oo))
		}
	}
	// A part the old row allowed must still be allowed, and one it did not require must not be required now; a part it
	// did not allow may become allowed (the new records that carry it are the new release's own).
	for _, p := range []struct{ name, old, new string }{{"tenant", o.Tenant, n.Tenant}, {"subject", o.Subject, n.Subject}, {"policy", o.Policy, n.Policy}} {
		lo, ln := level(p.old), level(p.new)
		if (lo >= 1 && ln == 0) || (lo < 2 && ln == 2) {
			out = append(out, fmt.Sprintf("%s: %s went from %s to %s", o.Name, p.name, nameOf(p.old), nameOf(p.new)))
		}
	}
	return append(out, compatEntity(o.Name, o.Entity, n.Entity)...)
}

// compatEntity compares the entity of two rows of Entity Management: the records of the old release carry what the old row
// says, so a row that gains an entity, changes its type or takes a member it did not carry makes them fail, and a member
// that goes makes the new schema refuse the old records.
func compatEntity(name string, o, n *entitySpec) []string {
	switch {
	case o == nil && n == nil:
		return nil
	case o == nil:
		return []string{name + ": the row gains an entity, which the records of the old release do not carry"}
	case n == nil:
		return []string{name + ": the row loses its entity"}
	}
	var out []string
	if o.Type != n.Type {
		out = append(out, fmt.Sprintf("%s: the type of the entity changed from %s to %s", name, o.Type, n.Type))
	}
	for _, m := range []struct {
		n      string
		is, to bool
	}{{"name", o.Name, n.Name}, {"uid", o.UID, n.UID}, {"version", o.Version, n.Version}} {
		switch {
		case m.is && !m.to:
			out = append(out, fmt.Sprintf("%s: the entity no longer has a %s", name, m.n))
		case !m.is && m.to:
			out = append(out, fmt.Sprintf("%s: the entity now has a %s, which the records of the old release do not carry", name, m.n))
		}
	}
	return out
}

func nameOf(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func compatFields(where string, old, cur *tableFile, o, n map[string]fieldSpec) []string {
	var out []string
	// A member that is new must be optional: a record of the old release does not carry it.
	for _, name := range sortedNames(n) {
		if _, ok := o[name]; !ok && n[name].Required {
			out = append(out, where+"."+name+": a new member is required (the records of the old release do not carry it)")
		}
	}
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

// oldRecordsUnder builds the example record of every action of the old table and validates it against the schemas of the
// new one; it returns the actions whose record fails.
// oldRecordsUnder builds the example record of every action of the old table and validates it against the schemas of the
// new one; it returns the actions whose record fails. It is the proof behind the rules above: what compat passes, the schemas
// accept.
func oldRecordsUnder(old, cur *tableFile) ([]string, error) {
	vec, err := buildVectors(old)
	if err != nil {
		return nil, err
	}
	var f struct {
		Cases []struct {
			Name     string `json:"name"`
			Expected string `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(vec, &f); err != nil {
		return nil, err
	}
	_, texts, err := schemaTexts(cur)
	if err != nil {
		return nil, err
	}
	schemas, err := audit.ParseSchemas(texts)
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, c := range f.Cases {
		if _, ok := texts[c.Name+".schema.json"]; !ok {
			continue // an action the new table lacks is found by compat
		}
		if schemas.Validate(c.Name+".schema.json", []byte(c.Expected)) != nil {
			bad = append(bad, c.Name)
		}
	}
	return bad, nil
}
