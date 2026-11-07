package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// A published schema identifier never changes, and an incompatible schema is a new version under a new path, beside the
// old one (ADR 0004 "Schemas are Protobuf", ADR 0013 "Compatibility between releases"; REQ-DATA-040). This file judges two
// trees of schemas, the committed one and the one of the last release:
//
//   - every schema of the release is still there, at the same path, with the same $id;
//   - every schema is compatible with its earlier self: whatever the old schema accepted, the new one accepts. A key may
//     be added and a bound may be looser; a key may not go, a type may not change, a key may not become required, a
//     pattern may not change, and a bound may not be tighter;
//   - a schema under a new path (a new version, a new name) is free: it is a new identifier.
//
// Compatibility of arbitrary JSON Schemas is not decidable here, so the judge knows the keywords that the generator writes
// (schema.go) and fails closed on any other: a keyword it cannot compare is a finding, never a pass.

// annotations carry no verdict: a change of one is compatible.
var annotations = map[string]bool{"title": true, "description": true, "$comment": true, "examples": true, "$defs": true}

// checkIDs lists the schemas of a tree whose $id is not the identifier of their path, or that are not schemas the generator
// makes, so that an identifier is the path and a path is an identifier.
func checkIDs(docs map[string]map[string]any) []string {
	var out []string
	for rel, d := range docs {
		if want := idBase + rel; d["$id"] != want {
			out = append(out, fmt.Sprintf("%s: the $id is not %s", rel, want))
		}
		if d["$schema"] != draft {
			out = append(out, fmt.Sprintf("%s: the dialect is not %s", rel, draft))
		}
	}
	sort.Strings(out)
	return out
}

// loadTree reads every schema below dir (dir/<name>/<version>/<name>.schema.json) by its path below dir.
func loadTree(dir string) (map[string]map[string]any, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*", "*.schema.json"))
	if err != nil {
		return nil, err
	}
	docs := map[string]map[string]any{}
	for _, p := range paths {
		raw, err := os.ReadFile(p) //nolint:gosec // a schema of the repository or of a release
		if err != nil {
			return nil, err
		}
		var d map[string]any
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		rel, _ := filepath.Rel(dir, p)
		docs[filepath.ToSlash(rel)] = d
	}
	return docs, nil
}

// compatTrees lists what the schemas of `cur` change against the schemas `old` of the last release in a way that a release
// of the same major version must not.
func compatTrees(old, cur map[string]map[string]any) []string {
	out := checkIDs(cur)
	for rel, o := range old {
		n, ok := cur[rel]
		if !ok {
			out = append(out, rel+": a published schema is gone")
			continue
		}
		if o["$id"] != n["$id"] {
			out = append(out, rel+": the $id of a published schema changed")
			continue
		}
		out = append(out, compatNode(rel, o, n, o, n, 0)...)
	}
	sort.Strings(out)
	return out
}

// resolve follows a local $ref ("#/$defs/Name") in the document it stands in.
func resolve(root, node map[string]any) (map[string]any, error) {
	for depth := 0; ; depth++ {
		ref, ok := node["$ref"].(string)
		if !ok {
			return node, nil
		}
		name, ok := strings.CutPrefix(ref, "#/$defs/")
		if !ok || depth > 8 {
			return nil, fmt.Errorf("a $ref the judge cannot follow")
		}
		defs, _ := root["$defs"].(map[string]any)
		next, ok := defs[name].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("a $ref to nothing")
		}
		// A schema with a $ref has its siblings as well (annotations only, in what the generator writes).
		for k := range node {
			if k != "$ref" && !annotations[k] {
				return nil, fmt.Errorf("a $ref beside the keyword %s", k)
			}
		}
		node = next
	}
}

// compatNode compares a schema of the old tree with the schema at the same place of the new one. A boolean schema is
// `true` (accepts all) or `false` (accepts nothing).
func compatNode(where string, oldRoot, newRoot, o, n map[string]any, depth int) []string {
	var out []string
	var err error
	if o, err = resolve(oldRoot, o); err != nil {
		return []string{where + ": " + err.Error()}
	}
	if n, err = resolve(newRoot, n); err != nil {
		return []string{where + ": " + err.Error()}
	}
	// A recursive message makes a recursive definition: the judge goes down a bounded way and says so.
	if depth > 32 {
		return []string{where + ": nested deeper than the judge goes"}
	}

	known := map[string]bool{"$schema": true, "$id": true, "type": true, "properties": true, "required": true, "items": true,
		"unevaluatedProperties": true, "pattern": true, "minLength": true, "maxLength": true, "minItems": true, "maxItems": true,
		"uniqueItems": true, "const": true, "enum": true, "minimum": true, "maximum": true, "minProperties": true,
		"propertyNames": true, "additionalProperties": true}
	for _, side := range []map[string]any{o, n} {
		for k := range side {
			if !known[k] && !annotations[k] {
				out = append(out, fmt.Sprintf("%s: the keyword %s is one the judge cannot compare", where, k))
			}
		}
	}
	if len(out) > 0 {
		return out
	}

	// The keywords that decide on their own: adding one, or changing it, accepts less.
	for _, k := range []string{"type", "pattern", "const"} {
		ov, oHas := o[k]
		nv, nHas := n[k]
		switch {
		case nHas && !oHas:
			out = append(out, fmt.Sprintf("%s: %s is new (the old schema accepted every value of it)", where, k))
		case nHas && oHas && !reflect.DeepEqual(ov, nv):
			out = append(out, fmt.Sprintf("%s: %s changed", where, k))
		}
	}
	// A set of values may grow and may not shrink.
	if ne, ok := n["enum"].([]any); ok {
		oe, oHas := o["enum"].([]any)
		if c, has := o["const"]; has {
			oe, oHas = []any{c}, true
		}
		switch {
		case !oHas:
			out = append(out, where+": enum is new")
		default:
			for _, v := range oe {
				if !contains(ne, v) {
					out = append(out, where+": enum lost a value")
					break
				}
			}
		}
	}
	// Bounds: a minimum may only fall, a maximum only rise, and none may appear.
	for _, k := range []string{"minLength", "minItems", "minProperties", "minimum"} {
		out = append(out, bound(where, k, o, n, func(old, cur float64) bool { return cur > old })...)
	}
	for _, k := range []string{"maxLength", "maxItems", "maximum"} {
		out = append(out, bound(where, k, o, n, func(old, cur float64) bool { return cur < old })...)
	}
	if u, _ := n["uniqueItems"].(bool); u {
		if ou, _ := o["uniqueItems"].(bool); !ou {
			out = append(out, where+": uniqueItems is new")
		}
	}
	// An unknown key was refused when the old schema said `false`: the new one may refuse it, or accept it. It may not
	// start refusing what the old one accepted.
	if v, has := n["unevaluatedProperties"]; has && v == false {
		if ov, ohas := o["unevaluatedProperties"]; !ohas || ov != false {
			out = append(out, where+": unknown keys are refused now")
		}
	}
	// Keys: none goes, none that was optional is required now.
	oreq, nreq := stringSet(o["required"]), stringSet(n["required"])
	for _, r := range nreq {
		if !contains(toAny(oreq), r) {
			out = append(out, fmt.Sprintf("%s.%s: the key was optional and is required now", where, r))
		}
	}
	oprops, _ := o["properties"].(map[string]any)
	nprops, _ := n["properties"].(map[string]any)
	for _, name := range sortedKeys(oprops) {
		w := where + "." + name
		np, ok := nprops[name]
		if !ok {
			// The old schema accepted the key; the new one does not know it. With unevaluatedProperties false that is a
			// key that goes, unless the old one refused it already (a retired key).
			if oprops[name] != false {
				out = append(out, w+": the key is gone")
			}
			continue
		}
		if np == false && oprops[name] != false {
			out = append(out, w+": the key is retired now")
			continue
		}
		if oprops[name] == false || np == false {
			continue
		}
		om, ook := oprops[name].(map[string]any)
		nm, nok := np.(map[string]any)
		if !ook || !nok {
			out = append(out, w+": a schema the judge cannot compare")
			continue
		}
		out = append(out, compatNode(w, oldRoot, newRoot, om, nm, depth+1)...)
	}
	// The names of the keys and the schema of the other keys' values are schemas of their own.
	for _, k := range []string{"propertyNames", "additionalProperties"} {
		nv, nHas := n[k].(map[string]any)
		ov, oHas := o[k].(map[string]any)
		switch {
		case nHas && !oHas:
			out = append(out, fmt.Sprintf("%s: %s is new", where, k))
		case nHas && oHas:
			out = append(out, compatNode(where+"."+k, oldRoot, newRoot, ov, nv, depth+1)...)
		}
	}
	if oi, ok := o["items"].(map[string]any); ok {
		ni, nok := n["items"].(map[string]any)
		if !nok {
			// The new schema has no schema for the items: it accepts any item, which is looser.
			return out
		}
		out = append(out, compatNode(where+"[]", oldRoot, newRoot, oi, ni, depth+1)...)
	} else if _, nok := n["items"]; nok {
		out = append(out, where+": items is new")
	}
	return out
}

func bound(where, k string, o, n map[string]any, tighter func(old, cur float64) bool) []string {
	nv, nHas := n[k].(float64)
	if !nHas {
		return nil
	}
	ov, oHas := o[k].(float64)
	if !oHas {
		return []string{fmt.Sprintf("%s: %s is new", where, k)}
	}
	if tighter(ov, nv) {
		return []string{fmt.Sprintf("%s: %s is tighter", where, k)}
	}
	return nil
}

func contains(list []any, v any) bool {
	for _, e := range list {
		if reflect.DeepEqual(e, v) {
			return true
		}
	}
	return false
}

func stringSet(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, e := range s {
		out[i] = e
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
