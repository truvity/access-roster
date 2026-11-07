package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base is a small schema of the shape the generator writes: a root with a nested definition, a list and a bounded string.
const base = `{
 "$schema": "https://json-schema.org/draft/2020-12/schema",
 "$id": "https://sluis.id/schema/demo/v1/demo.schema.json",
 "type": "object",
 "properties": {
  "$schema": {"const": "https://sluis.id/schema/demo/v1/demo.schema.json"},
  "name": {"type": "string", "pattern": "^[a-z]+$", "minLength": 1, "maxLength": 8, "description": "a name"},
  "mode": {"type": "string", "enum": ["a", "b"]},
  "dest": {"$ref": "#/$defs/Dest"},
  "keys": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/Key"}},
  "old": false
 },
 "required": ["name", "dest"],
 "unevaluatedProperties": false,
 "$defs": {
  "Dest": {"type": "object", "properties": {"path": {"type": "string", "pattern": "^/"}}, "required": ["path"], "unevaluatedProperties": false},
  "Key": {"type": "object", "properties": {"kid": {"type": "string"}}, "required": ["kid"], "unevaluatedProperties": false}
 }
}`

func doc(t *testing.T, text string) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(text), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// mutated returns the base with one change made by f.
func mutated(t *testing.T, f func(d map[string]any)) map[string]map[string]any {
	t.Helper()
	d := doc(t, base)
	f(d)
	return map[string]map[string]any{"demo/v1/demo.schema.json": d}
}

func props(d map[string]any) map[string]any { return d["properties"].(map[string]any) }
func defs(d map[string]any, n string) map[string]any {
	return d["$defs"].(map[string]any)[n].(map[string]any)
}

// verifies: REQ-DATA-040
//
// Each case changes one thing of the schema of a release. A change that accepts less, or moves a published identifier, is a
// finding; a change that only adds, loosens or explains is not. The cases are the mutations that show the judge bites.
func TestACompatibleChangeIsAllowedAndAnIncompatibleOneIsNot(t *testing.T) {
	old := map[string]map[string]any{"demo/v1/demo.schema.json": doc(t, base)}
	cases := []struct {
		name string
		f    func(d map[string]any)
		want string // a part of a finding; empty for none
	}{
		{"nothing changes", func(map[string]any) {}, ""},
		{"a description is rewritten", func(d map[string]any) { props(d)["name"].(map[string]any)["description"] = "another" }, ""},
		{"an optional key is added", func(d map[string]any) { props(d)["extra"] = map[string]any{"type": "string"} }, ""},
		{"a key is added to a definition", func(d map[string]any) {
			props(defs(d, "Dest"))["mode"] = map[string]any{"type": "string"}
		}, ""},
		{"a maximum rises", func(d map[string]any) { props(d)["name"].(map[string]any)["maxLength"] = 16.0 }, ""},
		{"a maximum goes", func(d map[string]any) { delete(props(d)["name"].(map[string]any), "maxLength") }, ""},
		{"a minimum falls", func(d map[string]any) { props(d)["name"].(map[string]any)["minLength"] = 0.0 }, ""},
		{"a pattern goes", func(d map[string]any) { delete(props(d)["name"].(map[string]any), "pattern") }, ""},
		{"a value is added to an enum", func(d map[string]any) { props(d)["mode"].(map[string]any)["enum"] = []any{"a", "b", "c"} }, ""},
		{"a required key becomes optional", func(d map[string]any) { d["required"] = []any{"name"} }, ""},
		{"the retired key is gone", func(d map[string]any) { delete(props(d), "old") }, ""},
		{"the retired key is a key again", func(d map[string]any) { props(d)["old"] = map[string]any{"type": "string"} }, ""},

		{"a key is gone", func(d map[string]any) { delete(props(d), "mode") }, "demo/v1/demo.schema.json.mode: the key is gone"},
		{"a key of a definition is gone", func(d map[string]any) { delete(props(defs(d, "Dest")), "path") }, "path: the key is gone"},
		{"a key is retired", func(d map[string]any) { props(d)["mode"] = false }, "mode: the key is retired now"},
		{"a type changes", func(d map[string]any) { props(d)["name"].(map[string]any)["type"] = "integer" }, "type changed"},
		{"a pattern changes", func(d map[string]any) { props(d)["name"].(map[string]any)["pattern"] = "^[a-z0-9]+$" }, "pattern changed"},
		{"a pattern is new", func(d map[string]any) { props(d)["mode"].(map[string]any)["pattern"] = "^a" }, "pattern is new"},
		{"a key becomes required", func(d map[string]any) { d["required"] = []any{"name", "dest", "keys"} }, "the key was optional and is required now"},
		{"a key of a definition becomes required", func(d map[string]any) {
			defs(d, "Key")["required"] = []any{"kid", "extra"}
		}, "the key was optional and is required now"},
		{"a minimum rises", func(d map[string]any) { props(d)["name"].(map[string]any)["minLength"] = 2.0 }, "minLength is tighter"},
		{"a minimum is new", func(d map[string]any) { props(d)["mode"].(map[string]any)["minLength"] = 1.0 }, "minLength is new"},
		{"a maximum falls", func(d map[string]any) { props(d)["name"].(map[string]any)["maxLength"] = 4.0 }, "maxLength is tighter"},
		{"a maximum is new", func(d map[string]any) { props(d)["keys"].(map[string]any)["maxItems"] = 4.0 }, "maxItems is new"},
		{"a list wants more items", func(d map[string]any) { props(d)["keys"].(map[string]any)["minItems"] = 2.0 }, "minItems is tighter"},
		{"a list wants unique items", func(d map[string]any) { props(d)["keys"].(map[string]any)["uniqueItems"] = true }, "uniqueItems is new"},
		{"an enum loses a value", func(d map[string]any) { props(d)["mode"].(map[string]any)["enum"] = []any{"a"} }, "enum lost a value"},
		{"an enum is new", func(d map[string]any) { props(d)["name"].(map[string]any)["enum"] = []any{"a"} }, "enum is new"},
		{"a constant changes", func(d map[string]any) { props(d)["$schema"].(map[string]any)["const"] = "https://example.com/x" }, "const changed"},
		{"the type of the items changes", func(d map[string]any) { props(defs(d, "Key"))["kid"].(map[string]any)["type"] = "integer" }, "type changed"},
		{"the items get a pattern", func(d map[string]any) { props(defs(d, "Key"))["kid"].(map[string]any)["pattern"] = "^k" }, "pattern is new"},
		{"a keyword the judge does not know", func(d map[string]any) { d["oneOf"] = []any{} }, "the keyword oneOf is one the judge cannot compare"},
		{"the identifier changes", func(d map[string]any) { d["$id"] = "https://sluis.id/schema/demo/v1/other.schema.json" }, "the $id of a published schema changed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := compatTrees(old, mutated(t, c.f))
			switch {
			case c.want == "" && len(got) != 0:
				t.Fatalf("findings: %v", got)
			case c.want != "" && !strings.Contains(strings.Join(got, "\n"), c.want):
				t.Fatalf("findings %v, want one with %q", got, c.want)
			}
		})
	}
}

// verifies: REQ-DATA-040
func TestAnOldSchemaThatNewlyRefusesUnknownKeysIsAFinding(t *testing.T) {
	d := doc(t, base)
	delete(d, "unevaluatedProperties")
	old := map[string]map[string]any{"demo/v1/demo.schema.json": d}
	cur := map[string]map[string]any{"demo/v1/demo.schema.json": doc(t, base)}
	if got := compatTrees(old, cur); len(got) != 1 || !strings.Contains(got[0], "unknown keys are refused now") {
		t.Fatalf("findings: %v", got)
	}
}

// verifies: REQ-DATA-040
//
// An incompatible schema is a new version under a new path, beside the old one: the old stays as it was, and the new is free.
func TestANewVersionBesideTheOldOneIsFree(t *testing.T) {
	v1 := doc(t, base)
	v2 := doc(t, strings.ReplaceAll(strings.ReplaceAll(base, "demo/v1/demo", "demo/v2/demo"), `"type": "string", "pattern": "^[a-z]+$"`, `"type": "integer"`))
	old := map[string]map[string]any{"demo/v1/demo.schema.json": v1}
	cur := map[string]map[string]any{"demo/v1/demo.schema.json": doc(t, base), "demo/v2/demo.schema.json": v2}
	if got := compatTrees(old, cur); len(got) != 0 {
		t.Fatalf("findings: %v", got)
	}
	// The same incompatible schema written over the old one is a finding; and the old one gone is another.
	cur = map[string]map[string]any{"demo/v1/demo.schema.json": v1}
	cur["demo/v1/demo.schema.json"] = doc(t, strings.ReplaceAll(base, `"type": "string", "pattern": "^[a-z]+$"`, `"type": "integer"`))
	if got := compatTrees(old, cur); len(got) == 0 {
		t.Fatal("an incompatible change of v1 passed")
	}
	if got := compatTrees(old, map[string]map[string]any{"demo/v2/demo.schema.json": v2}); len(got) == 0 || !strings.Contains(strings.Join(got, ""), "a published schema is gone") {
		t.Fatalf("a schema gone: %v", got)
	}
}

// verifies: REQ-DATA-040
//
// An identifier is its path: a schema whose $id is not the address of the file it is in is a finding, with or without a release.
func TestTheIdentifierIsThePath(t *testing.T) {
	cur := map[string]map[string]any{"demo/v1/demo.schema.json": doc(t, base)}
	if got := checkIDs(cur); len(got) != 0 {
		t.Fatalf("findings: %v", got)
	}
	moved := map[string]map[string]any{"demo/v2/demo.schema.json": doc(t, base)}
	if got := checkIDs(moved); len(got) != 1 || !strings.Contains(got[0], "the $id is not") {
		t.Fatalf("findings: %v", got)
	}
	other := doc(t, base)
	other["$schema"] = "https://json-schema.org/draft-07/schema#"
	if got := checkIDs(map[string]map[string]any{"demo/v1/demo.schema.json": other}); len(got) != 1 {
		t.Fatalf("findings: %v", got)
	}
}

// verifies: REQ-DATA-040
//
// The whole tool, as `just config-schema-compat` runs it: the committed schemas against a directory of the last release.
func TestTheToolJudgesTheCommittedSchemasAgainstARelease(t *testing.T) {
	cur, err := loadTree(filepath.Join(repoRoot, schemaDir))
	if err != nil || len(cur) == 0 {
		t.Fatalf("the committed schemas: %v (%d)", err, len(cur))
	}
	release := t.TempDir()
	write := func(rel string, d map[string]any) {
		t.Helper()
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(release, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for rel, d := range cur {
		write(rel, d)
	}
	if err := runAgainst(repoRoot, release); err != nil {
		t.Fatalf("the committed schemas against themselves: %v", err)
	}
	// A release that has a key the committed schema has lost: the change removes a key of a published schema.
	old := doc(t, string(mustJSON(t, cur["bootstrap/v1/bootstrap.schema.json"])))
	props(old)["a_key_of_the_release"] = map[string]any{"type": "string"}
	write("bootstrap/v1/bootstrap.schema.json", old)
	err = runAgainst(repoRoot, release)
	if err == nil || !strings.Contains(err.Error(), "a_key_of_the_release: the key is gone") {
		t.Fatalf("a key that went: %v", err)
	}
	// A release that has a schema the committed tree lacks.
	write("bootstrap/v1/bootstrap.schema.json", cur["bootstrap/v1/bootstrap.schema.json"])
	write("other/v1/other.schema.json", doc(t, strings.ReplaceAll(base, "demo", "other")))
	if err := runAgainst(repoRoot, release); err == nil || !strings.Contains(err.Error(), "a published schema is gone") {
		t.Fatalf("a schema that went: %v", err)
	}
	// An empty tree of the repository is not a pass.
	if err := runAgainst(t.TempDir(), release); err == nil {
		t.Fatal("a root with no schema passed")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A signed document is a mapping from item id to item: the judge compares the schema of the ids and of the items too.
const keyedBase = `{
 "$schema": "https://json-schema.org/draft/2020-12/schema",
 "$id": "https://sluis.id/schema/kinds/v1/kinds.schema.json",
 "type": "object",
 "minProperties": 1,
 "propertyNames": {"pattern": "^[a-z0-9._-]{1,128}$"},
 "additionalProperties": {"$ref": "#/$defs/Item"},
 "$defs": {
  "Item": {"type": "object", "properties": {"n": {"type": "integer", "minimum": 0, "maximum": 10}, "s": {"type": ["string", "null"]}}, "required": ["n"], "unevaluatedProperties": false}
 }
}`

// verifies: REQ-DATA-040
func TestTheJudgeComparesTheIdsAndTheItemsOfADocument(t *testing.T) {
	old := map[string]map[string]any{"kinds/v1/kinds.schema.json": doc(t, keyedBase)}
	change := func(f func(d map[string]any)) map[string]map[string]any {
		d := doc(t, keyedBase)
		f(d)
		return map[string]map[string]any{"kinds/v1/kinds.schema.json": d}
	}
	item := func(d map[string]any) map[string]any { return defs(d, "Item") }
	for _, c := range []struct {
		name string
		f    func(d map[string]any)
		want string
	}{
		{"nothing changes", func(map[string]any) {}, ""},
		{"a looser maximum", func(d map[string]any) { props(item(d))["n"].(map[string]any)["maximum"] = 20.0 }, ""},
		{"a key is added to the item", func(d map[string]any) { props(item(d))["t"] = map[string]any{"type": "string"} }, ""},
		{"fewer items are needed", func(d map[string]any) { delete(d, "minProperties") }, ""},
		{"a tighter maximum", func(d map[string]any) { props(item(d))["n"].(map[string]any)["maximum"] = 5.0 }, "maximum is tighter"},
		{"a higher minimum", func(d map[string]any) { props(item(d))["n"].(map[string]any)["minimum"] = 1.0 }, "minimum is tighter"},
		{"more items are needed", func(d map[string]any) { d["minProperties"] = 2.0 }, "minProperties is tighter"},
		{"the ids are another form", func(d map[string]any) { d["propertyNames"].(map[string]any)["pattern"] = "^[a-z]+$" }, "pattern changed"},
		{"the ids are bounded now", func(d map[string]any) {
			delete(d, "propertyNames")
			d["propertyNames"] = map[string]any{"pattern": "^[a-z0-9._-]{1,128}$"}
		}, ""},
		{"the item is retyped", func(d map[string]any) { props(item(d))["n"].(map[string]any)["type"] = "string" }, "type changed"},
		{"a key of the item goes", func(d map[string]any) { delete(props(item(d)), "s") }, "the key is gone"},
		{"a null is no longer taken", func(d map[string]any) { props(item(d))["s"].(map[string]any)["type"] = "string" }, "type changed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := compatTrees(old, change(c.f))
			switch {
			case c.want == "" && len(got) != 0:
				t.Fatalf("findings: %v", got)
			case c.want != "" && !strings.Contains(strings.Join(got, "\n"), c.want):
				t.Fatalf("findings %v, want one with %q", got, c.want)
			}
		})
	}
	// The ids pattern appears where the old schema had none: the ids are bounded now.
	bare := doc(t, keyedBase)
	delete(bare, "propertyNames")
	if got := compatTrees(map[string]map[string]any{"kinds/v1/kinds.schema.json": bare}, change(func(map[string]any) {})); len(got) != 1 || !strings.Contains(got[0], "propertyNames is new") {
		t.Fatalf("findings: %v", got)
	}
}
