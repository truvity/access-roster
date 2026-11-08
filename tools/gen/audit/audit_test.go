package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const root = "../../.."

// verifies: REQ-AUDIT-114
//
// The schemas, the example records and the tables compiled into the emitters are what the action table makes: a
// committed file that differs, or a schema file that no action makes, fails. `just audit-gen` writes them.
func TestTheCommittedFilesAreWhatTheTableMakes(t *testing.T) {
	files, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 40 {
		t.Fatalf("%d generated files: the generator made nearly nothing", len(files))
	}
	if err := compare(root, files); err != nil {
		t.Fatal(err)
	}
}

func parseTable(t *testing.T, text string) *tableFile {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	var tf tableFile
	if err := dec.Decode(&tf); err != nil {
		t.Fatal(err)
	}
	if err := tf.check(); err != nil {
		t.Fatal(err)
	}
	return &tf
}

const baseline = `
schema: 1
ocsf: "1.9.0"
product: sluis
types:
  word: {type: string, pattern: "^[a-z][a-z0-9_]{0,63}$"}
  ident: {type: string, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$"}
  uint: {type: integer, minimum: 0, maximum: 9007199254740991}
  text: {type: string, maxLength: 1024}
  reason: {type: string, pattern: "^[A-Za-z][A-Za-z0-9_.:-]{0,63}$"}
  spare: {type: string, maxLength: 8}
  operation: {type: string, pattern: "^[A-Za-z][A-Za-z0-9_.-]{0,63}$"}
actions:
  - name: a.b
    actor: a
    class: 6003
    activity: {id: 99, name: B}
    outcomes: [success]
    tenant: optional
    fields:
      kept: {type: word, required: true}
      list: {items: ident, max: 8}
      obj:
        fields: {inner: {type: uint}}
    example: {caller: c, operation: o, sluis: {kept: x, obj: {inner: 1}}}
`

// verifies: REQ-AUDIT-119
//
// A change of the table that removes or retypes a member of unmapped.sluis against the table of the last release is
// found, and one that only adds is not. Each case is a mutation of the baseline.
func TestCompatFindsWhatAReleaseOfTheSameMajorMustNotChange(t *testing.T) {
	for _, c := range []struct {
		name, from, to string
		want           string // a part of a finding; empty for none
	}{
		{"a new optional member", "      kept: {type: word, required: true}", "      kept: {type: word, required: true}\n      added: {type: word}", ""},
		{"a new member in an object", "fields: {inner: {type: uint}}", "fields: {inner: {type: uint}, more: {type: word}}", ""},
		{"a list that grows", "list: {items: ident, max: 8}", "list: {items: ident, max: 16}", ""},
		{"a member gone", "      kept: {type: word, required: true}\n", "", "a.b.kept: the member is gone"},
		{"a nested member gone", "fields: {inner: {type: uint}}", "fields: {}", "a.b.obj.inner: the member is gone"},
		{"a retyped member", "kept: {type: word, required: true}", "kept: {type: uint, required: true}", "a.b.kept: the type changed"},
		{"a scalar that became a list", "kept: {type: word, required: true}", "kept: {items: word, max: 2, required: true}", "a.b.kept: the member changed"},
		{"an optional member made required", "list: {items: ident, max: 8}", "list: {items: ident, max: 8, required: true}", "a.b.list: the member was optional and is required now"},
		{"a list that shrinks", "list: {items: ident, max: 8}", "list: {items: ident, max: 4}", "a.b.list: the bound of the list went from 8 to 4"},
		{"a pattern that changes", `word: {type: string, pattern: "^[a-z][a-z0-9_]{0,63}$"}`, `word: {type: string, pattern: "^[a-z][a-z0-9_]{0,31}$"}`, "a.b.kept: the pattern changed"},
		{"an action gone", "  - name: a.b", "  - name: a.c", "a.b: the action is gone"},
		{"a new required member", "      kept: {type: word, required: true}", "      kept: {type: word, required: true}\n      added: {type: word, required: true}", "a.b.added: a new member is required"},
		{"a new required member inside an object", "fields: {inner: {type: uint}}", "fields: {inner: {type: uint}, more: {type: word, required: true}}", "a.b.obj.more: a new member is required"},
		{"a new action", "actions:\n", "actions:\n  - name: a.new\n    actor: a\n    class: 6003\n    activity: {id: 99, name: N}\n    outcomes: [success]\n    example: {caller: c, operation: o}\n", ""},
		{"another actor", "actor: a\n    class", "actor: b\n    class", "a.b: the actor changed"},
		{"an activity gone", "activity: {id: 99, name: B}", "activity: {id: 98, name: B}", "a.b: the activity 99"},
		{"an activity added", "activity: {id: 99, name: B}", "activities: [{id: 99, name: B}, {id: 1}]", ""},
		{"an outcome gone", "outcomes: [success]", "outcomes: [failure]", "a.b: the outcome success is gone"},
		{"an outcome added", "outcomes: [success]", "outcomes: [success, failure]", ""},
		{"a tenant no longer allowed", "    tenant: optional\n", "", "a.b: tenant went from optional to none"},
		{"a subject now allowed", "    tenant: optional\n", "    tenant: optional\n    subject: optional\n", ""},
		{"a shared type tighter", "spare: {type: string, maxLength: 8}", "spare: {type: string, maxLength: 4}", "type spare: maxLength is tighter"},
		{"a shared type gone", "  spare: {type: string, maxLength: 8}\n", "", "type spare: the type is gone"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(baseline, c.from) {
				t.Fatalf("the baseline lacks %q", c.from)
			}
			cur := parseTable(t, strings.Replace(baseline, c.from, c.to, 1))
			got := compat(parseTable(t, baseline), cur)
			if c.want == "" && len(got) == 0 {
				// What compat passes is what the schemas prove: the records of the old table still validate.
				if bad := mustOldRecordsUnder(t, parseTable(t, baseline), cur); len(bad) > 0 {
					t.Fatalf("compat passes a change under which the old records fail: %v", bad)
				}
			}
			switch {
			case c.want == "" && len(got) > 0:
				t.Fatalf("findings for a change that only adds: %v", got)
			case c.want != "" && !strings.Contains(strings.Join(got, "\n"), c.want):
				t.Fatalf("findings %v, want one with %q", got, c.want)
			}
		})
	}
}

// The table of this repository is compatible with itself, and the real table passes its own checks.
func TestTheTableIsCompatibleWithItself(t *testing.T) {
	tf, err := load(filepath.Join(root, tablePath))
	if err != nil {
		t.Fatal(err)
	}
	if got := compat(tf, tf); len(got) != 0 {
		t.Fatal(got)
	}
}

// The table refuses what it must: an unbounded list, a pattern outside the subset, a member of the emitter's own, a
// type nobody declared.
func TestTheTableRefusesWhatItMust(t *testing.T) {
	for _, c := range []struct{ name, from, to, want string }{
		{"a list with no bound", "list: {items: ident, max: 8}", "list: {items: ident}", "unbounded"},
		{"lost is the emitter's", "      kept: {type: word, required: true}", "      kept: {type: word, required: true}\n      lost: {type: word}", "lost"},
		{"an unknown type", "kept: {type: word, required: true}", "kept: {type: nope, required: true}", "unknown type"},
		{"a pattern outside the subset", `"^[a-z][a-z0-9_]{0,63}$"`, `"^(a|b)+$"`, "outside the subset"},
		{"a member of two shapes", "kept: {type: word, required: true}", "kept: {type: word, items: word, max: 1}", "exactly one"},
		{"an action name that is no name", "name: a.b", "name: AB", "not a name"},
		{"an example that names a person the row does not allow", "example: {caller: c, operation: o, sluis:", "example: {subject: true, caller: c, operation: o, sluis:", "names a person"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dec := yaml.NewDecoder(strings.NewReader(strings.Replace(baseline, c.from, c.to, 1)))
			dec.KnownFields(true)
			var tf tableFile
			err := dec.Decode(&tf)
			if err == nil {
				err = tf.check()
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one with %q", err, c.want)
			}
		})
	}
}

// The example of every action is the event of a record that the Go library builds: the vector file is not stale, and a
// table whose example is refused by the library (a field of the wrong type) fails the generator.
func TestVectorsAreBuiltFromTheExamples(t *testing.T) {
	tf, err := load(filepath.Join(root, tablePath))
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildVectors(tf)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(root, vectorsOut))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, disk) {
		t.Fatal("kits/conformance/audit/action-vectors.json is stale: run `just audit-gen`")
	}
}

// verifies: REQ-AUDIT-147
//
// The release pipeline's step: the AuditCatalogue document of a release holds the release, every action of the table and the
// schema document of each, with the definitions; it differs from the local installation's document in the release only.
func TestTheCatalogueDocumentOfARelease(t *testing.T) {
	out := filepath.Join(t.TempDir(), "catalogue.yaml")
	if err := runCatalogue(root, out, "2.1.0-rc.1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out) //nolint:gosec // a temporary file
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Default struct {
			Release string   `yaml:"release"`
			Actions []string `yaml:"actions"`
			Schemas []struct {
				Name string `yaml:"name"`
				JSON string `yaml:"json"`
			} `yaml:"schemas"`
		} `yaml:"default"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	tf, err := load(filepath.Join(root, tablePath))
	if err != nil {
		t.Fatal(err)
	}
	_, texts, err := schemaTexts(tf)
	if err != nil {
		t.Fatal(err)
	}
	d := doc.Default
	if d.Release != "2.1.0-rc.1" || len(d.Actions) != len(tf.Actions) || len(d.Schemas) != len(tf.Actions)+1 {
		t.Fatalf("release %q, %d actions, %d schemas", d.Release, len(d.Actions), len(d.Schemas))
	}
	for _, s := range d.Schemas {
		if want, ok := texts[s.Name]; !ok || strings.TrimSpace(want) != s.JSON {
			t.Errorf("the schema %s is not the generated one", s.Name)
		}
	}
	local, err := os.ReadFile(filepath.Join(root, catalogueOut))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Replace(string(b), "release: 2.1.0-rc.1", "release: "+localRelease, 1) != string(local) {
		t.Error("the document of a release differs from the local installation's in more than the release")
	}
	for _, bad := range []string{"", "v1.0.0", "1.0", "latest", "01.0.0"} {
		if err := runCatalogue(root, out, bad); err == nil {
			t.Errorf("release %q accepted", bad)
		}
	}
}

// A person that a row now requires, where it allowed none, is not compatible: the records of the old release name no one.
func TestCompatFindsASubjectThatIsNowRequired(t *testing.T) {
	cur := strings.Replace(baseline, "    tenant: optional\n", "    tenant: optional\n    subject: required\n", 1)
	cur = strings.Replace(cur, "example: {caller: c, operation: o, sluis:", "example: {subject: true, caller: c, operation: o, sluis:", 1)
	got := compat(parseTable(t, baseline), parseTable(t, cur))
	if !strings.Contains(strings.Join(got, "\n"), "a.b: subject went from none to required") {
		t.Fatalf("findings %v", got)
	}
}

// The reason for the rule that a new member is optional: the old record lacks it and the new schema refuses the record. The
// compatibility check names what the schema would otherwise show only after the release.
func TestANewRequiredMemberIsWhatBreaksTheRecordsOfTheOldRelease(t *testing.T) {
	cur := parseTable(t, strings.Replace(baseline, "      kept: {type: word, required: true}", "      kept: {type: word, required: true}\n      added: {type: word, required: true}", 1))
	if bad := mustOldRecordsUnder(t, parseTable(t, baseline), cur); len(bad) != 1 || bad[0] != "a.b" {
		t.Fatalf("records that fail the new schema: %v, want a.b", bad)
	}
}

// The generator's own references need these types, whatever a row lists: the record's envelope uses them.
func TestTheTableMustDefineTheTypesTheEnvelopeUses(t *testing.T) {
	for _, name := range []string{"ident", "word", "uint", "text", "reason"} {
		dec := yaml.NewDecoder(strings.NewReader(strings.Replace(baseline, "  "+name+":", "  not_"+name+":", 1)))
		dec.KnownFields(true)
		var tf tableFile
		if err := dec.Decode(&tf); err != nil {
			continue // another rule refused it first
		}
		if err := tf.check(); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("a table without %s: err = %v", name, err)
		}
	}
}

func mustOldRecordsUnder(t *testing.T, old, cur *tableFile) []string {
	t.Helper()
	bad, err := oldRecordsUnder(old, cur)
	if err != nil {
		t.Fatal(err)
	}
	return bad
}

// The OCSF version and the product are in every record (metadata.version and metadata.product.name are constants of every
// schema), so a table that moves either leaves the records of the old release refused by the newest schema.
func TestCompatFindsAMovedOCSFVersionOrProduct(t *testing.T) {
	for name, c := range map[string]struct{ from, to, want string }{
		"another OCSF version": {`ocsf: "1.9.0"`, `ocsf: "1.10.0"`, "the OCSF version changed"},
		"another product":      {"product: sluis", "product: other", "the product changed"},
	} {
		cur := parseTable(t, strings.Replace(baseline, c.from, c.to, 1))
		got := compat(parseTable(t, baseline), cur)
		if !strings.Contains(strings.Join(got, "\n"), c.want) {
			t.Errorf("%s: findings %v", name, got)
		}
		if bad := mustOldRecordsUnder(t, parseTable(t, baseline), cur); len(bad) == 0 {
			t.Errorf("%s: the old records still validate, so the rule has no reason", name)
		}
	}
}

// runCompat runs the same proof as the unit tests: the old table's examples under the new schemas. A table that compat passes
// and under which an old record fails is a finding too.
func TestRunCompatProvesWithTheOldRecords(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("old.yaml", baseline)
	if err := runCompatTables(old, write("same.yaml", baseline)); err != nil {
		t.Fatalf("the same table: %v", err)
	}
	err := runCompatTables(old, write("moved.yaml", strings.Replace(baseline, `ocsf: "1.9.0"`, `ocsf: "1.10.0"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "the OCSF version changed") {
		t.Fatalf("a moved OCSF version: %v", err)
	}
}

const entityBaseline = `
schema: 1
ocsf: "1.9.0"
product: sluis
types:
  word: {type: string, pattern: "^[a-z][a-z0-9_]{0,63}$"}
  ident: {type: string, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$"}
  decimal: {type: string, pattern: "^[0-9]{1,16}$"}
  uint: {type: integer, minimum: 0, maximum: 9007199254740991}
  text: {type: string, maxLength: 1024}
  reason: {type: string, pattern: "^[A-Za-z][A-Za-z0-9_.:-]{0,63}$"}
actions:
  - name: a.make
    actor: a
    class: 3004
    activity: {id: 1}
    outcomes: [success]
    entity: {type: thing, name: true, version: true}
    example:
      entity: {name: n, version: "1"}
`

// verifies: REQ-AUDIT-119
//
// The entity of a row of Entity Management is part of what its records carry: a row that gains one, changes its type,
// drops a member or takes a new one makes the records of the last release fail the newest schema, and compat says so.
func TestCompatFindsWhatAnEntityMustNotChange(t *testing.T) {
	for _, c := range []struct{ name, from, to, want string }{
		{"the same entity", "entity: {type: thing, name: true, version: true}", "entity: {type: thing, name: true, version: true}", ""},
		{"another type", "type: thing", "type: other", "the type of the entity changed from thing to other"},
		{"a member gone", "name: true, version: true}", "name: true}", "the entity no longer has a version"},
		{"a member added", "name: true, version: true}", "name: true, uid: true, version: true}", "the entity now has a uid"},
		{"the entity gone", "    entity: {type: thing, name: true, version: true}\n", "", "x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(entityBaseline, c.from) {
				t.Fatalf("the baseline lacks %q", c.from)
			}
			to := strings.Replace(entityBaseline, c.from, c.to, 1)
			got := compatEntity("a.make", parseTable(t, entityBaseline).Actions[0].Entity, entityOf(t, to))
			joined := strings.Join(got, "\n")
			switch {
			case c.want == "" && len(got) > 0:
				t.Fatalf("findings for no change: %v", got)
			case c.want == "x" && len(got) == 0, c.want != "" && c.want != "x" && !strings.Contains(joined, c.want):
				t.Fatalf("findings %v, want one with %q", got, c.want)
			}
		})
	}
}

// entityOf reads the entity of the only row of a table text; a row without one is nil.
func entityOf(t *testing.T, text string) *entitySpec {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(text))
	dec.KnownFields(true)
	var tf tableFile
	if err := dec.Decode(&tf); err != nil {
		t.Fatal(err)
	}
	return tf.Actions[0].Entity
}

// A row of Entity Management names its entity and gives one in its example; no other row names one.
func TestTheTableHoldsEntityManagementToAnEntity(t *testing.T) {
	for _, c := range []struct{ name, from, to, want string }{
		{"no entity", "    entity: {type: thing, name: true, version: true}\n", "", "names its entity"},
		{"no example entity", "    example:\n      entity: {name: n, version: \"1\"}\n", "    example: {}\n", "names its entity"},
		{"a type that is no word", "type: thing", "type: Thing", "type word"},
		{"nothing to identify it", "name: true, version: true", "version: true", "type word"},
		{"an example that disagrees", "entity: {name: n, version: \"1\"}", "entity: {name: n}", "disagree"},
		{"another class", "class: 3004", "class: 6003", "only a row of Entity Management"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dec := yaml.NewDecoder(strings.NewReader(strings.Replace(entityBaseline, c.from, c.to, 1)))
			dec.KnownFields(true)
			var tf tableFile
			err := dec.Decode(&tf)
			if err == nil {
				err = tf.check()
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one with %q", err, c.want)
			}
		})
	}
}

// verifies: REQ-AUDIT-119
//
// Between two pre-releases nothing is promised (ADR 0013), so against a tag with a hyphen (v2.0.0-alpha.N) the findings of
// compat are printed and do not fail; against a stable tag, or none, the same findings fail, and a table that cannot be read
// fails against either.
func TestCompatAgainstAPreReleasePrintsAndAgainstAStableReleaseFails(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, filepath.Dir(tablePath))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	cur := strings.Replace(baseline, `ocsf: "1.9.0"`, `ocsf: "1.10.0"`, 1) // not compatible with the baseline
	if err := os.WriteFile(filepath.Join(root, tablePath), []byte(cur), 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(root, "old.yaml")
	if err := os.WriteFile(old, []byte(baseline), 0o600); err != nil {
		t.Fatal(err)
	}
	for tag, wantFail := range map[string]bool{"v2.0.0-alpha.1": false, "v2.0.0-rc.2": false, "v2.0.0": true, "v2.3.1": true, "": true} {
		err := runCompat(root, old, tag)
		switch {
		case wantFail && (err == nil || !strings.Contains(err.Error(), "the OCSF version changed")):
			t.Errorf("tag %q: err = %v, want the findings as a failure", tag, err)
		case !wantFail && err != nil:
			t.Errorf("tag %q: err = %v, want the findings printed and no failure", tag, err)
		}
	}
	// A table that cannot be read is never advisory.
	if err := runCompat(root, filepath.Join(root, "missing.yaml"), "v2.0.0-alpha.1"); err == nil {
		t.Error("an unreadable table of the last release passed against a pre-release")
	}
	for _, c := range []struct {
		tag string
		pre bool
	}{{"v2.0.0-alpha.1", true}, {"v2.1.0-rc.1", true}, {"v2.0.0", false}, {"v2.12.3", false}} {
		if preRelease(c.tag) != c.pre {
			t.Errorf("preRelease(%q) = %v", c.tag, !c.pre)
		}
	}
}

// verifies: REQ-AUDIT-119
//
// A row that changes its class makes the records of the last release fail the newest schema, and compat says so. The example of
// the new row is the new class's own (an API Activity row gives a caller and an operation, any other does not).
func TestCompatFindsAChangedClass(t *testing.T) {
	cur := strings.Replace(baseline, "class: 6003", "class: 6002", 1)
	cur = strings.Replace(cur, "example: {caller: c, operation: o, sluis:", "example: {sluis:", 1)
	cur = strings.Replace(cur, "    tenant: optional\n", "", 1) // an Application Lifecycle row names no person and no decision, and may name a tenant
	got := compat(parseTable(t, baseline), parseTable(t, cur))
	if !strings.Contains(strings.Join(got, "\n"), "a.b: the class changed") {
		t.Fatalf("findings %v, want the class changed", got)
	}
}
