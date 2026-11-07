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
actions:
  - name: a.b
    actor: a
    class: 6003
    activity: {id: 99, name: B}
    outcomes: [success]
    fields:
      kept: {type: word, required: true}
      list: {items: ident, max: 8}
      obj:
        fields: {inner: {type: uint}}
    example: {sluis: {kept: x, obj: {inner: 1}}}
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
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(baseline, c.from) {
				t.Fatalf("the baseline lacks %q", c.from)
			}
			cur := parseTable(t, strings.Replace(baseline, c.from, c.to, 1))
			got := compat(parseTable(t, baseline), cur)
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
		{"an example that names a person the row does not allow", "example: {sluis:", "example: {subject: true, sluis:", "names a person"},
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
