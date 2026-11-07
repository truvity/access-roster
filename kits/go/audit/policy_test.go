package audit

import (
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type policyCase struct {
	Name string            `json:"name"`
	OK   bool              `json:"ok"`
	Docs map[string]string `json:"docs"`
	Why  string            `json:"why"`
}

// verifies: REQ-AUDIT-149
//
// The policy of the schema documents of an AuditCatalogue, on the corpus the Rust crate reads too: the closed keywords, the
// references to the shared definitions only, patterns RE2 and Rust read alike, bounded depth and size. A document the policy
// takes also compiles; one it refuses never reaches the library (so a $ref to a file reads nothing).
func TestThePolicyOfTheCatalogueSchemas(t *testing.T) {
	var f struct {
		Cases []policyCase `json:"cases"`
	}
	readVectors(t, "schema-policy-vectors.json", &f)
	if len(f.Cases) < 50 {
		t.Fatalf("%d cases: the vector file lost its cases", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := ParseSchemas(c.Docs)
			if c.OK && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.OK && err == nil {
				t.Fatal("taken")
			}
			if err := CheckPolicy(c.Docs); c.OK != (err == nil) {
				t.Fatalf("CheckPolicy: %v", err)
			}
		})
	}
}

// A $ref to a file reads nothing, even where the policy is not in the way: the library has no loader but the catalogue's own.
func TestTheLibraryLoadsNothingFromOutsideTheCatalogue(t *testing.T) {
	// The policy refuses this document already; the compiler is reached by a document the policy takes only through its
	// own loader, so this proves the second line by asking the compiler directly.
	c := newCompilerForTest()
	if err := c.AddResource(schemaBase+"a.schema.json", mustJSON(t, `{"properties":{"a":{"$ref":"file:///etc/hostname"}}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Compile(schemaBase + "a.schema.json"); err == nil {
		t.Fatal("a $ref to a file compiled: the loader read it")
	}
}

type semverCases struct {
	Accept []string `json:"accept"`
	Reject []string `json:"reject"`
}

// verifies: REQ-AUDIT-149
//
// The releases a catalogue and a record may name, on the corpus the Rust crate reads too.
func TestValidRelease(t *testing.T) {
	var f semverCases
	readVectors(t, "semver-vectors.json", &f)
	if len(f.Accept) < 10 || len(f.Reject) < 20 {
		t.Fatal("the vector file lost its cases")
	}
	for _, s := range f.Accept {
		if !ValidRelease(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range f.Reject {
		if ValidRelease(s) {
			t.Errorf("%q taken", strings.TrimSpace(s))
		}
	}
}

func newCompilerForTest() *jsonschema.Compiler { return newCompiler() }

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
