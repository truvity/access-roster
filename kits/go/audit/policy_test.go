package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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
		PolicyVersion int          `json:"policy_version"`
		Cases         []policyCase `json:"cases"`
	}
	readVectors(t, "schema-policy-vectors.json", &f)
	if f.PolicyVersion != PolicyVersion {
		t.Fatalf("the corpus is for policy %d, the code is policy %d: change both together", f.PolicyVersion, PolicyVersion)
	}
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
// The file is a valid schema, so a loader that read it would compile; the compile must fail with the loader's refusal.
func TestTheLibraryLoadsNothingFromOutsideTheCatalogue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(path, []byte(`{"type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newCompiler()
	doc := mustJSON(t, `{"properties":{"a":{"$ref":"file://`+filepath.ToSlash(path)+`"}}}`)
	if err := c.AddResource(schemaBase+"a.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	_, err := c.Compile(schemaBase + "a.schema.json")
	if err == nil {
		t.Fatal("a $ref to a file compiled: the loader read it")
	}
	if !strings.Contains(err.Error(), "is not a document of the catalogue") {
		t.Fatalf("the compile failed, but not by the loader's refusal: %v", err)
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

func mustJSON(t *testing.T, s string) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// verifies: REQ-AUDIT-149
//
// The patterns the policy takes mean the same in both engines: each accepted pattern matches and refuses the strings of the
// corpus, here in RE2 and in the Rust test through the engine the Rust library uses.
func TestAcceptedPatternsMatchAsTheCorpusSays(t *testing.T) {
	var f struct {
		Matches []struct {
			Pattern string   `json:"pattern"`
			Yes     []string `json:"yes"`
			No      []string `json:"no"`
		} `json:"matches"`
	}
	readVectors(t, "schema-policy-vectors.json", &f)
	if len(f.Matches) < 8 {
		t.Fatal("the vector file lost its matches")
	}
	for _, m := range f.Matches {
		if err := checkPattern(m.Pattern); err != nil {
			t.Errorf("%s: refused by the policy: %v", m.Pattern, err)
			continue
		}
		re := regexp.MustCompile(m.Pattern)
		for _, s := range m.Yes {
			if !re.MatchString(s) {
				t.Errorf("%s does not match %q", m.Pattern, s)
			}
		}
		for _, s := range m.No {
			if re.MatchString(s) {
				t.Errorf("%s matches %q", m.Pattern, s)
			}
		}
	}
}

// verifies: REQ-AUDIT-149
//
// The policy is linear and the validation it admits is quick. The corpus is checked in well under a second, whatever it holds
// (a check that walked every duplicate reference did not finish in a minute), and a catalogue at the limit of cost validates
// a record that fails every branch in a few milliseconds.
func TestThePolicyIsFastAndWhatItAdmitsIsQuick(t *testing.T) {
	var f struct {
		Cases []policyCase `json:"cases"`
	}
	readVectors(t, "schema-policy-vectors.json", &f)
	start := time.Now()
	for _, c := range f.Cases {
		t0 := time.Now()
		_ = CheckPolicy(c.Docs)
		if d := time.Since(t0); d > 500*time.Millisecond {
			t.Errorf("%s: the policy took %v", c.Name, d)
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the corpus took %v", d)
	}
	// An accepted tower at about the limit: eight branches each of three levels, every one of which fails.
	for _, c := range f.Cases {
		if !strings.HasPrefix(c.Name, "three definitions that refer to the next eight times") {
			continue
		}
		s, err := ParseSchemas(c.Docs)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		_ = s.Validate("a.schema.json", []byte(`{"x":"not an integer"}`))
		if d := time.Since(t0); d > 100*time.Millisecond {
			t.Errorf("a catalogue at the limit took %v for one record", d)
		}
	}
}

// verifies: REQ-AUDIT-149
//
// The cost of the real catalogue is a fraction of the limit, so the limit loses nothing: the most a record of sluis costs is
// 885 (key.revoke), against 4000.
func TestTheRealCatalogueCostsAFractionOfTheLimit(t *testing.T) {
	files := map[string]string{}
	ents, err := os.ReadDir("../../conformance/audit/schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("../../conformance/audit/schema", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(b)
	}
	worst, err := MaxCost(files)
	if err != nil {
		t.Fatal(err)
	}
	if worst < 100 || worst > maxCost/2 {
		t.Fatalf("the worst cost of the real catalogue is %d, the limit %d", worst, maxCost)
	}
	t.Logf("the worst cost of the real catalogue: %d of %d", worst, maxCost)
}
