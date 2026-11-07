package signedconfig

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/v2/kits/go/configschema"
)

// kindOf turns the name of a file, key-plan, into the name of its kind, KeyPlan.
func kindOf(file string) string {
	var b strings.Builder
	for _, w := range strings.Split(file, "-") {
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}

// verifies: REQ-DATA-038, REQ-OPS-002
//
// The documents the local installation signs, and the boards with them, satisfy the schema of their kind: the example config
// is the first file that the schemas must not refuse (the files of the boards are made from it by tools/harness/sign-config).
func TestTheLocalConfigSatisfiesTheSchemaOfEachKind(t *testing.T) {
	files, err := filepath.Glob("../../../tests/installations/local/config/*.yaml")
	if err != nil || len(files) < 8 {
		t.Fatalf("the local config: %v (%d files)", err, len(files))
	}
	checked := 0
	var exempt []string
	for _, f := range files {
		kind := kindOf(strings.TrimSuffix(filepath.Base(f), ".yaml"))
		if _, ok, err := configschema.PayloadID(kind); err != nil {
			t.Fatal(err)
		} else if !ok {
			exempt = append(exempt, kind) // GrantVocabulary: policy's document, with a schema of its own
			continue
		}
		raw, err := os.ReadFile(f) //nolint:gosec // a file of the repository
		if err != nil {
			t.Fatal(err)
		}
		root, err := StrictYAML(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := ValidatePayload(kind, root); err != nil {
			t.Errorf("%s: the schema of %s refuses it: %v", f, kind, err)
		}
		checked++
	}
	if checked != 10 {
		t.Fatalf("%d documents checked, want the 10 kinds that have a schema", checked)
	}
	// A kind with no schema is a kind whose document nothing checks before it decodes it. Of the YAML kinds the exempt one is
	// GrantVocabulary, and Policy is Cedar text and has no YAML file; a new kind without a schema fails here and in store@'s
	// test of the same list (actors/store/tests/schema_vectors.rs).
	if !slices.Equal(exempt, []string{"GrantVocabulary"}) {
		t.Fatalf("kinds of the local config with no schema: %v, want only GrantVocabulary", exempt)
	}
	if _, ok, err := configschema.PayloadID("Policy"); err != nil || ok {
		t.Fatalf("Policy: %v, %v; its payload is Cedar text and has no schema", ok, err)
	}
}

// verifies: REQ-DATA-038, REQ-OPS-002
//
// Every action the audit table has is a name the AuditCatalogue schema takes: the names a catalogue lists are the names of the
// table (docs/architecture/audit-actions.yaml), and a pattern narrower than they are would refuse the catalogue of a release.
func TestEveryActionOfTheAuditTableIsACatalogueName(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/architecture/audit-actions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Actions []struct {
			Name string `yaml:"name"`
		} `yaml:"actions"`
	}
	if err := yaml.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Actions) < 40 {
		t.Fatalf("%d actions: the table was not read", len(table.Actions))
	}
	names := make([]any, 0, len(table.Actions))
	for _, a := range table.Actions {
		names = append(names, a.Name)
	}
	doc := map[string]any{"default": map[string]any{"release": "0.0.0", "actions": names}}
	if err := configschema.Validate("audit-catalogue/v1/audit-catalogue.schema.json", doc); err != nil {
		t.Fatalf("the catalogue of the whole table: %v", err)
	}
}
