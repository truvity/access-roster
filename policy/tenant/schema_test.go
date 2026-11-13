package tenant

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	policyconfig "github.com/truvity/policy/config"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/sluis/policy/compile"
)

// The schemas are for editors and for a company's CI; the decoder is what
// `sluisctl policy fragment check` runs. They must say the same thing.
const (
	fixtures   = "../../tests/fragment"
	schemaDir  = "../../schemas/policy/tenant"
	idPrefix   = "https://truvity.github.io/sluis/schemas/policy/tenant/"
	invalidDir = "invalid"
)

func readFile(t *testing.T, parts ...string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func schemaOf(t *testing.T, name string) []byte {
	t.Helper()

	return readFile(t, schemaDir, name+".schema.json")
}

// validates reports whether a YAML or JSON document satisfies the schema.
func validates(t *testing.T, schema, doc []byte) error {
	t.Helper()

	var v any
	if err := yaml.Unmarshal(doc, &v); err != nil {
		t.Fatal(err)
	}

	if v == nil {
		v = map[string]any{}
	}

	asJSON, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	var normalised any
	if err := json.Unmarshal(asJSON, &normalised); err != nil {
		t.Fatal(err)
	}

	return policyconfig.Validate(normalised, schema) //nolint:wrapcheck // the test reads it
}

func fixtureFiles(t *testing.T, dir, prefix string) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(fixtures, dir, prefix+"*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no %s*.yaml in %s/%s: %v", prefix, fixtures, dir, err)
	}

	return files
}

func TestSchemasHaveTheirIDs(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"fragment", "ceiling"} {
		var doc struct {
			ID string `json:"$id"`
		}

		if err := json.Unmarshal(schemaOf(t, name), &doc); err != nil {
			t.Fatal(err)
		}

		if want := idPrefix + name + ".schema.json"; doc.ID != want {
			t.Errorf("%s: $id %q, want %q", name, doc.ID, want)
		}
	}
}

// Every fragment fixture is held to the schema and to the decoder, and the
// two agree. A fixture the ceiling refuses is still well formed.
func TestFragmentSchemaAgreesWithTheDecoder(t *testing.T) {
	t.Parallel()

	schema := schemaOf(t, "fragment")

	files := append(fixtureFiles(t, ".", "fragment-"), fixtureFiles(t, invalidDir, "")...)
	for _, file := range files {
		base := filepath.Base(file)
		if strings.HasPrefix(base, "ceiling-") {
			continue
		}

		raw := readFile(t, file)
		_, decodeErr := DecodeFragment(raw)
		schemaErr := validates(t, schema, raw)

		if (decodeErr == nil) != (schemaErr == nil) {
			t.Errorf("%s: the decoder says %v and the schema says %v", base, decodeErr, schemaErr)
		}
	}
}

func TestFragmentSchemaRefusesWhatAFragmentCannotCarry(t *testing.T) {
	t.Parallel()

	schema := schemaOf(t, "fragment")

	for _, name := range []string{"matrix-key", "session-duration", "misspelt-key"} {
		if err := validates(t, schema, readFile(t, fixtures, invalidDir, name+".yaml")); err == nil {
			t.Errorf("%s: the schema accepted it", name)
		}
	}

	for _, name := range []string{"fragment-acme", "fragment-empty"} {
		if err := validates(t, schema, readFile(t, fixtures, name+".yaml")); err != nil {
			t.Errorf("%s: the schema refused it: %v", name, err)
		}
	}
}

func TestCeilingSchemaAgreesWithTheDecoder(t *testing.T) {
	t.Parallel()

	schema := schemaOf(t, "ceiling")

	files := append(fixtureFiles(t, ".", "ceiling-"), fixtureFiles(t, invalidDir, "ceiling-")...)
	for _, file := range files {
		raw := readFile(t, file)
		_, decodeErr := DecodeCeiling(raw)
		schemaErr := validates(t, schema, raw)

		if (decodeErr == nil) != (schemaErr == nil) {
			t.Errorf("%s: the decoder says %v and the schema says %v", filepath.Base(file), decodeErr, schemaErr)
		}
	}
}

// Drift: the keys a schema names are the keys the decoder reads, for every
// object of both documents. A key added to a wire type and not to the
// schema (or the other way) fails here.
func TestSchemasNameTheKeysTheDecoderReads(t *testing.T) {
	t.Parallel()

	fragment := parsed(t, "fragment")
	ceiling := parsed(t, "ceiling")

	cases := []struct {
		what   string
		schema map[string]any
		typ    reflect.Type
	}{
		{"fragment", fragment, reflect.TypeFor[fragmentWire]()},
		{"ceiling", ceiling, reflect.TypeFor[Ceiling]()},
		{"population", def(t, fragment, "population"), reflect.TypeFor[populationWire]()},
		{"project", def(t, fragment, "project"), reflect.TypeFor[projectWire]()},
		{"githubOrg", def(t, fragment, "githubOrg"), reflect.TypeFor[compile.GitHubOrg]()},
		{"githubTeam", def(t, fragment, "githubTeam"), reflect.TypeFor[compile.GitHubTeam]()},
		{"slackWorkspace", def(t, fragment, "slackWorkspace"), reflect.TypeFor[compile.SlackWorkspace]()},
		{"slackChannel", def(t, fragment, "slackChannel"), reflect.TypeFor[compile.SlackChannel]()},
		{"job", def(t, fragment, "job"), reflect.TypeFor[compile.GitHubJob]()},
		{"jobWorkflow", def(t, fragment, "jobWorkflow"), reflect.TypeFor[compile.GitHubJobWorkflow]()},
		{"workload", def(t, fragment, "workload"), reflect.TypeFor[workloadWire]()},
		{"awsRole", def(t, fragment, "awsRole"), reflect.TypeFor[compile.WorkloadAWS]()},
		{"appGrant", def(t, fragment, "appGrant"), reflect.TypeFor[AppGrant]()},
		{"gate", def(t, fragment, "gate"), reflect.TypeFor[gateWire]()},
	}

	for _, tc := range cases {
		props, _ := tc.schema["properties"].(map[string]any)

		var got []string
		for k := range props {
			got = append(got, k)
		}

		slices.Sort(got)

		want := yamlKeys(tc.typ)
		slices.Sort(want)

		if !slices.Equal(got, want) {
			t.Errorf("%s: the schema names %v, the decoder reads %v", tc.what, got, want)
		}

		if tc.schema["additionalProperties"] != false {
			t.Errorf("%s: the schema is not closed", tc.what)
		}
	}
}

func parsed(t *testing.T, name string) map[string]any {
	t.Helper()

	var out map[string]any
	if err := json.Unmarshal(schemaOf(t, name), &out); err != nil {
		t.Fatal(err)
	}

	return out
}

func def(t *testing.T, schema map[string]any, name string) map[string]any {
	t.Helper()

	defs, _ := schema["$defs"].(map[string]any)

	d, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("the schema has no $defs/%s", name)
	}

	return d
}

func yamlKeys(typ reflect.Type) []string {
	var keys []string

	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name != "" && name != "-" {
			keys = append(keys, name)
		}
	}

	return keys
}
