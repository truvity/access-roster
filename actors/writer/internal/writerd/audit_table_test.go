package writerd

import (
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

// openAuditTable is the action table of the test emitters: the actions these tests make records of, with schemas that
// accept any object. The tests probe the writer, which has its own catalogue; what the schemas of the table of sluis
// refuse is tested in kits/go/audit.
func openAuditTable(t testing.TB) *audit.Table {
	t.Helper()
	row := func(name string) audit.Row {
		return audit.Row{Name: name, Actor: "key", Class: 6003, Activities: []audit.Activity{{ID: 99, Name: "Sign"}},
			Outcomes: []audit.Status{audit.StatusSuccess, audit.StatusFailure}}
	}
	tb, err := audit.NewTable(
		[]audit.Row{row("key.sign"), row("key.nothing"), row("store.start")},
		map[string]string{
			audit.DefsName: `{}`, "key.sign.schema.json": `{"type":"object"}`, "key.nothing.schema.json": `{"type":"object"}`,
			"store.start.schema.json": `{"type":"object"}`,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// openSchemas parses schemas that accept any object, one for each action: the tests of the checks that are not the
// schema's own. What the real schemas accept and refuse is tested in catalogue_test.go.
func openSchemas(actions ...string) *audit.Schemas {
	files := map[string]string{audit.DefsName: `{}`}
	for _, a := range actions {
		files[a+".schema.json"] = `{"type":"object"}`
	}
	s, err := audit.ParseSchemas(files)
	if err != nil {
		panic(err)
	}
	return s
}

// openCatalogue is the AuditCatalogue of a release with schemas that accept any object.
func openCatalogue(release string, actions ...string) *configv2alpha1.AuditCatalogue {
	c := &configv2alpha1.AuditCatalogue{Release: release, Actions: actions}
	c.Schemas = append(c.Schemas, &configv2alpha1.AuditSchema{Name: audit.DefsName, Json: `{}`})
	for _, a := range actions {
		c.Schemas = append(c.Schemas, &configv2alpha1.AuditSchema{Name: a + ".schema.json", Json: `{"type":"object"}`})
	}
	return c
}
