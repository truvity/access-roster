package writerd

import (
	"testing"

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
