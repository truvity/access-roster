package audit

import "testing"

// openTable is a table whose schemas accept any object, for the tests of the emitter's own rules (bounds, the e-mail
// shape, the note of lost facts, the transport): they probe the mechanics with events that the schemas of the real
// table would refuse. What the real table refuses is in table_test.go.
func openTable(t testing.TB) *Table {
	t.Helper()
	tb, err := NewTable(
		[]Row{{Name: "key.sign", Actor: "key", Class: 6003, Activities: []Activity{{ID: 99, Name: "Sign"}}, Outcomes: []Status{StatusSuccess, StatusFailure}}},
		map[string]string{DefsName: `{}`, "key.sign.schema.json": `{"type":"object"}`},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}
