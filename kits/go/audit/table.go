package audit

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// An Activity is one OCSF activity that an action may have; Name is activity_name, empty when the record carries none.
type Activity struct {
	ID   int
	Name string
}

// A Row is one action of a table: the class and the activities it may have, and the outcomes it may report.
type Row struct {
	Name       string // metadata.event_code
	Actor      string // the actor that writes it
	Class      int
	Activities []Activity
	Outcomes   []Status
}

// A Table is the action table of one project's release with the schemas generated from it (ADR 0030, "The action
// table is code"). The emitter refuses an action that is not a row (REQ-AUDIT-022) and a record that does not validate
// against the schema of its row (REQ-AUDIT-099). A table is immutable and safe for concurrent use.
type Table struct {
	rows    map[string]Row
	schemas *Schemas
}

// schemaFile is the name of the schema document of an action.
func schemaFile(action string) string { return action + ".schema.json" }

// NewTable returns a table from rows and the schema documents (file name to JSON text), which must hold DefsName and
// the schema of every row.
func NewTable(rows []Row, schemas map[string]string) (*Table, error) {
	s, err := ParseSchemas(schemas)
	if err != nil {
		return nil, err
	}
	t := &Table{rows: map[string]Row{}, schemas: s}
	for _, r := range rows {
		if _, dup := t.rows[r.Name]; dup {
			return nil, fmt.Errorf("audit table: the action %q is twice in the table", r.Name)
		}
		if _, ok := s.compiled[schemaFile(r.Name)]; !ok {
			return nil, fmt.Errorf("audit table: the action %q has no schema", r.Name)
		}
		t.rows[r.Name] = r
	}
	return t, nil
}

var (
	sluisOnce  sync.Once
	sluisTable *Table
)

// Sluis is the action table of sluis itself, generated from docs/architecture/audit-actions.yaml. An emitter with no
// Table in its Config uses it.
func Sluis() *Table {
	sluisOnce.Do(func() {
		t, err := NewTable(sluisRows, sluisSchemas)
		if err != nil {
			panic("audit: the generated action table is broken: " + err.Error())
		}
		sluisTable = t
	})
	return sluisTable
}

// Row returns the row of the action.
func (t *Table) Row(name string) (Row, bool) {
	r, ok := t.rows[name]
	return r, ok
}

// Action returns the action of the row with its first activity, the one an action that has only one uses. An action
// whose activity depends on the call (entry's routes follow the method) picks the activity from Row.Activities.
func (t *Table) Action(name string) (Action, bool) {
	r, ok := t.rows[name]
	if !ok || len(r.Activities) == 0 {
		return Action{}, false
	}
	return Action{Name: r.Name, ClassUID: r.Class, ActivityID: r.Activities[0].ID, ActivityName: r.Activities[0].Name}, true
}

// Names returns the actions of the table in order.
func (t *Table) Names() []string { return slices.Sorted(maps.Keys(t.rows)) }

// CheckAction refuses an action that is not a row, or whose class, activity or activity name is not one the row
// has: an unknown action has no schema to hold its records to.
func (t *Table) CheckAction(a Action) error {
	r, ok := t.rows[a.Name]
	if !ok || r.Class != a.ClassUID {
		return refusal.New(connect.CodeInvalidArgument, "schema", "action")
	}
	for _, act := range r.Activities {
		if act.ID == a.ActivityID && act.Name == a.ActivityName {
			return nil
		}
	}
	return refusal.New(connect.CodeInvalidArgument, "schema", "action.activity")
}

// Validate checks a record (RFC 8785 bytes) against the schema of the action it names in metadata.event_code. The
// error names the keyword and the path of the member, never a value.
func (t *Table) Validate(record []byte) error {
	// The profile of a record first: no duplicate key, no float, no integer beyond 64 bits.
	v, err := ParseJSON(record)
	if err != nil {
		return refusal.New(connect.CodeInvalidArgument, "schema", "record")
	}
	root, _ := v.(map[string]any)
	md, _ := root["metadata"].(map[string]any)
	name, _ := md["event_code"].(string)
	if _, ok := t.rows[name]; !ok {
		return refusal.New(connect.CodeInvalidArgument, "schema", "metadata.event_code")
	}
	if err := t.schemas.Validate(schemaFile(name), record); err != nil {
		path := "record"
		var se *SchemaError
		if errors.As(err, &se) {
			path += se.Path
		}
		return refusal.New(connect.CodeInvalidArgument, "schema", path)
	}
	return nil
}
