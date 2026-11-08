package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// actionCases reads the example record of every action.
func actionCases(t *testing.T) []recordCase {
	t.Helper()
	var f recordFile
	readVectors(t, "action-vectors.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("the vector file is empty")
	}
	return f.Cases
}

// verifies: REQ-AUDIT-002
//
// Every action of the table has an example record, the example is what the library builds from its inputs, and it
// validates against the schema of its action: the schema is generated from the same row, so a row whose example the
// schema refuses is a generator bug, and the one whose example is not the library's bytes is a stale vector file.
func TestEveryActionHasAnExampleThatValidatesAgainstItsSchema(t *testing.T) {
	tb := Sluis()
	seen := map[string]bool{}
	for _, c := range actionCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			seen[c.Name] = true
			got, err := buildRecord(c.input(t))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.Expected {
				t.Fatalf("the library builds\n%s\nthe vector holds\n%s", got, c.Expected)
			}
			if err := tb.Validate(got); err != nil {
				t.Fatalf("the schema of %s refuses its own example: %v", c.Name, err)
			}
		})
	}
	for _, n := range tb.Names() {
		if !seen[n] {
			t.Errorf("the action %s has no example record", n)
		}
	}
	if len(seen) != len(tb.Names()) {
		t.Errorf("%d examples for %d actions", len(seen), len(tb.Names()))
	}
}

// schemaCase is a mutation of an example record and the verdict on the result.
type schemaCase struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Ops    []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"ops"`
	Valid bool `json:"valid"`
}

// mutate applies the ops to the example record and returns the text of the result.
func (c schemaCase) mutate(t *testing.T, example string) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(example))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		t.Fatal(err)
	}
	for _, op := range c.Ops {
		parts := strings.Split(op.Path, ".")
		parent := root
		for _, p := range parts[:len(parts)-1] {
			next, ok := parent[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				parent[p] = next
			}
			parent = next
		}
		last := parts[len(parts)-1]
		switch op.Op {
		case "set":
			vd := json.NewDecoder(bytes.NewReader(op.Value))
			vd.UseNumber()
			var v any
			if err := vd.Decode(&v); err != nil {
				t.Fatal(err)
			}
			parent[last] = v
		case "delete":
			delete(parent, last)
		default:
			t.Fatalf("op %q", op.Op)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// verifies: REQ-AUDIT-002, REQ-AUDIT-090, REQ-AUDIT-116, REQ-AUDIT-117, REQ-AUDIT-120, REQ-AUDIT-186
//
// The verdicts of kits/conformance/audit/schema-vectors.json: what the schemas accept and refuse. The Rust crate reads
// the same file. The cases include the member `lost` that the emitter adds to a record of any action (#1546) and the
// `documents` of a start as one object (#1552).
func TestSchemaVectors(t *testing.T) {
	var f struct {
		Cases []schemaCase `json:"cases"`
	}
	readVectors(t, "schema-vectors.json", &f)
	examples := map[string]string{}
	for _, c := range actionCases(t) {
		examples[c.Name] = c.Expected
	}
	if len(f.Cases) < 50 {
		t.Fatalf("%d cases: the vector file lost its cases", len(f.Cases))
	}
	tb := Sluis()
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			ex, ok := examples[c.Action]
			if !ok {
				t.Fatalf("no example for %s", c.Action)
			}
			err := tb.Validate(c.mutate(t, ex))
			if c.Valid && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.Valid && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// verifies: REQ-AUDIT-022
func TestTheEmitterRefusesAnActionThatIsNotInTheTable(t *testing.T) {
	tr := &fakeTransport{}
	e, err := New(Config{Actor: "key", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	for name, a := range map[string]Action{
		"a name that is no row":        {Name: "key.open", ClassUID: 6003, ActivityID: 99, ActivityName: "Open"},
		"another class than the row":   {Name: "key.sign", ClassUID: 3004, ActivityID: 99, ActivityName: "Sign"},
		"another activity":             {Name: "key.sign", ClassUID: 6003, ActivityID: 1},
		"another name of the activity": {Name: "key.sign", ClassUID: 6003, ActivityID: 99, ActivityName: "Open"},
	} {
		for how, emit := range map[string]func(context.Context, Event) error{
			"Emit": e.Emit, "EmitRequired": e.EmitRequired, "EmitBlocking": e.EmitBlocking, "EmitBlockingBestEffort": e.EmitBlockingBestEffort,
		} {
			ev := Event{Action: a, Status: StatusSuccess}
			if a.ClassUID == 6003 {
				ev.Caller, ev.Operation = "signer", "Sign"
			}
			err := emit(context.Background(), ev)
			r, _ := refusal.Reason(err)
			if p, _ := refusal.FieldPath(err); err == nil || r != "schema" || !strings.HasPrefix(p, "action") {
				t.Errorf("%s, %s: err = %v at %q, want the refusal schema at action", name, how, err, p)
			}
		}
	}
	if len(tr.reqs) != 0 {
		t.Fatalf("%d messages reached the transport", len(tr.reqs))
	}
}

// verifies: REQ-AUDIT-099
//
// An event whose record the schema of its action refuses is not emitted: a member the row lacks, a required member
// missing, a value of the wrong shape. The refusal is invalid_argument, names the path and never the value, and nothing
// reaches the transport.
func TestTheEmitterRefusesARecordThatDoesNotValidateBeforeItEmitsIt(t *testing.T) {
	tr := &fakeTransport{}
	e, err := New(Config{Actor: "key", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	sign := Action{Name: "key.sign", ClassUID: 6003, ActivityID: 99, ActivityName: "Sign"}
	good := map[string]any{"purpose": "token-signing", "key_id": "k1", "caller": "signer"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, s := range map[string]map[string]any{
		"a member the row lacks":    with("extra", "x"),
		"a required member missing": with("key_id", nil),
		"a name with a space":       with("key_id", "a secret value"),
		"an integer for a string":   with("purpose", int64(7)),
	} {
		err := e.Emit(context.Background(), Event{Action: sign, Status: StatusSuccess, Sluis: s, Caller: "signer", Operation: "Sign"})
		var ce *connect.Error
		if r, _ := refusal.Reason(err); err == nil || r != "schema" || !errors.As(err, &ce) || ce.Code() != connect.CodeInvalidArgument {
			t.Errorf("%s: err = %v", name, err)
			continue
		}
		if p, _ := refusal.FieldPath(err); strings.Contains(p, "secret") {
			t.Errorf("%s: the path %q holds a value", name, p)
		}
	}
	if len(tr.reqs) != 0 {
		t.Fatalf("%d messages reached the transport", len(tr.reqs))
	}
	if err := e.Emit(context.Background(), Event{Action: sign, Status: StatusSuccess, Sluis: good, Caller: "signer", Operation: "Sign"}); err != nil {
		t.Fatalf("a record that validates is emitted: %v", err)
	}
	if len(tr.reqs) != 1 {
		t.Fatalf("%d messages reached the transport", len(tr.reqs))
	}
}

// verifies: REQ-AUDIT-186
//
// The note of lost facts is part of the record, so the schema covers it: after a failure the next record carries
// unmapped.sluis.lost, and the emitter's own validation accepts the record that carries it, whatever the action.
func TestTheRecordThatCarriesTheNoteOfLostFactsValidates(t *testing.T) {
	tr := &fakeTransport{}
	e, err := New(Config{Actor: "adapter-upstream-oidc", Boundary: "dev", Release: "0.0.0-test", Transport: tr, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	begin := Action{Name: "upstream.begin", ClassUID: 3002, ActivityID: 99, ActivityName: "Upstream Begin"}
	e.recordLoss("", fixedNow.UnixMilli(), 1)
	if err := e.Emit(context.Background(), Event{Action: begin, Status: StatusSuccess}); err != nil {
		t.Fatalf("a record with the note: %v", err)
	}
	if len(tr.reqs) != 1 || !bytes.Contains(tr.reqs[0].GetMessage().GetRecord(), []byte(`"lost":{"process":`)) {
		t.Fatalf("the record does not carry the note: %v", tr.reqs)
	}
}

func TestTheGeneratedSchemasAreOnDisk(t *testing.T) {
	// The files under kits/conformance/audit/schema are what the emitters embed; `just audit-check` compares them with
	// the table. This test is the reader's: the directory holds a schema for every action and the shared definitions.
	dir := filepath.Join("..", "..", "conformance", "audit", "schema")
	for _, n := range append(Sluis().Names(), "defs") {
		if _, err := os.Stat(filepath.Join(dir, n+".schema.json")); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}
