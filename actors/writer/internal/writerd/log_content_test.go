//go:build sluis_test

package writerd

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
)

// keysOf collects every object key of a decoded JSON value, at any depth.
func keysOf(v any, into *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			*into = append(*into, k)
			keysOf(c, into)
		}
	case []any:
		for _, c := range x {
			keysOf(c, into)
		}
	}
}

// files lists the files below dir, as slash paths relative to it.
func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// verifies: REQ-AUDIT-115
func TestTheLogHoldsOnlyRecordsAndSealEntries(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	e.start()

	// Good records, a repeat, a refusal, and two messages that try to put a catalogue document and a schema entry
	// into the log as if they were records: the writer reads the catalogue from store@ and never writes it.
	a := newMessage(t, em, "key.sign", "acme")
	good := []message{a, newMessage(t, em, "store.start", ""), newMessage(t, em, "key.sign", "globex"), a}
	for _, m := range good {
		e.push(m)
	}
	e.push(newMessage(t, em, "key.nothing", "acme"))
	catalogueDoc := canonical(t, map[string]any{"release": "0.0.0", "actions": []any{"key.sign", "store.start"}})
	schemaEntry := canonical(t, map[string]any{"entry": "schema", "schema": map[string]any{"type": "object"}})
	e.tr.push(&transportv2alpha1.AuditMessage{Uid: "catalogue-doc", Record: catalogueDoc})
	e.tr.push(&transportv2alpha1.AuditMessage{Uid: "schema-entry", Record: schemaEntry})
	const sent = 4 + 1 + 2
	wait(t, "every message to be acknowledged", func() bool { return e.tr.ackedCount() == sent })

	// Every entry of the log is a record or a seal entry, and nothing in one names a catalogue or a schema.
	es := logEntries(t, e.logDir())
	if len(recordEntries(es)) != 3 || len(sealEntries(es)) == 0 {
		t.Fatalf("%d record entries and %d seal entries", len(recordEntries(es)), len(sealEntries(es)))
	}
	forbidden := []string{"actions", "catalogue", "schema", "release"}
	for i, en := range es {
		if k := en["entry"]; k != entryRecord && k != entrySeal {
			t.Fatalf("entry %d is of kind %v", i, k)
		}
		var ks []string
		keysOf(en, &ks)
		for _, f := range forbidden {
			if slices.Contains(ks, f) {
				t.Fatalf("entry %d has a %q field: %v", i, f, en)
			}
		}
	}
	// The same, inside the sealed records: each is a record of the form the emitter makes, not a document.
	for i, en := range recordEntries(es) {
		var rec map[string]any
		if err := json.Unmarshal(openEntry(t, e, en), &rec); err != nil {
			t.Fatal(err)
		}
		var ks []string
		keysOf(rec, &ks)
		for _, f := range forbidden {
			if slices.Contains(ks, f) {
				t.Fatalf("record %d has a %q field", i, f)
			}
		}
		if rec["metadata"].(map[string]any)["uid"] != en["metadata"].(map[string]any)["uid"] {
			t.Fatalf("record %d is not the record its entry names", i)
		}
	}

	// The tree holds a checkpoint, the checkpoints and the tiles, and no object of another kind; no object of the
	// blob is a catalogue or a schema.
	logFiles := files(t, e.logDir())
	if len(logFiles) == 0 {
		t.Fatal("the log directory is empty: nothing was swept")
	}
	for _, f := range logFiles {
		if top := strings.SplitN(f, "/", 2)[0]; top != "checkpoint" && top != "checkpoints" && top != "tile" {
			t.Fatalf("the log holds %s", f)
		}
		raw, err := os.ReadFile(filepath.Join(e.logDir(), filepath.FromSlash(f)))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{`"actions"`, `"catalogue"`, `"schema"`} {
			if bytes.Contains(raw, []byte(w)) {
				t.Fatalf("%s holds %s", f, w)
			}
		}
	}
	for _, f := range files(t, e.root) {
		if top := strings.SplitN(f, "/", 2)[0]; top != "audit" && top != "state" && top != "quarantine" {
			t.Fatalf("the blob holds %s", f)
		}
		if strings.Contains(f, "catalogue") || strings.Contains(f, "schema") {
			t.Fatalf("the blob holds %s", f)
		}
	}

	// What was not a record was refused and kept aside, with the reason; none of it is in the log.
	reports, _ := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if len(reports) != 3 {
		t.Fatalf("%d quarantine objects, want 3", len(reports))
	}
	uids := recordUIDs(es)
	if slices.Contains(uids, "catalogue-doc") || slices.Contains(uids, "schema-entry") {
		t.Fatalf("a catalogue document or a schema entry is in the log: %v", uids)
	}
	e.mustVerify(t)
}

// checkpointFiles lists the checkpoint pointer and every checkpoints/<size> of a log.
func checkpointFiles(t *testing.T, e *env) []string {
	t.Helper()
	paths := []string{filepath.Join(e.logDir(), "checkpoint")}
	hist, err := filepath.Glob(filepath.Join(e.logDir(), "checkpoints", "*"))
	if err != nil {
		t.Fatal(err)
	}
	return append(paths, hist...)
}

// verifies: REQ-AUDIT-125
func TestEachWriterInstanceSignsItsCheckpointsWithItsOwnLogKey(t *testing.T) {
	// Two installations, each with its own key@ and so its own log key, and the same project and origin.
	// The keys differ by construction (each fake key@ makes its own). What the test proves is that the writer signs
	// every checkpoint with the one key key@ gives it for audit-log; one key per instance, used by that instance
	// only, is key@'s part and is not tested here.
	a, b := newEnv(t), newEnv(t)
	b.cfg.Instance = "node-2"
	ema, emb := emitterOf(t, a), emitterOf(t, b)
	a.start()
	b.start()
	if a.verifier() == b.verifier() {
		t.Fatal("the two installations share a log key")
	}

	// Several batches each, so that several checkpoints are signed.
	for n := 1; n <= 3; n++ {
		a.push(newMessage(t, ema, "key.sign", "acme"))
		b.push(newMessage(t, emb, "key.sign", "acme"))
		wait(t, "both batches", func() bool { return a.tr.ackedCount() == n && b.tr.ackedCount() == n })
	}

	va, vb := newC2SPVerifier(t, a.verifier()), newC2SPVerifier(t, b.verifier())
	for _, c := range []struct {
		name       string
		e          *env
		own, other *c2spECDSAVerifier
	}{{"first", a, va, vb}, {"second", b, vb, va}} {
		paths := checkpointFiles(t, c.e)
		if len(paths) < 4 {
			t.Fatalf("%s writer: %d checkpoint objects, want the pointer and 3 checkpoints", c.name, len(paths))
		}
		for _, p := range paths {
			raw, err := os.ReadFile(p) //nolint:gosec // a test directory
			if err != nil {
				t.Fatal(err)
			}
			// Every checkpoint of the log verifies against the one public key of its writer ...
			if _, err := note.Open(raw, note.VerifierList(c.own)); err != nil {
				t.Fatalf("%s writer: %s does not verify with its own key: %v", c.name, filepath.Base(p), err)
			}
			// ... and none verifies against the other writer's.
			if _, err := note.Open(raw, note.VerifierList(c.other)); err == nil {
				t.Fatalf("%s writer: %s verifies with the other writer's key", c.name, filepath.Base(p))
			}
		}
		// The CLI an auditor runs says the same.
		if out, code := verifyWithCLI(t, c.e.logDir(), c.e.verifier()); code != 0 {
			t.Fatalf("%s writer: sluis audit verify with its key exited %d: %s", c.name, code, out)
		}
		other := a
		if c.e == a {
			other = b
		}
		if out, code := verifyWithCLI(t, c.e.logDir(), other.verifier()); code == 0 {
			t.Fatalf("%s writer: sluis audit verify accepted the log with the other writer's key: %s", c.name, out)
		}
	}
}
