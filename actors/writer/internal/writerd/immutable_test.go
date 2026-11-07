//go:build sluis_test

package writerd

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshot reads every object of the blob that the writer may not rewrite: all but the two pointers.
func snapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "state/writer-state" || rel == "audit/main/checkpoint" || strings.HasPrefix(rel, "state/") && !strings.HasPrefix(rel, "state/seen/") {
			return nil // the pointers of the port: the state and the checkpoint pointer
		}
		b, err := os.ReadFile(p) //nolint:gosec // a test directory
		out[rel] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A sealed batch is never changed: every entry bundle, hash tile, checkpoint and segment that a batch wrote is, byte
// for byte, what it was after the later batches, which only add. The blob port gives the writer no way to change one
// (create refuses a name that exists, whatever the bytes, and a put is for the two pointers only), and a writer that
// tries is stopped by the fence. This is the writer's half; the driver's half is the port test of drivers/writer/fs.
//
// verifies: REQ-AUDIT-025, REQ-ISO-022
func TestASealedBatchIsNeverChangedByTheBatchesAfterIt(t *testing.T) {
	e := newEnv(t)
	em := emitterOf(t, e)
	s := e.direct(t)

	process(t, s, newMessage(t, em, "key.sign", "acme"), newMessage(t, em, "key.sign", "acme"))
	first := snapshot(t, e.root)
	if len(first) < 3 {
		t.Fatalf("the first batch wrote %d objects: the snapshot checked nothing", len(first))
	}
	for range 3 {
		process(t, s, newMessage(t, em, "key.sign", "globex"), newMessage(t, em, "key.sign", "acme"))
	}
	later := snapshot(t, e.root)
	if len(later) <= len(first) {
		t.Fatalf("later batches added nothing: %d then %d objects", len(first), len(later))
	}
	for name, was := range first {
		if now, ok := later[name]; !ok || !bytes.Equal(now, was) {
			t.Errorf("%s was changed or removed after its batch was sealed", name)
		}
	}

	// The port gives no way to change a sealed object.
	var someTile string
	for name := range first {
		if strings.Contains(name, "/tile/") {
			someTile = name
			break
		}
	}
	if someTile == "" {
		t.Fatal("no tile in the first batch")
	}
	if err := s.blob.create(t.Context(), someTile, []byte("other bytes")); !errors.Is(err, errExists) {
		t.Fatalf("create over a sealed tile = %v, want the object exists", err)
	}
	if err := s.blob.createOnce(t.Context(), someTile, []byte("other bytes")); !errors.Is(err, ErrFence) {
		t.Fatalf("createOnce over a sealed tile = %v, want the fence", err)
	}
	if _, err := s.blob.put(t.Context(), someTile, []byte("other bytes"), ""); err == nil {
		t.Fatal("a put replaced a sealed tile")
	}
	if now := snapshot(t, e.root); !bytes.Equal(now[someTile], first[someTile]) {
		t.Fatal("the tile changed")
	}
	e.mustVerify(t)

	// A change made behind the writer's back is not hidden: the log no longer verifies.
	// The entry bundle the head reads is the newest partial one: the one with the most entries.
	var newest string
	for name := range later {
		if strings.Contains(name, "/tile/entries/") && (newest == "" || len(name) > len(newest) || len(name) == len(newest) && name > newest) {
			newest = name
		}
	}
	p := filepath.Join(e.root, filepath.FromSlash(newest))
	b, err := os.ReadFile(p) //nolint:gosec // a test file
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(p, b, 0o640); err != nil { //nolint:gosec // a test file
		t.Fatal(err)
	}
	if out, code := verifyWithCLI(t, e.logDir(), e.verifier()); code == 0 {
		t.Fatalf("a changed tile still verifies: %s", out)
	}
}
