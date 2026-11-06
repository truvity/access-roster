//go:build sluis_test

package writerd

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tests in this file move the clock of the writer and of the emitter by days. Both are injected; nothing waits.

const day = 24 * time.Hour

var windowStart = time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)

// testClock is a clock the test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// readState reads the state object the writer committed to the blob.
func readState(t *testing.T, e *env) stateDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.root, "state", "writer-state"))
	if err != nil {
		t.Fatal(err)
	}
	var doc stateDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func remembers(doc stateDoc, uid string) bool {
	for _, s := range doc.Seen {
		if s.ID == uid {
			return true
		}
	}
	return false
}

func recordUIDs(es []map[string]any) []string {
	var out []string
	for _, r := range recordEntries(es) {
		out = append(out, r["metadata"].(map[string]any)["uid"].(string))
	}
	return out
}

// verifies: REQ-AUDIT-052
func TestAnIdIsRememberedForFourteenDaysAndNoLonger(t *testing.T) {
	clk := &testClock{t: windowStart}
	e := newEnv(t)
	e.cfg.Now = clk.now
	em := emitterAt(t, clk.now)

	a := newMessage(t, em, "key.sign", "acme")
	process(t, e.direct(t), a)

	// Thirteen days later the writer has been restarted (the memory is in the blob, not in the process). A second
	// record is sealed, which rewrites the state, and the transport delivers the first one again: it is a repeat.
	clk.set(windowStart.Add(13 * day))
	s := e.direct(t)
	b := newMessage(t, em, "key.sign", "acme")
	process(t, s, b, a)

	es := logEntries(t, e.logDir())
	if got := recordUIDs(es); len(got) != 2 || got[0] != a.uid || got[1] != b.uid {
		t.Fatalf("records = %v, want %s once and %s once", got, a.uid, b.uid)
	}
	if seals := sealEntries(es); seals[len(seals)-1]["duplicates"] != float64(1) {
		t.Fatalf("the repeat after 13 days was not counted as a duplicate: %v", seals[len(seals)-1])
	}
	if doc := readState(t, e); !remembers(doc, a.uid) || !remembers(doc, b.uid) {
		t.Fatalf("after 13 days the state holds %v, want both ids", doc.Seen)
	}

	// Past fourteen days the next batch that is sealed drops the id of a. B was sealed at day 13 and is kept.
	clk.set(windowStart.Add(14*day + time.Hour))
	c := newMessage(t, em, "key.sign", "acme")
	process(t, s, c, b)
	doc := readState(t, e)
	if remembers(doc, a.uid) {
		t.Fatalf("the id of a record sealed 14 days and an hour ago is still remembered: %v", doc.Seen)
	}
	if !remembers(doc, b.uid) || !remembers(doc, c.uid) {
		t.Fatalf("the state holds %v, want the ids sealed within 14 days", doc.Seen)
	}
	if got := recordUIDs(logEntries(t, e.logDir())); len(got) != 3 {
		t.Fatalf("records = %v, want 3: b was delivered again inside its window", got)
	}
	e.mustVerify(t)
}

// logCapture collects what the writer logs for the length of a test.
func logCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// verifies: REQ-AUDIT-053
func TestARecordOlderThanTheWindowIsQuarantinedAndReported(t *testing.T) {
	clk := &testClock{t: windowStart}
	e := newEnv(t)
	e.cfg.Now = clk.now
	em := emitterAt(t, clk.now)
	s := e.direct(t)
	logs := logCapture(t)

	// Records made at three times; the writer's clock is windowStart.
	made := func(at time.Time) message {
		clk.set(at)
		defer clk.set(windowStart)
		return newMessage(t, em, "key.sign", "acme")
	}
	tooOld := made(windowStart.Add(-14*day - time.Minute))
	justInside := made(windowStart.Add(-14*day + time.Minute))
	recent := made(windowStart.Add(-time.Hour))

	process(t, s, tooOld, justInside, recent)

	es := logEntries(t, e.logDir())
	got := recordUIDs(es)
	if len(got) != 2 || got[0] != justInside.uid || got[1] != recent.uid {
		t.Fatalf("records = %v, want only the two inside the window", got)
	}
	if seals := sealEntries(es); seals[0]["refused"] != float64(1) || seals[0]["records"] != float64(2) {
		t.Fatalf("the seal entry = %v, want 2 records and 1 refusal", seals[0])
	}
	if remembers(readState(t, e), tooOld.uid) {
		t.Fatal("the id of a refused record was registered as sealed")
	}

	// Quarantined: one object, sealed, with the reason, and the message is not lost.
	reports, err := filepath.Glob(filepath.Join(e.root, "quarantine", "*"))
	if err != nil || len(reports) != 1 {
		t.Fatalf("quarantine objects = %v (%v), want 1", reports, err)
	}
	rep, m := openQuarantine(t, e, reports[0])
	if rep["reason"] != reasonStale || rep["path"] != "time" || rep["uid"] != tooOld.uid || rep["tenant"] != "acme" {
		t.Fatalf("report = %v", rep)
	}
	if !bytes.Equal(m.GetRecord(), tooOld.rec) {
		t.Fatal("the quarantined message is not the message that was delivered")
	}

	// Reported: an error line names the reason and the record, and the message is acknowledged.
	line := logs.String()
	for _, want := range []string{"level=ERROR", "reason=stale", "path=time", "uid=" + tooOld.uid} {
		if !strings.Contains(line, want) {
			t.Fatalf("the writer did not report the refusal (missing %q): %s", want, line)
		}
	}
	if n := e.tr.ackedCount(); n != 3 {
		t.Fatalf("%d acknowledged, want 3", n)
	}
	e.mustVerify(t)
}
