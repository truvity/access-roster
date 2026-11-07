//go:build sluis_test

package writerd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/truvity/sluis/v2/kits/go/audit"
)

// The tests in this file move the clock of the writer and of the emitter by days. Both are injected; nothing waits.

const day = 24 * time.Hour

var windowStart = time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC)

// testClock is a clock the test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
	m  time.Duration // the clock that does not step
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// set moves the clock to t as time passes: the clock that does not step moves with it when t is later.
func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m += max(t.Sub(c.t), 0)
	c.t = t
}

// jump moves the wall clock to t as a step does: the clock that does not step stays where it is.
func (c *testClock) jump(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *testClock) mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m
}

// uuidV7At makes a record id whose time is at, as the emitter does on a clock that is at. The emitter's counter never
// goes back within a process, so a test that moves time by days makes its ids itself.
func uuidV7At(t *testing.T, at time.Time) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	ms := at.UnixMilli()
	for i := range 6 {
		b[i] = byte(ms >> (8 * (5 - i)) & 0xff)
	}
	b[6] = 0x70 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// messageAt is a message of the emitter made at the time at: the record id carries that time.
func messageAt(t *testing.T, em *audit.Emitter, tenant string, at time.Time) message {
	t.Helper()
	m := newMessage(t, em, "key.sign", tenant)
	v, err := parseStrict(m.rec)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuidV7At(t, at)
	v.(map[string]any)["metadata"].(map[string]any)["uid"] = uid
	rec, err := audit.Canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	return message{uid, rec}
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

// remembers says whether the state the writer committed holds the id, in its hot ids or in a segment it names.
func remembers(t *testing.T, e *env, uid string) bool {
	t.Helper()
	st, err := loadState(context.Background(), e.writer().blob)
	if err != nil {
		t.Fatal(err)
	}
	has, err := st.seenID(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	return has
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
	e.cfg.Mono = clk.mono
	em := emitterAt(t, clk.now)

	a := messageAt(t, em, "acme", clk.now())
	process(t, e.direct(t), a)

	// Thirteen days later the writer has been restarted (the memory is in the blob, not in the process). A second
	// record is sealed, which rewrites the state, and the transport delivers the first one again: it is a repeat.
	clk.set(windowStart.Add(13 * day))
	s := e.direct(t)
	b := messageAt(t, em, "acme", clk.now())
	process(t, s, b, a)

	es := logEntries(t, e.logDir())
	if got := recordUIDs(es); len(got) != 2 || got[0] != a.uid || got[1] != b.uid {
		t.Fatalf("records = %v, want %s once and %s once", got, a.uid, b.uid)
	}
	if seals := sealEntries(es); seals[len(seals)-1]["duplicates"] != float64(1) {
		t.Fatalf("the repeat after 13 days was not counted as a duplicate: %v", seals[len(seals)-1])
	}
	if !remembers(t, e, a.uid) || !remembers(t, e, b.uid) {
		t.Fatal("after 13 days the state does not hold both ids")
	}

	// Past fourteen days the next batch that is sealed drops the id of a. B was sealed at day 13 and is kept.
	clk.set(windowStart.Add(14*day + time.Hour))
	c := messageAt(t, em, "acme", clk.now())
	process(t, s, c, b)
	if remembers(t, e, a.uid) {
		t.Fatal("the id of a record sealed 14 days and an hour ago is still remembered")
	}
	if !remembers(t, e, b.uid) || !remembers(t, e, c.uid) {
		t.Fatal("the state does not hold the ids sealed within 14 days")
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
	e.cfg.Mono = clk.mono
	em := emitterAt(t, clk.now)
	s := e.direct(t)
	logs := logCapture(t)

	// Records made at three times; the writer's clock is windowStart.
	made := func(at time.Time) message {
		clk.jump(at)
		defer clk.jump(windowStart)
		return messageAt(t, em, "acme", at)
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
	if remembers(t, e, tooOld.uid) {
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
