package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	keyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// grantLife is the life of a grant in these tests: 60 seconds (ADR 0007).
const grantLife = 60 * time.Second

// clock is the time of the fake policy and the fake key@; every Open of a batch takes openTook of it after key@ has
// checked the grant, as a pass over a log of thousands of records takes the time of its calls.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// fakeEvidenceKey is key@'s Open for evidence: it refuses, with the reason grant, a grant that has no more life (what
// checkGrant does, actors/key/internal/keyd/grant.go), and otherwise "opens" an envelope into itself. A grant is the text
// of the time it was made.
type fakeEvidenceKey struct {
	keyv2alpha1connect.KeyServiceClient
	c        *clock
	openTook time.Duration
	// refuseAll refuses every grant, for a key@ that does not accept the one policy gives (another holder, tenant).
	refuseAll bool
	// otherwise is a refusal of another reason that every Open answers with.
	otherwise *connect.Error
	opens     int
	refused   int
	batches   [][]string
}

func (f *fakeEvidenceKey) Open(_ context.Context, req *connect.Request[keyv2alpha1.OpenRequest]) (*connect.Response[keyv2alpha1.OpenResponse], error) {
	f.opens++
	defer func() { f.c.t = f.c.t.Add(f.openTook) }()
	if f.otherwise != nil {
		return nil, f.otherwise
	}
	made, err := time.Parse(time.RFC3339Nano, string(req.Msg.GetGrant()))
	if f.refuseAll || err != nil || !f.c.t.Before(made.Add(grantLife)) {
		f.refused++
		return nil, refusal.New(connect.CodePermissionDenied, "grant", "grant")
	}
	var out [][]byte
	var ids []string
	for _, it := range req.Msg.GetItems() {
		out = append(out, it.GetEnvelope())
		ids = append(ids, it.GetAddress().GetId())
	}
	f.batches = append(f.batches, ids)
	return connect.NewResponse(&keyv2alpha1.OpenResponse{Plaintexts: out}), nil
}

// auditLog writes a log of n record entries into a directory, as the writer's blob driver does, and returns it. The
// entry at each index of mine is a record of the run (it carries the correlation id and one of the wanted events); the
// others are records of other work. The sealed record of an entry is its own plaintext, which fakeEvidenceKey returns.
func auditLog(t *testing.T, n int, mine map[int]string) string {
	t.Helper()
	dir := t.TempDir()
	var entries []string
	for i := range n {
		ev, corr := "other.event", "someone-else"
		if e, ok := mine[i]; ok {
			ev, corr = e, "run-1"
		}
		rec, err := json.Marshal(map[string]any{"metadata": map[string]string{"event_code": ev, "correlation_uid": corr}})
		if err != nil {
			t.Fatal(err)
		}
		e, err := json.Marshal(map[string]any{
			"entry": "record", "sealed": base64.StdEncoding.EncodeToString(rec),
			"metadata": map[string]string{"uid": fmt.Sprintf("r%04d", i), "tenant_uid": "acme"},
		})
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, string(e))
	}
	for b := 0; b*bundleWidth < n; b++ {
		part := entries[b*bundleWidth : min(n, (b+1)*bundleWidth)]
		path := filepath.Join(dir, bundlePath(int64(b), len(part)))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // a test directory
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bundleOf(part...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "checkpoint"), fmt.Appendf(nil, "origin\n%d\nroot\n", n), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// policyOf is a policy that seals a grant as the time it is asked at.
func policyOf(c *clock, asked *int) *grantSource {
	return &grantSource{now: c.now, ask: func(context.Context) ([]byte, error) {
		*asked++
		return []byte(c.t.Format(time.RFC3339Nano)), nil
	}}
}

var theRun = map[int]string{0: "policy.decide", 1: "signer.sign", 2: "key.sign"}

// A log of a board that has run for days holds thousands of records, and the records of the run are the newest. A pass
// that has to read the old ones too (here the records of the run are the first three of 300, so the pass reads all) takes
// longer than the life of a grant: the board's step 3 failed with permission_denied, reason grant, field grant, at the
// first Open after the life of the grant.
//
// verifies: REQ-AUDIT-184
func TestAPassLongerThanTheLifeOfAGrantAsksPolicyAgain(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	key := &fakeEvidenceKey{c: c, openTook: 25 * time.Second}
	asked := 0
	log := auditLog(t, 300, theRun)

	s, err := scanLog(context.Background(), key, policyOf(c, &asked), log, "sluis", "", "run-1")
	if err != nil {
		t.Fatalf("scanLog: %v (opens %d, refused %d, asked policy %d times)", err, key.opens, key.refused, asked)
	}
	if !s.complete() || len(s.out.Found) != 3 || s.out.Records != 300 || s.out.Size != 300 {
		t.Errorf("the pass found %+v, complete %v", s.out, s.complete())
	}
	if key.opens < 5 {
		t.Fatalf("key@ saw %d Opens, want the 5 batches of 300 records", key.opens)
	}
	if key.refused != 0 {
		t.Errorf("key@ refused %d Opens: the pass held a grant past its life", key.refused)
	}
	if asked < 2 {
		t.Errorf("policy was asked %d times for a pass of %s, longer than a grant's life of %s", asked, time.Duration(key.opens)*key.openTook, grantLife)
	}
}

// When key@ refuses a grant that was just asked for, the pass stops: it asks once more and no more, and takes nothing
// from a refusal. key@'s check is not weakened and not walked around.
//
// verifies: REQ-AUDIT-185
func TestAPassStopsWhenKeyRefusesTheNewGrantToo(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	key := &fakeEvidenceKey{c: c, refuseAll: true}
	asked := 0
	s, err := scanLog(context.Background(), key, policyOf(c, &asked), auditLog(t, 10, theRun), "sluis", "", "run-1")
	if err == nil || !strings.Contains(err.Error(), `reason "grant", field "grant"`) {
		t.Fatalf("scanLog = %v, %v; want the refusal of key@", s, err)
	}
	if key.opens != 2 || asked != 2 {
		t.Errorf("Opens %d, policy asked %d times; want 2 and 2 (the grant, then one more)", key.opens, asked)
	}
}

// A refusal for another reason is not a grant that ran out: nothing is asked again.
//
// verifies: REQ-AUDIT-185
func TestARefusalOfAnotherReasonIsNotRetried(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	key := &fakeEvidenceKey{c: c, otherwise: refusal.New(connect.CodePermissionDenied, "rule", "items.purpose")}
	asked := 0
	if _, err := scanLog(context.Background(), key, policyOf(c, &asked), auditLog(t, 10, theRun), "sluis", "", "run-1"); err == nil {
		t.Fatal("a refusal by rule was taken for an answer")
	}
	if key.opens != 1 || asked != 1 {
		t.Errorf("Opens %d, policy asked %d times; want 1 and 1", key.opens, asked)
	}
}

// The records of the run are the newest: the pass reads from the end and stops when it has them, so a log of thousands
// costs one batch, and a grant held for less than half its life is reused.
//
// verifies: REQ-AUDIT-184
func TestThePassReadsTheNewestRecordsFirstAndStopsWhenItHasTheRun(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	key := &fakeEvidenceKey{c: c, openTook: time.Second}
	asked := 0
	s, err := scanLog(context.Background(), key, policyOf(c, &asked), auditLog(t, 300, map[int]string{297: "policy.decide", 298: "signer.sign", 299: "key.sign"}), "sluis", "", "run-1")
	if err != nil || !s.complete() {
		t.Fatalf("scanLog = %+v, %v", s, err)
	}
	if key.opens != 1 || asked != 1 || len(key.batches[0]) != openBatch {
		t.Errorf("Opens %d, policy asked %d times, first batch of %d; want 1, 1 and %d", key.opens, asked, len(key.batches[0]), openBatch)
	}
	if last := key.batches[0][len(key.batches[0])-1]; !strings.HasSuffix(last, "/r0299") {
		t.Errorf("the batch ends at %s, want the newest record r0299", last)
	}
}

// A grant that has run out by the time key@ sees it (a call that waited, a held grant that outlived its life) is
// refused with the reason grant; the pass asks policy once more and goes on.
//
// verifies: REQ-AUDIT-184
func TestAGrantThatRanOutBeforeKeySawItIsAskedForAgain(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	key := &fakeEvidenceKey{c: c}
	asked := 0
	g := &grantSource{now: c.now, ask: func(context.Context) ([]byte, error) {
		asked++
		made := c.t
		if asked == 1 {
			made = c.t.Add(-2 * grantLife)
		}
		return []byte(made.Format(time.RFC3339Nano)), nil
	}}
	s, err := scanLog(context.Background(), key, g, auditLog(t, 10, theRun), "sluis", "", "run-1")
	if err != nil || !s.complete() {
		t.Fatalf("scanLog = %+v, %v", s, err)
	}
	if key.opens != 2 || key.refused != 1 || asked != 2 {
		t.Errorf("Opens %d, refused %d, policy asked %d times; want 2, 1 and 2", key.opens, key.refused, asked)
	}
}

func TestAGrantIsKeptForHalfItsLifeAndNoLonger(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	asked := 0
	g := policyOf(c, &asked)
	for _, step := range []struct {
		after time.Duration
		fresh bool
		asked int
	}{{0, false, 1}, {grantReuse - time.Second, false, 1}, {2 * time.Second, false, 2}, {0, true, 3}} {
		c.t = c.t.Add(step.after)
		if _, err := g.get(context.Background(), step.fresh); err != nil {
			t.Fatal(err)
		}
		if asked != step.asked {
			t.Fatalf("after %s (fresh %v): policy asked %d times, want %d", step.after, step.fresh, asked, step.asked)
		}
	}
}
