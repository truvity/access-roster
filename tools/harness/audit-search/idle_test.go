package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is the time of a test: Sleep moves it, and nothing waits.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) Sleep(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// logServer answers Search from a list of records by the time of their event, as the audit front does with from_ms,
// and shows a record only 5 s after its event, as the seal and the index do.
func logServer(t *testing.T, clk *fakeClock, events []event) (*http.Client, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var q request
		if err := json.Unmarshal(b, &q); err != nil {
			t.Error(err)
		}
		from, _ := strconv.ParseInt(q.FromMs, 10, 64)
		var hits []hit
		for _, e := range events {
			if e.at.UnixMilli() < from || clk.Now().Sub(e.at) < 5*time.Second {
				continue
			}
			rec, _ := json.Marshal(map[string]any{"unmapped": map[string]any{"sluis": e.fields}})
			hits = append(hits, hit{Tenant: "acme", Action: e.action, StatusCode: e.status, ActorUID: e.actor, TimeMs: strconv.FormatInt(e.at.UnixMilli(), 10), Record: string(rec)})
		}
		_ = json.NewEncoder(w).Encode(response{Hits: hits})
	}))
	t.Cleanup(srv.Close)
	return srv.Client(), strings.TrimPrefix(srv.URL, "https://")
}

type event struct {
	at     time.Time
	action string
	status string
	actor  string
	fields map[string]any
}

var t0 = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func refusals(from time.Time, every time.Duration, until time.Time) []event {
	var out []event
	for at := from; at.Before(until); at = at.Add(every) {
		out = append(out, event{at: at, action: "store.refused", status: "absent", actor: "store@dev",
			fields: map[string]any{"caller": "exchange", "kind": "SessionChain", "verb": "get", "code": "not_found"}})
	}
	return out
}

func TestTheBoundIsTheHourlyBoundScaledToTheWindowAndRoundedDown(t *testing.T) {
	for _, c := range []struct {
		w    time.Duration
		want int
	}{{time.Hour, 60}, {180 * time.Second, 3}, {59 * time.Second, 0}, {30 * time.Minute, 30}, {119 * time.Second, 1}} {
		if got := idleBound(c.w); got != c.want {
			t.Errorf("idleBound(%v) = %d, want %d", c.w, got, c.want)
		}
	}
}

func opts() idleOptions {
	return idleOptions{Window: 180 * time.Second, After: 90 * time.Second}
}

// idle runs the check against a log of events that starts at t0 on the fake clock, and returns the status and the report.
func idle(t *testing.T, events []event, o idleOptions) (int, string) {
	t.Helper()
	clk := &fakeClock{t: t0}
	c, host := logServer(t, clk, events)
	var out strings.Builder
	code := runIdle(c, host, []string{"acme"}, o, clk, &out)
	return code, out.String()
}

// verifies: REQ-AUDIT-180
// A stack that writes a refusal every five seconds, as the health check of exchange did, fails, and the report names the
// refusal; the bound is 3 records in 180 s, and this makes 36.
func TestARefusalEveryFiveSecondsFailsTheIdleCheck(t *testing.T) {
	code, out := idle(t, refusals(t0.Add(-time.Hour), 5*time.Second, t0.Add(time.Hour)), opts())
	if code != 1 {
		t.Fatalf("status %d, want 1:\n%s", code, out)
	}
	for _, want := range []string{"store.refused", "caller=exchange kind=SessionChain verb=get code=not_found", "FAILED", "REQ-AUDIT-180"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
}

// verifies: REQ-AUDIT-180
// A log with nothing in the window passes, and records from before the window (a start-up, a smoke) are not counted: the
// window starts 90 s after the check does, and a burst that ends before it is the tail of what ran before.
func TestTheTailOfWhatRanBeforeIsNotCounted(t *testing.T) {
	code, out := idle(t, refusals(t0.Add(-time.Hour), 5*time.Second, t0.Add(80*time.Second)), opts())
	if code != 0 || !strings.Contains(out, "idle: 0 record(s)") || !strings.Contains(out, "idle: ok") {
		t.Fatalf("status %d:\n%s", code, out)
	}
}

// A record after the window is not counted either: the check reads the log 20 s after the window, and the records of its
// own search are later still.
func TestARecordAfterTheWindowIsNotCounted(t *testing.T) {
	code, out := idle(t, refusals(t0.Add(271*time.Second), 5*time.Second, t0.Add(285*time.Second)), opts())
	if code != 0 {
		t.Fatalf("status %d:\n%s", code, out)
	}
}

// verifies: REQ-AUDIT-180
// The bound is a count: three records in the window pass and four fail.
func TestTheBoundIsExact(t *testing.T) {
	// The window is (t0+90 s, t0+270 s]. The records are 40 s apart from t0+100 s.
	win := func(n int) []event {
		var ev []event
		for i := range n {
			ev = append(ev, event{at: t0.Add(time.Duration(100+i*40) * time.Second), action: "key.refuse", status: "open", actor: "key@dev"})
		}
		return ev
	}
	if code, out := idle(t, win(3), opts()); code != 0 {
		t.Fatalf("three records: status %d:\n%s", code, out)
	}
	if code, out := idle(t, win(4), opts()); code != 1 {
		t.Fatalf("four records: status %d:\n%s", code, out)
	}
}

// A log that cannot be read is a failure, not a pass.
func TestAnUnreadableLogFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer srv.Close()
	var out strings.Builder
	if code := runIdle(srv.Client(), strings.TrimPrefix(srv.URL, "https://"), []string{"acme"}, opts(), &fakeClock{t: t0}, &out); code != 1 {
		t.Fatalf("status %d:\n%s", code, out.String())
	}
}

func TestGroupsCountWhatWroteTheRecordsAndWhatWasRefused(t *testing.T) {
	var hits []hit
	for _, e := range refusals(t0, time.Second, t0.Add(3*time.Second)) {
		rec, _ := json.Marshal(map[string]any{"unmapped": map[string]any{"sluis": e.fields}})
		hits = append(hits, hit{Action: e.action, StatusCode: e.status, ActorUID: e.actor, Record: string(rec)})
	}
	hits = append(hits, hit{Action: "key.sign", StatusCode: "ok", ActorUID: "key@dev", Record: "not json"})
	var out strings.Builder
	printGroups(&out, countGroups(hits), len(hits))
	got := out.String()
	for _, want := range []string{"3  store.refused", "caller=exchange kind=SessionChain verb=get code=not_found", "1  key.sign", "4  in all"} {
		if !strings.Contains(got, want) {
			t.Errorf("the groups lack %q:\n%s", want, got)
		}
	}
}
