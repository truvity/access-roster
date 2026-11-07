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
// shows a record only 5 s after its event, as the seal and the index do, and gives at most page records at a time with a
// token for the next page (page 0 is "all of them at once").
func logServer(t *testing.T, clk *fakeClock, events []event, page int) (*http.Client, string) {
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
		start := 0
		if q.PageToken != "" {
			start, _ = strconv.Atoi(q.PageToken)
		}
		hits = hits[min(start, len(hits)):]
		next := ""
		if page > 0 && len(hits) > page {
			hits, next = hits[:page], strconv.Itoa(start+page)
		}
		_ = json.NewEncoder(w).Encode(response{Hits: hits, NextPageToken: next})
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
	return idlePaged(t, events, o, 0)
}

func idlePaged(t *testing.T, events []event, o idleOptions, page int) (int, string) {
	t.Helper()
	clk := &fakeClock{t: t0}
	c, host := logServer(t, clk, events, page)
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

// at is an event at this many seconds from t0.
func at(sec float64, action string) event {
	return event{at: t0.Add(time.Duration(sec * float64(time.Second))), action: action, status: "ok", actor: "x@dev"}
}

// The window is (t0+90 s, t0+270 s], read 20 s after it ends. A record that happened in the last second of the window shows
// only 5 s later, so the read must wait for it: a check that read at once would count 3 and pass.
func TestTheReadWaitsForTheLastRecordsOfTheWindow(t *testing.T) {
	ev := []event{at(100, "a"), at(150, "b"), at(200, "c"), at(269, "d")}
	if code, out := idle(t, ev, opts()); code != 1 {
		t.Fatalf("status %d, want 1 for 4 records, the last in the last second of the window:\n%s", code, out)
	}
}

// A record just after the window is not in it, though the read sees it: the bound is of the window, not of the read.
func TestARecordJustAfterTheWindowIsNotCounted(t *testing.T) {
	ev := []event{at(100, "a"), at(150, "b"), at(200, "c"), at(272, "d")}
	if code, out := idle(t, ev, opts()); code != 0 {
		t.Fatalf("status %d, want 0 for 3 records in the window and one after it:\n%s", code, out)
	}
}

// A record at the start of the window is not in it either: the window is open at its start.
func TestARecordAtTheStartOfTheWindowIsTheTailOfWhatRanBefore(t *testing.T) {
	ev := []event{at(90, "a"), at(150, "b"), at(200, "c"), at(250, "d")}
	if code, out := idle(t, ev, opts()); code != 0 {
		t.Fatalf("status %d, want 0:\n%s", code, out)
	}
}

// The defaults are what the recipe and the requirement need: a window of 180 s, 3 records at most, and a wait that is longer
// than the tail of a smoke (a seal, the indexer catching up, a grant asked for again, about 50 s).
func TestTheDefaultsWaitForTheTailOfTheSmokes(t *testing.T) {
	if defaultIdleWindow != 180*time.Second || idleBound(defaultIdleWindow) != 3 {
		t.Fatalf("the default window is %v with a bound of %d", defaultIdleWindow, idleBound(defaultIdleWindow))
	}
	if defaultIdleAfter < time.Minute {
		t.Fatalf("the default wait is %v, shorter than the tail of a smoke", defaultIdleAfter)
	}
	// A tail that ends 55 s after the check began is not counted with the defaults.
	var tail []event
	for i := range 8 {
		tail = append(tail, at(float64(5+i*7), "tail"))
	}
	if code, out := idle(t, tail, idleOptions{Window: defaultIdleWindow, After: defaultIdleAfter}); code != 0 {
		t.Fatalf("status %d with the default wait:\n%s", code, out)
	}
}

// The log comes in pages of 200 at most. A window of 4 records over two pages of 2 is 4, and a check that read the first
// page only would count 2 and pass. The flood in the second page is found as well.
func TestEveryPageOfTheLogIsRead(t *testing.T) {
	ev := []event{at(100, "a"), at(150, "b"), at(200, "c"), at(250, "d")}
	if code, out := idlePaged(t, ev, opts(), 2); code != 1 || !strings.Contains(out, "4 record(s) in 3m0s") {
		t.Fatalf("status %d, want 1 for 4 records over two pages:\n%s", code, out)
	}
	// 3 records over two pages pass, and the run holds all of them.
	if code, out := idlePaged(t, ev[:3], opts(), 2); code != 0 || !strings.Contains(out, "the run holds 3 record(s)") {
		t.Fatalf("status %d, want 0 for 3 records over two pages:\n%s", code, out)
	}
}

// folded is a summary record of key@'s limiter: the calls of a minute past the first 10, counted in one.
func folded(sec float64, n int) event {
	return event{at: t0.Add(time.Duration(sec * float64(time.Second))), action: "key.refuse", status: "open", actor: "key@dev",
		fields: map[string]any{"caller": "exchange", "op": "open", "code": "permission_denied", "suppressed": n, "window_s": 60}}
}

// verifies: REQ-AUDIT-180
// The regression that a window cannot see. exchange's check opens an envelope at key@ every 5 s and key@ refuses it. The
// shape of the log is the one measured (2026-11-07): 10 facts in the first minute, a summary of 2 at the end of each of the
// next minutes, and then nothing, because key@ limits a caller and a reason to 60 facts an hour and counts the rest into the
// summary of the hour's end. The check starts 8 minutes after the first refusal (a job that is slower than CI, or a re-run on a stack that has been up), and its window is empty; the summaries
// in the run fail it.
func TestAKeyOpenRefusedEveryFiveSecondsFailsEvenWhenItsFactsHaveStopped(t *testing.T) {
	start := -480.0 // the first refusal is 8 minutes before the check began
	ev := []event{at(start-60, "key.start"), at(start-50, "signer.sign")}
	for i := range 10 {
		e := folded(start+float64(i*5), 0)
		e.fields = map[string]any{"caller": "exchange", "op": "open", "purpose": "chain", "code": "permission_denied"}
		ev = append(ev, e)
	}
	for m := 1; m <= 5; m++ {
		ev = append(ev, folded(start+float64(m*60), 2))
	}
	code, out := idle(t, ev, idleOptions{Window: 180 * time.Second, After: 90 * time.Second, Expect: []string{"key.start", "signer.sign"}})
	if code != 1 {
		t.Fatalf("status %d, want 1:\n%s", code, out)
	}
	for _, want := range []string{"idle: 0 record(s) in 3m0s", "5 summary record(s) in the run carry 10 call(s)", "key.refuse", "caller=exchange op=open", "a flood of refusals was folded"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
}

// A run with the same records and no summary passes: the facts of a start-up and a few refusals are not a flood.
func TestARunWithNoSummaryAndAFewRefusalsPasses(t *testing.T) {
	ev := []event{at(-500, "key.start"), at(-490, "signer.sign"), folded(-400, 0), folded(-300, 0)}
	code, out := idle(t, ev, idleOptions{Window: 180 * time.Second, After: 90 * time.Second, Expect: []string{"key.start", "signer.sign"}})
	if code != 0 {
		t.Fatalf("status %d:\n%s", code, out)
	}
}

// The control. A 0 in the window means that the installation was quiet only if the front shows what it did before: a run
// that lacks the records the caller expects, or has none, fails.
func TestACountOfZeroNeedsTheRecordsOfTheRun(t *testing.T) {
	ev := []event{at(-500, "key.start")}
	if code, out := idle(t, ev, idleOptions{Window: 180 * time.Second, After: 90 * time.Second, Expect: []string{"key.start", "signer.sign"}}); code != 1 ||
		!strings.Contains(out, "no record of signer.sign") {
		t.Fatalf("status %d, want 1 for a run without the smoke's records:\n%s", code, out)
	}
	if code, out := idle(t, nil, opts()); code != 1 || !strings.Contains(out, "shows no record of the run") {
		t.Fatalf("status %d, want 1 for an empty front:\n%s", code, out)
	}
}

func TestTheListOfExpectedActions(t *testing.T) {
	if got := splitList(" key.start, ,signer.sign,"); len(got) != 2 || got[0] != "key.start" || got[1] != "signer.sign" {
		t.Fatalf("%q", got)
	}
}
