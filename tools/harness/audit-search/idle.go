package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The idle check of the local installation (REQ-AUDIT-180): an installation with no traffic writes at most 60 audit
// records an hour. It reads the audit log through the audit front, the way a person does, and counts the records whose
// event time lies in one window, which starts a fixed time after the check does, so a record of the start-up, or of a smoke
// that ran before, is not counted, and a recurring record is, whatever its cause. The bound is the hourly bound scaled to the
// window, rounded down, so it never allows more than the requirement does.
//
// A window cannot see everything. key@ limits its refusals for each caller and reason (rpc.Limiter): the first 10 of a minute
// are facts, the rest of the minute one summary with their number, and an hour holds at most 60 facts of a key, after which
// the rest are carried into one summary at the hour's end. A refusal every 5 seconds therefore writes records for about the
// first 5 minutes after it began and none after, and a window that starts later reads 0. So the check also reads the whole
// run: any record that carries a `suppressed` number (a summary) is a flood of refusals that the limiter folded, however long
// ago, and fails the check with the number of calls; an idle installation and the smokes make none. And a check that reads
// nothing proves nothing: the run must hold the records that the caller says it ran (Expect), so that a 0 cannot be "the
// front saw nothing".
//
// The check reads the log once, after the window, and never during the wait: a search is itself audited (entry.search,
// reader.search, and the decision of the grant that the reader asks for, which the writer then seals), so a check that
// searched while it waited for quiet would never find it.
//
// What the check does not measure: the hours of a real board (the boards' own check is the manual one in the requirement),
// and a record that the installation writes less often than once in the window.
const (
	idlePerHour       = 60 // REQ-AUDIT-180
	defaultIdleWindow = 180 * time.Second
	// defaultIdleAfter is how long the check waits before its window starts: the tail of a start-up or of a smoke (a seal,
	// the indexer catching up, a grant that is asked for again) is over by then.
	defaultIdleAfter = 90 * time.Second

	// idleLag is the time that a record needs to appear in a search after its event: the writer seals every 5 s and the
	// indexer follows. The window is read this long after it ends.
	idleLag = 20 * time.Second
	// idleMaxRecords is what one read of the window counts at most; a window that fills it has failed any bound.
	idleMaxRecords = 1000
	// idleRunMax is what the read of the whole run takes at most. The summaries of a flood are among the oldest records of
	// the run, so a read that stopped at the newest ones would miss them: a run past it is reported, not read half.
	idleRunMax = 50000
)

// clock is the time of the check; a test replaces it, so that the check takes no real time.
type clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type realClock struct{}

func (realClock) Now() time.Time        { return time.Now() }
func (realClock) Sleep(d time.Duration) { time.Sleep(d) }

type idleOptions struct {
	Window, After time.Duration
	// Expect are actions that the run must hold, whatever the window says: the control that the front shows records at all.
	Expect []string
}

// idleBound is the number of records that a window of this length may hold: the hourly bound scaled to the window and
// rounded down.
func idleBound(window time.Duration) int {
	return int(int64(idlePerHour) * int64(window) / int64(time.Hour))
}

// group is one kind of record: what wrote it and, for a refusal, what was refused.
type group struct {
	Action, Actor, Status, Detail string
}

func (g group) String() string {
	s := fmt.Sprintf("%-22s %-12s %-12s", g.Action, g.Actor, g.Status)
	if g.Detail != "" {
		s += " " + g.Detail
	}
	return s
}

// sluisFields are the fields of a record's `unmapped.sluis` that say what a refusal was about, in the order they are shown.
var sluisFields = []string{"caller", "kind", "verb", "op", "purpose", "code"}

// groupOf names the group of a hit. The detail is only the closed set of fields above, each a name and never a value of
// the person's.
func groupOf(h hit) group {
	g := group{Action: h.Action, Actor: strings.SplitN(h.ActorUID, "@", 2)[0], Status: h.StatusCode}
	var rec struct {
		Unmapped struct {
			Sluis map[string]any `json:"sluis"`
		} `json:"unmapped"`
	}
	if json.Unmarshal([]byte(h.Record), &rec) != nil {
		return g
	}
	var parts []string
	for _, f := range sluisFields {
		if v, ok := rec.Unmapped.Sluis[f].(string); ok && v != "" {
			parts = append(parts, f+"="+v)
		}
	}
	g.Detail = strings.Join(parts, " ")
	return g
}

func countGroups(hits []hit) map[group]int {
	out := map[group]int{}
	for _, h := range hits {
		out[groupOf(h)]++
	}
	return out
}

// printGroups writes the groups, the most frequent first.
func printGroups(w io.Writer, counts map[group]int, total int) {
	gs := make([]group, 0, len(counts))
	for g := range counts {
		gs = append(gs, g)
	}
	sort.Slice(gs, func(i, j int) bool {
		if counts[gs[i]] != counts[gs[j]] {
			return counts[gs[i]] > counts[gs[j]]
		}
		return gs[i].String() < gs[j].String()
	})
	for _, g := range gs {
		_, _ = fmt.Fprintf(w, "%6d  %s\n", counts[g], g)
	}
	_, _ = fmt.Fprintf(w, "%6d  in all\n", total)
}

// foldedIn is the number of calls that the record says were counted and not reported one by one (`suppressed`), or 0.
func foldedIn(h hit) int64 {
	var rec struct {
		Unmapped struct {
			Sluis struct {
				Suppressed json.Number `json:"suppressed"`
			} `json:"sluis"`
		} `json:"unmapped"`
	}
	if json.Unmarshal([]byte(h.Record), &rec) != nil {
		return 0
	}
	n, err := rec.Unmapped.Sluis.Suppressed.Int64()
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// runIdle waits, reads the log once, and returns the exit status: 0 when the run holds what the caller expects, the window
// holds no more than its share of the hour's bound and no summary of a flood is in the run, 1 otherwise or when the log
// could not be read.
func runIdle(c *http.Client, host string, tenants []string, o idleOptions, clk clock, w io.Writer) int {
	say := func(format string, args ...any) { _, _ = fmt.Fprintf(w, format+"\n", args...) }
	say("idle: waiting %s for the tail of what ran before, then counting for %s", o.After, o.Window)
	clk.Sleep(o.After)
	from := clk.Now()
	to := from.Add(o.Window)
	clk.Sleep(o.Window + idleLag)
	run, err := search(c, host, request{Tenants: tenants}, idleRunMax)
	if err != nil {
		say("idle: %v", err)
		return 1
	}
	failed := false

	// The control: the front shows the run's records, so a 0 below is a 0 of the installation.
	have := map[string]int{}
	for _, h := range run {
		have[h.Action]++
	}
	say("idle: the run holds %d record(s)", len(run))
	if len(run) >= idleRunMax {
		say("idle: FAILED: the run holds %d record(s) or more, past what the check reads; the summaries of a flood may be among the ones it did not read", idleRunMax)
		failed = true
	}
	if len(run) == 0 {
		say("idle: FAILED: the audit front shows no record of the run, so a count of 0 proves nothing")
		failed = true
	}
	for _, a := range o.Expect {
		if have[a] == 0 {
			say("idle: FAILED: the run holds no record of %s, which it must (the control): a count of 0 may mean that the front saw nothing", a)
			failed = true
		}
	}

	// The window.
	var in []hit
	for _, h := range run {
		ms, _ := strconv.ParseInt(h.TimeMs, 10, 64)
		if t := time.UnixMilli(ms); t.After(from) && !t.After(to) {
			in = append(in, h)
		}
	}
	bound := idleBound(o.Window)
	say("idle: %d record(s) in %s from %s (the bound of %d an hour allows %d)", len(in), o.Window, from.UTC().Format("15:04:05"), idlePerHour, bound)
	if len(in) > 0 {
		printGroups(w, countGroups(in), len(in))
	}
	if len(in) > bound {
		say("idle: FAILED: %d record(s) in %s is a rate of %d an hour, over %d (REQ-AUDIT-180)", len(in), o.Window, int64(len(in))*int64(time.Hour)/int64(o.Window), idlePerHour)
		failed = true
	}

	// The whole run: a summary is a flood that the limiter folded, whenever it happened.
	var folded int64
	var floods []hit
	for _, h := range run {
		if n := foldedIn(h); n > 0 {
			folded += n
			floods = append(floods, h)
		}
	}
	if len(floods) > 0 {
		say("idle: %d summary record(s) in the run carry %d call(s) that were folded, not reported one by one:", len(floods), folded)
		printGroups(w, countGroups(floods), len(floods))
		say("idle: FAILED: a flood of refusals was folded in this run (key@ and the transport fold at more than 10 a minute for a caller and a reason), and its facts stop after about 5 minutes, so a window cannot see it (REQ-AUDIT-180)")
		failed = true
	}
	if failed {
		return 1
	}
	say("idle: ok")
	return 0
}
