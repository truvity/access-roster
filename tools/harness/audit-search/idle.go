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

// runIdle waits, counts the records of one window and returns the exit status: 0 within the bound,
// 1 over it or when the log could not be read.
func runIdle(c *http.Client, host string, tenants []string, o idleOptions, clk clock, w io.Writer) int {
	_, _ = fmt.Fprintf(w, "idle: waiting %s for the tail of what ran before, then counting for %s\n", o.After, o.Window)
	clk.Sleep(o.After)
	from := clk.Now()
	to := from.Add(o.Window)
	clk.Sleep(o.Window + idleLag)
	hits, err := search(c, host, request{Tenants: tenants, FromMs: strconv.FormatInt(from.UnixMilli(), 10)}, idleMaxRecords)
	if err != nil {
		_, _ = fmt.Fprintf(w, "idle: %v\n", err)
		return 1
	}
	var in []hit
	for _, h := range hits {
		ms, _ := strconv.ParseInt(h.TimeMs, 10, 64)
		if t := time.UnixMilli(ms); t.After(from) && !t.After(to) {
			in = append(in, h)
		}
	}
	hits = in
	bound := idleBound(o.Window)
	_, _ = fmt.Fprintf(w, "idle: %d record(s) in %s from %s (the bound of %d an hour allows %d)\n", len(hits), o.Window, from.UTC().Format("15:04:05"), idlePerHour, bound)
	if len(hits) > 0 {
		printGroups(w, countGroups(hits), len(hits))
	}
	if len(hits) > bound {
		_, _ = fmt.Fprintf(w, "idle: FAILED: %d record(s) in %s is a rate of %d an hour, over %d (REQ-AUDIT-180)\n", len(hits), o.Window, int64(len(hits))*int64(time.Hour)/int64(o.Window), idlePerHour)
		return 1
	}
	_, _ = fmt.Fprintln(w, "idle: ok")
	return 0
}
