package writerd

import (
	"log/slog"
	"time"
)

// The wall clock decides two things: what a message may be (not older than 14 days, not ahead of the clock), and
// what the writer may forget. Neither is trusted on a clock the writer has no reason to believe, and the writer does
// not stop for want of one: it accepts and remembers, forgets nothing, and its seal entry says the time checks did
// not run and why (0029, "Sealing"; principle 4: a check that cannot run is reported as not run).

const (
	// clockSlack is how far the wall clock may move against the clock that does not step before it is taken for a
	// step; the kernel's slewing is far less than this in a day.
	clockSlack = time.Hour
	// clockSteady is how long a clock that has stepped must hold its new offset, with the kernel calling it
	// synchronised, before the writer takes it as right again.
	clockSteady = 30 * time.Minute
	// clockWarnEvery is how often the writer says again that the clock is not trusted.
	clockWarnEvery = 10 * time.Minute
)

// The reasons the time checks do not run.
const (
	whyUnobserved     = "unobserved"     // the kernel was not asked or did not answer (adjtimex refused)
	whyUnsynchronised = "unsynchronised" // the kernel says the clock is not synchronised
	whyStepped        = "stepped"        // the wall clock moved against the clock that does not step
)

// clockTrust is the writer's view of its clock for one batch: whether the time checks run and the forgetting is
// allowed, and, when not, why.
type clockTrust struct {
	ok  bool
	why string
}

// timeChecks is how a seal entry says it: {"run": true}, or {"run": false, "why": ...}.
func (c clockTrust) timeChecks() map[string]any {
	if c.ok {
		return map[string]any{"run": true}
	}
	return map[string]any{"run": false, "why": c.why}
}

// clockGate remembers the offset of the wall clock against the clock that does not step. The first call on a clock
// the kernel calls synchronised anchors it; a later offset within clockSlack of the anchor is the same clock, and one
// outside is a step. A step that holds for clockSteady, with the kernel still calling the clock synchronised, becomes
// the new anchor, so a clock stepped by time synchronisation or by an operator is taken as right again without a
// restart of the writer.
type clockGate struct {
	anchored   bool
	anchorMS   int64 // wall less mono when the clock was taken as right
	candidate  bool
	candMS     int64         // the offset of a step being watched
	candSince  time.Duration // on the clock that does not step
	untrusted  bool
	since      time.Duration
	lastWarned time.Duration
}

// clockTrust asks the kernel and compares the wall clock with the clock that does not step.
func (s *Server) clockTrust(now time.Time) clockTrust {
	g, mono := &s.gate, s.mono()
	obs := s.clock()
	off := now.UnixMilli() - mono.Milliseconds()
	var t clockTrust
	switch {
	case !obs.Observed:
		g.anchored, g.candidate = false, false
		t = clockTrust{false, whyUnobserved}
	case !obs.Synced:
		g.anchored, g.candidate = false, false
		t = clockTrust{false, whyUnsynchronised}
	case !g.anchored:
		g.anchored, g.anchorMS, g.candidate = true, off, false
		t = clockTrust{true, ""}
	case max(off-g.anchorMS, g.anchorMS-off) <= clockSlack.Milliseconds():
		g.candidate = false
		t = clockTrust{true, ""}
	default:
		if !g.candidate || max(off-g.candMS, g.candMS-off) > clockSlack.Milliseconds() {
			g.candidate, g.candMS, g.candSince = true, off, mono
		}
		if mono-g.candSince >= clockSteady {
			g.anchorMS, g.candidate = off, false
			t = clockTrust{true, ""}
		} else {
			t = clockTrust{false, whyStepped}
		}
	}
	s.noteTrust(t, mono)
	return t
}

// noteTrust says in the log that the clock is not trusted when it becomes so, again every clockWarnEvery, and when it
// is trusted again, with how long it was not. The writer has no metrics endpoint to count it in.
func (s *Server) noteTrust(t clockTrust, mono time.Duration) {
	g := &s.gate
	switch {
	case !t.ok && !g.untrusted:
		g.untrusted, g.since, g.lastWarned = true, mono, mono
		slog.Warn("the clock is not trusted: nothing is forgotten and no message is refused by its time", "why", t.why)
	case !t.ok && mono-g.lastWarned >= clockWarnEvery:
		g.lastWarned = mono
		slog.Warn("the clock is still not trusted: nothing is forgotten and the state grows", "why", t.why, "for", (mono - g.since).Round(time.Second).String())
	case t.ok && g.untrusted:
		g.untrusted = false
		slog.Info("the clock is trusted again", "after", (mono - g.since).Round(time.Second).String())
	}
}
