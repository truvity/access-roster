// Package backoff is the restart back-off of the executables of sluis, kept in the program and not in the unit (owner decision
// 24 A, 2026-11-09). A generated unit has Restart=on-failure and RestartSec=2s and no start limit (REQ-DEPLOY-044), and the
// systemd of Amazon Linux 2023 (252) does not know RestartSteps= and RestartMaxDelaySec= (254), so a unit that fails would
// restart every 2 s for ever there. So a program that is about to exit with a failure under systemd first sleeps 2, 4, 8, 16,
// 30, 30 ... seconds, by the count of failures in a row that it keeps in a small file, and the same unit then behaves the same on
// every systemd.
//
// The file is the one the unit names in SLUIS_RESTART_FILE, in a directory the unit already writes (its run directory), per
// instance and per unit. Outside systemd (neither INVOCATION_ID nor NOTIFY_SOCKET is set), or with no file named, a Guard is nil and
// every method of a nil Guard does nothing: the program exits at once, as it always did. The count is reset when the program
// has run for Healthy without failing, or exits cleanly. The sleep ends at once when its context is cancelled (SIGTERM).
//
// During the sleep the process is "active (running)" to systemd and its restart count does not move, so a deploy that waits for
// units to stand still would take a failing unit for a settled one. So the file says it: "N wait" while the process sleeps
// before its exit, and plain "N" once a process has started (Begin). A unit whose file says "wait" has not settled
// (deploy/boards/remote-lib.sh, settle_units).
package backoff

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// EnvFile names the file that holds the count of failures in a row, as the unit sets it.
	EnvFile = "SLUIS_RESTART_FILE"
	// Base is the sleep after the first failure; each failure after it doubles the sleep, up to Cap.
	Base = 2 * time.Second
	// Cap is the longest sleep. It is below the deploy's wait (60 s), so a unit that waited for an unlock comes up within
	// Cap of it.
	Cap = 30 * time.Second
	// Healthy is how long a program must run without failing for the count to be forgotten.
	Healthy = 60 * time.Second

	// waitMark follows the count in the file while the process sleeps before its exit.
	waitMark = "wait"
	// maxCount bounds what is read from the file and written to it; the delay is Cap long before.
	maxCount = 1000
)

// Delay is the sleep after the failures-th failure in a row (the first is 1): 2, 4, 8, 16, 30, 30 ... seconds.
func Delay(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	d := Base
	for i := 1; i < failures && d < Cap; i++ {
		d *= 2
	}
	return min(d, Cap)
}

// Clock is the time the guard uses, so that a test needs no wall clock.
type Clock interface {
	Now() time.Time
	// Sleep waits d, or until ctx is done, and reports whether the whole wait passed.
	Sleep(ctx context.Context, d time.Duration) bool
	// AfterFunc runs f once d has passed. The returned stop prevents it and reports whether it did (false: f has run).
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// SystemClock is the wall clock.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// Sleep implements Clock.
func (SystemClock) Sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// AfterFunc implements Clock.
func (SystemClock) AfterFunc(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }

// UnderSystemd reports whether the environment says the process was started by systemd: INVOCATION_ID is set on every unit,
// and NOTIFY_SOCKET on one that is notified.
func UnderSystemd(getenv func(string) string) bool {
	return getenv("INVOCATION_ID") != "" || getenv("NOTIFY_SOCKET") != ""
}

// Guard keeps the count of failures in a row of one unit instance. A nil Guard does nothing.
type Guard struct {
	file  string
	clock Clock

	mu      sync.Mutex
	started time.Time
	stop    func() bool
}

// New returns the guard of the process, or nil when it is not under systemd or the unit names no file (a nil Guard exits at
// once). A nil clock is the wall clock.
func New(getenv func(string) string, clock Clock) *Guard {
	file := getenv(EnvFile)
	if file == "" || !UnderSystemd(getenv) {
		return nil
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &Guard{file: file, clock: clock}
}

// Begin marks the start of the service. Once it has run for Healthy the count is forgotten, even if the process is later killed
// without a chance to call Done or Failed.
func (g *Guard) Begin() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.started = g.clock.Now()
	g.stop = g.clock.AfterFunc(Healthy, func() { forget(g.file) })
	if n, wait := load(g.file); wait {
		store(g.file, n, false) // the process before this one slept and exited; this one is running
	}
}

// Done records a clean exit: the count is forgotten.
func (g *Guard) Done() {
	if g == nil {
		return
	}
	g.cancelTimer()
	forget(g.file)
}

// Failed is called when the process is about to exit with a failure. A process that ran for Healthy has no start problem: the
// count is forgotten and it exits at once. Otherwise the failure is counted, and the process sleeps Delay(count) unless ctx is
// done (a stop must not wait). It returns the time it slept, or would have slept when ctx ended it.
func (g *Guard) Failed(ctx context.Context) time.Duration {
	if g == nil {
		return 0
	}
	g.cancelTimer()
	g.mu.Lock()
	ran := g.clock.Now().Sub(g.started)
	started := !g.started.IsZero()
	g.mu.Unlock()
	if started && ran >= Healthy {
		forget(g.file)
		return 0
	}
	prev, _ := load(g.file)
	n := min(prev+1, maxCount)
	store(g.file, n, true)
	d := Delay(n)
	if ctx.Err() != nil {
		return 0
	}
	slog.Warn("exiting with a failure; waiting before the restart", "failures_in_a_row", n, "wait", d.String())
	g.clock.Sleep(ctx, d)
	return d
}

func (g *Guard) cancelTimer() {
	g.mu.Lock()
	stop := g.stop
	g.stop = nil
	g.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// load reads the count and whether the file says "wait"; a missing, unreadable, odd or non-regular file is 0.
func load(file string) (n int, wait bool) {
	fi, err := os.Lstat(file)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > 16 {
		return 0, false
	}
	b, err := os.ReadFile(file) //nolint:gosec // the unit names the file
	if err != nil {
		return 0, false
	}
	count, mark, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	n, err = strconv.Atoi(count)
	if err != nil || n < 0 || (mark != "" && mark != waitMark) {
		return 0, false
	}
	return min(n, maxCount), mark == waitMark
}

// store writes the count by a rename, so a reader never sees half a file. A failure is not an error: the back-off is a
// courtesy to the journal, and a program that cannot write its count must still exit.
func store(file string, n int, wait bool) {
	tmp := file + ".tmp"
	_ = os.Remove(tmp)                                                   // a leftover, or a link put there: O_EXCL below never follows one
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // the unit names the file
	if err != nil {
		slog.Debug("restart count: not written", "err", err)
		return
	}
	text := strconv.Itoa(n)
	if wait {
		text += " " + waitMark
	}
	_, werr := f.WriteString(text + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, file)
	}
	if werr != nil {
		_ = os.Remove(tmp)
		slog.Debug("restart count: not written", "err", werr)
	}
}

func forget(file string) { _ = os.Remove(file) }
