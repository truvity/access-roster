package exports

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/rails"
)

// Pacing of the attempts, as defaults a test replaces.
const (
	// DefaultSettle is how long after a change the export waits for more
	// changes before it copies: a console action writes several keys.
	DefaultSettle = 2 * time.Second
	// DefaultMinGap is the least between the starts of two attempts of one
	// export that a change causes. A person's link rotates its tokens on every
	// refresh, and a copy of every one of them is not worth the writes.
	DefaultMinGap = 30 * time.Second
	// DefaultBackoff and DefaultMaxBackoff bound the wait after a failure,
	// which doubles from the first to the second.
	DefaultBackoff    = 5 * time.Second
	DefaultMaxBackoff = 5 * time.Minute
	// attemptTimeout bounds one attempt: a store that hangs is a store that
	// is down, and the lease must not be held for it.
	attemptTimeout = 2 * time.Minute
	// stagger spreads the first attempts of a restart, so that every export
	// is not a login at once.
	stagger = 10 * time.Second
)

// Runner makes the copies and keeps them current.
type Runner struct {
	Specs   []Spec
	Sources Sources
	Export  port.Export
	// State is the State port: where the exactly-one-writer lease is taken
	// and where a change to a source is watched.
	State port.State
	// Leases takes the per-export lease; its State is [Runner.State]'s.
	Leases *rails.Leases
	Log    *slog.Logger

	Settle, MinGap, Backoff, MaxBackoff time.Duration
	// NoStagger starts every export at once, for a test.
	NoStagger bool
}

func (r *Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func pick(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// Run makes every export once at start, again when its source changes, and
// again every interval, until ctx ends. One failing export never delays
// another: each has its own worker. It returns nil: an export is never a
// reason for the service to stop.
func (r *Runner) Run(ctx context.Context) error {
	if len(r.Specs) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	wakes := make([]chan struct{}, len(r.Specs))
	for i := range r.Specs {
		wakes[i] = make(chan struct{}, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.work(ctx, r.Specs[i], wakes[i])
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.watch(ctx, wakes)
	}()
	r.log().InfoContext(ctx, "exports are running: each copies a secret out of the service, asynchronously, and none is a dependency",
		"exports", len(r.Specs))
	wg.Wait()
	return nil
}

// work is one export's loop.
func (r *Runner) work(ctx context.Context, spec Spec, wake <-chan struct{}) {
	first := time.Duration(0)
	if !r.NoStagger {
		first = rand.N(stagger) //nolint:gosec // a spread, not a secret
	}
	failures := 0
	next := time.NewTimer(first)
	defer next.Stop()
	var lastStart time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-next.C:
		case <-wake:
			// A change: let the console action finish writing, and not copy
			// more often than the gap, whatever the changes arrive at.
			if !sleep(ctx, pick(r.Settle, DefaultSettle)) {
				return
			}
			if wait := pick(r.MinGap, DefaultMinGap) - time.Since(lastStart); !lastStart.IsZero() && wait > 0 {
				if !sleep(ctx, wait) {
					return
				}
			}
			drain(wake)
		}
		lastStart = time.Now()
		var wait time.Duration
		if r.attempt(ctx, spec, failures) {
			failures, wait = 0, spec.Interval
		} else {
			failures++
			wait = backoff(pick(r.Backoff, DefaultBackoff), pick(r.MaxBackoff, DefaultMaxBackoff), failures)
		}
		if !next.Stop() {
			select {
			case <-next.C:
			default:
			}
		}
		next.Reset(wait)
	}
}

// attempt makes one copy under the export's lease and reports whether it is
// done: made, found already made, nothing to copy, or being made by another
// replica. False is a failure, to be retried with backoff.
func (r *Runner) attempt(ctx context.Context, spec Spec, failures int) (done bool) {
	done = true
	ran, err := r.Leases.Do(ctx, KindExport, spec.Name, func(held context.Context) {
		done = r.once(held, spec, failures)
	})
	switch {
	case err != nil:
		// The lease could not be taken at all: the State is down. Nothing was
		// attempted, and nothing is claimed to have been.
		meters.attempts.Add(context.WithoutCancel(ctx), 1, attemptAttrs(spec.Name, OutcomeFailed))
		r.log().WarnContext(ctx, "an export could not take its lease, so the copy is stale; trying again",
			"export", spec.Name, "error", err)
		return false
	case !ran:
		meters.contended.Add(ctx, 1, nameAttr(spec.Name))
	}
	return done
}

func (r *Runner) once(ctx context.Context, spec Spec, failures int) bool {
	ctx, end := start(ctx, spec.Name)
	ctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	properties, found, err := r.Sources.Read(ctx, spec)
	switch {
	case err != nil:
		end(OutcomeFailed)
		r.log().WarnContext(ctx, "an export could not read its source, so the copy is stale; trying again",
			"export", spec.Name, "target", spec.Target.String(), "attempt", failures+1, "error", err)
		return false
	case !found:
		end(OutcomeSkipped)
		r.log().DebugContext(ctx, "an export has nothing to copy yet", "export", spec.Name)
		return true
	}
	if err = r.Export.Put(ctx, spec.Target, properties, spec.Mode()); err != nil {
		end(OutcomeFailed)
		// The target and the properties' names, never a value.
		r.log().WarnContext(ctx, "an export failed, so the copy is stale; trying again",
			"export", spec.Name, "target", spec.Target.String(), "mode", spec.Mode().String(),
			"attempt", failures+1, "error", err)
		return false
	}
	end(OutcomeOK)
	if failures > 0 {
		r.log().InfoContext(ctx, "an export is made again after failing", "export", spec.Name, "target", spec.Target.String())
	}
	return true
}

// watch wakes the exports whose source changed. A watch that ends, or fails,
// is made again with backoff and wakes every export, since what changed while
// it was down is not known.
func (r *Runner) watch(ctx context.Context, wakes []chan struct{}) {
	prefixes := map[string][]int{}
	for i := range r.Specs {
		for _, prefix := range r.Specs[i].Prefixes() {
			prefixes[prefix] = append(prefixes[prefix], i)
		}
	}
	var wg sync.WaitGroup
	for prefix, who := range prefixes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.watchPrefix(ctx, prefix, who, wakes)
		}()
	}
	wg.Wait()
}

func (r *Runner) watchPrefix(ctx context.Context, prefix string, who []int, wakes []chan struct{}) {
	failures := 0
	for ctx.Err() == nil {
		events, err := r.State.Watch(ctx, prefix)
		switch {
		case errors.Is(err, port.ErrUnsupported):
			r.log().InfoContext(ctx, "this State cannot be watched, so a change to a source is copied at the next interval, not at once",
				"prefix", prefix)
			return
		case err != nil:
			failures++
			r.log().WarnContext(ctx, "an export's watch of the State could not start; trying again", "prefix", prefix, "error", err)
			if !sleep(ctx, backoff(DefaultBackoff, DefaultMaxBackoff, failures)) {
				return
			}
			continue
		}
		if failures > 0 {
			for _, i := range who {
				poke(wakes[i])
			}
		}
		failures = 0
		for event := range events {
			if event.Err != nil {
				r.log().WarnContext(ctx, "an export's watch of the State failed; watching again", "prefix", prefix, "error", event.Err)
				failures = 1
				break
			}
			for _, i := range who {
				poke(wakes[i])
			}
		}
		if ctx.Err() == nil {
			failures++
			if !sleep(ctx, backoff(DefaultBackoff, DefaultMaxBackoff, failures)) {
				return
			}
		}
	}
}

// Describe is one line per export for the log at start: what is copied and
// where, never a value.
func Describe(specs []Spec) []string {
	out := make([]string, 0, len(specs))
	for i := range specs {
		s := &specs[i]
		out = append(out, fmt.Sprintf("%s -> %s (%s, every %s)", s.Name, s.Target, s.Mode(), s.Interval))
	}
	return out
}

func poke(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func drain(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// backoff doubles from base for each failure, capped, with up to a fifth
// taken off at random so that replicas do not retry in step.
func backoff(base, limit time.Duration, failures int) time.Duration {
	d := base
	for i := 1; i < failures && d < limit; i++ {
		d *= 2
	}
	d = min(d, limit)
	return d - rand.N(d/5+1) //nolint:gosec // a spread, not a secret
}
