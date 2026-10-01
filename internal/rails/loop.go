package rails

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// A console answering under another policy is, almost always, a rollout
// still under way: the Service goes on routing some questions to a replica
// on the previous policy until that replica has gone. A pass that met one
// is tried again soon, not after a whole interval — PolicyRetries times,
// each wait twice the last and no longer than PolicyRetryCap, then the
// interval again. A difference that outlasts every retry is not a rollout,
// and asking every few seconds would not end it.
const (
	DefaultPolicyRetry = 5 * time.Second
	PolicyRetryCap     = time.Minute
	PolicyRetries      = 6
)

// Pacing is how often a reconciler passes and how it reacts to a console
// that is mid-rollout.
type Pacing struct {
	// Interval is the time between the starts of two passes. It must be
	// positive.
	Interval time.Duration
	// PolicyRetry is the first wait after a pass that met another policy;
	// each further retry waits twice as long. Zero is [DefaultPolicyRetry].
	PolicyRetry time.Duration
	// Wake, when it receives, ends the wait for the next pass early: the
	// pass runs now and the interval starts over. Nil never wakes it.
	Wake <-chan struct{}
}

// Run calls pass now and then every Interval, until the context ends. A
// pass that reports otherPolicy is tried again soon (see [PolicyRetries]).
func Run(ctx context.Context, log *slog.Logger, p Pacing, pass func(context.Context) (otherPolicy bool)) error {
	if p.Interval <= 0 {
		return errors.New("rails: Run needs a positive interval")
	}
	if p.PolicyRetry <= 0 {
		p.PolicyRetry = DefaultPolicyRetry
	}
	if log == nil {
		log = slog.Default()
	}
	retries := 0
	for {
		started := time.Now()
		otherPolicy := pass(ctx)
		wait := p.Interval - time.Since(started)
		if otherPolicy && retries < PolicyRetries {
			wait = min(p.PolicyRetry<<retries, PolicyRetryCap, p.Interval)
			retries++
			log.InfoContext(ctx, "the console answered under another policy, as it does while a rollout replaces it; passing again soon",
				"in", wait, "retry", retries, "of", PolicyRetries)
		} else {
			retries = 0
		}
		timer := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		case <-p.Wake:
			timer.Stop()
			retries = 0
		}
	}
}
