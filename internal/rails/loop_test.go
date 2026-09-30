package rails_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/rails"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// An interval that is not positive is refused rather than spun on.
func TestRunNeedsAnInterval(t *testing.T) {
	t.Parallel()
	err := rails.Run(context.Background(), quiet(), rails.Pacing{}, func(context.Context) bool { return false })
	if err == nil {
		t.Fatal("Run accepted a zero interval")
	}
}

// A pass that met another policy is tried again at once-ish, the first
// pass plus PolicyRetries retries, then left to the interval.
func TestRunRetriesAnotherPolicyABoundedNumberOfTimes(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		done <- rails.Run(ctx, quiet(), rails.Pacing{Interval: time.Hour, PolicyRetry: time.Millisecond},
			func(context.Context) bool { calls.Add(1); return true })
	}()
	for deadline := time.Now().Add(10 * time.Second); calls.Load() < rails.PolicyRetries+1; {
		if time.Now().After(deadline) {
			t.Fatalf("only %d passes", calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	if got := calls.Load(); got != rails.PolicyRetries+1 {
		t.Errorf("%d passes, want a first and %d retries", got, rails.PolicyRetries)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Run ended with %v, want the context's error", err)
	}
}

// A pass under the same policy waits out the interval, and a retry streak
// starts over after one.
func TestRunWaitsTheIntervalWhenThePolicyAgrees(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = rails.Run(ctx, quiet(), rails.Pacing{Interval: time.Hour, PolicyRetry: time.Millisecond},
			func(context.Context) bool { calls.Add(1); return false })
	}()
	time.Sleep(100 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Errorf("%d passes inside the interval, want 1", got)
	}
}

// A pass that returns again and again after the context ends is not run.
func TestRunStopsWithItsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int32
	err := rails.Run(ctx, quiet(), rails.Pacing{Interval: time.Millisecond},
		func(context.Context) bool { calls.Add(1); return false })
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Errorf("err=%v calls=%d, want one pass and the context's error", err, calls.Load())
	}
}

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
