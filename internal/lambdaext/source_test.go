package lambdaext_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/lambdaext"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	src       *lambdaext.Source
	clk       *clock
	subjects  atomic.Int32
	exchanges atomic.Int32
	failNext  atomic.Bool
	logs      []string
	logMu     sync.Mutex
}

func newHarness(ttl time.Duration) *harness {
	h := &harness{clk: &clock{t: time.Unix(1_800_000_000, 0)}}
	h.src = &lambdaext.Source{
		Now: h.clk.now,
		Subject: func(context.Context) (string, error) {
			return fmt.Sprintf("subject-%d", h.subjects.Add(1)), nil
		},
		Exchange: func(_ context.Context, subject string) (string, time.Duration, error) {
			n := h.exchanges.Add(1)
			if h.failNext.Load() {
				return "", 0, errors.New("issuer down")
			}
			return fmt.Sprintf("tok-%d(%s)", n, subject), ttl, nil
		},
		Logf: func(f string, a ...any) {
			h.logMu.Lock()
			h.logs = append(h.logs, fmt.Sprintf(f, a...))
			h.logMu.Unlock()
		},
	}
	return h
}

func TestTokenIsCachedUntilItsRefreshWindow(t *testing.T) {
	h := newHarness(15 * time.Minute) // refresh at 10 minutes
	ctx := context.Background()
	first, err := h.src.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.clk.advance(9 * time.Minute)
	again, _ := h.src.Token(ctx)
	if again != first || h.exchanges.Load() != 1 {
		t.Fatalf("expected the cached token, got %q after %d exchanges", again, h.exchanges.Load())
	}
	h.clk.advance(2 * time.Minute) // inside the window, token still valid
	fresh, _ := h.src.Token(ctx)
	if fresh == first || h.exchanges.Load() != 2 {
		t.Fatalf("expected a refreshed token, got %q after %d exchanges", fresh, h.exchanges.Load())
	}
}

func TestRefreshHappensAfterAFreeze(t *testing.T) {
	// Lambda freezes the environment: no timer runs, the clock just jumps.
	h := newHarness(15 * time.Minute)
	first, _ := h.src.Token(context.Background())
	h.clk.advance(3 * time.Hour)
	later, err := h.src.Token(context.Background())
	if err != nil || later == first {
		t.Fatalf("a token expired during a freeze must be replaced on demand: %q %v", later, err)
	}
}

func TestConcurrentCallersShareOneRefresh(t *testing.T) {
	h := newHarness(time.Hour)
	gate := make(chan struct{})
	inner := h.src.Subject
	h.src.Subject = func(ctx context.Context) (string, error) { <-gate; return inner(ctx) }

	var wg sync.WaitGroup
	got := make([]string, 20)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = h.src.Token(context.Background())
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	if h.subjects.Load() != 1 || h.exchanges.Load() != 1 {
		t.Fatalf("expected one STS call and one exchange, got %d and %d", h.subjects.Load(), h.exchanges.Load())
	}
	for _, g := range got {
		if g != got[0] || g == "" {
			t.Fatalf("callers disagree: %v", got)
		}
	}
}

func TestFailureIsRefusedBacksOffAndLogsOncePerWindow(t *testing.T) {
	h := newHarness(time.Hour)
	h.failNext.Store(true)
	for range 5 {
		if _, err := h.src.Token(context.Background()); err == nil {
			t.Fatal("expected an error with no token")
		}
	}
	if h.exchanges.Load() != 1 {
		t.Fatalf("retries inside the backoff must not reach the issuer, got %d", h.exchanges.Load())
	}
	h.clk.advance(10 * time.Second)
	_, _ = h.src.Token(context.Background())
	if h.exchanges.Load() != 2 || len(h.logs) != 1 {
		t.Fatalf("one retry after the backoff, one log line: %d exchanges, logs %v", h.exchanges.Load(), h.logs)
	}
	h.failNext.Store(false)
	h.clk.advance(10 * time.Second)
	if _, err := h.src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(h.logs) != 2 || !strings.Contains(h.logs[1], "again") {
		t.Fatalf("recovery is logged once: %v", h.logs)
	}
}

func TestAStillValidTokenIsUsedWhenRefreshFails(t *testing.T) {
	h := newHarness(15 * time.Minute)
	first, _ := h.src.Token(context.Background())
	h.clk.advance(11 * time.Minute) // in the window, valid for 4 more
	h.failNext.Store(true)
	got, err := h.src.Token(context.Background())
	if err != nil || got != first {
		t.Fatalf("want the old token, got %q %v", got, err)
	}
	h.clk.advance(10 * time.Minute) // expired
	if _, err = h.src.Token(context.Background()); err == nil {
		t.Fatal("an expired token must not be used")
	}
}

func TestInvalidateForcesAFreshToken(t *testing.T) {
	h := newHarness(time.Hour)
	first, _ := h.src.Token(context.Background())
	h.src.Invalidate(first)
	next, _ := h.src.Token(context.Background())
	if next == first {
		t.Fatal("an invalidated token was handed out again")
	}
	h.src.Invalidate("some-other-token") // not the cached one: no effect
	if again, _ := h.src.Token(context.Background()); again != next {
		t.Fatal("invalidating a stale token must not drop the current one")
	}
}

func TestOnTokenSeesEachNewToken(t *testing.T) {
	h := newHarness(15 * time.Minute)
	var seen []string
	h.src.OnToken = func(tok string) { seen = append(seen, tok) }
	_, _ = h.src.Token(context.Background())
	_, _ = h.src.Token(context.Background())
	h.clk.advance(11 * time.Minute)
	_, _ = h.src.Token(context.Background())
	if len(seen) != 2 {
		t.Fatalf("OnToken fires per mint, got %v", seen)
	}
}
