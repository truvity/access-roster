package rpc

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// counter collects what a Limiter reports, with a clock the test moves.
type counter struct {
	mu       sync.Mutex
	events   int
	folded   int
	folds    []Fold
	now      time.Time
	inflight atomic.Int64
	most     atomic.Int64
	block    chan struct{}
}

func newCounter() *counter { return &counter{now: time.Unix(1_800_000_000, 0)} }

func (c *counter) limiter(cfg LimiterConfig) *Limiter {
	l := NewLimiter(cfg, func(any) {
		c.enter()
		defer c.inflight.Add(-1)
		c.mu.Lock()
		c.events++
		c.mu.Unlock()
	}, func(_ any, f Fold) {
		c.enter()
		defer c.inflight.Add(-1)
		c.mu.Lock()
		c.folded += f.Suppressed
		c.folds = append(c.folds, f)
		c.mu.Unlock()
	})
	l.now = func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
	return l
}

func (c *counter) enter() {
	n := c.inflight.Add(1)
	for {
		m := c.most.Load()
		if n <= m || c.most.CompareAndSwap(m, n) {
			break
		}
	}
	if c.block != nil {
		<-c.block
	}
}

func (c *counter) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func (c *counter) total() int { c.mu.Lock(); defer c.mu.Unlock(); return c.events + c.folded }

// A key reports its burst and counts the rest; the count is reported when the window is over, whether the next call comes
// or the timer fires; and no call is lost.
func TestLimiterReportsTheBurstAndCountsTheRest(t *testing.T) {
	c := newCounter()
	l := c.limiter(LimiterConfig{Burst: 3})
	for range 100 {
		l.Note("a", 1)
	}
	if c.events != 3 || c.folded != 0 {
		t.Fatalf("events %d folded %d, want 3 and none before the window ends", c.events, c.folded)
	}
	c.advance(DefaultWindow + time.Second)
	l.Note("a", 1) // the first call of the next window reports the end of the last
	if c.events != 4 || c.folded != 97 {
		t.Fatalf("events %d folded %d, want 4 and 97", c.events, c.folded)
	}
	l.Close()
	if c.total() != 101 {
		t.Fatalf("%d reported or counted of 101 calls", c.total())
	}
}

// The number of keys counted apart is bounded: past it a key is counted in one shared bucket, whose summary names nobody.
func TestLimiterBoundsItsBucketsAndNamesNobodyInTheOverflow(t *testing.T) {
	c := newCounter()
	l := c.limiter(LimiterConfig{})
	const keys = 1000
	for i := range keys {
		l.Note(fmt.Sprintf("uid-%d", i), i)
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > 256+1 {
		t.Fatalf("%d buckets for %d keys, want at most %d and the overflow", n, keys, 256)
	}
	// 256 keys were heard once each; the overflow bucket heard its burst of 10 of the other 744.
	if c.events != 256+10 {
		t.Fatalf("%d events, want %d", c.events, 256+10)
	}
	l.Close()
	if c.total() != keys {
		t.Fatalf("%d reported or counted of %d calls", c.total(), keys)
	}
	if len(c.folds) != 1 || !c.folds[0].Overflow || c.folds[0].Suppressed != keys-256-10 {
		t.Fatalf("folds %+v, want one overflow summary of %d", c.folds, keys-256-10)
	}
}

// A full table is swept of the buckets whose window is over and that count nothing, so a new key is not put in the overflow
// for ever.
func TestLimiterSweepsEndedBucketsWhenFull(t *testing.T) {
	c := newCounter()
	l := c.limiter(LimiterConfig{})
	for i := range 256 {
		l.Note(fmt.Sprintf("old-%d", i), i)
	}
	c.advance(DefaultWindow + time.Second)
	l.Note("new", 0)
	l.mu.Lock()
	_, own := l.buckets["new"]
	_, over := l.buckets[overflowKey]
	n := len(l.buckets)
	l.mu.Unlock()
	if !own || over || n != 1 {
		t.Fatalf("new key has its own bucket %v, overflow used %v, %d buckets: want its own, no overflow, and 1", own, over, n)
	}
	l.Close()
}

// In the asynchronous mode at most Inflight calls of the event and fold functions run at once, summaries included, and a call
// that finds them busy is counted, not lost.
func TestLimiterRunsAtMostItsInflightCallsAtOnce(t *testing.T) {
	c := newCounter()
	c.block = make(chan struct{})
	l := c.limiter(LimiterConfig{Async: true})
	const calls = 200
	for i := range calls {
		l.Note(fmt.Sprintf("k-%d", i%50), i)
	}
	time.Sleep(50 * time.Millisecond) // let the goroutines start and block
	if m := c.most.Load(); m > 8 {
		t.Fatalf("%d calls at once, want at most %d", m, 8)
	}
	c.advance(DefaultWindow + time.Second)
	for i := range 50 {
		l.Note(fmt.Sprintf("k-%d", i), i) // ends the windows: summaries are made, and wait for a slot
	}
	time.Sleep(50 * time.Millisecond)
	if m := c.most.Load(); m > 8 {
		t.Fatalf("%d calls at once with the summaries, want at most %d", m, 8)
	}
	close(c.block)
	l.Close()
	if c.total() != calls+50 {
		t.Fatalf("%d reported or counted of %d calls", c.total(), calls+50)
	}
	if m := c.most.Load(); m > 8 {
		t.Fatalf("%d calls at once, want at most %d", m, 8)
	}
}

// A key makes at most Hourly facts an hour, however many windows it floods; the rest is carried, and Close reports it.
func TestLimiterCapsTheFactsOfAKeyInAnHour(t *testing.T) {
	c := newCounter()
	l := c.limiter(LimiterConfig{})
	notes := 0
	for range 50 { // 50 minutes, each a window of 100 calls
		for range 100 {
			l.Note("k", 1)
			notes++
		}
		c.advance(DefaultWindow + time.Second)
	}
	c.mu.Lock()
	facts := c.events + len(c.folds)
	c.mu.Unlock()
	if facts > 60 {
		t.Fatalf("%d facts in an hour of floods, want at most %d", facts, 60)
	}
	l.Close()
	if c.total() != notes {
		t.Fatalf("%d reported or counted of %d calls: the carry was lost", c.total(), notes)
	}
}

// A panic in the hook is logged and does not end the process, in a goroutine of the limiter or in Close.
func TestLimiterSurvivesAPanickingHook(_ *testing.T) {
	l := NewLimiter(LimiterConfig{Async: true, Burst: 1}, func(any) { panic("event") }, func(any, Fold) { panic("fold") })
	l.Note("a", 1)
	l.Note("a", 1)
	l.Close()
	s := NewLimiter(LimiterConfig{Burst: 1}, func(any) {}, func(any, Fold) { panic("fold") })
	s.Note("a", 1)
	s.Note("a", 1)
	s.Close() // the fold of the pending count panics inside Close
}
