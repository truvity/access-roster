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
	l := c.limiter(LimiterConfig{Total: 1 << 20})
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
	l := c.limiter(LimiterConfig{Total: 1 << 20})
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
	l := c.limiter(LimiterConfig{Async: true, Total: 1 << 20})
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

// A flood that spans several windows while the event function is held, with every slot busy: each call is heard or counted,
// and every window's summary is delivered once the function is released (REQ-AUDIT-180). The summaries arrive one after
// the other, so a reader sees the whole count only when the last has come (TestOnRefusedIsRateLimitedAndNeverHoldsTheCaller
// waits for it); none is lost.
func TestLimiterLosesNoCountOverSeveralWindowsWithEverySlotBusy(t *testing.T) {
	c := newCounter()
	c.block = make(chan struct{})
	l := c.limiter(LimiterConfig{Async: true, Burst: 3, Window: time.Second, Hourly: 1 << 20, Total: 1 << 20})
	const windows, perWindow = 12, 500
	for range windows {
		for range perWindow {
			l.Note("a", 1)
		}
		c.advance(2 * time.Second) // the window is over; the next call ends it
	}
	l.Note("a", 1) // ends the last full window
	close(c.block)
	l.Close()
	if want := windows*perWindow + 1; c.total() != want {
		t.Fatalf("%d heard or counted of %d calls (%d heard, %d folded in %d summaries): a count was lost", c.total(), want, c.events, c.folded, len(c.folds))
	}
	if len(c.folds) < windows {
		t.Fatalf("%d summaries for %d windows", len(c.folds), windows)
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

// Past the bound of buckets, the hour state of a key is the overflow key's, and what that state carries is reported when the
// hour is over: the timer is armed for the state in use, not for the key the call named. With two buckets and a cap of
// three facts an hour, the third key floods, its facts stop at the cap, and the timer of the hour reports the rest.
func TestLimiterReportsWhatTheOverflowHourHeldBack(t *testing.T) {
	var mu sync.Mutex
	var events, folded int
	var overflowFolds int
	l := NewLimiter(LimiterConfig{Buckets: 2, Burst: 100, Hourly: 3, Total: 1000, Window: 20 * time.Millisecond},
		func(any) { mu.Lock(); events++; mu.Unlock() },
		func(_ any, f Fold) {
			mu.Lock()
			folded += f.Suppressed
			if f.Overflow {
				overflowFolds++
			}
			mu.Unlock()
		})
	l.hourLen = 300 * time.Millisecond
	l.Note("a", 1)
	l.Note("b", 1)
	for range 50 {
		l.Note("c", 1) // past the two buckets: the shared overflow bucket and its hour state
	}
	time.Sleep(100 * time.Millisecond) // the window of the overflow bucket ends: its summary finds the cap and is carried
	mu.Lock()
	early := folded
	mu.Unlock()
	if early != 0 {
		t.Fatalf("%d folded before the hour is over, want none: the cap of the overflow state was passed", early)
	}
	time.Sleep(400 * time.Millisecond) // the hour is over: the timer reports the carry
	mu.Lock()
	got := events + folded
	of := overflowFolds
	mu.Unlock()
	if got != 52 || of != 1 {
		t.Fatalf("%d reported or counted of 52 calls, %d overflow summaries: the carry of the overflow state was never reported", got, of)
	}
	l.Close()
}

// The whole Limiter makes at most Total facts an hour: past it every key counts into the overflow summary, which the next
// hour reports.
func TestLimiterCapsTheTotalOfAnHourAcrossKeys(t *testing.T) {
	c := newCounter()
	l := c.limiter(LimiterConfig{Total: 20, Burst: 2})
	const calls = 400
	for i := range calls {
		l.Note(fmt.Sprintf("k-%d", i%100), i)
	}
	c.mu.Lock()
	facts := c.events + len(c.folds)
	c.mu.Unlock()
	if facts > 20 {
		t.Fatalf("%d facts in an hour, want at most 20", facts)
	}
	l.Close()
	if c.total() != calls {
		t.Fatalf("%d reported or counted of %d calls", c.total(), calls)
	}
	over := 0
	for _, f := range c.folds {
		if f.Overflow {
			over += f.Suppressed
		}
	}
	if over == 0 {
		t.Fatal("nothing was counted in the overflow summary past the total")
	}
}

// Close takes at most CloseTimeout, however many summaries are pending and however slow the hook is, and a note after it
// is dropped.
func TestLimiterCloseIsBoundedInTime(t *testing.T) {
	l := NewLimiter(LimiterConfig{Burst: 1, Total: 1000, Hourly: 1000, CloseTimeout: 200 * time.Millisecond},
		func(any) {}, func(any, Fold) { time.Sleep(500 * time.Millisecond) })
	for i := range 40 {
		l.Note(fmt.Sprintf("k-%d", i), 1)
		l.Note(fmt.Sprintf("k-%d", i), 1) // one counted for each key: forty summaries of half a second would take 20 s
	}
	began := time.Now()
	l.Close()
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("Close took %v with forty slow summaries, want about its timeout of 200 ms", took)
	}
	l.Note("late", 1) // dropped, not a panic
}

// verifies: REQ-AUDIT-186
// A call after Close is not lost without a trace. With a Late function it is the holder's to report, once for each call and
// with its value, and the limiter does not count it; without one it is dropped and Dropped says how many.
func TestACallAfterCloseIsGivenToLateOrCountedAsDropped(t *testing.T) {
	var late []any
	var events int
	l := NewLimiter(LimiterConfig{Late: func(v any) { late = append(late, v) }}, func(any) { events++ }, nil)
	l.Close()
	for i := range 5 {
		l.Note("k", i)
	}
	if len(late) != 5 || late[0] != 0 || late[4] != 4 || events != 0 || l.Late() != 5 || l.Dropped() != 0 {
		t.Fatalf("late %v events %d Late() %d Dropped() %d, want the 5 calls given to Late, none dropped", late, events, l.Late(), l.Dropped())
	}

	none := NewLimiter(LimiterConfig{}, func(any) { events++ }, nil)
	none.Close()
	for range 7 {
		none.Note("k", 1)
	}
	if none.Dropped() != 7 || none.Late() != 0 || events != 0 {
		t.Fatalf("Dropped() %d Late() %d events %d, want 7 dropped and none reported", none.Dropped(), none.Late(), events)
	}

	// A panic in Late ends nothing.
	boom := NewLimiter(LimiterConfig{Late: func(any) { panic("late") }}, func(any) {}, nil)
	boom.Close()
	boom.Note("k", 1)
	if boom.Late() != 1 {
		t.Fatalf("Late() %d", boom.Late())
	}
}

// verifies: REQ-AUDIT-186
// The guard's limiter passes a refusal that reaches it after the server stopped to the holder's hook: the request that was
// still running when the server stopped is a fact, not a count that is dropped.
func TestAGuardRefusalAfterTheServerStoppedReachesTheHook(t *testing.T) {
	var got []Refused
	var mu sync.Mutex
	l := newRefusalLimiter(ServerConfig{Actor: "key", OnRefused: func(r Refused) { mu.Lock(); got = append(got, r); mu.Unlock() }})
	l.Close()
	l.Note("1/true/caller", Refused{Reason: "caller", Peer: Peer{Name: "exchange", UID: 61003}, Known: true, Procedure: "/p"})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Reason != "caller" || got[0].Peer.Name != "exchange" || got[0].Suppressed != 0 {
		t.Fatalf("the hook got %+v, want the refusal as it was", got)
	}
	if l.Dropped() != 0 {
		t.Fatalf("Dropped() = %d", l.Dropped())
	}
}
