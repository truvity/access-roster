//go:build sluis_test

package writerd

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"
)

// retrySim replaces the wait of Run between two streams with a simulated one: it returns at once, moves the clock
// and records the wait. A hook runs at each wait, where a test changes the world.
type retrySim struct {
	clk     *testClock
	mu      sync.Mutex
	waits   []time.Duration
	elapsed time.Duration
	hook    func(elapsed time.Duration)
}

func (r *retrySim) sleep(ctx context.Context, d time.Duration) {
	r.mu.Lock()
	r.waits = append(r.waits, d)
	r.elapsed += d
	el, hook := r.elapsed, r.hook
	r.mu.Unlock()
	r.clk.set(r.clk.now().Add(d))
	if hook != nil {
		hook(el)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Millisecond): // let the stream of the last try end
	}
}

func (r *retrySim) seen() ([]time.Duration, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.waits), r.elapsed
}

// verifies: REQ-AUDIT-180, REQ-AUDIT-183
// key@ is locked: every try that reaches policy is refused ("ask policy for a grant: unavailable: keys"), and is a
// decision and a record. Run backs off from 1 s to 30 s, so a simulated hour is about 124 tries and not 3,600. When
// key@ is unlocked the writer recovers within the wait it is in, 30 s at most, and the first failure after a success
// waits 1 s again.
func TestAWriterWhoseKeyIsLockedBacksOffFromOneSecondToThirtyAndRecoversAtTheNextTry(t *testing.T) {
	clk := &testClock{t: windowStart}
	e := newEnv(t)
	e.cfg.Now, e.cfg.Mono = clk.now, clk.mono
	e.cfg.BatchWindow = time.Millisecond
	sim := &retrySim{clk: clk}
	e.cfg.Sleep = sim.sleep
	setMode := func(mode string) {
		e.pol.mu.Lock()
		e.pol.mode = mode
		e.pol.mu.Unlock()
	}
	setMode("fail")
	em := emitterAt(t, clk.now)
	e.push(messageAt(t, em, "acme", clk.now()))

	var unlocked sync.Once
	var atUnlock int
	sim.hook = func(elapsed time.Duration) {
		if elapsed >= time.Hour {
			unlocked.Do(func() {
				atUnlock = len(e.pol.requests())
				setMode("")
			})
		}
	}
	r := e.start()
	wait(t, "the record to be sealed after the unlock", func() bool { return e.tr.ackedCount() == 1 })

	waits, elapsed := sim.seen()
	if want := []time.Duration{1, 2, 4, 8, 16, 30, 30}; !slices.Equal(waits[:7], mulSeconds(want)) {
		t.Fatalf("the first waits are %v, want 1 s, 2 s, 4 s, 8 s, 16 s, 30 s, 30 s", waits[:7])
	}
	for _, w := range waits {
		if w < time.Second || w > 30*time.Second {
			t.Fatalf("a wait of %v; the waits are between 1 s and 30 s", w)
		}
	}
	// A simulated hour of refusals: 5 tries in the first 31 s and then one every 30 s; the unlock follows the first
	// wait that ends the hour, and the next try succeeds.
	if atUnlock < 118 || atUnlock > 126 {
		t.Fatalf("%d tries reached policy in the hour key@ refused; want about 124 (it was one a second, 3,600)", atUnlock)
	}
	if elapsed < time.Hour || elapsed > time.Hour+30*time.Second {
		t.Fatalf("the unlock was seen after %v of waits; the writer recovers within one wait (30 s) of it", elapsed)
	}
	if got := len(e.pol.requests()); got != atUnlock+1 {
		t.Fatalf("%d decisions, want the %d refused and one that succeeded", got, atUnlock)
	}

	// After the success the next failure is a new one and waits 1 s.
	setMode("fail")
	n := len(waits)
	e.push(messageAt(t, em, "acme", clk.now()))
	clk.set(clk.now().Add(time.Minute)) // the grant of the success has expired, so the new record needs a decision
	wait(t, "a wait after the success", func() bool { w, _ := sim.seen(); return len(w) > n })
	if w, _ := sim.seen(); w[n] != time.Second {
		t.Fatalf("the first wait after a success is %v, want 1 s", w[n])
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}

func mulSeconds(s []time.Duration) []time.Duration {
	out := make([]time.Duration, len(s))
	for i, d := range s {
		out[i] = d * time.Second
	}
	return out
}
