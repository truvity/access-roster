package rpc

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// The defaults of a Limiter.
const (
	DefaultBurst  = 10
	DefaultWindow = time.Minute
	// DefaultHourly is the most facts of one key in an hour: the heard events and the summaries together.
	DefaultHourly = 60
	// DefaultInflight is the number of event calls that may run at once in the asynchronous mode.
	DefaultInflight = 8
	// DefaultBuckets bounds the keys that are counted apart.
	DefaultBuckets = 256
	hour           = time.Hour
)

// Fold is what a summary call says about the calls that were counted and not reported one by one.
type Fold struct {
	// Suppressed is the number of calls of the key that were not reported.
	Suppressed int
	// Window is the length of the window the count was made in.
	Window time.Duration
	// Overflow says that the key is not one key but the shared bucket that takes every key past the bound of buckets. The
	// value of the call is then the latest one of any of them, and names nobody.
	Overflow bool
}

// LimiterConfig sets a Limiter. A zero field is the default.
type LimiterConfig struct {
	Burst    int           // the calls of a key reported one by one in a window
	Window   time.Duration // the length of the window
	Hourly   int           // the most reported calls and summaries of a key in an hour
	Buckets  int           // the keys counted apart
	Inflight int           // the calls of the event function that run at once (Async only)
	// Async runs the event function off the goroutine of Note, in at most Inflight goroutines; a call that finds them all
	// busy is counted. Without it the event function runs in Note, on the caller's goroutine, after the lock is released.
	Async bool
}

// A Limiter turns a stream of calls that must be accounted for (refusals that become audit facts) into a bounded stream: per
// key, the first Burst calls of a Window are passed to the event function one by one, and the rest are counted and reported
// once, by the fold function, at the end of the window. No call is lost: each is either reported or counted in a summary.
// At most Hourly facts (events and summaries) are made for a key in an hour; what the hour has no room for is carried into
// the summary that comes when it has. Memory is bounded by Buckets. A summary is also made, with what is pending, when the
// Limiter is closed. The functions are called with the lock released; a panic in one that runs in a goroutine of the Limiter
// is logged and does not end the process.
type Limiter struct {
	cfg   LimiterConfig
	event func(v any)
	fold  func(v any, f Fold)
	now   func() time.Time
	sem   chan struct{}

	mu      sync.Mutex
	buckets map[string]*bucket
	hours   map[string]*hourState
	gen     uint64
	closed  bool
	wg      sync.WaitGroup
}

type bucket struct {
	start      time.Time
	heard      int
	suppressed int
	last       any
	gen        uint64
	timer      *time.Timer
}

type hourState struct {
	start time.Time
	facts int
	carry int // calls counted in windows whose summary the hour had no room for
	last  any
	gen   uint64
	timer *time.Timer
}

const overflowKey = "\x00overflow"

// NewLimiter makes a Limiter. event is called for a call that is reported one by one; fold, for a summary. fold may be nil
// when nothing is counted (it is then logged only).
func NewLimiter(cfg LimiterConfig, event func(v any), fold func(v any, f Fold)) *Limiter {
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Hourly <= 0 {
		cfg.Hourly = DefaultHourly
	}
	if cfg.Buckets <= 0 {
		cfg.Buckets = DefaultBuckets
	}
	if cfg.Inflight <= 0 {
		cfg.Inflight = DefaultInflight
	}
	return &Limiter{cfg: cfg, event: event, fold: fold, now: time.Now, sem: make(chan struct{}, cfg.Inflight),
		buckets: map[string]*bucket{}, hours: map[string]*hourState{}}
}

// Note counts a call of key and reports it if the window and the hour have room. v is what the event function gets. It
// never blocks, except in the synchronous mode, where the event function runs on the caller's goroutine.
func (l *Limiter) Note(key string, v any) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	now := l.now()
	if _, ok := l.buckets[key]; !ok && len(l.buckets) >= l.cfg.Buckets {
		l.sweepLocked(now)
		if len(l.buckets) >= l.cfg.Buckets {
			key = overflowKey
		}
	}
	b := l.buckets[key]
	var ended *summary
	if b != nil && now.Sub(b.start) >= l.cfg.Window {
		ended = l.closeLocked(key, b, now, false) // the window is over and its timer has not fired yet
		b = nil
	}
	if b == nil {
		l.gen++
		b = &bucket{start: now, gen: l.gen}
		l.buckets[key] = b
	}
	b.last = v
	hr := l.hourLocked(key, now)
	hr.last = v
	hear := b.heard < l.cfg.Burst && hr.facts < l.cfg.Hourly
	if hear && l.cfg.Async {
		select {
		case l.sem <- struct{}{}:
		default:
			hear = false // every slot of the event function is busy: count it
		}
	}
	if hear {
		b.heard++
		hr.facts++
	} else {
		b.suppressed++
		if b.timer == nil {
			gen := b.gen
			b.timer = time.AfterFunc(l.cfg.Window-now.Sub(b.start), func() { l.flush(key, gen) })
		}
	}
	l.mu.Unlock()
	if ended != nil {
		l.deliver(ended)
	}
	if !hear {
		return
	}
	if l.cfg.Async {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer func() { <-l.sem }()
			l.call(func() { l.event(v) })
		}()
		return
	}
	l.event(v)
}

type summary struct {
	v any
	f Fold
}

// deliver reports a summary. A summary does not bypass the bound of the event function: in the asynchronous mode it waits
// for a slot in its own goroutine (at most one is made for each bucket and window, and the buckets are bounded).
func (l *Limiter) deliver(s *summary) {
	if s == nil {
		return
	}
	slog.Info("refusals folded", "suppressed", s.f.Suppressed, "window", s.f.Window, "overflow", s.f.Overflow)
	if l.fold == nil {
		return
	}
	run := func() { l.call(func() { l.fold(s.v, s.f) }) }
	if !l.cfg.Async {
		run()
		return
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.sem <- struct{}{}
		defer func() { <-l.sem }()
		run()
	}()
}

// call runs f and keeps a panic in it from ending the process: the audit of a refusal is not worth a crash.
func (l *Limiter) call(f func()) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("a refusal hook panicked", "panic", fmt.Sprint(r))
		}
	}()
	f()
}

// flush ends the window of a bucket whose timer fired.
func (l *Limiter) flush(key string, gen uint64) {
	l.mu.Lock()
	b := l.buckets[key]
	var s *summary
	if b != nil && b.gen == gen && !l.closed {
		s = l.closeLocked(key, b, l.now(), false)
	}
	l.mu.Unlock()
	l.deliver(s)
}

// closeLocked removes a bucket and returns the summary of what it counted, if the hour has room for one; what it has no
// room for is carried in the hour state and comes out when the hour is over. force makes the summary regardless of the hour.
func (l *Limiter) closeLocked(key string, b *bucket, now time.Time, force bool) *summary {
	delete(l.buckets, key)
	if b.timer != nil {
		b.timer.Stop()
	}
	hr := l.hourLocked(key, now)
	total := b.suppressed + hr.carry
	if total == 0 {
		return nil
	}
	if hr.facts >= l.cfg.Hourly && !force {
		hr.carry = total
		hr.last = b.last
		if hr.timer == nil {
			gen := hr.gen
			hr.timer = time.AfterFunc(hour-now.Sub(hr.start), func() { l.flushHour(key, gen) })
		}
		return nil
	}
	hr.carry = 0
	hr.facts++
	return &summary{v: b.last, f: Fold{Suppressed: total, Window: l.cfg.Window, Overflow: key == overflowKey}}
}

// flushHour ends an hour that held back a summary.
func (l *Limiter) flushHour(key string, gen uint64) {
	l.mu.Lock()
	var s *summary
	if hr := l.hours[key]; hr != nil && hr.gen == gen && !l.closed {
		hr.timer = nil
		hr.start, hr.facts = l.now(), 0
		if hr.carry > 0 {
			s = &summary{v: hr.last, f: Fold{Suppressed: hr.carry, Window: hour, Overflow: key == overflowKey}}
			hr.carry = 0
			hr.facts++
		}
	}
	l.mu.Unlock()
	l.deliver(s)
}

// hourLocked is the hour state of a key, started afresh when its hour is over and nothing is carried.
func (l *Limiter) hourLocked(key string, now time.Time) *hourState {
	hr := l.hours[key]
	if hr == nil {
		if len(l.hours) >= l.cfg.Buckets {
			for k, h := range l.hours {
				if h.carry == 0 && now.Sub(h.start) >= hour {
					delete(l.hours, k)
				}
			}
			if len(l.hours) >= l.cfg.Buckets {
				key = overflowKey
				hr = l.hours[key]
			}
		}
		if hr == nil {
			l.gen++
			hr = &hourState{start: now, gen: l.gen}
			l.hours[key] = hr
		}
		return hr
	}
	if hr.carry == 0 && now.Sub(hr.start) >= hour {
		hr.start, hr.facts = now, 0
	}
	return hr
}

// sweepLocked drops the buckets whose window is over and that count nothing.
func (l *Limiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.suppressed == 0 && now.Sub(b.start) >= l.cfg.Window {
			delete(l.buckets, k)
		}
	}
}

// Close stops the timers and reports, once, what every bucket and hour still counts, so that a shutdown loses no count. It
// waits for the calls in flight. The Limiter takes no further calls.
func (l *Limiter) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	now := l.now()
	var pending []*summary
	for k, b := range l.buckets {
		if s := l.closeLocked(k, b, now, true); s != nil {
			pending = append(pending, s)
		}
	}
	for k, hr := range l.hours {
		if hr.timer != nil {
			hr.timer.Stop()
		}
		if hr.carry > 0 {
			pending = append(pending, &summary{v: hr.last, f: Fold{Suppressed: hr.carry, Window: hour, Overflow: k == overflowKey}})
			hr.carry = 0
		}
	}
	l.mu.Unlock()
	for _, s := range pending {
		slog.Info("refusals folded", "suppressed", s.f.Suppressed, "window", s.f.Window, "overflow", s.f.Overflow)
		if l.fold != nil {
			if l.cfg.Async {
				l.sem <- struct{}{} // the same bound as every other call
			}
			l.call(func() { l.fold(s.v, s.f) })
			if l.cfg.Async {
				<-l.sem
			}
		}
	}
	l.wg.Wait()
}
