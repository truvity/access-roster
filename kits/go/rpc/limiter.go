package rpc

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// The defaults of a Limiter.
const (
	DefaultBurst  = 10
	DefaultWindow = time.Minute
	// DefaultHourly is the most facts of one key in an hour: the heard events and the summaries together.
	DefaultHourly = 60
	// DefaultTotal is the most facts of a whole Limiter in an hour, over all its keys.
	DefaultTotal = 120
	// DefaultInflight is the number of event calls that may run at once in the asynchronous mode.
	DefaultInflight = 8
	// DefaultBuckets bounds the keys that are counted apart.
	DefaultBuckets = 256
	// DefaultCloseTimeout bounds how long Close may take to report what is pending.
	DefaultCloseTimeout = 5 * time.Second
	hour                = time.Hour
)

// Fold is what a summary call says about the calls that were counted and not reported one by one.
type Fold struct {
	// Suppressed is the number of calls of the key that were not reported.
	Suppressed int
	// Window is the length of the window the count was made in (an hour for what an hour held back).
	Window time.Duration
	// Overflow says that the key is not one key but the shared bucket that takes every key past the bound of buckets and
	// every call past the total of the hour. The value of the call is then the latest one of any of them, and names nobody.
	Overflow bool
}

// LimiterConfig sets a Limiter. A zero field is the default.
type LimiterConfig struct {
	Burst        int           // the calls of a key reported one by one in a window
	Window       time.Duration // the length of the window
	Hourly       int           // the most facts (calls reported and summaries) of a key in an hour
	Total        int           // the most facts of the whole Limiter in an hour
	Buckets      int           // the keys counted apart
	Inflight     int           // the calls of the event function that run at once (Async only)
	CloseTimeout time.Duration // the most time Close takes to report what is pending
	// Late is called, on the caller's goroutine, for a call that comes after Close, with the value of the call: a call that
	// holds the limiter across its Close (a handler that read the limiter before it was replaced) reaches it, and the holder
	// reports it itself, as a fact on its own, so that the emitter counts it lost if that fails. Without it the call is
	// dropped, counted by Dropped, and logged once.
	Late func(v any)
	// Async runs the event function off the goroutine of Note, in at most Inflight goroutines; a call that finds them all
	// busy is counted. Without it the event function runs in Note, on the caller's goroutine, after the lock is released.
	Async bool
}

// A Limiter turns a stream of calls that must be accounted for (refusals that become audit facts) into a bounded stream.
//
// Per key, the first Burst calls of a Window are passed to the event function one by one, and the rest are counted and
// reported once, by the fold function, at the end of the window. A key makes at most Hourly facts an hour, and the whole
// Limiter at most Total: past either, the calls are counted, the counts of keys past the total go to one shared overflow
// key, and what an hour has no room for is carried into the summaries that come when the next hour starts. Memory is bounded
// by Buckets keys.
//
// Nothing is lost while the process lives: each call is either reported or counted, and Close (at most CloseTimeout) reports
// what is pending. A crash or a kill loses the counts that are pending. A call after Close goes to Late when the holder gave one,
// and is otherwise dropped and counted by Dropped. The functions are called with the lock released; a panic in one is logged and does not end the process.
type Limiter struct {
	cfg   LimiterConfig
	event func(v any)
	fold  func(v any, f Fold)
	now   func() time.Time
	// hourLen is the length of an hour of the caps; a test shortens it.
	hourLen time.Duration
	sem     chan struct{}

	mu        sync.Mutex
	buckets   map[string]*bucket
	hours     map[string]*keyHour
	hourStart time.Time
	total     int
	hourTimer *time.Timer
	gen       uint64
	closed    bool
	wg        sync.WaitGroup
	dropped   atomic.Int64 // calls after Close that nobody took (no Late)
	late      atomic.Int64 // calls after Close that Late took
}

// Dropped is the number of calls after Close that were dropped: the limiter had no Late to give them to, and they are in no
// fact and no summary.
func (l *Limiter) Dropped() int64 { return l.dropped.Load() }

// Late is the number of calls after Close that were given to LimiterConfig.Late.
func (l *Limiter) Late() int64 { return l.late.Load() }

type bucket struct {
	start      time.Time
	heard      int
	suppressed int
	last       any
	gen        uint64
	timer      *time.Timer
}

// keyHour is what a key has made, and held back, in the hour of the Limiter.
type keyHour struct {
	facts int
	carry int // calls counted in windows whose summary the hour had no room for
	last  any
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
	if cfg.Total <= 0 {
		cfg.Total = DefaultTotal
	}
	if cfg.Buckets <= 0 {
		cfg.Buckets = DefaultBuckets
	}
	if cfg.Inflight <= 0 {
		cfg.Inflight = DefaultInflight
	}
	if cfg.CloseTimeout <= 0 {
		cfg.CloseTimeout = DefaultCloseTimeout
	}
	l := &Limiter{cfg: cfg, event: event, fold: fold, now: time.Now, hourLen: hour, sem: make(chan struct{}, cfg.Inflight),
		buckets: map[string]*bucket{}, hours: map[string]*keyHour{}}
	l.hourStart = l.now()
	return l
}

// Note counts a call of key and reports it if the window, the key's hour and the Limiter's hour have room. v is what the
// event function gets. It never blocks, except in the synchronous mode, where the event function runs on the caller's
// goroutine.
func (l *Limiter) Note(key string, v any) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		if l.cfg.Late != nil {
			l.late.Add(1)
			l.call(func() { l.cfg.Late(v) })
			return
		}
		if l.dropped.Add(1) == 1 {
			slog.Warn("a call after the limiter was closed is dropped; Dropped counts them")
		}
		return
	}
	now := l.now()
	l.rollLocked(now)
	if key != overflowKey {
		if l.total >= l.cfg.Total {
			key = overflowKey // the hour is full: every key counts into the shared bucket
		} else if _, ok := l.buckets[key]; !ok && len(l.buckets) >= l.cfg.Buckets {
			l.sweepLocked(now)
			if len(l.buckets) >= l.cfg.Buckets {
				key = overflowKey
			}
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
	kh := l.keyHourLocked(key)
	kh.last = v
	hear := b.heard < l.cfg.Burst && kh.facts < l.cfg.Hourly && l.total < l.cfg.Total
	if hear && l.cfg.Async {
		select {
		case l.sem <- struct{}{}:
		default:
			hear = false // every slot of the event function is busy: count it
		}
	}
	if hear {
		b.heard++
		kh.facts++
		l.total++
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
		now := l.now()
		l.rollLocked(now)
		s = l.closeLocked(key, b, now, false)
	}
	l.mu.Unlock()
	l.deliver(s)
}

// keyHourLocked is the hour state of a key. Past the bound of buckets it is the overflow key's.
func (l *Limiter) keyHourLocked(key string) *keyHour {
	kh := l.hours[key]
	if kh == nil {
		if key != overflowKey && len(l.hours) >= l.cfg.Buckets {
			return l.keyHourLocked(overflowKey)
		}
		kh = &keyHour{}
		l.hours[key] = kh
	}
	return kh
}

// effectiveKey is the key whose hour state keyHourLocked returns for key.
func (l *Limiter) effectiveKey(key string) string {
	if _, ok := l.hours[key]; ok || key == overflowKey || len(l.hours) < l.cfg.Buckets {
		return key
	}
	return overflowKey
}

// rollLocked starts a new hour for the Limiter when the old one is over: the facts of every key and the total are counted
// afresh, and the states that carry nothing are dropped.
func (l *Limiter) rollLocked(now time.Time) {
	if now.Sub(l.hourStart) < l.hourLen {
		return
	}
	l.hourStart, l.total = now, 0
	for k, kh := range l.hours {
		kh.facts = 0
		if kh.carry == 0 {
			delete(l.hours, k)
		}
	}
}

// closeLocked removes a bucket and returns the summary of what it counted, if the hour has room for one; what it has no room
// for is carried in the hour state of the key actually used (the overflow key's past the bounds) and comes out when the next
// hour starts. force makes the summary regardless of the hour.
func (l *Limiter) closeLocked(key string, b *bucket, now time.Time, force bool) *summary {
	delete(l.buckets, key)
	if b.timer != nil {
		b.timer.Stop()
	}
	eff := l.effectiveKey(key)
	kh := l.keyHourLocked(key)
	total := b.suppressed + kh.carry
	if total == 0 {
		return nil
	}
	if !force && (kh.facts >= l.cfg.Hourly || l.total >= l.cfg.Total) {
		kh.carry = total
		kh.last = b.last
		l.armHourLocked(now)
		return nil
	}
	kh.carry = 0
	kh.facts++
	l.total++
	return &summary{v: b.last, f: Fold{Suppressed: total, Window: l.cfg.Window, Overflow: eff == overflowKey}}
}

// armHourLocked sets the timer that reports what the hour held back, once the next hour has started.
func (l *Limiter) armHourLocked(now time.Time) {
	if l.hourTimer != nil {
		return
	}
	d := l.hourLen - now.Sub(l.hourStart)
	if d < time.Millisecond {
		d = time.Millisecond
	}
	l.hourTimer = time.AfterFunc(d, l.flushHour)
}

// flushHour starts the next hour and reports what the last one held back: a summary for each key that carries a count,
// while the new hour has room, and one overflow summary for the rest.
func (l *Limiter) flushHour() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.hourTimer = nil
	now := l.now()
	l.hourStart, l.total = now, 0
	for _, kh := range l.hours {
		kh.facts = 0
	}
	var out []*summary
	rest := 0
	var restLast any
	for k, kh := range l.hours {
		if kh.carry == 0 {
			continue
		}
		if k == overflowKey || l.total >= l.cfg.Total-1 { // keep a place for the overflow summary
			rest += kh.carry
			restLast = kh.last
		} else {
			out = append(out, &summary{v: kh.last, f: Fold{Suppressed: kh.carry, Window: l.hourLen}})
			kh.facts++
			l.total++
		}
		kh.carry = 0
	}
	if rest > 0 {
		out = append(out, &summary{v: restLast, f: Fold{Suppressed: rest, Window: l.hourLen, Overflow: true}})
		l.keyHourLocked(overflowKey).facts++
		l.total++
	}
	for k, kh := range l.hours {
		if kh.carry == 0 && kh.facts == 0 {
			delete(l.hours, k)
		}
	}
	l.mu.Unlock()
	for _, s := range out {
		l.deliver(s)
	}
}

// sweepLocked drops the buckets whose window is over and that count nothing.
func (l *Limiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.suppressed == 0 && now.Sub(b.start) >= l.cfg.Window {
			delete(l.buckets, k)
		}
	}
}

// Close stops the timers and reports, once, what every bucket and hour still counts, so that a shutdown loses no count that
// the process still holds. It waits for the calls in flight and for the summaries, but at most CloseTimeout in all: past
// it, what is not reported is logged with its number and Close returns, so that a transport that is down cannot hold up the
// stop of the process. The Limiter takes no further calls.
func (l *Limiter) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	if l.hourTimer != nil {
		l.hourTimer.Stop()
	}
	now := l.now()
	var pending []*summary
	for k, b := range l.buckets {
		if s := l.closeLocked(k, b, now, true); s != nil {
			pending = append(pending, s)
		}
	}
	for k, kh := range l.hours {
		if kh.carry > 0 {
			pending = append(pending, &summary{v: kh.last, f: Fold{Suppressed: kh.carry, Window: l.hourLen, Overflow: k == overflowKey}})
			kh.carry = 0
		}
	}
	l.mu.Unlock()

	var left atomic.Int64 // the suppressed calls of the summaries not yet reported
	var undone atomic.Int64
	for _, s := range pending {
		left.Add(int64(s.f.Suppressed))
		undone.Add(1)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
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
			left.Add(-int64(s.f.Suppressed))
			undone.Add(-1)
		}
		l.wg.Wait()
	}()
	t := time.NewTimer(l.cfg.CloseTimeout)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		slog.Error("the refusal counts were not all reported before the stop; they are lost",
			"summaries", undone.Load(), "suppressed", left.Load(), "timeout", l.cfg.CloseTimeout)
	}
}
