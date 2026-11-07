package rpc

import (
	"log/slog"
	"sync"
	"time"
)

const (
	defaultRefusalBurst  = 10
	defaultRefusalWindow = time.Minute
	// refusalInflight is the number of calls of OnRefused that may run at once. A refusal that finds all of them busy is
	// folded into the count of its window, so a hook that waits for a full spool holds up eight goroutines and no more.
	refusalInflight = 8
	// refusalBuckets bounds the peers and reasons that are counted apart. The uids that reach one socket are the few the
	// socket's directory lets in; past the bound a refusal is counted with the others in one shared bucket.
	refusalBuckets = 256
)

// refusalLimiter hands the refusals of one server to its OnRefused hook at a bounded rate: the worst case is
// refusalBuckets * (burst + 1) calls of the hook in a window, and in practice (burst + 1) for each peer uid and reason
// that reaches the socket. Memory is bounded by refusalBuckets.
type refusalLimiter struct {
	hook   func(Refused)
	burst  int
	window time.Duration
	now    func() time.Time
	sem    chan struct{}

	mu      sync.Mutex
	buckets map[refusalKey]*refusalBucket
	gen     uint64
}

type refusalKey struct {
	uid      uint32
	known    bool
	reason   string
	overflow bool
}

type refusalBucket struct {
	start      time.Time
	heard      int
	suppressed int
	last       Refused // the peer of the latest refusal, for the summary
	gen        uint64
	timer      *time.Timer
}

func newRefusalLimiter(cfg ServerConfig) *refusalLimiter {
	if cfg.OnRefused == nil {
		return nil
	}
	l := &refusalLimiter{hook: cfg.OnRefused, burst: cfg.RefusalBurst, window: cfg.RefusalWindow, now: time.Now,
		sem: make(chan struct{}, refusalInflight), buckets: map[refusalKey]*refusalBucket{}}
	if l.burst <= 0 {
		l.burst = defaultRefusalBurst
	}
	if l.window <= 0 {
		l.window = defaultRefusalWindow
	}
	return l
}

// note counts a refusal and hands it to the hook if the window still has room. It never blocks.
func (l *refusalLimiter) note(r Refused) {
	if l == nil {
		return
	}
	l.mu.Lock()
	key := refusalKey{uid: r.Peer.UID, known: r.Known, reason: r.Reason}
	b := l.buckets[key]
	if b == nil && len(l.buckets) >= refusalBuckets {
		l.sweepLocked()
		if len(l.buckets) >= refusalBuckets {
			key = refusalKey{reason: r.Reason, overflow: true}
			b = l.buckets[key]
		}
	}
	now := l.now()
	var summary *Refused
	if b != nil && now.Sub(b.start) >= l.window {
		summary = l.closeLocked(key, b) // the window ended and its timer has not fired yet
		b = nil
	}
	if b == nil {
		l.gen++
		b = &refusalBucket{start: now, gen: l.gen}
		l.buckets[key] = b
	}
	b.last = r
	hear := b.heard < l.burst
	if hear {
		select {
		case l.sem <- struct{}{}:
			b.heard++
		default:
			hear = false // every slot of the hook is busy: count it
		}
	}
	if !hear {
		b.suppressed++
		if b.timer == nil {
			gen := b.gen
			b.timer = time.AfterFunc(l.window-now.Sub(b.start), func() { l.flush(key, gen) })
		}
	}
	l.mu.Unlock()
	if summary != nil {
		go l.hook(*summary)
	}
	if hear {
		go func() {
			defer func() { <-l.sem }()
			l.hook(r)
		}()
	}
}

// flush ends the window of a bucket whose timer fired, and reports what it suppressed.
func (l *refusalLimiter) flush(key refusalKey, gen uint64) {
	l.mu.Lock()
	b := l.buckets[key]
	var summary *Refused
	if b != nil && b.gen == gen {
		summary = l.closeLocked(key, b)
	}
	l.mu.Unlock()
	if summary != nil {
		l.hook(*summary)
	}
}

// closeLocked removes a bucket and returns the summary of what it suppressed, if anything.
func (l *refusalLimiter) closeLocked(key refusalKey, b *refusalBucket) *Refused {
	delete(l.buckets, key)
	if b.timer != nil {
		b.timer.Stop()
	}
	if b.suppressed == 0 {
		return nil
	}
	s := b.last
	s.Procedure, s.Suppressed, s.Window = "", b.suppressed, l.window
	slog.Info("refusals folded", "reason", s.Reason, "uid", s.Peer.UID, "suppressed", s.Suppressed)
	return &s
}

// sweepLocked drops the buckets whose window is over and that hold nothing to report.
func (l *refusalLimiter) sweepLocked() {
	now := l.now()
	for k, b := range l.buckets {
		if b.suppressed == 0 && now.Sub(b.start) >= l.window {
			delete(l.buckets, k)
		}
	}
}
