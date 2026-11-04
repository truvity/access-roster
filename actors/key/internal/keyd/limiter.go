package keyd

import (
	"sync"
	"time"
)

// The signing rate limit of a purpose: a token bucket of 50 a second with a burst of 100 (ADR 0006: "Every
// signature is rate-limited").
const (
	signRate  = 50.0
	signBurst = 100.0
)

type bucket struct {
	tokens float64
	last   time.Time
}

// limiters is one token bucket per purpose.
type limiters struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*bucket
}

func newLimiters(now func() time.Time) *limiters {
	return &limiters{now: now, m: map[string]*bucket{}}
}

// allow takes one token of the purpose's bucket, and says whether there was one.
func (l *limiters) allow(purpose string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.m[purpose]
	if b == nil {
		b = &bucket{tokens: signBurst, last: now}
		l.m[purpose] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(signBurst, b.tokens+d.Seconds()*signRate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
