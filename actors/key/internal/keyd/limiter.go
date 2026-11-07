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
func (l *limiters) allow(purpose string) bool { return l.allowAt(purpose, signRate, signBurst) }

// The signing rate limit of a certificate (Sign for the x509-intermediate purpose): the intermediate's key needs about one
// signature in 13 months, and a ca that retries after a failure waits up to a quarter of an hour, so a burst of four and five
// an hour (one every twelve minutes, so that an attempt every fifteen always finds a token) is more than any honest ca uses. It is a bucket of its own: the hand-off's SignRequest shares the key and not the
// bucket, so a flood of Sign calls cannot stop `sluis key request`.
const (
	certRate  = 5.0 / 3600
	certBurst = 4.0
)

// allowCertificate takes one token of the bucket of certificate signatures.
func (l *limiters) allowCertificate() bool { return l.allowAt("certificate", certRate, certBurst) }

// allowAt takes one token of the named bucket, which fills at rate a second up to burst.
func (l *limiters) allowAt(name string, rate, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.m[name]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		l.m[name] = b
	}
	// The clock can step back (the boards have no RTC): a bucket whose last time lies ahead of now would not fill until the
	// clock passed it, so a step back only moves last, and keeps the tokens.
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(burst, b.tokens+d.Seconds()*rate)
		b.last = now
	} else if d < 0 {
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
