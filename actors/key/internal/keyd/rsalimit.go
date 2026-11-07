package keyd

import (
	"sync"
	"time"
)

// The rate limit of the RS256 purpose on a card. One private-key operation of an RSA-2048 key takes seconds on a YubiKey (the
// design note's figure is 2.3 s, to be measured), the card does one thing at a time, and the card driver admits only a few RSA
// signatures at once. The purpose's bucket of 50 a second (limiter.go) would let a burst of a hundred requests through to a
// driver that refuses all but two; a bucket that matches the card keeps the refusals here, at key@, where a refusal is cheap and
// is audited like the others, and leaves the card's time to the ES384 signatures, the ECDH unwraps and the audit checkpoints
// that wait behind an RSA signature.
const (
	// cardRSARate is the sustained rate, in signatures a second: one in four seconds, below what a card does (about 0.43 a
	// second at 2.3 s).
	cardRSARate = 0.25
	// cardRSABurst is how many signatures may come at once: a sign-in and a refresh.
	cardRSABurst = 2.0
)

// rateBucket is a token bucket of its own, for a purpose whose cost is not the default's.
type rateBucket struct {
	mu     sync.Mutex
	now    func() time.Time
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateBucket(now func() time.Time, rate, burst float64) *rateBucket {
	return &rateBucket{now: now, rate: rate, burst: burst, tokens: burst, last: now()}
}

// allow takes one token, and says whether there was one.
func (b *rateBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(b.burst, b.tokens+d.Seconds()*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
