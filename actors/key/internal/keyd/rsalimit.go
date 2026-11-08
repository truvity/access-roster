package keyd

import (
	"sync"
	"time"
)

// The rate limit of the RS256 purpose on a card. One private-key operation of an RSA-2048 key takes about 0.17 s on a YubiKey 5 with
// firmware 5.8 (measured 2026-11-08: median 173 ms over 50 signatures, an ES384 signature 148 ms on the same card), the card does one
// thing at a time, and the card driver admits one RSA signature at once. The purpose's bucket of 50 a second (limiter.go) would let a
// burst of a hundred requests through to a driver that refuses all but one, and an RSA signature every 0.17 s would keep the card
// busy for the ES384 signatures, the ECDH unwraps and the audit checkpoints that wait behind it. A bucket that matches the card keeps
// the refusals here, at key@, where a refusal is cheap and is audited like the others, and caps the card's time that RSA can take
// at about a third.
const (
	// cardRSARate is the sustained rate, in signatures a second: 2, a third of what the card does (about 5.8 a second at 173 ms),
	// which leaves the rest of the card's time to the other keys.
	cardRSARate = 2.0
	// cardRSABurst is how many signatures may come at once: a sign-in and a refresh for each of two clients.
	cardRSABurst = 4.0
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
