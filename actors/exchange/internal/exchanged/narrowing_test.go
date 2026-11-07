package exchanged

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// The names of a small world, so that random sets collide often: a collision is where narrowing could go wrong.
var (
	scopes = []string{"dev", "acme", "prod"}
	things = []string{"app", "billing", "x"}
	roles  = []string{"user", "operator", "admin"}
)

func randomName(r *rand.Rand) string {
	switch r.IntN(12) {
	case 0:
		return "bad"
	case 1:
		return "dev:app:"
	case 2:
		return "*:" + things[r.IntN(len(things))] + ":" + roles[r.IntN(len(roles))]
	case 3:
		return scopes[r.IntN(len(scopes))] + ":*:" + roles[r.IntN(len(roles))]
	case 4:
		return "dev:app:user:extra"
	}
	return scopes[r.IntN(len(scopes))] + ":" + things[r.IntN(len(things))] + ":" + roles[r.IntN(len(roles))]
}

func randomNames(r *rand.Rand) []string {
	out := make([]string, r.IntN(9))
	for i := range out {
		out[i] = randomName(r)
	}
	return out
}

// verifies: REQ-EXCH-004
func TestNarrowOnlyEverKeepsWhatWasHeldAndWhatTheAudienceAsksFor(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 8))
	for range 20000 {
		held, requires := randomNames(r), randomNames(r)
		got := narrow(held, requires)
		if got == nil {
			t.Fatalf("narrow(%v, %v) is nil", held, requires)
		}
		if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Fatalf("narrow(%v, %v) = %v: not sorted or with repeats", held, requires, got)
		}
		pairs := map[string]bool{}
		for _, q := range requires {
			if p, ok := pairOf(q); ok {
				pairs[p] = true
			}
		}
		for _, g := range got {
			// Never wider than the held set: nothing is invented, and nothing from the audience's requires is added.
			if !slices.Contains(held, g) {
				t.Fatalf("narrow(%v, %v) gave %q, which was not held", held, requires, g)
			}
			// Never a wildcard, from either side.
			if strings.Contains(g, "*") {
				t.Fatalf("narrow(%v, %v) gave the wildcard %q", held, requires, g)
			}
			if p, ok := pairOf(g); !ok || !pairs[p] {
				t.Fatalf("narrow(%v, %v) gave %q, whose pair the audience does not ask for", held, requires, g)
			}
		}
		// Complete: every held name of a pair the audience asks for is kept.
		for _, h := range held {
			if p, ok := pairOf(h); ok && pairs[p] && !slices.Contains(got, h) {
				t.Fatalf("narrow(%v, %v) dropped %q", held, requires, h)
			}
		}
		// Idempotent, and monotone in the held set: a person who holds more never gets less, one who holds less never
		// gets more.
		if again := narrow(got, requires); !slices.Equal(again, got) {
			t.Fatalf("narrow is not idempotent: %v then %v", got, again)
		}
		sub := narrow(held[:len(held)/2], requires)
		for _, g := range sub {
			if !slices.Contains(got, g) {
				t.Fatalf("a smaller held set gave %q, which the larger did not", g)
			}
		}
	}
}

// verifies: REQ-EXCH-004
func TestTheLifetimeOfAnExchangeIsNeverLongerThanTheSubjectTokenOrAnyCap(t *testing.T) {
	r := rand.New(rand.NewPCG(15, 16))
	now := time.Unix(1_800_000_000, 0)
	secs := func(max int) time.Duration {
		return time.Duration(r.IntN(max)) * time.Second
	}
	for range 50000 {
		issuer := secs(7200)
		clientCap := time.Duration(0)
		if r.IntN(2) == 0 {
			clientCap = secs(7200)
		}
		subjectExp := now.Add(secs(7200) + time.Duration(r.IntN(1000))*time.Millisecond - time.Second)
		iat, exp, ok := lifetime(now, issuer, clientCap, subjectExp)

		// The longest it may be: the earliest of the issuer's, the client's cap, the built-in hour and the end of the
		// subject token, in whole seconds.
		limit := min(issuer, hardCap)
		if clientCap > 0 {
			limit = min(limit, clientCap)
		}
		limitSecs := min(int64(limit/time.Second), subjectExp.Unix()-now.Unix())
		if ok != (limitSecs >= 1) {
			t.Fatalf("issuer %v cap %v subject %v: ok = %v, but the longest life is %d s", issuer, clientCap, subjectExp.Sub(now), ok, limitSecs)
		}
		if !ok {
			continue
		}
		if iat != now.Unix() || exp-iat != limitSecs {
			t.Fatalf("issuer %v cap %v subject %v: life %d s, want %d s", issuer, clientCap, subjectExp.Sub(now), exp-iat, limitSecs)
		}
		if exp > subjectExp.Unix() {
			t.Fatalf("the token outlives the subject token: exp %d, subject %d", exp, subjectExp.Unix())
		}
		if exp-iat > int64(hardCap/time.Second) {
			t.Fatalf("the token outlives the built-in maximum: %d s", exp-iat)
		}
	}
}
