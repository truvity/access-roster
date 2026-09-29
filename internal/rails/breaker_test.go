package rails_test

import (
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

// The same set of lines, in any order, names the same fingerprint: an
// operator confirms it once and the confirmation holds however the set is
// later listed.
func TestFingerprintIgnoresOrder(t *testing.T) {
	t.Parallel()
	a := rails.Fingerprint([]string{"x|", "y|team", "z|"})
	b := rails.Fingerprint([]string{"z|", "x|", "y|team"})
	if a != b {
		t.Errorf("fingerprints differ by order: %q vs %q", a, b)
	}
	if c := rails.Fingerprint([]string{"x|", "y|team"}); c == a {
		t.Errorf("a different set produced the same fingerprint %q", c)
	}
}

// Nothing trips the breaker when the target is empty, or the change
// concerns half or less of it: half exactly is not more than half.
func TestBreakerDoesNotTripAtOrUnderHalf(t *testing.T) {
	t.Parallel()
	if b := rails.CheckBreaker(0, nil, 0, ""); b != nil {
		t.Errorf("CheckBreaker(empty target) = %+v, want nil", b)
	}
	if b := rails.CheckBreaker(2, []string{"a|", "b|"}, 4, ""); b != nil {
		t.Errorf("CheckBreaker(half) = %+v, want nil", b)
	}
}

// Past half, the breaker trips and stays open until the exact fingerprint
// it names is confirmed; a changed set does not reuse an old confirmation.
func TestBreakerTripsUntilItsExactFingerprintIsConfirmed(t *testing.T) {
	t.Parallel()
	lines := []string{"x|", "y|", "z|"}
	open := rails.CheckBreaker(3, lines, 4, "")
	if open == nil || open.Confirmed {
		t.Fatalf("CheckBreaker(unconfirmed) = %+v, want tripped and unconfirmed", open)
	}
	if open.Affected != 3 || open.Total != 4 {
		t.Errorf("CheckBreaker = %+v, want 3 of 4", open)
	}

	closed := rails.CheckBreaker(3, lines, 4, open.Fingerprint)
	if closed == nil || !closed.Confirmed {
		t.Fatalf("CheckBreaker(confirmed) = %+v, want confirmed", closed)
	}

	changed := append([]string{"w|"}, lines...)
	stillOpen := rails.CheckBreaker(4, changed, 5, open.Fingerprint)
	if stillOpen == nil || stillOpen.Confirmed {
		t.Errorf("a changed set went ahead on an old confirmation: %+v", stillOpen)
	}
}
