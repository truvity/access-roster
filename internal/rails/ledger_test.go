package rails_test

import (
	"slices"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

func TestLedgerRecordsEachKeyOnceWhileItStaysHeld(t *testing.T) {
	t.Parallel()
	var l rails.Ledger
	if got := l.Fresh("t", []string{"a", "b"}, nil); !slices.Equal(got, []bool{true, true}) {
		t.Errorf("first pass %v", got)
	}
	if got := l.Fresh("t", []string{"a", "b", "c"}, nil); !slices.Equal(got, []bool{false, false, true}) {
		t.Errorf("second pass %v", got)
	}
	// b stopped being held, so holding it again is news.
	if got := l.Fresh("t", []string{"a", "c"}, nil); !slices.Equal(got, []bool{false, false}) {
		t.Errorf("third pass %v", got)
	}
	if got := l.Fresh("t", []string{"a", "b"}, nil); !slices.Equal(got, []bool{false, true}) {
		t.Errorf("fourth pass %v", got)
	}
}

func TestLedgerTargetsAreIndependent(t *testing.T) {
	t.Parallel()
	var l rails.Ledger
	l.Fresh("one", []string{"a"}, nil)
	if got := l.Fresh("two", []string{"a"}, nil); !slices.Equal(got, []bool{true}) {
		t.Errorf("another target %v", got)
	}
}

// The first pass of a restarted process takes the last pass from the
// persisted report; later passes never ask again.
func TestLedgerIsSeededOnceFromTheLastReport(t *testing.T) {
	t.Parallel()
	var l rails.Ledger
	seeded := 0
	seed := func() []string { seeded++; return []string{"a"} }
	if got := l.Fresh("t", []string{"a", "b"}, seed); !slices.Equal(got, []bool{false, true}) {
		t.Errorf("after a restart %v", got)
	}
	l.Fresh("t", nil, seed)
	l.Fresh("t", []string{"a"}, seed)
	if seeded != 1 {
		t.Errorf("seeded %d times, want 1", seeded)
	}
}

// Nothing to seed from records everything again, the safe way to be wrong;
// a key repeated in one pass is fresh each time.
func TestLedgerWithNoSeedRecordsAgainAndDuplicatesAreEachFresh(t *testing.T) {
	t.Parallel()
	var l rails.Ledger
	if got := l.Fresh("t", []string{"a", "a"}, func() []string { return nil }); !slices.Equal(got, []bool{true, true}) {
		t.Errorf("%v", got)
	}
}
