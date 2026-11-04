package audit

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUUIDv7VersionVariantAndTime(t *testing.T) {
	// Far ahead of the other tests: the generator never goes back, and they share its state.
	now := time.UnixMilli(time.Now().UnixMilli() + 1e12)
	u := NewUUIDv7(now)
	if len(u) != 36 || u[8] != '-' || u[13] != '-' || u[18] != '-' || u[23] != '-' {
		t.Fatalf("shape: %s", u)
	}
	if u[14] != '7' {
		t.Errorf("version nibble = %c, want 7 (RFC 9562 section 5.7)", u[14])
	}
	if !strings.ContainsRune("89ab", rune(u[19])) {
		t.Errorf("variant nibble = %c, want one of 89ab (RFC 9562 section 4.1)", u[19])
	}
	// The first 48 bits are the Unix time in milliseconds.
	ms, err := strconv.ParseUint(strings.ReplaceAll(u[:13], "-", ""), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	if ms != uint64(now.UnixMilli()) {
		t.Errorf("time prefix = %d, want the clock", ms)
	}
}

func TestUUIDv7IncreasesWithinOneMillisecond(t *testing.T) {
	now := time.UnixMilli(1793750500000)
	prev := ""
	// More than the 4,096 values of the counter: the timestamp has to move on instead of the value repeating.
	for i := range 6000 {
		u := NewUUIDv7(now)
		if u <= prev {
			t.Fatalf("value %d (%s) does not follow %s", i, u, prev)
		}
		prev = u
	}
}

func TestUUIDv7NeverStepsBackWithTheClock(t *testing.T) {
	a := NewUUIDv7(time.UnixMilli(1793750600000))
	b := NewUUIDv7(time.UnixMilli(1793750599000))
	if b <= a {
		t.Fatalf("%s does not follow %s", b, a)
	}
}
