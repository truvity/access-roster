package logsafe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/logsafe"
)

// A value carrying a newline can forge a log record: a refusal that reads
// as a success, an identity that was never there.
func TestNothingCanForgeARecord(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ in, want string }{
		"an ordinary address": {"ada@north.example", "ada@north.example"},
		"a forged line":       {"ada@north.example\nauthorization granted", "ada@north.exampleauthorization granted"},
		"a carriage return":   {"a\r\nb", "ab"},
		"a tab, which splits a record in half the formats there are": {"a\tb", "ab"},
		"a bare control character":                                   {"a\x00\x1bb", "ab"},
		"a delete":                                                   {"a\x7fb", "ab"},
		"unicode, which is not the problem":                          {"ада@север.example", "ада@север.example"},
	} {
		if got := logsafe.Value(tc.in); got != tc.want {
			t.Errorf("%s: %q became %q, want %q", name, tc.in, got, tc.want)
		}
	}

	// One field must not be able to bury a record.
	long := logsafe.Value(strings.Repeat("a", logsafe.Limit*3))
	if len(long) > logsafe.Limit+4 {
		t.Errorf("a long value was kept at %d characters", len(long))
	}

	// An error is worth its own call because the interesting ones carry
	// the input that caused them.
	if got := logsafe.Error(errors.New("read ada@north.example\nfailed")); strings.Contains(got, "\n") {
		t.Errorf("an error kept its newline: %q", got)
	}
	if logsafe.Error(nil) != "" {
		t.Error("a nil error is not a message")
	}
}
