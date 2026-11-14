package handoff

import (
	"testing"
	"time"
)

// A certificate's notAfter is 13 calendar months after its notBefore, the same day and time or the last day of the month when it has
// none (the contract's "What is issued"). time.AddDate would carry 31 January plus one month into March.
func TestCertificateExpiryIsTheContractsMonth(t *testing.T) {
	for _, c := range []struct{ from, want string }{
		{"2027-01-31T10:00:00Z", "2028-02-29T10:00:00Z"}, // 2028 is a leap year: the last day of February
		{"2026-01-31T10:00:00Z", "2027-02-28T10:00:00Z"},
		{"2027-03-15T08:30:05Z", "2028-04-15T08:30:05Z"},
		{"2027-08-31T23:59:59Z", "2028-09-30T23:59:59Z"},
	} {
		from, _ := time.Parse(time.RFC3339, c.from)
		want, _ := time.Parse(time.RFC3339, c.want)
		if got := CertificateExpiry(from); !got.Equal(want) {
			t.Errorf("CertificateExpiry(%s) = %s, want %s", c.from, got.Format(time.RFC3339), c.want)
		}
	}
}
