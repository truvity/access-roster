//go:build sluis_test

package keyd

import (
	"testing"
	"time"
)

// verifies: REQ-ISO-006
// The clock can step back (a board has no RTC, so after a restart it can start from an old time): a bucket does not stay
// empty until the clock passes the time it last saw. It keeps its tokens, fills from the new time, and the burst still holds.
func TestABucketFillsAfterTheClockStepsBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		take  func(*limiters) bool
		rate  float64
		burst int
	}{
		{"token", func(l *limiters) bool { return l.allow("token-signing") }, signRate, int(signBurst)},
		{"certificate", func(l *limiters) bool { return l.allowCertificate() }, certRate, int(certBurst)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC).Add(30 * 24 * time.Hour)
			l := newLimiters(func() time.Time { return now })
			for i := range tc.burst {
				if !tc.take(l) {
					t.Fatalf("take %d of the burst refused", i+1)
				}
			}
			if tc.take(l) {
				t.Fatal("the bucket gave more than its burst")
			}
			// Thirty days back: still empty, nothing has filled.
			now = now.Add(-30 * 24 * time.Hour)
			if tc.take(l) {
				t.Fatal("a step back of the clock refilled the bucket")
			}
			// And it fills from the new time: about one token needs 1/rate seconds.
			now = now.Add(time.Duration(1.01 / tc.rate * float64(time.Second)))
			if !tc.take(l) {
				t.Fatal("one token's time after the step back the bucket is still empty")
			}
			if tc.take(l) {
				t.Fatal("more than the elapsed time filled")
			}
			// A long quiet after the step back gives the burst, not more.
			now = now.Add(48 * time.Hour)
			for i := range tc.burst {
				if !tc.take(l) {
					t.Fatalf("take %d of the refilled burst refused", i+1)
				}
			}
			if tc.take(l) {
				t.Fatal("the refilled bucket gave more than its burst")
			}
		})
	}
}
