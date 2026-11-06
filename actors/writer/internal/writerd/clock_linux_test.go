//go:build linux && sluis_test

package writerd

import "testing"

// verifies: REQ-AUDIT-036
func TestTheKernelClockObservationReadsUnitAndSyncFlags(t *testing.T) {
	const timeOK = 0 // TIME_OK
	tests := []struct {
		name   string
		offset int64
		status int32
		state  int
		want   clockObservation
	}{
		{"microseconds are kept", 1234, 0, timeOK, clockObservation{Observed: true, Synced: true, OffsetMicros: 1234}},
		{"nanoseconds are divided by a thousand", 5_678_000, staNano, timeOK, clockObservation{Observed: true, Synced: true, OffsetMicros: 5678}},
		{"a negative nanosecond offset", -2_500_000, staNano, timeOK, clockObservation{Observed: true, Synced: true, OffsetMicros: -2500}},
		{"STA_UNSYNC is not synchronised", 7, staUnsync, timeOK, clockObservation{Observed: true, Synced: false, OffsetMicros: 7}},
		{"TIME_ERROR is not synchronised", 7, 0, timeError, clockObservation{Observed: true, Synced: false, OffsetMicros: 7}},
		{"both flags and nanoseconds", 9_000, staNano | staUnsync, timeError, clockObservation{Observed: true, Synced: false, OffsetMicros: 9}},
		{"another state is synchronised", 0, 0, 1, clockObservation{Observed: true, Synced: true, OffsetMicros: 0}},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			if got := observeTimex(c.offset, c.status, c.state); got != c.want {
				t.Fatalf("observeTimex(%d, %#x, %d) = %+v, want %+v", c.offset, c.status, c.state, got, c.want)
			}
		})
	}
}
