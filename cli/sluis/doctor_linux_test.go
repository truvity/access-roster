//go:build linux

package main

import "testing"

// verifies: REQ-AUDIT-017
func TestDoctorReadsAdjtimexAsTheAuditWriterDoes(t *testing.T) {
	cases := []struct {
		offset int64
		status int32
		state  int
		want   clockState
	}{
		{1234, 0, 0, clockState{true, true, 1234}},
		{5_678_000, staNano, 0, clockState{true, true, 5678}},
		{7, staUnsync, 0, clockState{true, false, 7}},
		{7, 0, timeError, clockState{true, false, 7}},
		{0, 0, 1, clockState{true, true, 0}},
	}
	for _, c := range cases {
		if got := clockFromTimex(c.offset, c.status, c.state); got != c.want {
			t.Errorf("clockFromTimex(%d, %#x, %d) = %+v, want %+v", c.offset, c.status, c.state, got, c.want)
		}
	}
}
