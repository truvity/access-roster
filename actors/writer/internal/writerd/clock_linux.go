//go:build linux

package writerd

import "syscall"

// The bits of timex.status the observation reads (adjtimex(2)).
const (
	staUnsync = 0x0040 // STA_UNSYNC: the clock is not synchronised
	staNano   = 0x2000 // STA_NANO: the offset is in nanoseconds
	timeError = 5      // TIME_ERROR: the clock is not synchronised
)

// kernelClock asks the kernel how well its clock is disciplined, without changing it (adjtimex with no mode).
// The unit's system-call filter may refuse the call; the observation then says it saw nothing, and the writer
// still seals (the seal entry records "observed": false).
func kernelClock() clockObservation {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return clockObservation{}
	}
	off := tx.Offset
	if tx.Status&staNano != 0 {
		off /= 1000
	}
	return clockObservation{Observed: true, Synced: tx.Status&staUnsync == 0 && state != timeError, OffsetMicros: off}
}
