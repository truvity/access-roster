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
	return observeTimex(tx.Offset, tx.Status, state)
}

// observeTimex turns what adjtimex answered into the observation: the offset in microseconds (the kernel counts
// nanoseconds when STA_NANO is set), and synchronised when neither STA_UNSYNC nor the TIME_ERROR state says not.
func observeTimex(offset int64, status int32, state int) clockObservation {
	if status&staNano != 0 {
		offset /= 1000
	}
	return clockObservation{Observed: true, Synced: status&staUnsync == 0 && state != timeError, OffsetMicros: offset}
}
