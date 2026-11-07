//go:build linux

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// The bits of timex.status the observation reads (adjtimex(2)); the same reading as the audit writer's
// (actors/writer/internal/writerd/clock_linux.go), which an executable cannot import.
const (
	staUnsync = 0x0040 // STA_UNSYNC: the clock is not synchronised
	staNano   = 0x2000 // STA_NANO: the offset is in nanoseconds
	timeError = 5      // TIME_ERROR: the clock is not synchronised
)

// grndNonblock is GRND_NONBLOCK of getrandom(2): fail with EAGAIN instead of waiting for an uninitialised generator.
const grndNonblock = 0x1

// realHost reads this machine. Nothing in it writes.
func realHost() *host {
	return &host{
		linux:         true,
		kernelRelease: kernelRelease,
		randomReady:   randomReady,
		readFile:      os.ReadFile,
		systemdRunning: func() bool {
			fi, err := os.Stat("/run/systemd/system")
			return err == nil && fi.IsDir()
		},
		systemdVersion: systemctlVersion,
		kernelClock:    kernelClock,
	}
}

func kernelRelease() (string, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", err
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) //nolint:gosec // G115: a release string is ASCII; Utsname is int8 on amd64 and uint8 on arm64
	}
	return string(b), nil
}

// randomReady asks getrandom(2) for one byte without waiting, and throws the byte away: EAGAIN means the generator is
// not initialised. The byte is not used for anything.
func randomReady() (bool, error) {
	var b [1]byte
	for {
		_, _, errno := syscall.Syscall(sysGetrandom, uintptr(unsafe.Pointer(&b[0])), 1, grndNonblock) //nolint:gosec // G103: the one pointer is to a one-byte array that lives across the call
		switch errno {
		case 0:
			return true, nil
		case syscall.EAGAIN:
			return false, nil
		case syscall.EINTR:
			continue
		default:
			return false, errno
		}
	}
}

// kernelClock asks the kernel how well its clock is disciplined, without changing it (adjtimex with no mode).
func kernelClock() clockState {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return clockState{}
	}
	return clockFromTimex(tx.Offset, tx.Status, state)
}

// clockFromTimex turns what adjtimex answered into the state: the offset in microseconds (the kernel counts nanoseconds
// when STA_NANO is set), and synchronised when neither STA_UNSYNC nor the state TIME_ERROR says not.
func clockFromTimex(offset int64, status int32, state int) clockState {
	if status&staNano != 0 {
		offset /= 1000
	}
	return clockState{Observed: true, Synced: status&staUnsync == 0 && state != timeError, OffsetMicros: offset}
}
