//go:build !linux

package writerd

// kernelClock has nothing to ask on a system without adjtimex: the writer runs on Linux only, and this file lets the
// package build elsewhere.
func kernelClock() clockObservation { return clockObservation{} }
