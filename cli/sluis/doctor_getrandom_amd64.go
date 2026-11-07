//go:build linux && amd64

package main

// sysGetrandom is the number of getrandom(2); the syscall package, which is frozen, does not name it.
const sysGetrandom = 318
