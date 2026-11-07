//go:build !linux

package main

// realHost is a host that is not Linux: the checks of the kernel cannot run, and say so.
func realHost() *host { return &host{} }
