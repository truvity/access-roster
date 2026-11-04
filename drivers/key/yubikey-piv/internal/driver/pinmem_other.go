//go:build !linux

package driver

import "errors"

var errMemory = errors.New("driver: the PIN cannot be held in locked memory on this system")

// pinMemory is the PIN holder of a system that is not Linux: it holds nothing, so a driver there stays locked.
type pinMemory struct{}

func (*pinMemory) set([]byte) error    { return errMemory }
func (*pinMemory) held() bool          { return false }
func (*pinMemory) get() (string, bool) { return "", false }
func (*pinMemory) wipe()               {}
func (*pinMemory) release()            {}

func hardenProcess() error { return nil }
