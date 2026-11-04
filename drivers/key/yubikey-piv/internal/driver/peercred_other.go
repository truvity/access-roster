//go:build !linux

package driver

import "net"

// peerUID reads nothing off Linux: every admin call is refused.
func peerUID(net.Conn) (uint32, bool) { return 0, false }
