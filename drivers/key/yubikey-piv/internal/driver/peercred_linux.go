//go:build linux

package driver

import (
	"net"
	"syscall"
)

// peerUID reads SO_PEERCRED of a Unix socket: the uid of the process that connected, as the kernel recorded it at
// connect time (unix(7)). It is false when the credentials cannot be read.
func peerUID(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred *syscall.Ucred
		serr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || serr != nil {
		return 0, false
	}
	return cred.Uid, true
}
