//go:build linux

package rpc

import (
	"fmt"
	"net"
	"syscall"
)

// peerCred reads SO_PEERCRED of a Unix socket: the pid, uid and gid of the process that connected, as the kernel
// recorded them at connect time (unix(7)).
func peerCred(c *net.UnixConn) (ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return ucred{}, err
	}
	var (
		cred *syscall.Ucred
		serr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return ucred{}, err
	}
	if serr != nil {
		return ucred{}, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return ucred{uid: cred.Uid, gid: cred.Gid, pid: cred.Pid}, nil
}
