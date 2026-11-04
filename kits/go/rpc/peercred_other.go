//go:build !linux

package rpc

import (
	"errors"
	"net"
)

// peerCred is not available off Linux: sluis serves on Linux only, and a development build elsewhere refuses
// every call (no peer, so no caller).
func peerCred(*net.UnixConn) (ucred, error) {
	return ucred{}, errors.New("peer credentials need Linux")
}
