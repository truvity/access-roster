package rpc

import (
	"context"
	"net"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// Peer is the caller of a call, as the transport knows it.
type Peer struct {
	UID, GID uint32
	PID      int32
	Name     string // the actor or driver name of the uid: registry.NameForUID
	UIDBlock uint32 // the uid block of the caller's boundary: registry.NameForUID
}

// NameResolver maps a uid to a name and a uid block. The default is registry.NameForUID.
type NameResolver func(uid uint32) (name string, uidBlock uint32, ok bool)

type peerKey struct{}

// connPeer is what ConnContext stores: the credentials of the connection, and whether they could be read and
// named. A connection whose credentials could not be read, or whose uid is not in the registry, has known == false.
type connPeer struct {
	Peer
	known bool
}

// PeerFromContext returns the caller of the call that ctx belongs to. It is false when the credentials were not
// read or the uid is not in the registry; the interceptor never lets such a call reach a handler.
func PeerFromContext(ctx context.Context) (Peer, bool) {
	p, ok := ctx.Value(peerKey{}).(connPeer)
	if !ok || !p.known {
		return Peer{}, false
	}
	return p.Peer, true
}

func withPeer(ctx context.Context, p connPeer) context.Context {
	return context.WithValue(ctx, peerKey{}, p)
}

// peerOf reads the peer credentials of a connection once and names the uid.
func peerOf(c net.Conn, resolve NameResolver) connPeer {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return connPeer{}
	}
	cred, err := peerCred(uc)
	if err != nil {
		return connPeer{}
	}
	p := connPeer{Peer: Peer{UID: cred.uid, GID: cred.gid, PID: cred.pid}}
	if resolve == nil {
		resolve = registry.NameForUID
	}
	if name, block, ok := resolve(cred.uid); ok && name != "" {
		p.Name, p.UIDBlock, p.known = name, block, true
	}
	return p
}

type ucred struct {
	uid, gid uint32
	pid      int32
}

// OwnerOnly allows only the owner of a driver: the driver's socket serves nobody else (docs/architecture, the
// socket layout). The owner is the actor's registry name, e.g. registry.DriverOwner("driver-store-rqlite").
func OwnerOnly(owner string) func(Peer, string) bool {
	return ExactCaller(owner)
}

// ExactCaller allows only the caller with the given name. key@ passes it per socket, one socket for each caller.
func ExactCaller(name string) func(Peer, string) bool {
	return func(p Peer, _ string) bool { return name != "" && p.Name == name }
}
