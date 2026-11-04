package rpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/registry"
)

// shutdownGrace bounds the graceful shutdown of a server (the brief of the kit: 5 s).
const shutdownGrace = 5 * time.Second

// readMaxBytes bounds a request message; it is far above any message of the contracts.
const readMaxBytes = 4 << 20

// ServerConfig is the configuration of one server: one actor or driver, on one socket.
type ServerConfig struct {
	Actor    string // the callee's registry name, e.g. "store"
	Boundary string
	Socket   string      // absolute path; see the socket layout in docs
	Mode     os.FileMode // 0660 for actor sockets, 0600 for driver sockets; 0 means 0660
	// GID, when not 0, is the group of the socket file. A driver whose owner is another uid sets it with Mode 0660, so
	// that the members of the group, and only they, can connect to the socket. The process must be a member of the
	// group. It changes who may connect and nothing else: the guard still decides, from the peer's uid, who may call.
	// The default, 0, leaves the group the kernel gave and the mode as it is.
	GID uint32
	// DefaultDeadline is the deadline of a call that carries none. 0 means DefaultDeadlineValue.
	DefaultDeadline time.Duration
	// Allow decides whether a peer may call. The default (nil) is registry.MayCall(peer.Name, Actor).
	// Drivers pass OwnerOnly(owner); key@ passes ExactCaller(name) per socket.
	Allow func(peer Peer, procedure string) bool

	resolve NameResolver
}

// Handler is one generated service: the path and handler that New<Service>Handler returns.
type Handler struct {
	Path string
	H    http.Handler
}

// ownBlock returns the uid block of this process: the block of the boundary this server serves, taken from the
// process's own uid as the registry maps it (REQ-ISO-072: uid = 61000 + ordinal + 1000 x block). A caller from
// another block is refused. It is false when the process's uid is not an actor or driver uid.
func (c ServerConfig) ownBlock() (uint32, bool) {
	resolve := c.resolve
	if resolve == nil {
		resolve = registry.NameForUID
	}
	name, block, ok := resolve(uint32(os.Getuid())) //nolint:gosec // a uid is non-negative
	return block, ok && name != ""
}

func (c ServerConfig) deadline() DeadlineDefault {
	d := c.DefaultDeadline
	if d == 0 {
		d = DefaultDeadlineValue
	}
	return DeadlineDefault{d}
}

// HandlerOptions returns the options of every generated New<Service>Handler of a server: the interceptor with the
// default-deny check, the correlation id and the default deadline. The server wraps the handlers in the same
// check at the HTTP layer, so a refused call is answered before its message is decoded.
func HandlerOptions(cfg ServerConfig) []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithInterceptors(interceptor{guard: newGuard(cfg), deadline: cfg.deadline()}),
		connect.WithReadMaxBytes(readMaxBytes),
	}
}

// Serve listens on cfg.Socket (removing a stale socket file, refusing a symlink), sets its mode, reads
// SO_PEERCRED once per connection, and serves the handlers through h2c with the check in front of every
// procedure. It returns when ctx ends, after a graceful shutdown bounded by 5 s.
func Serve(ctx context.Context, cfg ServerConfig, handlers ...Handler) error {
	if cfg.Actor == "" {
		return errors.New("rpc: ServerConfig.Actor is empty")
	}
	mode := cfg.Mode
	if mode == 0 {
		mode = 0o660
	}
	if _, ok := cfg.ownBlock(); !ok {
		return errors.New("rpc: the uid of this process is not an actor or driver uid of the registry")
	}
	ln, err := listen(cfg.Socket, mode, cfg.GID)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	for _, h := range handlers {
		mux.Handle(h.Path, h.H)
	}
	srv := &http.Server{
		Handler:           newGuard(cfg).middleware(newDenyHandlers(), mux),
		Protocols:         serverProtocols(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
		ConnContext: func(c context.Context, conn net.Conn) context.Context {
			return withPeer(c, peerOf(conn, cfg.resolve))
		},
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	defer func() { _ = os.Remove(cfg.Socket) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("rpc: serve %s: %w", cfg.Actor, err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		slog.Warn("server shutdown timed out; closed", "actor", cfg.Actor)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("rpc: serve %s: %w", cfg.Actor, err)
	}
	return nil
}

// listen makes the socket of a server. A stale socket file is replaced; a symlink, another kind of file, or a
// socket that a live server holds is refused. The socket is created under a temporary name, given its mode, and
// renamed to its path, so that it is never reachable with the wrong mode or group.
func listen(path string, mode os.FileMode, gid uint32) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("rpc: socket path %q is not absolute", path)
	}
	fi, err := os.Lstat(path)
	switch {
	case err == nil:
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			return nil, fmt.Errorf("rpc: socket path %q is a symlink", path)
		case fi.Mode()&os.ModeSocket == 0:
			return nil, fmt.Errorf("rpc: socket path %q exists and is not a socket", path)
		}
		c, derr := net.DialTimeout("unix", path, time.Second)
		if derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("rpc: socket %q is in use", path)
		}
		if !errors.Is(derr, os.ErrNotExist) && !isRefused(derr) {
			return nil, fmt.Errorf("rpc: socket %q: %w", path, derr)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("rpc: remove stale socket: %w", err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("rpc: socket path %q: %w", path, err)
	}

	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(rnd[:])
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("rpc: listen: %w", err)
	}
	ul := ln.(*net.UnixListener)
	ul.SetUnlinkOnClose(false)
	if gid != 0 {
		// The group is set before the mode, and both before the final name, so that the socket is never reachable by a
		// group that was not asked for.
		if err := os.Chown(tmp, -1, int(gid)); err != nil {
			_ = ul.Close()
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("rpc: set the socket group: %w", err)
		}
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = ul.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("rpc: chmod socket: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ul.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("rpc: place socket: %w", err)
	}
	return ln, nil
}
