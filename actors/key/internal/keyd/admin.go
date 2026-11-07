package keyd

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

	"github.com/truvity/sluis/v2/gen/go/sluis/key/v2alpha1/keyv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/signedconfig"
)

// The admin socket of key@ is where an operator delivers a key revocation declaration (ADR 0041, "A person declares,
// and a suspicion counts"): <run-dir>/admin.sock, mode 0600 in key@'s own run directory, served only to root, as the
// card driver's admin socket is (ADR 0006, "Touch and PIN"). It is not part of the actor call graph: the caller is a
// person with a shell on the node, whom the registry has no name for, and the peer is checked from the transport
// (SO_PEERCRED) before the request is read. The channel only carries the declaration; its authority is the signature.

// adminSocketName is the admin socket in the run directory.
const adminSocketName = "admin.sock"

// adminReadLimit bounds a request on the admin socket: a declaration is at most signedconfig.MaxDocument.
const adminReadLimit = signedconfig.MaxDocument + 4096

// serveAdmin serves KeyAdminService on the admin socket until ctx ends.
func (s *Server) serveAdmin(ctx context.Context) error {
	path := filepath.Join(s.cfg.RunDir, adminSocketName)
	ln, err := listenAdmin(path)
	if err != nil {
		return err
	}
	hpath, h := keyv2alpha1connect.NewKeyAdminServiceHandler(s, connect.WithReadMaxBytes(adminReadLimit))
	mux := http.NewServeMux()
	mux.Handle(hpath, h)
	// The hand-off calls share the socket, and so the root-only guard (handoff.go).
	hopath, ho := keyv2alpha1connect.NewKeyHandoffServiceHandler(s, connect.WithReadMaxBytes(maxHandoffRequest))
	mux.Handle(hopath, ho)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // h2c, as every other socket of sluis (kits/go/rpc)
	srv := &http.Server{
		Handler:           guardAdmin(s.adminAllow, mux),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(c context.Context, conn net.Conn) context.Context {
			uid, ok := peerUID(conn)
			return context.WithValue(c, adminPeerKey{}, adminPeer{uid: uid, ok: ok})
		},
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	defer func() { _ = os.Remove(path) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("the admin socket: %w", err)
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
	}
	return nil
}

type (
	adminPeerKey struct{}
	adminPeer    struct {
		uid uint32
		ok  bool
	}
)

// adminPeerOf is the uid of the peer of an admin call, from the transport.
func adminPeerOf(ctx context.Context) (uint32, bool) {
	p, ok := ctx.Value(adminPeerKey{}).(adminPeer)
	return p.uid, ok && p.ok
}

// rootOnly is the rule of the admin socket: only root.
func rootOnly(uid uint32) bool { return uid == 0 }

// guardAdmin refuses a call whose peer is not root, before the request body is read.
func guardAdmin(allow func(uint32) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(adminPeerKey{}).(adminPeer)
		if !p.ok || allow == nil || !allow(p.uid) {
			slog.Info("admin call refused", "reason", reasonCaller, "uid", p.uid, "path", r.URL.Path)
			// 403 is permission_denied in the Connect protocol; the body is not read.
			http.Error(w, "", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// listenAdmin makes the socket: a stale file is replaced, a symlink, another kind of file or a live socket is refused.
// The socket is made under a temporary name, given its mode and renamed, so that it is never reachable with a wider
// mode.
func listenAdmin(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("admin socket path %q exists and is not a socket", path)
		}
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("admin socket %q is in use", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("remove the stale admin socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("admin socket path %q: %w", path, err)
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(rnd[:])
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("listen on the admin socket: %w", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("chmod the admin socket: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("place the admin socket: %w", err)
	}
	return ln, nil
}
