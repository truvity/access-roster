package driver

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

	"github.com/truvity/sluis/v2/drivers/key/yubikey-piv/internal/card"
	keystorev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/keystore/v2alpha1/keystorev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// AdminConfig is the local admin socket of the driver. It is not part of the actor call graph: the caller is a
// person with a shell on the node, not an actor, so the registry knows no name for it. The caller is known from the
// transport only (SO_PEERCRED), and the check is made before the message, the PIN, is read.
type AdminConfig struct {
	// Socket is the absolute path of the socket.
	Socket string
	// Allow decides from the peer's uid whether it is an administrator. The executable passes "root".
	Allow func(uid uint32) bool
}

const (
	adminMode      = 0o600
	adminReadLimit = 4096
	// pinMin and pinMax are the lengths of a PIV PIN (NIST SP 800-73-4, part 2, 3.2.1: 6 to 8 octets).
	pinMin, pinMax = 6, 8
)

// The reasons of the unlock service.
const (
	reasonCaller  = "caller"
	reasonPIN     = "pin"
	reasonBlocked = "pin_blocked"
	reasonNode    = "node"
	reasonMemory  = "memory"
	// reasonRetries: the card has one attempt left. A wrong PIN would block it and need the PUK, which is the owners'
	// procedure; the driver does not send a PIN then (ADR 0006: a bad unlock cannot lock the card).
	reasonRetries = "pin_retries"
)

// admin implements the unlock service over a Service.
type admin struct {
	keystorev2alpha1connect.UnimplementedUnlockServiceHandler
	s *Service
}

// Status says whether the driver holds the PIN and what the card allows. It asks the card with a VERIFY that
// carries no PIN, which reads the counter and does not change it.
func (a admin) Status(context.Context, *connect.Request[keystorev2alpha1.StatusRequest]) (*connect.Response[keystorev2alpha1.StatusResponse], error) {
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	retries, err := a.s.card.PINRetries()
	if err != nil {
		retries = -1
		if errors.Is(err, card.ErrCardGone) {
			a.s.cardGone("Status")
		}
	}
	return connect.NewResponse(&keystorev2alpha1.StatusResponse{
		Node: a.s.node, Locked: !a.s.pin.held(), PinRetries: int32(retries),
	}), nil
}

// Unlock gives the PIN to the card once. The PIN is first put in locked memory (a PIN the driver cannot keep is not
// sent), then tried. A PIN the card refuses is dropped and never tried again: the card blocks after three wrong PINs
// and then needs the PUK (ADR 0006, "Touch and PIN"). An administrator who mistyped types it again.
func (a admin) Unlock(ctx context.Context, req *connect.Request[keystorev2alpha1.UnlockRequest]) (*connect.Response[keystorev2alpha1.UnlockResponse], error) {
	pin := req.Msg.GetPin()
	defer clear(pin)
	if len(pin) < pinMin || len(pin) > pinMax {
		return nil, refuse(ctx, "Unlock", connect.CodeInvalidArgument, reasonPIN, "pin")
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	if a.s.pin.held() {
		return connect.NewResponse(&keystorev2alpha1.UnlockResponse{}), nil // already unlocked: the card is not asked again
	}
	// Ask the card how many attempts it has left (a VERIFY without a PIN reads the counter and does not change it). With
	// one left, a wrong PIN would block the card; with none it is blocked already. A counter that cannot be read is a
	// refusal too: the driver does not guess.
	retries, rerr := a.s.card.PINRetries()
	switch {
	case errors.Is(rerr, card.ErrCardGone):
		a.s.cardGone("Unlock")
		return nil, refuse(ctx, "Unlock", connect.CodeUnavailable, reasonCard, "")
	case rerr != nil:
		slog.Error("unlock refused: the PIN counter cannot be read", "error", rerr.Error())
		return nil, refuse(ctx, "Unlock", connect.CodeFailedPrecondition, reasonCard, "")
	case retries == 0:
		slog.Error("unlock refused: the card is blocked and needs the PUK")
		return nil, refuse(ctx, "Unlock", connect.CodeFailedPrecondition, reasonBlocked, "pin")
	case retries == 1:
		slog.Error("unlock refused: the card has one PIN attempt left; the PUK procedure is the owners'")
		return nil, refuse(ctx, "Unlock", connect.CodeFailedPrecondition, reasonRetries, "pin")
	}
	if err := a.s.pin.set(pin); err != nil {
		slog.Error("unlock refused: the PIN cannot be held in locked memory", "error", err.Error())
		return nil, refuse(ctx, "Unlock", connect.CodeFailedPrecondition, reasonMemory, "")
	}
	if err := a.s.card.Login(pin); err != nil {
		a.s.pin.wipe()
		if errors.Is(err, card.ErrCardGone) {
			a.s.cardGone("Unlock")
			return nil, refuse(ctx, "Unlock", connect.CodeUnavailable, reasonCard, "")
		}
		var pe *card.PINError
		if errors.As(err, &pe) {
			if pe.Retries == 0 {
				slog.Error("unlock refused: the card is blocked and needs the PUK")
				return nil, refuse(ctx, "Unlock", connect.CodeFailedPrecondition, reasonBlocked, "pin")
			}
			slog.Warn("unlock refused: the card did not accept the PIN", "retries", pe.Retries)
			return nil, refuse(ctx, "Unlock", connect.CodePermissionDenied, reasonPIN, "pin")
		}
		slog.Error("unlock failed", "error", err.Error())
		return nil, refusal.New(connect.CodeInternal, reasonStore, "")
	}
	slog.Info("unlocked: the driver holds the PIN in locked memory")
	return connect.NewResponse(&keystorev2alpha1.UnlockResponse{}), nil
}

// ServeAdmin serves the unlock service on cfg.Socket until ctx ends. The socket is mode 0600 and the peer is
// checked against cfg.Allow before the handler reads the request.
func ServeAdmin(ctx context.Context, cfg AdminConfig, s *Service) error {
	if cfg.Socket == "" || cfg.Allow == nil {
		return errors.New("driver: the admin socket needs a path and a rule for who may use it")
	}
	ln, err := listenAdmin(cfg.Socket)
	if err != nil {
		return err
	}
	path, h := keystorev2alpha1connect.NewUnlockServiceHandler(admin{s: s}, connect.WithReadMaxBytes(adminReadLimit))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // h2c, as every other socket of sluis (kits/go/rpc)
	srv := &http.Server{
		Handler:           guardAdmin(cfg.Allow, mux),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(c context.Context, conn net.Conn) context.Context {
			uid, ok := peerUID(conn)
			return context.WithValue(c, uidKey{}, adminPeer{uid: uid, ok: ok})
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
		return fmt.Errorf("driver: serve the admin socket: %w", err)
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
	uidKey    struct{}
	adminPeer struct {
		uid uint32
		ok  bool
	}
)

// guardAdmin refuses a call whose peer is not an administrator, before the request body is read.
func guardAdmin(allow func(uint32) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(uidKey{}).(adminPeer)
		if !p.ok || !allow(p.uid) {
			slog.Info("admin call refused", "reason", reasonCaller, "uid", p.uid, "path", r.URL.Path)
			// 403 is permission_denied in the Connect protocol; the body is not read.
			http.Error(w, "", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// listenAdmin makes the socket: a stale file is replaced, a symlink, another kind of file or a live socket is
// refused. The socket is made under a temporary name, given its mode and renamed, so that it is never reachable
// with the wrong mode.
func listenAdmin(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("driver: admin socket path %q is not absolute", path)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("driver: admin socket path %q exists and is not a socket", path)
		}
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil, fmt.Errorf("driver: admin socket %q is in use", path)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("driver: remove stale admin socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("driver: admin socket path %q: %w", path, err)
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	tmp := path + ".tmp-" + hex.EncodeToString(rnd[:])
	ln, err := net.Listen("unix", tmp)
	if err != nil {
		return nil, fmt.Errorf("driver: listen: %w", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := os.Chmod(tmp, adminMode); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("driver: chmod admin socket: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = ln.Close()
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("driver: place admin socket: %w", err)
	}
	return ln, nil
}
