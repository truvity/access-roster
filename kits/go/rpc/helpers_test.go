//go:build sluis_test

package rpc_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	conformancev2alpha1 "github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1"
	"github.com/truvity/sluis/v2/kits/conformance/kit/gen/go/sluis/conformance/v2alpha1/conformancev2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// asSelf resolves the uid of the test process to the given name and uid block. The registry's pinned uids do not
// apply to a test that runs as an ordinary user.
func asSelf(name string, block uint32) rpc.NameResolver {
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	return func(uid uint32) (string, uint32, bool) { return name, block, uid == self }
}

// shortDir returns a short temporary directory: a Unix socket path holds about 108 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// recorder is an EchoService that records what its handler saw.
type recorder struct {
	conformancev2alpha1connect.UnimplementedEchoServiceHandler
	calls    chan struct{} // one value per call that reached a method
	peer     chan rpc.Peer
	deadline chan time.Duration // the time left of the deadline, or -1 when there is none
	corr     chan string
	// next, when set, is called by Echo with the context of the call (a nested call).
	next func(ctx context.Context) (string, error)
}

func newRecorder() *recorder {
	return &recorder{
		calls: make(chan struct{}, 16), peer: make(chan rpc.Peer, 16),
		deadline: make(chan time.Duration, 16), corr: make(chan string, 16),
	}
}

func (r *recorder) Echo(ctx context.Context, req *connect.Request[conformancev2alpha1.EchoRequest]) (*connect.Response[conformancev2alpha1.EchoResponse], error) {
	r.calls <- struct{}{}
	if p, ok := rpc.PeerFromContext(ctx); ok {
		r.peer <- p
	}
	d := time.Duration(-1)
	if dl, ok := ctx.Deadline(); ok {
		d = time.Until(dl)
	}
	r.deadline <- d
	r.corr <- rpc.CorrelationID(ctx)
	msg := req.Msg.GetMessage()
	if r.next != nil {
		var err error
		if msg, err = r.next(ctx); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(&conformancev2alpha1.EchoResponse{Message: msg}), nil
}

func (r *recorder) Count(_ context.Context, _ *connect.Request[conformancev2alpha1.CountRequest], _ *connect.ServerStream[conformancev2alpha1.CountResponse]) error {
	r.calls <- struct{}{}
	return nil
}

// start serves the recorder on a new socket and returns the socket path and a function that stops the server and
// waits for it. The server is stopped at the end of the test.
func start(t *testing.T, cfg rpc.ServerConfig, svc conformancev2alpha1connect.EchoServiceHandler) (socket string, stop func()) {
	t.Helper()
	if cfg.Socket == "" {
		cfg.Socket = filepath.Join(shortDir(t), "s.sock")
	}
	path, h := conformancev2alpha1connect.NewEchoServiceHandler(svc, rpc.HandlerOptions(cfg)...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	waitSocket(t, cfg.Socket, done)
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after its context ended")
		}
	}
	t.Cleanup(stop)
	return cfg.Socket, stop
}

func waitSocket(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("Serve returned early: %v", err)
		default:
		}
		// A dial that succeeds proves a server listens; a stale socket file proves nothing.
		if c, err := net.Dial("unix", path); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("socket %s did not appear", path)
}

func echoClient(socket string, withKit bool) conformancev2alpha1connect.EchoServiceClient {
	hc, url := rpc.Dial(socket)
	if withKit {
		return conformancev2alpha1connect.NewEchoServiceClient(hc, url, rpc.ClientOptions()...)
	}
	return conformancev2alpha1connect.NewEchoServiceClient(hc, url)
}

func recv[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not report")
		panic("unreachable")
	}
}

func none[T any](t *testing.T, c <-chan T, what string) {
	t.Helper()
	select {
	case <-c:
		t.Fatalf("%s: the handler was entered", what)
	case <-time.After(50 * time.Millisecond):
	}
}
