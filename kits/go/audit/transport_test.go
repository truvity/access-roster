//go:build sluis_test

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// spool is a TransportService that records the emits and answers with err.
type spool struct {
	transportv2alpha1connect.UnimplementedTransportServiceHandler
	mu   sync.Mutex
	reqs []*transportv2alpha1.EmitRequest
	peer []rpc.Peer
	err  error
}

func (s *spool) Emit(ctx context.Context, r *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r.Msg)
	p, _ := rpc.PeerFromContext(ctx)
	s.peer = append(s.peer, p)
	if s.err != nil {
		return nil, s.err
	}
	return connect.NewResponse(&transportv2alpha1.EmitResponse{}), nil
}

// startSpool serves the spool on a Unix socket, as the emit socket of a boundary; the test process is "key".
func startSpool(t *testing.T, s *spool) transportv2alpha1connect.TransportServiceClient {
	t.Helper()
	dir, err := os.MkdirTemp("", "a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	self := uint32(os.Getuid()) //nolint:gosec // a uid is non-negative
	cfg := rpc.WithNameResolver(rpc.ServerConfig{
		Actor: "driver-writer-spool", Boundary: "dev", Socket: filepath.Join(dir, "emit.sock"),
		Allow: func(p rpc.Peer, _ string) bool { return p.Name == "key" },
	}, func(uid uint32) (string, uint32, bool) { return "key", 0, uid == self })
	path, h := transportv2alpha1connect.NewTransportServiceHandler(s, rpc.HandlerOptions(cfg)...)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(ctx, cfg, rpc.Handler{Path: path, H: h}) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	hc, url := rpc.Dial(cfg.Socket)
	c := transportv2alpha1connect.NewTransportServiceClient(hc, url, rpc.ClientOptions()...)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := c.Ack(context.Background(), connect.NewRequest(&transportv2alpha1.AckRequest{}))
		if connect.CodeOf(err) != connect.CodeUnavailable || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	s.reqs, s.peer = nil, nil
	s.mu.Unlock()
	return c
}

func TestEmitOverTheEmitSocket(t *testing.T) {
	s := &spool{}
	e := newTestEmitter(t, startSpool(t, s), nil)

	if err := e.Emit(context.Background(), signEvent); err != nil {
		t.Fatal(err)
	}
	if err := e.EmitBlocking(rpc.WithCorrelationID(context.Background(), "req-9"), signEvent); err != nil {
		t.Fatal(err)
	}
	if len(s.reqs) != 2 || s.reqs[0].GetBlocking() || !s.reqs[1].GetBlocking() {
		t.Fatalf("requests = %v", s.reqs)
	}
	if s.peer[0].Name != "key" {
		t.Errorf("peer = %+v", s.peer[0])
	}
	if len(s.reqs[1].GetMessage().GetRecord()) == 0 || s.reqs[1].GetMessage().GetUid() == "" {
		t.Error("the message is empty")
	}
}

func TestABlockingEmitReturnsTheTransportsErrorAndDoesNotRetry(t *testing.T) {
	s := &spool{err: refusal.New(connect.CodeUnavailable, "engine", "")}
	e := newTestEmitter(t, startSpool(t, s), nil)

	err := e.EmitBlocking(context.Background(), signEvent)
	if err == nil {
		t.Fatal("the transport's error was swallowed")
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
	if reason, _ := refusal.Reason(err); reason != "engine" {
		t.Errorf("reason = %q", reason)
	}
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) != 1 || !s.reqs[0].GetBlocking() {
		t.Fatalf("the transport saw %d requests, want 1 with blocking=true", len(s.reqs))
	}
}
