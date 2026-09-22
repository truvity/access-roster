package audit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	auditv1 "github.com/truvity/audit/gen/audit/v1"
	"github.com/truvity/audit/gen/audit/v1/auditv1connect"

	"github.com/truvity/access-roster/internal/audit"
)

// installation is a receiver: it answers the catalogue's registration and
// the sink on one address, the way the real one does, and can be told to
// refuse either.
type installation struct {
	auditv1connect.UnimplementedRegistryServiceHandler
	auditv1connect.UnimplementedSinkServiceHandler
	mu            sync.Mutex
	problems      []string // registration is refused with these, when set
	sinkDown      atomic.Bool
	unauth        atomic.Bool
	written       atomic.Int64
	registrations atomic.Int64
}

func (i *installation) RegisterCatalogue(
	_ context.Context, _ *connect.Request[auditv1.RegisterCatalogueRequest],
) (*connect.Response[auditv1.RegisterCatalogueResponse], error) {
	i.registrations.Add(1)
	if i.unauth.Load() {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no"))
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return connect.NewResponse(&auditv1.RegisterCatalogueResponse{Problems: i.problems}), nil
}

func (i *installation) Write(
	_ context.Context, req *connect.Request[auditv1.WriteRequest],
) (*connect.Response[auditv1.WriteResponse], error) {
	if i.sinkDown.Load() {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("the archive is unreachable"))
	}
	n := int32(len(req.Msg.GetRecords()))
	i.written.Add(int64(n))
	return connect.NewResponse(&auditv1.WriteResponse{Accepted: n}), nil
}

func serve(t *testing.T, i *installation) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(auditv1connect.NewRegistryServiceHandler(i))
	mux.Handle(auditv1connect.NewSinkServiceHandler(i))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("a-projected-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A connected trail registers on the receiver's own address, and a block
// record is kept there before RecordDurable returns.
func TestAConnectedTrailRegistersAndKeepsABlockRecord(t *testing.T) {
	inst := &installation{}
	srv := serve(t, inst)
	trail, err := audit.Open(context.Background(), audit.Config{Writer: srv.URL, TokenFile: tokenFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	if !trail.Connected() || inst.registrations.Load() != 1 {
		t.Fatalf("connected=%v registrations=%d", trail.Connected(), inst.registrations.Load())
	}
	err = trail.RecordDurable(context.Background(),
		audit.RecoverySignedIn(audit.RecoveryIdentity("recovery"), "console", "recovery", audit.Succeeded()))
	if err != nil {
		t.Fatalf("a block record against a working sink: %v", err)
	}
	if inst.written.Load() == 0 {
		t.Fatal("RecordDurable returned before the receiver had the record")
	}
}

// With the sink down, a block record fails -- that is what refuses a
// recovery sign-in -- while an async record is accepted into the queue and
// the request it belongs to goes on.
func TestABlockRecordFailsWhenTheSinkIsDownAndAsyncDoesNot(t *testing.T) {
	inst := &installation{}
	srv := serve(t, inst)
	trail, err := audit.Open(context.Background(), audit.Config{Writer: srv.URL, TokenFile: tokenFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	inst.sinkDown.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = trail.RecordDurable(ctx,
		audit.RecoverySignedIn(audit.RecoveryIdentity("recovery"), "console", "recovery", audit.Succeeded()))
	if err == nil || !strings.Contains(err.Error(), "could not be kept") {
		t.Fatalf("a block record with the sink down = %v, want a refusal", err)
	}
	// Async: no error to the caller, ever.
	trail.Record(context.Background(), audit.SignedIn(audit.Person("a@example.com"), "console", "google", audit.Succeeded()))
}

// RecordDurable on an action the catalogue declares async is a bug in the
// caller, and is refused rather than answered with a durability it does not
// have.
func TestRecordDurableRefusesAnAsyncAction(t *testing.T) {
	inst := &installation{}
	srv := serve(t, inst)
	trail, err := audit.Open(context.Background(), audit.Config{Writer: srv.URL, TokenFile: tokenFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	err = trail.RecordDurable(context.Background(),
		audit.SignedIn(audit.Person("a@example.com"), "console", "google", audit.Succeeded()))
	if err == nil || !strings.Contains(err.Error(), "not a block action") {
		t.Fatalf("got %v, want a refusal naming the delivery", err)
	}
}

// A catalogue refused at start stops the start.
func TestACatalogueRefusedAtStartStopsTheStart(t *testing.T) {
	inst := &installation{problems: []string{"action roster.person.signed_in: no such category"}}
	srv := serve(t, inst)
	_, err := audit.Open(context.Background(), audit.Config{Writer: srv.URL, TokenFile: tokenFile(t)})
	if err == nil || !strings.Contains(err.Error(), "refused the catalogue") {
		t.Fatalf("got %v, want the refusal", err)
	}
}

// An installation unreachable at start does not stop the start; registration
// is retried, and a refusal on that retry reaches OnFatal.
func TestARefusalFoundOnRetryIsFatal(t *testing.T) {
	inst := &installation{unauth: atomic.Bool{}}
	inst.unauth.Store(true) // the first attempt fails: not reachable in the sense that matters
	srv := serve(t, inst)
	fatal := make(chan error, 1)
	trail, err := audit.Open(context.Background(), audit.Config{
		Writer: srv.URL, TokenFile: tokenFile(t),
		OnFatal: func(err error) { fatal <- err },
	})
	if err != nil {
		t.Fatalf("an unreachable installation stopped the start: %v", err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	// Now it answers, and refuses.
	inst.mu.Lock()
	inst.problems = []string{"action roster.person.signed_in: no such category"}
	inst.mu.Unlock()
	inst.unauth.Store(false)
	select {
	case err := <-fatal:
		if !strings.Contains(err.Error(), "refused the catalogue") {
			t.Fatalf("OnFatal got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a refusal on retry did not reach OnFatal")
	}
}
