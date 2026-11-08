//go:build sluis_test

package keyd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	transportv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1"
	"github.com/truvity/sluis/v2/gen/go/sluis/port/transport/v2alpha1/transportv2alpha1connect"
	"github.com/truvity/sluis/v2/kits/go/audit"
)

// downTransport is a spool that refuses every emit, and counts them.
type downTransport struct {
	transportv2alpha1connect.TransportServiceClient
	mu    sync.Mutex
	calls int
}

func (d *downTransport) Emit(context.Context, *connect.Request[transportv2alpha1.EmitRequest]) (*connect.Response[transportv2alpha1.EmitResponse], error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return nil, errors.New("spool full")
}

func (d *downTransport) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// lostAuditor is key@'s Auditor as the binary makes it (actors/key/audit.go): the real emitter of the library, with the action
// table of sluis, on a spool that is full. Its Lost() is the total that the next record would carry.
type lostAuditor struct{ e *audit.Emitter }

func newLostAuditor(t *testing.T, tr transportv2alpha1connect.TransportServiceClient) *lostAuditor {
	t.Helper()
	e, err := audit.New(audit.Config{Actor: "key", Boundary: testBoundary, Release: "0.0.0-test", Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	return &lostAuditor{e}
}

func (a *lostAuditor) Emit(ctx context.Context, ev Event) error {
	return EmitFact(ctx, a.e, ev)
}

// waitLost waits for the emitter's total to reach want, then checks that it stays there: a refusal counted twice, or a summary
// counted as one, would show.
func waitLost(t *testing.T, a *lostAuditor, want int64) {
	t.Helper()
	for end := time.Now().Add(15 * time.Second); a.e.Lost() < want && time.Now().Before(end); {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	if got := a.e.Lost(); got != want {
		t.Fatalf("Lost() = %d, want %d: every refusal is either a fact whose loss is one or a count in a summary whose loss is its number", got, want)
	}
}

// verifies: REQ-AUDIT-186, REQ-AUDIT-180
// One caller's limiter in key@'s handlers is saturated while the spool is full. Each refusal is a fact (the burst), whose loss
// is one, or is folded into the summary of its window, whose loss is the number it carries: the total of lost facts is the
// number of refusals, through the producers of refuse.go and the real emitter. A summary counted as one fact would give 2 + 1.
func TestALostSummaryOfAHandlerLimiterCountsEveryRefusal(t *testing.T) {
	e := newTestEnv(t, "development")
	tr := &downTransport{}
	a := newLostAuditor(t, tr)
	n := e.startedNode(nodeOpts{audit: a, refusalWindow: time.Second, refusalBurst: 2})
	const total = 40
	base := a.e.Lost() // the facts of the start (key.start, the wraps) were lost as well
	for range total {
		_, err := seal1(n.client("exchange"), "cookie", "cookie", "", "s1", []byte("x"), nil)
		wantRefusalNamed(t, "a handler refusal", err, connect.CodePermissionDenied, "rule")
	}
	waitLost(t, a, base+total)
	if calls := tr.count(); calls < 2 || calls >= total {
		t.Fatalf("%d emits for %d refusals: want a burst and a summary, and fewer than one for each", calls, total)
	}
}

// verifies: REQ-AUDIT-186, REQ-AUDIT-180
// The same for the guard of a socket: a peer that is not the caller of it, refused 40 times, through auditTransportRefusal.
func TestALostSummaryOfTheGuardCountsEveryRefusal(t *testing.T) {
	e := newTestEnv(t, "development")
	tr := &downTransport{}
	a := newLostAuditor(t, tr)
	n := e.startedNode(nodeOpts{audit: a, refusalWindow: time.Second, refusalBurst: 2})
	stranger := n.as("exchange", "session")
	const total = 40
	base := a.e.Lost()
	for range total {
		_, err := seal1(stranger, "cookie", "cookie", "", "s1", []byte("x"), nil)
		wantRefusalNamed(t, "a guard refusal", err, connect.CodePermissionDenied, "call_graph")
	}
	waitLost(t, a, base+total)
	if calls := tr.count(); calls < 2 || calls >= total {
		t.Fatalf("%d emits for %d refusals: want a burst and a summary, and fewer than one for each", calls, total)
	}
}
