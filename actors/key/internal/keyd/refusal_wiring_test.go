//go:build sluis_test

package keyd

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// verifies: REQ-KEYS-031
// The audit fact of a refusal of a handler is made under the context of the request, so it carries the caller's correlation
// id: the refused Sign is asked under an id and the fact is emitted under the same one.
func TestAHandlersRefusalFactCarriesTheCorrelationID(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	ctx := rpc.WithCorrelationID(context.Background(), "corr-0192f4a0")
	if _, err := n.client("signer").Sign(ctx, signReq("audit-log", []byte("x"))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Sign = %v", err)
	}
	got := n.audit.correlationOf(ActionRefuse)
	if len(got) != 1 || got[0] != "corr-0192f4a0" {
		t.Fatalf("the refusal fact was emitted under correlation ids %v, want [corr-0192f4a0]", got)
	}
}

// floodFor makes the call, which must be refused, as fast as the socket allows for the time, and returns how many it made.
func floodFor(t *testing.T, d time.Duration, call func() error) int {
	t.Helper()
	count := 0
	for end := time.Now().Add(d); time.Now().Before(end); count++ {
		if err := call(); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("the flood got %v", err)
		}
	}
	return count
}

// verifies: REQ-KEYS-031, REQ-AUDIT-180
// The caps of Config reach both limiters. Over a couple of seconds of windows of 150 ms and a burst of 10, which would make
// well over a hundred facts without a cap: the handlers' limiter stops at RefusalHourly for one caller and reason and at
// RefusalTotal for all its keys, and the guard's stops at the same numbers for a peer. Without the numbers being passed on,
// the default of 60 and 120 would let more through, and each case below asks for fewer. With the defaults themselves
// (negative in the options), a flood of a few seconds makes no more than the default hourly cap of 60 facts, and the counts
// that the hour held back are all reported when the node stops.
func TestTheCapsOfTheConfigReachTheHandlersAndTheGuard(t *testing.T) {
	signer := func(n *node) func() error {
		return func() error {
			_, err := n.client("signer").Sign(context.Background(), signReq("audit-log", []byte("x")))
			return err
		}
	}
	stranger := func(n *node) func() error {
		c := n.as("exchange", "session")
		return func() error {
			_, err := seal1(c, "cookie", "cookie", "", "s1", []byte("x"), nil)
			return err
		}
	}
	facts := func(n *node, reasons ...string) int {
		total := 0
		for _, r := range reasons {
			_, _, f := ruleFacts(n, r)
			total += f
		}
		return total
	}
	cases := []struct {
		name    string
		opts    nodeOpts
		call    func(*node) func() error
		reasons []string
		most    int
	}{
		{"the handlers' hourly cap", nodeOpts{refusalHourly: 7}, signer, []string{reasonRule}, 7},
		{"the handlers' total", nodeOpts{refusalTotal: 12}, signer, []string{reasonRule}, 12},
		{"the guard's hourly cap", nodeOpts{refusalHourly: 9}, stranger, []string{"call_graph"}, 9},
		{"the guard's total", nodeOpts{refusalTotal: 11}, stranger, []string{"call_graph"}, 11},
		{"the default hourly cap of the handlers", nodeOpts{refusalHourly: -1, refusalTotal: -1}, signer, []string{reasonRule}, 60},
		{"the default hourly cap of the guard", nodeOpts{refusalHourly: -1, refusalTotal: -1}, stranger, []string{"call_graph"}, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, "development")
			c.opts.refusalWindow, c.opts.refusalBurst = 150*time.Millisecond, 10
			n := e.startedNode(c.opts)
			total := floodFor(t, 3*time.Second, c.call(n))
			time.Sleep(400 * time.Millisecond)
			if got := facts(n, c.reasons...); got < min(c.most, 11) || got > c.most {
				t.Fatalf("%d facts for %d refusals in about 20 windows, want between %d and %d", got, total, min(c.most, 11), c.most)
			}
			// Nothing is lost: what the caps held back is reported when the node stops.
			n.stop()
			singles, folded := 0, 0
			for _, r := range c.reasons {
				s, f, _ := ruleFacts(n, r)
				singles, folded = singles+s, folded+f
			}
			if singles+folded != total {
				t.Fatalf("after the stop %d single facts + %d folded = %d, want %d", singles, folded, singles+folded, total)
			}
		})
	}
}

// verifies: REQ-KEYS-031
// A request of an allowed caller that Connect cannot decode is a refusal with a trace: the same limiter counts it under
// (caller, "undecodable"), and a refusal of a handler for a request that did decode (it has the Refusal detail) is not
// taken for one. A hundred malformed requests make the burst of facts and a count, and the answer is the same Connect error.
func TestAMalformedRequestOfAnAllowedCallerIsCountedNotSilent(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalWindow: time.Hour, refusalBurst: 10})
	n.as("signer", "signer")
	hc, url := rpc.Dial(n.runDir + "/signer/" + socketName)
	post := func(path, body string) int {
		req, _ := http.NewRequest(http.MethodPost, url+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	const seal = "/sluis.key.v2alpha1.KeyService/Seal"
	for range 100 {
		if code := post(seal, "{not json"); code != http.StatusBadRequest {
			t.Fatalf("a malformed request got %d, want 400", code)
		}
	}
	undec := func() (singles, folded int) { s, f, _ := ruleFacts(n, reasonUndecodable); return s, f }
	if s, f := undec(); s != 10 || f != 0 {
		t.Fatalf("%d single facts and %d folded before the stop, want 10 and none", s, f)
	}
	for _, ev := range n.audit.all() {
		if ev.Reason == reasonUndecodable && (field(ev, "caller") != "signer" || field(ev, "op") != "seal" || field(ev, "code") != "invalid_argument") {
			t.Fatalf("the fact is %+v, want caller signer, op seal, code invalid_argument", ev.Fields)
		}
	}
	// A request that decodes and that the handler refuses (no purpose) is a refusal of its own reason, not an undecodable one.
	before, _ := undec()
	if code := post(seal, `{"purpose":"data","address":{"kind":"x","tenant":"acme","id":"AAAA"},"plaintext":"eA=="}`); code == http.StatusOK {
		t.Fatal("the signer sealed")
	}
	if after, _ := undec(); after != before {
		t.Fatal("a refusal of a handler was taken for an undecodable request")
	}
	n.stop()
	if s, f := undec(); s != 10 || f != 90 {
		t.Fatalf("after the stop %d single facts and %d folded, want 10 and 90", s, f)
	}
}
