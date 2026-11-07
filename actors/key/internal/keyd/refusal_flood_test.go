//go:build sluis_test

package keyd

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/rpc"
)

// transportFacts adds up the refusals that the guard's facts account for: one for each fact of a single refusal, and the
// number folded for each summary.
func transportFacts(n *node) (singles, folded, facts int) {
	for _, ev := range n.audit.all() {
		if ev.Action != ActionRefuse || (ev.Reason != "call_graph" && ev.Reason != "caller") {
			continue
		}
		facts++
		if k, ok := ev.Fields["suppressed"].(int64); ok {
			folded += int(k)
		} else {
			singles++
		}
	}
	return
}

// verifies: REQ-KEYS-031, REQ-AUDIT-180
// A peer that is not the caller of a socket cannot fill the audit spool and stop the signatures. 100,000 refusals of one
// peer at the guard write a bounded number of facts (the burst of 10 and one summary for each window of the limiter),
// every refusal is either one of them or counted in a summary, and none of them is lost; key@ signs a token with a blocking
// audit fact straight after; and a refusal after the window is audited again. The worst case of the whole socket set is
// the burst and a summary for each peer uid and reason on each of key@'s sockets in each window: about 30 sockets, a
// socket's directory letting in one uid besides root, two reasons, 22 facts a window, 660 a minute at the most, and in
// practice (one peer, one reason) 11.
func TestAFloodOfRefusalsAtTheGuardIsCountedAndSigningGoesOn(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalWindow: 2 * time.Second, refusalBurst: 10, refusalHourly: 60})
	_, kid := publicKey(t, n, "signer", "token-signing")
	stranger := n.as("exchange", "session")
	const total = 100_000
	var next atomic.Int64
	var wg sync.WaitGroup
	began := time.Now()
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for next.Add(1) <= total {
				if _, err := seal1(stranger, "cookie", "cookie", "", "s1", []byte("x"), nil); connect.CodeOf(err) != connect.CodePermissionDenied {
					t.Errorf("the stranger got %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d refusals in %v", total, time.Since(began))
	time.Sleep(2500 * time.Millisecond) // the window ends and its timer folds the rest
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, folded, _ := transportFacts(n); folded > 0 {
			break
		}
	}
	singles, folded, facts := transportFacts(n)
	if singles+folded != total {
		t.Fatalf("%d single facts + %d folded = %d, want %d: a refusal is neither audited nor counted", singles, folded, singles+folded, total)
	}
	// 100,000 requests take a few seconds: they fall in a few windows of 2 s, each of which is a burst of 10 and a summary.
	windows := int(time.Since(began)/(2*time.Second)) + 2
	if facts > windows*11 || facts < 11 {
		t.Fatalf("%d facts for %d refusals in about %d windows, want at most 11 for each window", facts, total, windows)
	}
	// Signing goes on with the flood over: the blocking audit fact of the signature is made.
	if _, err := n.client("signer").Sign(context.Background(), signReq("token-signing", tokenInput(kid, "", ""))); err != nil {
		t.Fatalf("Sign after the flood: %v", err)
	}
	// A refusal after the window is audited again, one by one.
	_, err := seal1(stranger, "cookie", "cookie", "", "s1", []byte("x"), nil)
	wantRefusalNamed(t, "a refusal after the flood", err, connect.CodePermissionDenied, "call_graph")
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if s, _, _ := transportFacts(n); s > singles {
			return
		}
	}
	t.Fatal("a refusal after the window was not audited")
}

// verifies: REQ-KEYS-031
// The operation of a refusal at the guard is from a closed set. A caller chooses the path of its request, and the guard
// refuses before the path is looked at: a path with a character the emitter rejects, one of 1 MiB and one that is not
// UTF-8 each still leave a fact (with the operation "unknown"), and the method of KeyService leaves its own name.
func TestTheOperationOfAGuardRefusalIsFromAClosedSet(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{})
	n.as("exchange", "session")
	hc, url := rpc.Dial(n.runDir + "/session/" + socketName)
	paths := map[string]string{
		"/x/a@b.cc":                           "unknown",
		"/" + strings.Repeat("a", 1<<16):      "unknown",
		"/%ff%fe/%c0":                         "unknown",
		"/sluis.key.v2alpha1.KeyService/Nope": "unknown",
		"/sluis.key.v2alpha1.KeyService/Seal": "Seal",
	}
	for path, want := range paths {
		before := n.audit.count(ActionRefuse)
		req, _ := http.NewRequest(http.MethodPost, url+path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		res, err := hc.Do(req)
		if err == nil {
			_ = res.Body.Close()
		}
		waitForRefusal(n, before)
		ev, ok := lastRefusal(n)
		if !ok || n.audit.count(ActionRefuse) != before+1 || ev.Fields["op"] != want || ev.Reason != "call_graph" {
			t.Errorf("path of %d bytes: fact %+v (%d new), want one with op %q", len(path), ev.Fields, n.audit.count(ActionRefuse)-before, want)
		}
	}
}

// waitForRefusal waits, for up to five seconds, for a refusal fact beyond the count before. The guard hands its refusals
// to the audit off the request, so the fact may follow the answer.
func waitForRefusal(n *node, before int) {
	for end := time.Now().Add(5 * time.Second); n.audit.count(ActionRefuse) == before && time.Now().Before(end); {
		time.Sleep(5 * time.Millisecond)
	}
}

// ruleFacts adds up the refusals by rule that the facts of key@ account for: one for each single fact, and the number folded
// for each summary.
func ruleFacts(n *node, reason string) (singles, folded, facts int) {
	for _, ev := range n.audit.all() {
		if ev.Action != ActionRefuse || ev.Reason != reason {
			continue
		}
		facts++
		if k, ok := ev.Fields["suppressed"].(int64); ok {
			folded += int(k)
		} else {
			singles++
		}
	}
	return
}

// verifies: REQ-KEYS-031, REQ-AUDIT-180
// A caller that holds a socket of its own cannot fill the audit spool either. The signer asks 50,000 times for a purpose it
// has no rule for: the refusals by rule write at most the burst and a summary for each window, every one is either a fact or
// counted, and the signer's own Sign of its token goes on being signed with its blocking audit fact. The limit is per caller,
// operation and reason, so another caller's refusals are facts of their own.
func TestAFloodOfRefusalsByRuleFromACallerIsCountedAndSigningGoesOn(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalWindow: 2 * time.Second, refusalBurst: 10, refusalHourly: 60})
	_, kid := publicKey(t, n, "signer", "token-signing")
	signer := n.client("signer")
	const total = 50_000
	began := time.Now()
	for range total {
		if _, err := signer.Sign(context.Background(), signReq("audit-log", []byte("x"))); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("the signer got %v", err)
		}
	}
	t.Logf("%d refusals in %v", total, time.Since(began))
	time.Sleep(2500 * time.Millisecond)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if _, folded, _ := ruleFacts(n, reasonRule); folded > 0 {
			break
		}
	}
	singles, folded, facts := ruleFacts(n, reasonRule)
	if singles+folded != total {
		t.Fatalf("%d single facts + %d folded = %d, want %d", singles, folded, singles+folded, total)
	}
	windows := int(time.Since(began)/(2*time.Second)) + 2
	if facts > windows*11 {
		t.Fatalf("%d facts for %d refusals in about %d windows, want at most 11 for each window", facts, total, windows)
	}
	if _, err := signer.Sign(context.Background(), signReq("token-signing", tokenInput(kid, "", ""))); err != nil {
		t.Fatalf("Sign after the flood: %v", err)
	}
	// Another caller's refusals are counted apart.
	before, _, _ := ruleFacts(n, reasonRule)
	if _, err := n.client("session").Sign(context.Background(), signReq("audit-log", []byte("x"))); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("session got %v", err)
	}
	if after, _, _ := ruleFacts(n, reasonRule); after != before+1 {
		t.Fatalf("another caller's refusal made %d facts, want 1", after-before)
	}
}

// verifies: REQ-KEYS-031
// What the limiters still count when key@ stops is reported, so that a shutdown loses no count: after a hundred refusals in a
// window that is an hour long, stopping the node makes the summary fact of the ninety that were counted.
func TestWhatIsCountedIsReportedWhenKeyAtStops(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalWindow: time.Hour, refusalBurst: 10, refusalHourly: 60})
	for range 100 {
		if _, err := n.client("signer").Sign(context.Background(), signReq("audit-log", []byte("x"))); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatal(err)
		}
	}
	if singles, folded, _ := ruleFacts(n, reasonRule); singles != 10 || folded != 0 {
		t.Fatalf("before the stop: %d singles and %d folded, want 10 and none", singles, folded)
	}
	n.stop()
	if singles, folded, _ := ruleFacts(n, reasonRule); singles != 10 || folded != 90 {
		t.Fatalf("after the stop: %d singles and %d folded, want 10 and 90", singles, folded)
	}
}

// verifies: REQ-KEYS-031
// The same for the guard: a stranger's hundred refusals in a long window are ten facts and a count, and the count is made a
// fact when key@ stops.
func TestWhatTheGuardCountsIsReportedWhenKeyAtStops(t *testing.T) {
	e := newTestEnv(t, "development")
	n := e.startedNode(nodeOpts{refusalWindow: time.Hour, refusalBurst: 10, refusalHourly: 60})
	stranger := n.as("exchange", "session")
	for range 100 {
		if _, err := seal1(stranger, "cookie", "cookie", "", "s1", []byte("x"), nil); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatal(err)
		}
	}
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if s, _, _ := transportFacts(n); s == 10 {
			break
		}
	}
	n.stop()
	if singles, folded, _ := transportFacts(n); singles != 10 || folded != 90 {
		t.Fatalf("after the stop: %d singles and %d folded, want 10 and 90", singles, folded)
	}
}
