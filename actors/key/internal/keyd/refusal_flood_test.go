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
	n := e.startedNode(nodeOpts{refusalWindow: 2 * time.Second})
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
