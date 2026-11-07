//go:build sluis_test

package sessiond_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// testGrace is the grace window of the design (v1's 30 seconds). The tests state it here, and do not import it, so a
// change of the constant fails them.
const testGrace = 30 * time.Second

// replica is another session, as a second instance or a restarted one: made from the same clients, it shares nothing
// with e.svc but store@, key@ and the rest of the installation.
func (e *env) replica() *sessiond.Service {
	e.t.Helper()
	s, err := sessiond.New(e.opts)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// tokenAt presents a refresh token to a given replica, as entry would.
func tokenAt(t *testing.T, s *sessiond.Service, rt string) (int32, map[string]any) {
	t.Helper()
	res, err := s.Token(context.Background(), connect.NewRequest(refreshRequest(rt)))
	if err != nil {
		t.Errorf("Token: %v", err)
		return 0, nil
	}
	var b map[string]any
	if res.Msg.GetStatus() == http.StatusOK {
		b = body(t, res.Msg)
	}
	return res.Msg.GetStatus(), b
}

func (e *env) chain(sid string) (c *sessionv2alpha1.SessionChain, version uint64, ok bool) {
	e.t.Helper()
	raw, v, found := e.store.raw("session-chain", testTenant, sid)
	if !found {
		return nil, 0, false
	}
	return protoOf(e.t, raw, &sessionv2alpha1.SessionChain{}), v, true
}

// count says how many audit records carry the event code (and, when reason is not empty, that failure reason).
func (e *env) count(code, reason string) int {
	e.t.Helper()
	n := 0
	for _, r := range e.records() {
		if r["metadata"].(map[string]any)["event_code"] != code {
			continue
		}
		if reason != "" {
			st, _ := r["status_code"].(string)
			if st != reason {
				continue
			}
		}
		n++
	}
	return n
}

// grants counts the audit records of refreshes that were granted, and how many of them say they were a replay.
func (e *env) grants() (granted, replays int) {
	e.t.Helper()
	for _, r := range e.records() {
		if r["metadata"].(map[string]any)["event_code"] != "session.refresh" {
			continue
		}
		if st, _ := r["status_code"].(string); st != "" {
			continue
		}
		granted++
		un, _ := r["unmapped"].(map[string]any)
		fields, _ := un["sluis"].(map[string]any)
		if fields["replay"] == true {
			replays++
		}
	}
	return granted, replays
}

// A token whose rotation was a moment ago is answered again with the token its rotation made, and nothing is written.
//
// verifies: REQ-SESS-013
func TestRefreshGraceAnswersASpentTokenWithTheSameSuccessor(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")

	e.clk.advance(time.Hour)
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	_, versionAfterRotation, _ := e.chain(sid)

	// The retry of a client that lost the response, 10 seconds later, and again at the very end of the window.
	for _, after := range []time.Duration{10 * time.Second, testGrace - 10*time.Second} {
		e.clk.advance(after)
		r := e.token(refreshRequest(rt1))
		if r.GetStatus() != http.StatusOK {
			t.Fatalf("replay %v after the rotation: %d %s", after, r.GetStatus(), r.GetBody())
		}
		b := body(t, r)
		if b["refresh_token"] != rt2 {
			t.Errorf("replay %v after the rotation: refresh token %v, want the one the rotation made", after, b["refresh_token"])
		}
		// A real answer: new tokens of the same session, signed now.
		if _, at := tokenClaims(t, b["access_token"].(string)); at["sid"] != sid {
			t.Errorf("access token = %v", at)
		}
	}
	// Nothing was written for the replays: the chain is the one the rotation left (REQ-SESS-001 holds: one rotation).
	chain, version, ok := e.chain(sid)
	if !ok || version != versionAfterRotation || len(chain.GetSpentHashes()) != 1 {
		t.Errorf("chain: present %v, version %d (was %d), %d spent", ok, version, versionAfterRotation, len(chain.GetSpentHashes()))
	}
	// The successor is the live token: it rotates on.
	if r := e.token(refreshRequest(rt2)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the successor: %s", r.GetBody())
	}
	if n := e.count("session.chain.end", ""); n != 0 {
		t.Errorf("%d chain ends", n)
	}
	// The record says which grants were replays (the rotation, 2 replays and the successor's rotation).
	if granted, replays := e.grants(); granted != 4 || replays != 2 {
		t.Errorf("%d refreshes granted, %d of them replays, want 4 and 2", granted, replays)
	}
}

// A token that comes back after the window is a reuse: the chain ends and the successor ends with it.
//
// verifies: REQ-SESS-014
func TestRefreshAfterTheGraceWindowEndsTheChain(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)

	e.clk.advance(testGrace + time.Nanosecond)
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain survived a reuse after the window")
	}
	assertOAuth(t, e.token(refreshRequest(rt2)), http.StatusBadRequest, "invalid_grant")
	if n := e.count("session.chain.end", ""); n != 1 {
		t.Errorf("%d chain ends, want 1", n)
	}
	if n := e.count("session.refresh", "reuse"); n != 1 {
		t.Errorf("%d refusals for reuse, want 1", n)
	}
}

// The window is for the token the last rotation replaced and no other: an older one is a theft even in the window.
//
// verifies: REQ-SESS-014
func TestRefreshGraceIsOnlyForTheLastRotation(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	e.clk.advance(time.Second)
	rt3 := body(t, e.token(refreshRequest(rt2)))["refresh_token"].(string)

	e.clk.advance(time.Second)
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain survived the replay of a token two rotations old")
	}
	assertOAuth(t, e.token(refreshRequest(rt3)), http.StatusBadRequest, "invalid_grant")
}

// A replay in the window does not start a new window: it answers the retry and leaves the clock of the rotation alone.
//
// verifies: REQ-SESS-014
func TestRefreshGraceIsNotRenewedByAReplay(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	body(t, e.token(refreshRequest(rt1)))

	e.clk.advance(testGrace - time.Second)
	if r := e.token(refreshRequest(rt1)); r.GetStatus() != http.StatusOK {
		t.Fatalf("replay inside the window: %s", r.GetBody())
	}
	e.clk.advance(2 * time.Second)
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the window was renewed by a replay")
	}
}

// Policy decides again at a replay: a person held after the rotation gets nothing from the window, and neither does a
// session that reached its limit.
//
// verifies: REQ-SESS-013
func TestRefreshGraceStillAsksPolicyAndKeepsTheLimits(t *testing.T) {
	t.Run("held after the rotation", func(t *testing.T) {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		body(t, e.token(refreshRequest(rt1)))
		e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
			return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-held", Digest: "digest-1"}, nil
		}
		assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
		if _, _, ok := e.chain(sid); !ok {
			t.Error("a denial ended the chain; it must leave the session to expire or to step up")
		}
	})
	t.Run("the idle limit passed inside the window", func(t *testing.T) {
		// An idle limit shorter than the window, which no default is, makes the check visible: the store's own expiry
		// follows the absolute limit only.
		e := newEnv(t, func(o *options) { o.lifetime.RefreshIdle = durationpb.New(10 * time.Second) })
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		e.clk.advance(5 * time.Second)
		body(t, e.token(refreshRequest(rt1)))
		e.clk.advance(11 * time.Second)
		assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
		if _, _, ok := e.chain(sid); ok {
			t.Error("the window outlived the idle limit")
		}
		if n := e.count("session.refresh", "expired"); n != 1 {
			t.Errorf("%d refusals for expiry, want 1", n)
		}
	})
	t.Run("the absolute limit passed inside the window", func(t *testing.T) {
		e := newEnv(t, nil) // absolute limit 12 hours
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		e.clk.advance(12*time.Hour - 10*time.Second)
		body(t, e.token(refreshRequest(rt1)))
		e.clk.advance(11 * time.Second)
		assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
		if _, _, ok := e.chain(sid); ok {
			t.Error("the window outlived the session")
		}
	})
}

// A retry after a restart, or on another replica, is answered the same: the state is store@'s and key@'s, none of it
// is in the process.
//
// verifies: REQ-SESS-013
func TestRefreshGraceSurvivesARestartAndIsTheSameOnEveryReplica(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)

	fresh := e.replica() // a process that has never seen this session
	e.clk.advance(5 * time.Second)
	status, b := tokenAt(t, fresh, rt1)
	if status != http.StatusOK || b["refresh_token"] != rt2 {
		t.Fatalf("replay on a fresh replica: %d %v", status, b)
	}
	// And the fresh replica rotates the successor, which the first one then sees as spent.
	status, b = tokenAt(t, fresh, rt2)
	if status != http.StatusOK {
		t.Fatalf("rotation on a fresh replica: %d", status)
	}
	rt3 := b["refresh_token"].(string)
	if r := e.token(refreshRequest(rt3)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the first replica refuses what the fresh one issued: %s", r.GetBody())
	}
	// After the window the fresh replica ends a chain on a reuse, and the first replica sees it ended.
	e.clk.advance(time.Minute)
	if status, _ := tokenAt(t, fresh, rt1); status != http.StatusBadRequest {
		t.Fatalf("reuse on a fresh replica: %d", status)
	}
	assertOAuth(t, e.token(refreshRequest(rt3)), http.StatusBadRequest, "invalid_grant")
}

// Requests that carry one token and arrive together must not both rotate it. They are answered with one successor, and
// the chain is rotated once.
//
// verifies: REQ-SESS-013
func TestRefreshOfOneTokenAtOnceRotatesOnceAndAnswersAllTheSame(t *testing.T) {
	const requests = 12
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	_, before, _ := e.chain(sid)
	replicas := []*sessiond.Service{e.svc, e.replica(), e.replica()}

	// Hold every request after policy decided and before it writes (key@ is asked for the successor between the two),
	// until all of them are there: each has read the chain at the same version, so the conditional write decides.
	var arrived sync.WaitGroup
	arrived.Add(requests)
	release := make(chan struct{})
	e.key.macHook = func(label string) {
		if label == "sluis-refresh-successor-v1" {
			arrived.Done()
			<-release
		}
	}
	type answer struct {
		status int32
		token  string
	}
	answers := make([]answer, requests)
	var done sync.WaitGroup
	for i := range answers {
		done.Add(1)
		go func() {
			defer done.Done()
			s, b := tokenAt(t, replicas[i%len(replicas)], rt1)
			answers[i] = answer{s, ""}
			if b != nil {
				answers[i].token, _ = b["refresh_token"].(string)
			}
		}()
	}
	arrived.Wait()
	close(release)
	done.Wait()

	for i, a := range answers {
		if a.status != http.StatusOK || a.token == "" || a.token != answers[0].token {
			t.Fatalf("answer %d = %+v, first = %+v", i, a, answers[0])
		}
	}
	chain, version, ok := e.chain(sid)
	if !ok || version != before+1 || len(chain.GetSpentHashes()) != 1 {
		t.Fatalf("chain: present %v, version %d (was %d), %d spent: it was rotated more than once or ended", ok, version, before, len(chain.GetSpentHashes()))
	}
	// One of the twelve rotated; the other eleven were answered as retries, and the record of each says so.
	if granted, replays := e.grants(); granted != requests || replays != requests-1 {
		t.Errorf("%d refreshes granted, %d of them replays, want %d and %d", granted, replays, requests, requests-1)
	}
	// The one successor is live.
	e.key.macHook = nil
	if r := e.token(refreshRequest(answers[0].token)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the successor does not rotate: %s", r.GetBody())
	}
	if n := e.count("session.chain.end", ""); n != 0 {
		t.Errorf("%d chain ends", n)
	}
	// One conditional write won, so the others lost the race and still got an answer: that path was taken.
	updates := 0
	e.store.mu.Lock()
	for _, w := range e.store.writes {
		for _, op := range w {
			if op.GetAddress().GetKind() == "session-chain" && op.GetAddress().GetId() == sid && op.GetIfVersion() == before {
				updates++
			}
		}
	}
	e.store.mu.Unlock()
	if updates != 1 {
		t.Errorf("%d accepted writes at version %d, want 1", updates, before)
	}
}

// The same without holding anyone back, over many rounds and replicas: the race detector and the scheduler choose
// the interleaving.
//
// verifies: REQ-SESS-013
func TestRefreshOfOneTokenAtOnceFreeRunning(t *testing.T) {
	for round := range 8 {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		replicas := []*sessiond.Service{e.svc, e.replica()}
		tokens := make([]string, 10)
		var wg sync.WaitGroup
		for i := range tokens {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if status, b := tokenAt(t, replicas[i%2], rt1); status == http.StatusOK {
					tokens[i], _ = b["refresh_token"].(string)
				}
			}()
		}
		wg.Wait()
		for i, tk := range tokens {
			if tk == "" || tk != tokens[0] {
				t.Fatalf("round %d: answer %d = %q, first = %q", round, i, tk, tokens[0])
			}
		}
		if chain, version, ok := e.chain(sid); !ok || version != 2 || len(chain.GetSpentHashes()) != 1 {
			t.Fatalf("round %d: chain present %v, version %d, %d spent", round, ok, version, len(chain.GetSpentHashes()))
		}
	}
}

// A flood of replays of a spent token, after the window, ends the chain once and records one refusal for each request.
// It does not record an end for each request, and a record names the session and a closed reason, never a list.
//
// verifies: REQ-SESS-014
func TestRefreshReplayStormIsBoundedInTheAuditLog(t *testing.T) {
	const storm = 24
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	e.clk.advance(testGrace + time.Second)
	before := len(e.records())

	replicas := []*sessiond.Service{e.svc, e.replica()}
	var wg sync.WaitGroup
	for i := range storm {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := tokenAt(t, replicas[i%2], rt1); status != http.StatusBadRequest {
				t.Errorf("replay %d: status %d", i, status)
			}
		}()
	}
	wg.Wait()
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain survived")
	}
	// After the end, every presentation is the presentation of an unknown token: one refusal, no end.
	for range storm {
		if status, _ := tokenAt(t, e.svc, rt2); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	}
	recs := e.records()[before:]
	ends, refusals := 0, 0
	for _, r := range recs {
		md := r["metadata"].(map[string]any)
		switch md["event_code"] {
		case "session.chain.end":
			ends++
		case "session.refresh":
			refusals++
		default:
			t.Errorf("unexpected record %v", md["event_code"])
		}
		un, _ := r["unmapped"].(map[string]any)
		fields, _ := un["sluis"].(map[string]any)
		for k, v := range fields {
			if _, isText := v.(string); !isText || len(v.(string)) > 64 || (k != "sid" && k != "reason" && k != "grant_type") {
				t.Errorf("record field %s = %v: only the session id, a closed reason and the grant type belong in a refusal", k, v)
			}
		}
	}
	if ends != 1 || refusals != 2*storm {
		t.Errorf("%d chain ends and %d refusals for %d + %d requests, want 1 and %d", ends, refusals, storm, storm, 2*storm)
	}
}

// replicaAt is another instance whose clock is off from the test clock by offset (positive: ahead).
func (e *env) replicaAt(offset time.Duration) *sessiond.Service {
	e.t.Helper()
	o := e.opts
	o.Now = func() time.Time { return e.clk.now().Add(offset) }
	s, err := sessiond.New(o)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

const successorLabel = "sluis-refresh-successor-v1"

// A replica whose clock runs ahead stamps a rotation in the future. That stamp must not open the window for as long as
// the clock is ahead (a replay 90 minutes later is a reuse), and one inside the tolerance of a few seconds is a retry.
//
// verifies: REQ-SESS-014
func TestRefreshGraceIgnoresAStampFromAClockThatRunsAhead(t *testing.T) {
	rotateAhead := func(t *testing.T, ahead time.Duration) (*env, string, string, string) {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		status, b := tokenAt(t, e.replicaAt(ahead), rt1)
		if status != http.StatusOK {
			t.Fatalf("rotation on the fast replica: %d", status)
		}
		return e, rt1, b["refresh_token"].(string), sid
	}
	t.Run("two hours ahead, replay 90 minutes later", func(t *testing.T) {
		e, rt1, _, sid := rotateAhead(t, 2*time.Hour)
		e.clk.advance(90 * time.Minute)
		assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
		if _, _, ok := e.chain(sid); ok {
			t.Fatal("a stamp from the future held the window open")
		}
	})
	t.Run("inside the tolerance", func(t *testing.T) {
		e, rt1, rt2, _ := rotateAhead(t, 3*time.Second)
		status, b := tokenAt(t, e.svc, rt1)
		if status != http.StatusOK || b["refresh_token"] != rt2 {
			t.Fatalf("retry on the honest replica: %d %v", status, b)
		}
	})
	t.Run("just outside the tolerance", func(t *testing.T) {
		e, rt1, _, sid := rotateAhead(t, 6*time.Second)
		assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
		if _, _, ok := e.chain(sid); ok {
			t.Fatal("the window was opened by a stamp 6 s ahead")
		}
	})
}

// holdFirstSuccessor makes the first request that asks key@ for a successor wait for release, after it has read the
// chain, decided with policy and before it writes; it returns when that request is there.
func (e *env) holdFirstSuccessor() (entered <-chan struct{}, release func()) {
	in, out := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.key.macHook = func(label string) {
		if label != successorLabel {
			return
		}
		held := false
		once.Do(func() { held = true })
		if held {
			close(in)
			<-out
		}
	}
	return in, func() { close(out) }
}

// A request that loses the conditional write and finds the chain moved on by more than its own token has presented a
// token two rotations old: the chain ends, once, and the live token of the chain ends with it.
//
// verifies: REQ-SESS-014
func TestRefreshLoserFindsTheChainMovedPastItsTokenAndEndsIt(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	entered, release := e.holdFirstSuccessor()

	var status int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		status, _ = tokenAt(t, e.replica(), rt1)
	}()
	<-entered
	// While it waits, the token rotates, and its successor rotates again.
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	rt3 := body(t, e.token(refreshRequest(rt2)))["refresh_token"].(string)
	release()
	<-done

	if status != http.StatusBadRequest {
		t.Fatalf("the loser was answered %d", status)
	}
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain survived a token two rotations old")
	}
	assertOAuth(t, e.token(refreshRequest(rt3)), http.StatusBadRequest, "invalid_grant")
	if n := e.count("session.chain.end", ""); n != 1 {
		t.Errorf("%d chain ends, want 1", n)
	}
}

// A request that stalled (in key@, in policy) while its retry won found a recent rotation, not one from the future:
// the clock is read again when it looks, and it is answered as the retry it is. The person is not signed out in the very
// case the window exists for.
//
// verifies: REQ-SESS-013
func TestRefreshLoserThatStalledIsStillARetry(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	entered, release := e.holdFirstSuccessor()

	var status int32
	var got map[string]any
	done := make(chan struct{})
	go func() {
		defer close(done)
		status, got = tokenAt(t, e.replica(), rt1)
	}()
	<-entered
	// The request began at T and stalled for 6 seconds, longer than the tolerance; its retry rotated meanwhile.
	e.clk.advance(6 * time.Second)
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	release()
	<-done

	if status != http.StatusOK || got["refresh_token"] != rt2 {
		t.Fatalf("the stalled request was answered %d %v, want the retry's successor", status, got)
	}
	if _, _, ok := e.chain(sid); !ok {
		t.Fatal("the chain was ended")
	}
	if n := e.count("session.chain.end", ""); n != 0 {
		t.Errorf("%d chain ends", n)
	}
}

// A loser ends the chain when, by a clock read when it looks, the rotation it found is old: here the request stalled
// for 31 seconds after its twin rotated.
//
// verifies: REQ-SESS-014
func TestRefreshLoserEndsTheChainWhenTheRotationIsOldByAFreshClock(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	entered, release := e.holdFirstSuccessor()

	var status int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		status, _ = tokenAt(t, e.replica(), rt1)
	}()
	<-entered
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	e.clk.advance(testGrace + time.Second)
	release()
	<-done

	if status != http.StatusBadRequest {
		t.Fatalf("the loser was answered %d", status)
	}
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain survived")
	}
	assertOAuth(t, e.token(refreshRequest(rt2)), http.StatusBadRequest, "invalid_grant")
}

// A replica whose clock is behind (a board before its time service has set it) sees the stamps of correct replicas in its
// future. A current token still rotates there, and the chain is not ended for it; a spent one is not in the window. The
// new stamp is the slow replica's own time, so the chain idles out earlier for the others, never later.
//
// verifies: REQ-SESS-013
func TestRefreshOnAReplicaThatRunsBehindStillRotatesACurrentToken(t *testing.T) {
	const behind = -2 * time.Hour
	t.Run("current token", func(t *testing.T) {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		e.clk.advance(time.Minute) // a correct replica stamped the rotation a minute ago
		status, b := tokenAt(t, e.replicaAt(behind), rt1)
		if status != http.StatusOK {
			t.Fatalf("a current token on the slow replica: %d", status)
		}
		rt2 := b["refresh_token"].(string)
		chain, version, ok := e.chain(sid)
		if !ok || version != 2 {
			t.Fatalf("chain present %v, version %d", ok, version)
		}
		// The stamp is the slow replica's time; it is not pushed forward to the stamp it found.
		if want := e.clk.now().Add(behind); !chain.GetRefreshedAt().AsTime().Equal(want) {
			t.Errorf("refreshed_at = %v, want %v", chain.GetRefreshedAt().AsTime(), want)
		}
		// A correct replica goes on with the successor.
		if r := e.token(refreshRequest(rt2)); r.GetStatus() != http.StatusOK {
			t.Fatalf("the correct replica after the slow one: %s", r.GetBody())
		}
	})
	t.Run("spent token", func(t *testing.T) {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt1 := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt1, ".")
		body(t, e.token(refreshRequest(rt1))) // rotated at T by a correct replica
		e.clk.advance(time.Minute)
		status, _ := tokenAt(t, e.replicaAt(behind), rt1)
		if status != http.StatusBadRequest {
			t.Fatalf("a spent token on the slow replica: %d", status)
		}
		// Not in the window by its clock, so a reuse: the chain ends.
		if _, _, ok := e.chain(sid); ok {
			t.Fatal("the chain survived a spent token that was not in the window")
		}
	})
}

// The end of a chain is not given up when the store keeps moving the chain under the delete: three attempts at the
// version read, then an end at any version. One end, and one record of it.
//
// verifies: REQ-SESS-014
func TestRefreshChainIsEndedWhateverTheStoreDoesToItsVersion(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	rt2 := body(t, e.token(refreshRequest(rt1)))["refresh_token"].(string)
	e.clk.advance(testGrace + time.Second)

	var conditional, unconditional int
	e.store.beforeWrite = func(f *fakeStore, ops []*storev2alpha1.Operation) {
		for _, op := range ops {
			if op.GetVerb() != storev2alpha1.Verb_DELETE || op.GetAddress().GetKind() != "session-chain" {
				continue
			}
			if op.GetIfVersion() == 0 {
				unconditional++
				continue
			}
			conditional++
			// A refresh landed between the read and the delete, every time.
			f.items[key("session-chain", testTenant, sid)].version++
		}
	}
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if conditional != 3 || unconditional != 1 {
		t.Errorf("%d deletes at a version and %d at any, want 3 and 1", conditional, unconditional)
	}
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain was not ended")
	}
	assertOAuth(t, e.token(refreshRequest(rt2)), http.StatusBadRequest, "invalid_grant")
	if n := e.count("session.chain.end", ""); n != 1 {
		t.Errorf("%d chain ends, want 1", n)
	}
}

// The chain is gone when its end cannot be recorded. The answer is still the refusal, and the lost fact is counted
// for the next record to carry (ADR 0029), not turned into an outage of the token endpoint.
//
// verifies: REQ-SESS-014
func TestRefreshChainEndIsAnswerEvenWhenItsRecordIsLost(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	body(t, e.token(refreshRequest(rt1)))
	e.clk.advance(testGrace + time.Second)

	before := e.audit.Lost()
	e.transport.mu.Lock()
	e.transport.err = connect.NewError(connect.CodeUnavailable, errors.New("spool full"))
	e.transport.mu.Unlock()
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if _, _, ok := e.chain(sid); ok {
		t.Fatal("the chain was not ended")
	}
	// The refusal and the end are two facts; both are counted.
	if lost := e.audit.Lost() - before; lost != 2 {
		t.Errorf("%d facts counted lost, want 2 (the refusal and the end)", lost)
	}
}

// The successor is pinned by a known answer: the label, the encoding of the input, the cut to 256 bits and base64url.
// Two replicas of different builds that derive differently, in a rolling deploy, turn every retry in the window into a
// sign-out, so this vector changes only with a migration. The mac key is the fake key@'s, whose construction is
// HMAC-SHA384 over u16(len label) | label | input (REQ-KEYS-042), and the answer was computed apart from the code.
//
// verifies: REQ-SESS-013
func TestRefreshSuccessorKnownAnswer(t *testing.T) {
	const (
		sid    = "abcdefghijklmnopqrstuvwxyz"
		secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"
		// HMAC-SHA384("test mac key|mac|", u16(26) | label | u32(4) "acme" | u32(26) sid | u32(48) SHA-384(secret))[:32]
		successor = "Bk-SNMY1n3BU79iKajCsWU7Nqae_KyDhe-a9kELJYlw"
	)
	e := newEnv(t, nil)
	now := e.clk.now()
	facts, err := e.key.sealForTest("chain", &typev2alpha1.Address{Kind: "session-chain", Tenant: testTenant, Id: sid},
		&sessionv2alpha1.SignInFacts{Accounts: []string{"workforce/alice"}})
	if err != nil {
		t.Fatal(err)
	}
	e.store.put("session-chain", testTenant, sid, &sessionv2alpha1.SessionChain{
		Subject: "subject-1", ClientId: testClient, Class: "human", Scope: "openid", RefreshHash: sha384Of(secret),
		StartedAt: timestampOf(now), EndsAt: timestampOf(now.Add(12 * time.Hour)), RefreshedAt: timestampOf(now),
		AuthTime: timestampOf(now), SealedFacts: facts,
	})
	r := e.token(refreshRequest(sid + "." + secret))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh: %d %s", r.GetStatus(), r.GetBody())
	}
	if got := body(t, r)["refresh_token"]; got != sid+"."+successor {
		t.Errorf("refresh token = %v, want %s.%s", got, sid, successor)
	}
}

// What the spent markers do not remember is not a reuse. A chain keeps the hashes of its last 16 rotations, so a token
// older than that is refused like any token the chain does not know, and the chain goes on. This pins that edge as it
// is (REQ-SESS-014 is partial because of it).
func TestRefreshTokenOlderThanTheSpentMarkersIsRefusedAndTheChainLives(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	rt := rt1
	for range 17 {
		e.clk.advance(time.Second)
		rt = body(t, e.token(refreshRequest(rt)))["refresh_token"].(string)
	}
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	chain, _, ok := e.chain(sid)
	if !ok || len(chain.GetSpentHashes()) != 16 {
		t.Fatalf("chain present %v, %d spent markers", ok, len(chain.GetSpentHashes()))
	}
	if r := e.token(refreshRequest(rt)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the live token: %s", r.GetBody())
	}
}

// An ordinary sign-in, code and refresh of a person who is not held must not write a refusal at store@ for every
// expected absence: store@ audits each Get that finds nothing (ADR 0005), so the hold is looked up by a linearizable
// listing. Holds of others do not hold this person, over many pages, and this person's does.
func TestRefreshAndSignInDoNotGetWhatIsExpectedToBeAbsent(t *testing.T) {
	e := newEnv(t, nil)
	// Holds of 450 other people, so that the listing spans three pages of 200.
	for i := range 450 {
		e.store.putRaw("person-hold", testTenant, fmt.Sprintf("2%04d", i), []byte{1})
	}
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	r := e.token(refreshRequest(rt1))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh: %s", r.GetBody())
	}
	rt2 := body(t, r)["refresh_token"].(string)
	e.store.mu.Lock()
	for _, k := range e.store.absentGets {
		if k == "person-hold" {
			t.Error("a Get of a PersonHold found nothing: store@ wrote a refusal for it")
		}
	}
	for _, l := range e.store.lists {
		if l.GetKind() == "person-hold" && l.GetConsistency() != storev2alpha1.Consistency_LINEARIZABLE {
			t.Errorf("a listing of holds read with %v", l.GetConsistency())
		}
	}
	e.store.mu.Unlock()

	// The person's own hold is found among the others, after 450 others, on the third page of 200 (the fake store asks policy with the state).
	var state string
	e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		state = r.GetPerson().GetState()
		return allowAll(r), nil
	}
	e.store.putRaw("person-hold", testTenant, e.store.ids("person", testTenant)[0], []byte{1})
	e.token(refreshRequest(rt2))
	if state != "held" {
		t.Errorf("state = %q, want held", state)
	}
}
