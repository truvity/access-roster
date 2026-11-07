//go:build sluis_test

package sessiond_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

func (e *env) revoke(r *sessionv2alpha1.RevokeRequest) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.Revoke(context.Background(), connect.NewRequest(r))
	if err != nil {
		e.t.Fatalf("Revoke: %v", err)
	}
	return res.Msg
}

func revokeRequest(token string) *sessionv2alpha1.RevokeRequest {
	return &sessionv2alpha1.RevokeRequest{Token: token, ClientId: testClient}
}

func sidOf(refreshToken string) string {
	sid, _, _ := strings.Cut(refreshToken, ".")
	return sid
}

func (e *env) chainExists(sid string) bool {
	_, _, ok := e.store.raw("session-chain", testTenant, sid)
	return ok
}

// sameAnswer fails when a reply differs from the reply of a revocation that did something: the status, every header and the body.
func sameAnswer(t *testing.T, what string, got, want *typev2alpha1.HttpReply) {
	t.Helper()
	if got.GetStatus() != want.GetStatus() || string(got.GetBody()) != string(want.GetBody()) || len(got.GetHeaders()) != len(want.GetHeaders()) {
		t.Errorf("%s: answered %d %q with %d headers, the revocation that ended a chain answered %d %q with %d", what,
			got.GetStatus(), got.GetBody(), len(got.GetHeaders()), want.GetStatus(), want.GetBody(), len(want.GetHeaders()))
		return
	}
	for i, h := range got.GetHeaders() {
		if h.GetName() != want.GetHeaders()[i].GetName() || h.GetValue() != want.GetHeaders()[i].GetValue() {
			t.Errorf("%s: header %s: %q, want %q", what, h.GetName(), h.GetValue(), want.GetHeaders()[i].GetValue())
		}
	}
}

// verifies: REQ-TOKEN-009, REQ-TOKEN-025
// A client revokes the refresh token it holds, with its client id (a public client authenticates by its id alone, as at the
// token endpoint): the chain is gone, the refresh token and every older one of it stop working, and the answer is 200 with
// nothing cached. Exactly that grant ends: the same person's other session at the same client, from another sign-in, keeps
// working. The end is recorded as the end of a session (reason revoked) and as the request.
func TestRevokeEndsExactlyTheGrantOfTheRefreshToken(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	second, _ := e.redeemed()
	rt1, rt2 := first["refresh_token"].(string), second["refresh_token"].(string)
	if e.store.count("session-chain", testTenant) != 2 {
		t.Fatal("the test needs two chains")
	}
	// The first chain has turned over once: the token revoked is the second of it, and the first is spent.
	rotated := body(t, e.token(refreshRequest(rt1)))
	rt1b := rotated["refresh_token"].(string)

	r := e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt1b, TokenTypeHint: "refresh_token", ClientId: testClient})
	if r.GetStatus() != http.StatusOK || len(r.GetBody()) != 0 {
		t.Fatalf("answered %d %q", r.GetStatus(), r.GetBody())
	}
	if cc, pr := headerOf(r, "Cache-Control"), headerOf(r, "Pragma"); len(cc) != 1 || cc[0] != "no-store" || len(pr) != 1 || pr[0] != "no-cache" {
		t.Errorf("Cache-Control %v Pragma %v", cc, pr)
	}
	if e.chainExists(sidOf(rt1)) {
		t.Error("the chain of the revoked token is still there")
	}
	if !e.chainExists(sidOf(rt2)) {
		t.Fatal("the other session of the person ended")
	}
	assertOAuth(t, e.token(refreshRequest(rt1b)), http.StatusBadRequest, "invalid_grant")
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if r := e.token(refreshRequest(rt2)); r.GetStatus() != http.StatusOK {
		t.Errorf("the other session stopped refreshing: %d %s", r.GetStatus(), r.GetBody())
	}

	var ended, asked bool
	for _, rec := range e.records() {
		switch rec["metadata"].(map[string]any)["event_code"] {
		case "session.chain.end":
			ended = ended || strings.Contains(string(mustJSON(rec)), `"revoked"`)
		case "session.revoke":
			asked = rec["status_code"] == nil && strings.Contains(string(mustJSON(rec)), sidOf(rt1))
		}
	}
	if !ended || !asked {
		t.Errorf("records %v: end recorded %v, request recorded %v", e.eventCodes(), ended, asked)
	}
	for _, rec := range e.records() {
		if raw := string(mustJSON(rec)); strings.Contains(raw, rt1b) || strings.Contains(raw, rt1) {
			t.Fatal("a record holds a refresh token")
		}
	}

	// A token that has been spent can be revoked too: it proves the holder had a token of the chain. And again is not an error.
	before := len(e.records())
	sameAnswer(t, "the token revoked again", e.revoke(revokeRequest(rt1b)), r)
	if got := len(e.records()); got != before {
		t.Errorf("a revocation of a chain that is gone wrote %d records", got-before)
	}
	third, _ := e.redeemed()
	rt3 := third["refresh_token"].(string)
	body(t, e.token(refreshRequest(rt3)))
	e.revoke(revokeRequest(rt3)) // the spent token of the chain
	if e.chainExists(sidOf(rt3)) {
		t.Error("a spent token of the chain did not end it")
	}
}

// verifies: REQ-TOKEN-026
// What is not revoked is answered as what is: 200, the same status, headers and body as a revocation that ended a chain. So
// the answer does not tell a token that never existed from one that ended, and a client learns nothing about another
// client's tokens. The unknown token, the right sid with a wrong secret, a token of another client, an expired chain and
// tokens that are not even a refresh token's shape are each this case; the chains that should stay do stay.
func TestRevokeAnswersTheSameForWhatItDoesNotRevoke(t *testing.T) {
	e := newEnv(t, func(o *options) { o.extra = append(o.extra, clientOf("other-app")) })
	mine, _ := e.redeemed()
	rt := mine["refresh_token"].(string)
	sid := sidOf(rt)

	// What a revocation that does something answers, from a chain of its own.
	other, _ := e.redeemed()
	want := e.revoke(revokeRequest(other["refresh_token"].(string)))
	if want.GetStatus() != http.StatusOK || e.chainExists(sidOf(other["refresh_token"].(string))) {
		t.Fatalf("setup: %d", want.GetStatus())
	}

	// A token of this chain, presented by another client that the installation declares.
	asOther := e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: "other-app"})
	sameAnswer(t, "a token of another client", asOther, want)
	if !e.chainExists(sid) {
		t.Fatal("another client ended this client's session")
	}
	cases := map[string]string{
		"an unknown token":                      strings.Repeat("b", 26) + "." + strings.Repeat("c", 43),
		"the sid with a wrong secret":           sid + "." + strings.Repeat("a", 43),
		"a secret that is too short":            sid + ".short",
		"a token that is not a refresh token's": "just-some-text",
		"a sid that is no id":                   "UPPER-CASE-AND-DASHES-SID." + strings.Repeat("c", 43),
		"a token of three dots":                 "a.b.c.d",
		"a very long opaque token":              strings.Repeat("z", 4000),
	}
	for what, tok := range cases {
		sameAnswer(t, what, e.revoke(revokeRequest(tok)), want)
	}
	if !e.chainExists(sid) {
		t.Fatal("a guess ended the session")
	}
	if r := e.token(refreshRequest(rt)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the real token stopped working: %s", r.GetBody())
	}

	// The chain of a token that has outlived its session: gone from the store, the same answer.
	e.clk.advance(13 * time.Hour)
	sameAnswer(t, "an expired session", e.revoke(revokeRequest(rt)), want)

	// A hint that names the other kind, or nothing, changes nothing.
	third, _ := e.redeemed()
	for _, hint := range []string{"access_token", "something-else", ""} {
		tok := third["refresh_token"].(string)
		sameAnswer(t, "hint "+hint, e.revoke(&sessionv2alpha1.RevokeRequest{Token: tok, TokenTypeHint: hint, ClientId: testClient}), want)
		if hint == "access_token" && e.chainExists(sidOf(tok)) {
			t.Fatal("the hint stopped the revocation")
		}
		if hint == "access_token" {
			third, _ = e.redeemed()
		}
	}
}

// verifies: REQ-TOKEN-009
// The revocation request is a request of a client: the token is required, the client authenticates as at the token endpoint (a
// public client by its id alone, and one that sends a secret is refused, because a secret it was never given proves nothing), an
// unknown client is refused, and each refusal is audited with a closed reason and holds no part of the token.
func TestRevokeIsARequestOfAClient(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	sid := sidOf(rt)

	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt}), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: "nobody"}), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: testClient, ClientSecret: "s3cret"}), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: testClient, Authorization: "Basic Zm9vOmJhcg=="}), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{ClientId: testClient}), http.StatusBadRequest, "invalid_request")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: "a\x01b", ClientId: testClient}), http.StatusBadRequest, "invalid_request")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: testClient, TokenTypeHint: strings.Repeat("h", 65)}), http.StatusBadRequest, "invalid_request")
	if !e.chainExists(sid) {
		t.Fatal("a refused request ended the session")
	}
	n := 0
	for _, rec := range e.records() {
		if rec["metadata"].(map[string]any)["event_code"] != "session.revoke" {
			continue
		}
		n++
		if rec["status_code"] == nil {
			t.Errorf("a refusal recorded as a success: %v", rec)
		}
		if strings.Contains(string(mustJSON(rec)), rt) || strings.Contains(string(mustJSON(rec)), "s3cret") {
			t.Errorf("a record holds a secret: %v", rec)
		}
	}
	if n != 7 {
		t.Errorf("%d records of refused requests, want 7", n)
	}
}

// verifies: REQ-TOKEN-026
// A token the endpoint does not revoke is not taken for an unknown one. An access token and an ID token are JWTs, and the answer
// to anything of that shape is 400 unsupported_token_type (RFC 7009 section 2.2.1), true or invented, so it is a function of the shape
// and tells nothing about the token. The session behind the access token is not touched.
func TestRevokeDoesNotRevokeAnAccessToken(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	sid := sidOf(b["refresh_token"].(string))
	for _, tok := range []string{b["access_token"].(string), b["id_token"].(string), "e30.e30.c2ln", "a.b."} {
		assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: tok, TokenTypeHint: "access_token", ClientId: testClient}), http.StatusBadRequest, "unsupported_token_type")
	}
	if !e.chainExists(sid) {
		t.Fatal("revoking an access token ended the session")
	}
	if r := e.token(refreshRequest(b["refresh_token"].(string))); r.GetStatus() != http.StatusOK {
		t.Fatalf("the refresh token stopped working: %s", r.GetBody())
	}
}

// verifies: REQ-TOKEN-025
// The chain is deleted under a grant that policy gave for it, as every end of a chain is. A person policy will not give one for
// (a held person) cannot have the chain ended: the answer is 503 (RFC 7009 section 2.2.1) and not a 200 that says the session ended,
// the chain stays, and the denial is recorded. Once policy allows, the same token ends it.
func TestRevokeNeedsTheGrantOfPolicyToEndAChain(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-deny", Digest: "digest-1"}, nil
	}
	_, err := e.client.Revoke(context.Background(), connect.NewRequest(revokeRequest(rt)))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("answered %v, want unavailable (503 at entry)", err)
	}
	if !e.chainExists(sidOf(rt)) {
		t.Fatal("a chain ended with no grant")
	}
	var denied bool
	for _, rec := range e.records() {
		denied = denied || rec["metadata"].(map[string]any)["event_code"] == "session.revoke" && rec["status_code"] == "denied"
	}
	if !denied {
		t.Errorf("the denial is not recorded: %v", e.eventCodes())
	}
	e.policy.decide = nil
	e.revoke(revokeRequest(rt))
	if e.chainExists(sidOf(rt)) {
		t.Error("the chain did not end once policy allowed")
	}
}

// verifies: REQ-TOKEN-025
// The end of a session that a client asked for is not held back by the audit transport: with it down the chain is deleted and the
// answer is 200 (a 503 after the delete would have the retry read "absent", answer 200 and record nothing). The records that were not
// accepted are counted in the next one. With the transport back, the next revocation records as always.
func TestRevokeIsNotHeldBackByTheAuditTransport(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	e.transport.mu.Lock()
	e.transport.err = connect.NewError(connect.CodeUnavailable, nil)
	e.transport.mu.Unlock()
	if r := e.revoke(revokeRequest(rt)); r.GetStatus() != http.StatusOK {
		t.Fatalf("answered %d with the audit transport down", r.GetStatus())
	}
	if e.chainExists(sidOf(rt)) {
		t.Fatal("the chain is still there")
	}
	e.transport.mu.Lock()
	e.transport.err = nil
	e.transport.mu.Unlock()
	c, _ := e.redeemed()
	e.revoke(revokeRequest(c["refresh_token"].(string)))
	var lost bool
	for _, rec := range e.records() {
		lost = lost || strings.Contains(string(mustJSON(rec)), `"lost"`)
	}
	if !lost {
		t.Errorf("the facts that were not accepted are not counted: %v", e.eventCodes())
	}
}

// verifies: REQ-TOKEN-025
// A client ends any chain of its own that it holds a token of, whatever the class of the chain; and the record says which token it was:
// the current one or a spent one.
func TestRevokeEndsAChainOfAnyClassAndSaysWhichTokenItHeld(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	sid := sidOf(rt)
	raw, _, _ := e.store.raw("session-chain", testTenant, sid)
	ch := protoOf(t, raw, &sessionv2alpha1.SessionChain{})
	ch.Class = "agent"
	e.store.put("session-chain", testTenant, sid, ch)
	e.revoke(revokeRequest(rt))
	if e.chainExists(sid) {
		t.Error("a chain of another class was not ended")
	}
	for _, spent := range []bool{false, true} {
		c, _ := e.redeemed()
		tok := c["refresh_token"].(string)
		if spent {
			body(t, e.token(refreshRequest(tok)))
		}
		e.revoke(revokeRequest(tok))
		want := "current"
		if spent {
			want = "spent"
		}
		var got any
		for _, rec := range e.records() {
			if rec["metadata"].(map[string]any)["event_code"] == "session.revoke" && rec["status_code"] == nil && strings.Contains(string(mustJSON(rec)), sidOf(tok)) {
				got = rec["unmapped"].(map[string]any)["sluis"].(map[string]any)["ended_by"]
			}
		}
		if got != want {
			t.Errorf("ended_by = %v, want %s", got, want)
		}
	}
}

// verifies: REQ-TOKEN-026
// A revocation of a token with no chain behind it reads the chain once and writes nothing: no delete, no policy decision, no
// key call, no record of session's. The read of an item that is not there is a refusal that store@ audits (ADR 0005); that is
// the one fact a guess leaves besides entry's record of the request.
func TestRevokeOfAnUnknownTokenCostsOneReadAndNoWrite(t *testing.T) {
	e := newEnv(t, nil)
	e.redeemed()
	e.key.reset()
	before := len(e.policy.requests())
	records := len(e.records())
	writes := len(e.store.writes)
	var gets atomic.Int32
	e.store.beforeGet = func(_ *fakeStore, a *typev2alpha1.Address) {
		if a.GetKind() == "session-chain" {
			gets.Add(1)
		}
	}
	for range 20 {
		e.revoke(revokeRequest(strings.Repeat("b", 26) + "." + strings.Repeat("c", 43)))
	}
	if gets.Load() != 20 {
		t.Errorf("%d reads for 20 requests, want one each", gets.Load())
	}
	if len(e.policy.requests()) != before || len(e.key.called()) != 0 || len(e.store.writes) != writes || len(e.records()) != records {
		t.Errorf("an unknown token caused a decision, a key call, a write or a record")
	}
}

// verifies: REQ-TOKEN-009
// A dependency that fails makes the revocation fail closed: an error for entry to turn into 503, never the answer 200 for a
// chain that was not ended.
func TestRevokeFailsClosedWhenADependencyFails(t *testing.T) {
	call := func(e *env, rt string) error {
		_, err := e.client.Revoke(context.Background(), connect.NewRequest(revokeRequest(rt)))
		return err
	}
	t.Run("policy down", func(t *testing.T) {
		e := newEnv(t, nil)
		b, _ := e.redeemed()
		e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
			return nil, connect.NewError(connect.CodeUnavailable, nil)
		}
		if connect.CodeOf(call(e, b["refresh_token"].(string))) != connect.CodeUnavailable {
			t.Error("answered while policy was down")
		}
		if !e.chainExists(sidOf(b["refresh_token"].(string))) {
			t.Error("the chain ended")
		}
	})
	t.Run("the delete is refused", func(t *testing.T) {
		e := newEnv(t, nil)
		b, _ := e.redeemed()
		e.store.mu.Lock()
		e.store.failWrites = connect.NewError(connect.CodeUnavailable, nil)
		e.store.mu.Unlock()
		if connect.CodeOf(call(e, b["refresh_token"].(string))) != connect.CodeUnavailable {
			t.Error("answered 200 for a chain that was not ended")
		}
	})
}

// verifies: REQ-TOKEN-009
// The discovery document says how a client authenticates to the revocation endpoint, and session does as it says: the only method
// is none (a public client's id), and a client that sends a secret by either confidential method is refused.
func TestDiscoveryTellsHowToAuthenticateToRevoke(t *testing.T) {
	doc := goldenDiscovery(t)
	if got := listed(t, doc, "revocation_endpoint_auth_methods_supported"); len(got) != 1 || got[0] != "none" {
		t.Fatalf("revocation_endpoint_auth_methods_supported = %v", got)
	}
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	rt := b["refresh_token"].(string)
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, ClientId: testClient, ClientSecret: "x"}), http.StatusUnauthorized, "invalid_client")
	assertOAuth(t, e.revoke(&sessionv2alpha1.RevokeRequest{Token: rt, Authorization: "Basic Zm9vOmJhcg=="}), http.StatusUnauthorized, "invalid_client")
	if r := e.revoke(revokeRequest(rt)); r.GetStatus() != http.StatusOK {
		t.Fatalf("by none: %d", r.GetStatus())
	}
}
