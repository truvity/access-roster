//go:build sluis_test

package sessiond_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// userinfo calls the endpoint as entry does: with the Authorization header and nothing else.
func (e *env) userinfo(authorization string) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.UserInfo(context.Background(), connect.NewRequest(&sessionv2alpha1.UserInfoRequest{Authorization: authorization}))
	if err != nil {
		e.t.Fatalf("UserInfo: %v", err)
	}
	return res.Msg
}

func bearerOf(t string) string { return "Bearer " + t }

// resign makes a token the way signer would, with the claims of a real one changed by edit, under the key of the fake
// signer (so only the claims are what is wrong) and the typ given.
func (e *env) resign(token, typ string, edit func(map[string]any)) string {
	e.t.Helper()
	_, c := tokenClaims(e.t, token)
	if edit != nil {
		edit(c)
	}
	b, err := json.Marshal(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return signAs(e.signer.signingKey(), fakeKID, typ, b)
}

// assertBearer checks a refusal of RFC 6750 section 3: the status, the challenge, and a body that holds no variable part.
func assertBearer(t *testing.T, r *typev2alpha1.HttpReply, status int32, code string) {
	t.Helper()
	if r.GetStatus() != status {
		t.Fatalf("status %d (%s), want %d %s", r.GetStatus(), r.GetBody(), status, code)
	}
	wa := headerOf(r, "WWW-Authenticate")
	want := `Bearer realm="sluis"`
	if code != "" {
		want += `, error="` + code + `"`
	}
	if len(wa) != 1 || wa[0] != want {
		t.Errorf("WWW-Authenticate = %v, want %q", wa, want)
	}
	if cc := headerOf(r, "Cache-Control"); len(cc) != 1 || cc[0] != "no-store" {
		t.Errorf("Cache-Control = %v", cc)
	}
	if code != "" && body(t, r)["error"] != code {
		t.Errorf("body %s", r.GetBody())
	}
}

// lastRecord is the last audit record of an action.
func (e *env) lastRecord(action string) map[string]any {
	e.t.Helper()
	var out map[string]any
	for _, r := range e.records() {
		if r["metadata"].(map[string]any)["event_code"] == action {
			out = r
		}
	}
	return out
}

func (e *env) count(action string) int {
	n := 0
	for _, c := range e.eventCodes() {
		if c == action {
			n++
		}
	}
	return n
}

// verifies: REQ-SEC-038, REQ-TOKEN-008
// A live access token gets the one claim that is released, and it is the sub of the ID token of the same sign-in: the
// UserInfo sub must equal the ID token's (OpenID Connect Core section 5.3.2). Nothing else is in the answer, whatever the
// scope: no name or e-mail address is released until the allow-list of REQ-TOKEN-006 exists. The success is audited with the
// session and the person, and holds no token.
func TestUserInfoAnswersTheSubjectOfALiveSession(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	at := b["access_token"].(string)

	r := e.userinfo(bearerOf(at))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
	}
	got := body(t, r)
	_, idc := tokenClaims(t, b["id_token"].(string))
	if len(got) != 1 || got["sub"] == "" || got["sub"] != idc["sub"] {
		t.Errorf("answer %v, want only the sub %v of the ID token", got, idc["sub"])
	}
	if ct := headerOf(r, "Content-Type"); len(ct) != 1 || ct[0] != "application/json" {
		t.Errorf("Content-Type = %v", ct)
	}
	if cc, pr := headerOf(r, "Cache-Control"), headerOf(r, "Pragma"); len(cc) != 1 || cc[0] != "no-store" || len(pr) != 1 || pr[0] != "no-cache" {
		t.Errorf("Cache-Control %v Pragma %v", cc, pr)
	}
	// The scheme is not case sensitive (RFC 7235 section 2.1).
	if r := e.userinfo("bearer " + at); r.GetStatus() != http.StatusOK {
		t.Errorf("lower-case scheme: %d", r.GetStatus())
	}

	rec := e.lastRecord("session.userinfo")
	if rec == nil || rec["status_code"] != nil {
		t.Fatalf("no success record: %v", rec)
	}
	raw := string(mustJSON(rec))
	sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
	if !strings.Contains(raw, sid) {
		t.Errorf("the record does not name the session: %s", raw)
	}
	for _, secret := range []string{at, b["id_token"].(string), b["refresh_token"].(string), idc["sub"].(string)} {
		if strings.Contains(raw, secret) {
			t.Errorf("the record holds a secret: %.20s", secret)
		}
	}
}

// verifies: REQ-SEC-038
// Every bearer endpoint refuses what is not a live access token of the client: an ID token, a token of another client or
// audience, a token signed by a key the issuer does not publish, a token of a type or algorithm that is not an access token's,
// an expired one, and a request with no usable credentials. The answer to each token is the same 401 invalid_token in the
// same words, so the caller cannot tell which check refused; the audit record names it. The check that is the
// subject of each case is the only thing wrong with its token (it is a real token with one change), which is how each case
// bites: remove the check and the case answers 200.
func TestABearerEndpointRefusesWhatIsNotALiveAccessToken(t *testing.T) {
	e := newEnv(t, func(o *options) { o.extra = append(o.extra, clientOf("other-app")) })
	b, _ := e.redeemed()
	at := b["access_token"].(string)
	if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the unchanged token: %d %s", r.GetStatus(), r.GetBody())
	}
	other, err := ecdsaKey()
	if err != nil {
		t.Fatal(err)
	}
	_, c := tokenClaims(t, at)
	claims, _ := json.Marshal(c)

	cases := []struct {
		name, token, reason string
	}{
		{"an ID token (typ JWT)", b["id_token"].(string), "token_type"},
		{"an access token whose typ was made JWT", e.resign(at, "JWT", nil), "token_type"},
		{"a typ in the long form", e.resign(at, "application/at+jwt", nil), "token_type"},
		{"a token of another client (a client the installation declares)", e.resign(at, "at+jwt", func(c map[string]any) { c["aud"], c["client_id"] = "other-app", "other-app" }), "token_client"},
		{"a token of a client nobody declared", e.resign(at, "at+jwt", func(c map[string]any) { c["aud"], c["client_id"] = "nobody", "nobody" }), "token_client"},
		{"a token for another audience (an exchange product)", e.resign(at, "at+jwt", func(c map[string]any) { c["aud"] = "https://api.example.test" }), "token_client"},
		{"a token whose audience is a list", e.resign(at, "at+jwt", func(c map[string]any) { c["aud"] = []string{testClient} }), "bearer_token"},
		{"a token of another issuer", e.resign(at, "at+jwt", func(c map[string]any) { c["iss"] = "https://other.example.test" }), "bearer_token"},
		{"an expired token", e.resign(at, "at+jwt", func(c map[string]any) { c["exp"] = e.clk.now().Add(-time.Second).Unix() }), "bearer_token"},
		{"a token with no exp", e.resign(at, "at+jwt", func(c map[string]any) { delete(c, "exp") }), "bearer_token"},
		{"a token with no sid", e.resign(at, "at+jwt", func(c map[string]any) { delete(c, "sid") }), "bearer_token"},
		{"a token with no sub", e.resign(at, "at+jwt", func(c map[string]any) { delete(c, "sub") }), "bearer_token"},
		{"a token with no jti", e.resign(at, "at+jwt", func(c map[string]any) { delete(c, "jti") }), "bearer_token"},
		{"a token with no client_id", e.resign(at, "at+jwt", func(c map[string]any) { delete(c, "client_id") }), "bearer_token"},
		{"a token signed by a key the issuer does not publish", signAs(other, fakeKID, "at+jwt", claims), "bearer_token"},
		{"a token with a kid the issuer does not publish", signAs(e.signer.signingKey(), "kid-unknown", "at+jwt", claims), "bearer_token"},
		{"a token with no kid", signAs(e.signer.signingKey(), "", "at+jwt", claims), "bearer_token"},
		{"a token with a damaged signature", at[:len(at)-4] + "AAAA", "bearer_token"},
		{"an unsigned token (alg none)", "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0." + strings.Split(at, ".")[1] + ".", "bearer_token"},
		{"not a token at all", "not-a-token", "bearer_token"},
	}
	var first []byte
	for _, tc := range cases {
		before := e.count("session.userinfo")
		r := e.userinfo(bearerOf(tc.token))
		assertBearer(t, r, http.StatusUnauthorized, "invalid_token")
		if first == nil {
			first = r.GetBody()
		} else if string(first) != string(r.GetBody()) {
			t.Errorf("%s: the body %s differs from the others %s", tc.name, r.GetBody(), first)
		}
		if e.count("session.userinfo") != before+1 {
			t.Errorf("%s: no record of the refusal", tc.name)
			continue
		}
		if rec := e.lastRecord("session.userinfo"); rec["status_code"] != tc.reason {
			t.Errorf("%s: status_code = %v, want %s", tc.name, rec["status_code"], tc.reason)
		}
	}

	// A request with no usable credentials: the challenge carries no error code (RFC 6750 section 3.1) for none or another
	// scheme, and is a 400 for a Bearer that is not a token.
	for _, h := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer "} {
		code := ""
		status := int32(http.StatusUnauthorized)
		if strings.HasPrefix(h, "Bearer") {
			code, status = "invalid_request", http.StatusBadRequest
		}
		assertBearer(t, e.userinfo(h), status, code)
	}
	assertBearer(t, e.userinfo("Bearer a b"), http.StatusBadRequest, "invalid_request")
	assertBearer(t, e.userinfo("Bearer "+strings.Repeat("a", 5000)), http.StatusBadRequest, "invalid_request")
}

// verifies: REQ-SEC-038, REQ-TOKEN-024
// A token whose session chain has ended is refused though it has not expired: signed out in effect by a reused refresh
// token, by the chain reaching its absolute limit, by it sitting idle past its limit, and by the chain being lost. The check
// reads the chain on each request, so a chain that ends between two requests is seen by the second. A chain that belongs to
// another client than the token names is not served either.
func TestAnAccessTokenOfAnEndedSessionIsRefused(t *testing.T) {
	t.Run("a refresh token used twice", func(t *testing.T) {
		e := newEnv(t, nil)
		b, _ := e.redeemed()
		at, rt := b["access_token"].(string), b["refresh_token"].(string)
		if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
			t.Fatalf("before: %d", r.GetStatus())
		}
		body(t, e.token(refreshRequest(rt)))
		e.clk.advance(time.Minute)                                                          // past any grace window for a retry
		assertOAuth(t, e.token(refreshRequest(rt)), http.StatusBadRequest, "invalid_grant") // the reuse ends the chain
		if _, _, ok := e.store.raw("session-chain", testTenant, strings.SplitN(rt, ".", 2)[0]); ok {
			t.Fatal("the chain is still there")
		}
		// The token is far from its exp and is refused all the same.
		if _, c := tokenClaims(t, at); time.Unix(num(c, "exp"), 0).Sub(e.clk.now()) < 5*time.Minute {
			t.Fatalf("the test needs a token with time left")
		}
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
		if rec := e.lastRecord("session.userinfo"); rec["status_code"] != "session_ended" {
			t.Errorf("status_code = %v", rec["status_code"])
		}
	})
	t.Run("the chain reaches its absolute limit before the token expires", func(t *testing.T) {
		e := newEnv(t, func(o *options) {
			o.lifetime.HumanSessionAbsolute = durationpb.New(time.Hour)
			o.lifetime.AccessToken = durationpb.New(10 * time.Minute)
		})
		b, _ := e.redeemed()
		at := b["access_token"].(string)
		sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
		raw, _, _ := e.store.raw("session-chain", testTenant, sid)
		ch := protoOf(t, raw, &sessionv2alpha1.SessionChain{})
		// The store has not dropped the chain yet (its own clock lags); the limit written in the chain is what ends it.
		e.clk.advance(time.Minute)
		ch.EndsAt = timestampOf(e.clk.now())
		e.store.put("session-chain", testTenant, sid, ch)
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
	})
	t.Run("the chain sat idle past its limit", func(t *testing.T) {
		e := newEnv(t, func(o *options) {
			o.lifetime.RefreshIdle = durationpb.New(2 * time.Minute)
			o.lifetime.AccessToken = durationpb.New(10 * time.Minute)
		})
		b, _ := e.redeemed()
		at := b["access_token"].(string)
		e.clk.advance(time.Minute)
		if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
			t.Fatalf("inside the idle limit: %d", r.GetStatus())
		}
		e.clk.advance(2 * time.Minute)
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
	})
	t.Run("the chain is lost", func(t *testing.T) {
		e := newEnv(t, nil)
		b, _ := e.redeemed()
		at := b["access_token"].(string)
		sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
		if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
			t.Fatalf("before: %d", r.GetStatus())
		}
		e.store.mu.Lock()
		delete(e.store.items, key("session-chain", testTenant, sid))
		e.store.mu.Unlock()
		// The very next request sees it: a live chain is never remembered.
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
	})
	t.Run("the chain is another client's", func(t *testing.T) {
		e := newEnv(t, func(o *options) { o.extra = append(o.extra, clientOf("other-app")) })
		b, _ := e.redeemed()
		at := b["access_token"].(string)
		sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
		raw, _, _ := e.store.raw("session-chain", testTenant, sid)
		ch := protoOf(t, raw, &sessionv2alpha1.SessionChain{})
		ch.ClientId = "other-app"
		e.store.put("session-chain", testTenant, sid, ch)
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
		if rec := e.lastRecord("session.userinfo"); rec["status_code"] != "token_client" {
			t.Errorf("status_code = %v", rec["status_code"])
		}
	})
}

// verifies: REQ-SEC-038
// An ended session, presented again and again, reads the chain at store@ once, not once for each request: an item that is
// not there is a refusal that store@ audits (ADR 0005), and a stranger who holds one expired-in-effect token must not be
// able to write one for every request. Each request still has the records of its own, which are session's (one) and entry's.
// What is remembered is only "this id is gone", which cannot go wrong: an id is made once.
func TestAnEndedSessionIsReadOnceFromTheStore(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	at := b["access_token"].(string)
	sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
	e.store.mu.Lock()
	delete(e.store.items, key("session-chain", testTenant, sid))
	e.store.mu.Unlock()

	var gets atomic.Int32
	e.store.beforeGet = func(_ *fakeStore, a *typev2alpha1.Address) {
		if a.GetKind() == "session-chain" {
			gets.Add(1)
		}
	}
	const n = 50
	for range n {
		assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")
	}
	if g := gets.Load(); g != 1 {
		t.Errorf("%d reads of the chain for %d requests, want 1", g, n)
	}
	if got := e.count("session.userinfo"); got != n {
		t.Errorf("%d session records for %d refusals: each refusal is audited once", got, n)
	}
	// And a live chain is read every time.
	e2 := newEnv(t, nil)
	b2, _ := e2.redeemed()
	var live atomic.Int32
	e2.store.beforeGet = func(_ *fakeStore, a *typev2alpha1.Address) {
		if a.GetKind() == "session-chain" {
			live.Add(1)
		}
	}
	for range 5 {
		e2.userinfo(bearerOf(b2["access_token"].(string)))
	}
	if live.Load() != 5 {
		t.Errorf("%d reads of a live chain for 5 requests, want 5", live.Load())
	}
}

// verifies: REQ-SEC-038
// A token signed by a key that was revoked is refused once the key set that this check holds has been fetched again: the
// set is kept for ten seconds, so that is the longest such a token is still accepted. A token signed by a key the set never
// held is refused at once, with one fetch of the set and at most one in thirty seconds.
func TestARevokedSigningKeyEndsItsTokensWithinTheKeySetLifetime(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	at := b["access_token"].(string)
	if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
		t.Fatalf("%d", r.GetStatus())
	}
	e.signer.mu.Lock()
	e.signer.hideKey = true // signer's KeySet drops a revoked kid
	e.signer.mu.Unlock()
	e.clk.advance(5 * time.Second)
	if r := e.userinfo(bearerOf(at)); r.GetStatus() != http.StatusOK {
		t.Errorf("inside the key set's lifetime the held set still has the key: %d", r.GetStatus())
	}
	e.clk.advance(6 * time.Second)
	assertBearer(t, e.userinfo(bearerOf(at)), http.StatusUnauthorized, "invalid_token")

	// A flood of tokens with kids nobody publishes asks signer for the key set once in thirty seconds.
	e.signer.mu.Lock()
	base := e.signer.keySets
	e.signer.mu.Unlock()
	_, c := tokenClaims(t, at)
	claims, _ := json.Marshal(c)
	for i := range 20 {
		assertBearer(t, e.userinfo(bearerOf(signAs(e.signer.signingKey(), "kid-x"+string(rune('a'+i)), "at+jwt", claims))), http.StatusUnauthorized, "invalid_token")
	}
	e.signer.mu.Lock()
	defer e.signer.mu.Unlock()
	if d := e.signer.keySets - base; d > 1 {
		t.Errorf("%d fetches of the key set for 20 unknown kids in one moment, want at most 1", d)
	}
}

// verifies: REQ-SEC-038
// A session that was not granted the openid scope gets no UserInfo (OpenID Connect Core section 5.3.1): 403
// insufficient_scope, with the error in the challenge (RFC 6750 section 3.1).
func TestUserInfoNeedsTheOpenIDScope(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	sid, _, _ := strings.Cut(b["refresh_token"].(string), ".")
	raw, _, _ := e.store.raw("session-chain", testTenant, sid)
	ch := protoOf(t, raw, &sessionv2alpha1.SessionChain{})
	ch.Scope = "offline_access"
	e.store.put("session-chain", testTenant, sid, ch)
	assertBearer(t, e.userinfo(bearerOf(b["access_token"].(string))), http.StatusForbidden, "insufficient_scope")
	if rec := e.lastRecord("session.userinfo"); rec["status_code"] != "scope" {
		t.Errorf("status_code = %v", rec["status_code"])
	}
}

// verifies: REQ-SEC-038
// A dependency that fails makes UserInfo fail closed: the audit transport down gives an error and no answer for a success
// that was not recorded, and signer down (once the held key set is stale) gives an error and no token accepted on a guess.
func TestUserInfoFailsClosedWhenADependencyFails(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	at := b["access_token"].(string)

	call := func() error {
		_, err := e.client.UserInfo(context.Background(), connect.NewRequest(&sessionv2alpha1.UserInfoRequest{Authorization: bearerOf(at)}))
		return err
	}
	if err := call(); err != nil {
		t.Fatal(err)
	}
	e.transport.mu.Lock()
	e.transport.err = connect.NewError(connect.CodeUnavailable, nil)
	e.transport.mu.Unlock()
	if connect.CodeOf(call()) != connect.CodeUnavailable {
		t.Errorf("audit down: an answer was given for a success that was not recorded")
	}
	e.transport.mu.Lock()
	e.transport.err = nil
	e.transport.mu.Unlock()

	e.signer.mu.Lock()
	e.signer.err = connect.NewError(connect.CodeUnavailable, nil)
	e.signer.mu.Unlock()
	e.clk.advance(time.Minute) // past the held key set
	if connect.CodeOf(call()) != connect.CodeUnavailable {
		t.Errorf("signer down: %v", call())
	}
}
