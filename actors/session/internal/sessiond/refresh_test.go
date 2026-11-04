//go:build sluis_test

package sessiond_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

func refreshRequest(rt string) *sessionv2alpha1.TokenRequest {
	return &sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: rt, ClientId: testClient}
}

func TestRefreshRotatesTheToken(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, _, _ := strings.Cut(rt1, ".")
	_, id1 := tokenClaims(t, first["id_token"].(string))

	e.clk.advance(time.Hour)
	r := e.token(refreshRequest(rt1))
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh: %d %s", r.GetStatus(), r.GetBody())
	}
	second := body(t, r)
	rt2 := second["refresh_token"].(string)
	if rt2 == rt1 || !strings.HasPrefix(rt2, sid+".") {
		t.Fatalf("refresh token %q after %q", rt2, rt1)
	}
	_, id2 := tokenClaims(t, second["id_token"].(string))
	_, at2 := tokenClaims(t, second["access_token"].(string))
	// The same session and person, a later iat, and the upstream's auth_time unchanged by the refresh (0020).
	if id2["sid"] != id1["sid"] || id2["sub"] != id1["sub"] || num(id2, "auth_time") != num(id1, "auth_time") || num(id2, "iat")-num(id1, "iat") != 3600 {
		t.Errorf("ID tokens: %v then %v", id1, id2)
	}
	if _, has := id2["nonce"]; has {
		t.Error("a refreshed ID token carries the nonce of the first request")
	}
	if at2["sid"] != sid {
		t.Errorf("access token = %v", at2)
	}
	if second["scope"] != "openid" {
		t.Errorf("scope = %v", second["scope"])
	}
	// The new token rotates again; the chain keeps the old hashes as spent markers.
	e.clk.advance(time.Minute)
	if r := e.token(refreshRequest(rt2)); r.GetStatus() != http.StatusOK {
		t.Fatalf("second refresh: %s", r.GetBody())
	}
	chainRaw, version, _ := e.store.raw("session-chain", testTenant, sid)
	chain := protoOf(t, chainRaw, &sessionv2alpha1.SessionChain{})
	if len(chain.GetSpentHashes()) != 2 || version != 3 {
		t.Errorf("spent %d, version %d", len(chain.GetSpentHashes()), version)
	}
	// Policy decided at every refresh.
	reqs := e.policy.requests()
	if last := reqs[len(reqs)-1]; strings.Join(last.GetGrantStoreVerbs(), ",") != "update,delete" || last.GetPerson().GetAccounts()[0] != "workforce/alice" {
		t.Errorf("decision = %v", last)
	}
	if codes := e.eventCodes(); codes[len(codes)-1] != "session.refresh" {
		t.Errorf("records = %v", codes)
	}
}

func TestRefreshOfASpentTokenEndsTheChain(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	second := body(t, e.token(refreshRequest(rt1)))
	rt2 := second["refresh_token"].(string)

	// The old token again: refused, and the chain ends at once (REQ-SESS-001), so the new token is dead as well.
	assertOAuth(t, e.token(refreshRequest(rt1)), http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != 0 {
		t.Fatalf("%d chains after a reuse", n)
	}
	assertOAuth(t, e.token(refreshRequest(rt2)), http.StatusBadRequest, "invalid_grant")
	var ended bool
	for _, r := range e.records() {
		if md := r["metadata"].(map[string]any); md["event_code"] == "session.chain.end" {
			ended = true
		}
	}
	if !ended {
		t.Error("the end is not recorded")
	}
}

func TestRefreshWithAnUnknownSecretLeavesTheChainAlone(t *testing.T) {
	// The sid is in every token, so it is not a secret: a guess at the secret must not end the person's session.
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	sid, _, _ := strings.Cut(first["refresh_token"].(string), ".")
	assertOAuth(t, e.token(refreshRequest(sid+"."+strings.Repeat("a", 43))), http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != 1 {
		t.Fatalf("%d chains", n)
	}
	if r := e.token(refreshRequest(first["refresh_token"].(string))); r.GetStatus() != http.StatusOK {
		t.Fatalf("the real token stopped working: %s", r.GetBody())
	}
	// And nothing was decided for the guess: only the sign-in, the code and the real refresh asked policy.
	if n := len(e.policy.requests()); n != 3 {
		t.Errorf("%d decisions", n)
	}
}

func TestRefreshRefusesWhatIsNotARefreshToken(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	sid, secret, _ := strings.Cut(first["refresh_token"].(string), ".")
	cases := map[string]string{
		"empty":            "",
		"no dot":           sid + secret,
		"short sid":        "abc." + secret,
		"short secret":     sid + ".abc",
		"unknown sid":      strings.Repeat("a", 26) + "." + secret,
		"path in sid":      "../../../../person/x/" + "." + secret,
		"control in token": sid + "." + secret[:42] + "\n",
		"two dots":         sid + "." + secret + ".x",
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			assertOAuth(t, e.token(refreshRequest(rt)), http.StatusBadRequest, "invalid_grant")
		})
	}
	if n := e.store.count("session-chain", testTenant); n != 1 {
		t.Fatalf("%d chains", n)
	}
}

func TestRefreshBelongsToTheClientThatGotIt(t *testing.T) {
	e := newEnv(t, func(o *options) {
		o.extra = nil
	})
	first, _ := e.redeemed()
	e.store.put("installation-client", "", "other-app", clientOf("other-app"))
	req := refreshRequest(first["refresh_token"].(string))
	req.ClientId = "other-app"
	assertOAuth(t, e.token(req), http.StatusBadRequest, "invalid_grant")
	// A public client that sends a secret is refused, on refresh as on a code.
	req = refreshRequest(first["refresh_token"].(string))
	req.ClientSecret = "x"
	assertOAuth(t, e.token(req), http.StatusUnauthorized, "invalid_client")
	// The chain is intact.
	if r := e.token(refreshRequest(first["refresh_token"].(string))); r.GetStatus() != http.StatusOK {
		t.Fatalf("refresh: %s", r.GetBody())
	}
}

func TestRefreshLimits(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		e := newEnv(t, nil) // idle 8h, absolute 12h
		first, _ := e.redeemed()
		e.clk.advance(8*time.Hour + time.Second)
		assertOAuth(t, e.token(refreshRequest(first["refresh_token"].(string))), http.StatusBadRequest, "invalid_grant")
		if n := e.store.count("session-chain", testTenant); n != 0 {
			t.Errorf("%d chains after the idle limit", n)
		}
	})
	t.Run("absolute, never reset by use", func(t *testing.T) {
		e := newEnv(t, nil)
		first, _ := e.redeemed()
		rt := first["refresh_token"].(string)
		sid, _, _ := strings.Cut(rt, ".")
		start := e.clk.now()
		// A refresh every 7 hours is inside the idle limit, but the chain began at start and ends 12 hours after it.
		e.clk.advance(7 * time.Hour)
		r := e.token(refreshRequest(rt))
		if r.GetStatus() != http.StatusOK {
			t.Fatalf("refresh at 7h: %s", r.GetBody())
		}
		rt = body(t, r)["refresh_token"].(string)
		// The lifetime passed with the write is what is left of the 12 hours, not 12 hours again.
		if ttl := e.store.ttls[key("session-chain", testTenant, sid)]; ttl != 5*time.Hour {
			t.Errorf("chain ttl after a refresh = %v, want 5h0m0s", ttl)
		}
		// The token is capped at the end of the chain too: 5 hours left, the token lives 10 minutes.
		e.clk.advance(7 * time.Hour)
		if now := e.clk.now(); now.Sub(start) <= 12*time.Hour {
			t.Fatal("the test did not pass the limit")
		}
		assertOAuth(t, e.token(refreshRequest(rt)), http.StatusBadRequest, "invalid_grant")
	})
	t.Run("exp is capped at the end of the chain", func(t *testing.T) {
		e := newEnv(t, func(o *options) { o.lifetime.HumanSessionAbsolute = durationpb.New(time.Hour) })
		first, _ := e.redeemed()
		e.clk.advance(55 * time.Minute)
		r := e.token(refreshRequest(first["refresh_token"].(string)))
		if r.GetStatus() != http.StatusOK {
			t.Fatalf("refresh: %s", r.GetBody())
		}
		_, at := tokenClaims(t, body(t, r)["access_token"].(string))
		if got := num(at, "exp") - num(at, "iat"); got != 300 {
			t.Errorf("exp-iat = %d, want the 5 minutes left", got)
		}
	})
}

func TestRefreshScopeMayNarrowNotWiden(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.Scope = "openid profile"
	a := e.authorize(p.req)
	up := location(t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: up.Query().Get("state"), Cookie: cookieValue(t, a)})
	code := location(t, cb).Query().Get("code")
	first := body(t, e.token(codeRequest(code, p)))
	if first["scope"] != "openid profile" {
		t.Fatalf("scope = %v", first["scope"])
	}
	rt := first["refresh_token"].(string)

	wider := refreshRequest(rt)
	wider.Scope = "openid profile email"
	assertOAuth(t, e.token(wider), http.StatusBadRequest, "invalid_scope")
	narrower := refreshRequest(rt)
	narrower.Scope = "openid"
	r := e.token(narrower)
	if r.GetStatus() != http.StatusOK {
		t.Fatalf("narrower: %s", r.GetBody())
	}
	if got := body(t, r)["scope"]; got != "openid" {
		t.Errorf("scope = %v", got)
	}
}

func TestRefreshPolicyDecidesEveryTime(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt := first["refresh_token"].(string)
	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{
			Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-no", Digest: "digest-1",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "example-app-fresh-mfa", Annotations: map[string]string{"step_up": "max_age=900"}}},
		}, nil
	}
	b := assertOAuth(t, e.token(refreshRequest(rt)), http.StatusBadRequest, "insufficient_user_authentication")
	if b["max_age"] != "900" {
		t.Errorf("answer = %v", b)
	}
	// A denial does not rotate the token: the person may step up and the old token still names the chain.
	e.policy.decide = nil
	if r := e.token(refreshRequest(rt)); r.GetStatus() != http.StatusOK {
		t.Fatalf("after the denial: %s", r.GetBody())
	}
}

func TestRefreshOfAHeldPersonIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	e.store.putRaw("person-hold", testTenant, e.store.ids("person", testTenant)[0], []byte{1})
	var state string
	e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		state = r.GetPerson().GetState()
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-held", Digest: "digest-1"}, nil
	}
	assertOAuth(t, e.token(refreshRequest(first["refresh_token"].(string))), http.StatusBadRequest, "invalid_grant")
	if state != "held" {
		t.Errorf("state = %q", state)
	}
}

func TestRefreshConcurrentUseOfOneTokenEndsTheChain(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt := first["refresh_token"].(string)
	var wg sync.WaitGroup
	results := make([]int32, 6)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.client.Token(context.Background(), connect.NewRequest(refreshRequest(rt)))
			if err == nil {
				results[i] = res.Msg.GetStatus()
			}
		}()
	}
	wg.Wait()
	ok := 0
	for _, s := range results {
		if s == http.StatusOK {
			ok++
		}
	}
	if ok > 1 {
		t.Fatalf("%d of 6 refreshes of one token succeeded: %v", ok, results)
	}
}

func TestRefreshTokenIsNotStored(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	_, secret, _ := strings.Cut(first["refresh_token"].(string), ".")
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	for k, it := range e.store.items {
		if strings.Contains(string(it.value), secret) || strings.Contains(k, secret) {
			t.Errorf("the refresh secret is stored in %q", strings.ReplaceAll(k, "\x00", "/"))
		}
	}
}
