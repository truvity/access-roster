//go:build sluis_test

package sessiond_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// codeRequest is the token request of the CLI for a code.
func codeRequest(code string, p authorizeParams) *sessionv2alpha1.TokenRequest {
	return &sessionv2alpha1.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectUri: p.req.GetRedirectUri(),
		CodeVerifier: p.verifier, ClientId: p.req.GetClientId(),
	}
}

// body decodes a JSON body.
func body(t *testing.T, r *typev2alpha1.HttpReply) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.GetBody(), &m); err != nil {
		t.Fatalf("body %q: %v", r.GetBody(), err)
	}
	return m
}

// tokenClaims reads a token of the fake signer: the type and the claims.
func tokenClaims(t *testing.T, token string) (typ string, claims map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", token)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(dec(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	return string(dec(parts[0])), claims
}

func num(m map[string]any, k string) int64 {
	f, _ := m[k].(float64)
	return int64(f)
}

// redeemed signs in and redeems the code; it returns the answer, ready for a test of the tokens.
func (e *env) redeemed() (map[string]any, authorizeParams) {
	e.t.Helper()
	code, p := e.signIn()
	r := e.token(codeRequest(code, p))
	if r.GetStatus() != http.StatusOK {
		e.t.Fatalf("token: %d %s", r.GetStatus(), r.GetBody())
	}
	return body(e.t, r), p
}

func TestTokenCodeGrantIssuesTheTokens(t *testing.T) {
	e := newEnv(t, nil)
	code, p := e.signIn()
	r := e.token(codeRequest(code, p))

	if r.GetStatus() != http.StatusOK {
		t.Fatalf("status %d: %s", r.GetStatus(), r.GetBody())
	}
	if ct := headerOf(r, "Content-Type"); len(ct) != 1 || ct[0] != "application/json" {
		t.Errorf("Content-Type = %v", ct)
	}
	if cc, pr := headerOf(r, "Cache-Control"), headerOf(r, "Pragma"); len(cc) != 1 || cc[0] != "no-store" || len(pr) != 1 || pr[0] != "no-cache" {
		t.Errorf("Cache-Control %v Pragma %v (RFC 6749 section 5.1)", cc, pr)
	}
	b := body(t, r)
	if b["token_type"] != "Bearer" || b["scope"] != "openid" || num(b, "expires_in") != 600 {
		t.Errorf("response = %v", b)
	}
	person := e.store.ids("person", testTenant)[0]

	// The ID token (OpenID Connect Core section 2): the client is the audience, the nonce is the client's own, and the
	// acr is absent because the upstream said none, though the methods show a second factor (0031).
	typ, id := tokenClaims(t, b["id_token"].(string))
	if typ != "JWT" {
		t.Errorf("ID token typ = %q", typ)
	}
	if id["iss"] != testIssuer || id["aud"] != testClient || id["nonce"] != "client-nonce-1" {
		t.Errorf("ID token = %v", id)
	}
	if _, has := id["acr"]; has {
		t.Errorf("an acr was made up: %v", id["acr"])
	}
	if amr, _ := id["amr"].([]any); len(amr) != 3 || amr[2] != "mfa" {
		t.Errorf("amr = %v", id["amr"])
	}
	if num(id, "auth_time") != e.clk.now().Add(-30*time.Second).Unix() {
		t.Errorf("auth_time = %v", id["auth_time"])
	}
	if num(id, "exp")-num(id, "iat") != 600 || num(id, "iat") != e.clk.now().Unix() {
		t.Errorf("iat %v exp %v", id["iat"], id["exp"])
	}
	if g, _ := id["groups"].([]any); len(g) != 1 || g[0] != testGroup {
		t.Errorf("groups = %v", id["groups"])
	}
	// sub is the tenant's pairwise subject, not the person's own id (0034).
	sub, _ := id["sub"].(string)
	if sub == "" || sub == person || strings.Contains(sub, person) || strings.Contains(sub, "alice") {
		t.Errorf("sub = %q", sub)
	}
	if len(sub) != 43 {
		t.Errorf("sub %q is not 256 bits of base64url", sub)
	}

	// The access token (RFC 9068 section 2.2): typ at+jwt, jti, client_id, the same sub and sid, and no nonce.
	typ, at := tokenClaims(t, b["access_token"].(string))
	if typ != "at+jwt" {
		t.Errorf("access token typ = %q", typ)
	}
	for _, k := range []string{"iss", "sub", "aud", "exp", "iat", "jti", "client_id", "sid"} {
		if at[k] == nil {
			t.Errorf("access token lacks %s", k)
		}
	}
	if at["sub"] != sub || at["sid"] != id["sid"] || at["client_id"] != testClient {
		t.Errorf("access token = %v", at)
	}
	if _, has := at["nonce"]; has {
		t.Error("an access token carries a nonce")
	}

	// The refresh token names the chain, and the chain holds a hash of its secret and nothing else of it.
	rt := b["refresh_token"].(string)
	sid, secret, _ := strings.Cut(rt, ".")
	if sid != id["sid"] || len(secret) != 43 {
		t.Fatalf("refresh token %q", rt)
	}
	raw, _, ok := e.store.raw("session-chain", testTenant, sid)
	if !ok {
		t.Fatal("no session chain")
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "alice") {
		t.Error("the chain holds the secret or the account in the clear")
	}
	chain := protoOf(t, raw, &sessionv2alpha1.SessionChain{})
	if len(chain.GetRefreshHash()) != 48 || chain.GetClass() != "human" || chain.GetSubject() != person || chain.GetClientId() != testClient {
		t.Errorf("chain = %v", chain)
	}
	if ttl := e.store.ttls[key("session-chain", testTenant, sid)]; ttl != 12*time.Hour {
		t.Errorf("chain ttl = %v, want the absolute limit", ttl)
	}

	// The code is spent, not deleted, so a replay can be told from a code that never existed.
	raw, _, _ = e.store.raw("auth-code", testTenant, sha384hex(code))
	if ac := protoOf(t, raw, &sessionv2alpha1.AuthCode{}); !ac.GetSpent() || ac.GetSessionId() != sid {
		t.Errorf("AuthCode = %v", ac)
	}

	// Policy decided again with the person's own subject, for the verbs this step needs.
	reqs := e.policy.requests()
	last := reqs[len(reqs)-1]
	if last.GetPerson().GetSubject() != person || last.GetPerson().GetAccounts()[0] != "workforce/alice" ||
		strings.Join(last.GetGrantStoreVerbs(), ",") != "update,create" || len(last.GetGrantKeyOps()) != 0 {
		t.Errorf("decision = %v", last)
	}
	// What was signed is what the signer is allowed to sign: types JWT and at+jwt, one per token.
	sr := e.signer.requests()
	if len(sr) != 2 || sr[0].GetTyp() != "JWT" || sr[1].GetTyp() != "at+jwt" {
		t.Errorf("signer requests = %v", sr)
	}
}

func TestTokenIsAudited(t *testing.T) {
	e := newEnv(t, nil)
	b, _ := e.redeemed()
	codes := e.eventCodes()
	if strings.Join(codes, ",") != "session.authorize,session.signin,session.token" {
		t.Fatalf("records = %v", codes)
	}
	raw := string(mustJSON(e.records()[2]))
	for _, secret := range []string{b["access_token"].(string), b["id_token"].(string), b["refresh_token"].(string), "alice", "client-nonce", "client-state"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the record holds a secret: %.20s", secret)
		}
	}
	if !strings.Contains(raw, `"d-2"`) {
		t.Errorf("the record does not name the decision: %s", raw)
	}
}

func TestTokenCodeWorksOnce(t *testing.T) {
	e := newEnv(t, nil)
	code, p := e.signIn()
	first := e.token(codeRequest(code, p))
	if first.GetStatus() != http.StatusOK {
		t.Fatalf("first: %s", first.GetBody())
	}
	rt := body(t, first)["refresh_token"].(string)

	second := e.token(codeRequest(code, p))
	assertOAuth(t, second, http.StatusBadRequest, "invalid_grant")
	// A replayed code revokes what it issued: the refresh token of the first redemption is dead.
	assertOAuth(t, e.token(&sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: rt, ClientId: testClient}),
		http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != 0 {
		t.Errorf("%d chains survive a replayed code", n)
	}
	var reuse bool
	for _, c := range e.eventCodes() {
		if c == "session.chain.end" {
			reuse = true
		}
	}
	if !reuse {
		t.Error("the end of the chain is not recorded")
	}
}

func TestTokenConcurrentRedemptionsMakeOneSession(t *testing.T) {
	e := newEnv(t, nil)
	code, p := e.signIn()
	var wg sync.WaitGroup
	results := make([]int32, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := e.client.Token(context.Background(), connect.NewRequest(codeRequest(code, p)))
			if err != nil {
				return
			}
			results[i] = res.Msg.GetStatus()
		}()
	}
	wg.Wait()
	ok := 0
	for _, s := range results {
		if s == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d of 8 redemptions succeeded: %v", ok, results)
	}
}

func assertOAuth(t *testing.T, r *typev2alpha1.HttpReply, status int32, code string) map[string]any {
	t.Helper()
	if r.GetStatus() != status {
		t.Fatalf("status %d (%s), want %d %s", r.GetStatus(), r.GetBody(), status, code)
	}
	b := body(t, r)
	if b["error"] != code {
		t.Fatalf("error = %v, want %s", b["error"], code)
	}
	if ct := headerOf(r, "Content-Type"); len(ct) != 1 || ct[0] != "application/json" {
		t.Errorf("Content-Type = %v", ct)
	}
	if cc := headerOf(r, "Cache-Control"); len(cc) != 1 || cc[0] != "no-store" {
		t.Errorf("Cache-Control = %v", cc)
	}
	if (status == http.StatusUnauthorized) != (len(headerOf(r, "WWW-Authenticate")) == 1) {
		t.Errorf("WWW-Authenticate = %v for %d", headerOf(r, "WWW-Authenticate"), status)
	}
	return b
}

func TestTokenChecksThePKCEVerifierTheClientAndTheRedirect(t *testing.T) {
	e := newEnv(t, func(o *options) {
		o.extra = []*configv2alpha1.InstallationClient{{Id: "other-app", Kind: "public", Redirects: []string{"http://127.0.0.1/callback"}}}
	})
	code, p := e.signIn()
	cases := map[string]func(*sessionv2alpha1.TokenRequest){
		"wrong verifier":        func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = strings.Repeat("v", 43) },
		"verifier of the plain": func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = p.req.GetCodeChallenge() },
		"another client":        func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "other-app" },
		"another redirect":      func(r *sessionv2alpha1.TokenRequest) { r.RedirectUri = "http://127.0.0.1:1/callback" },
		"another code":          func(r *sessionv2alpha1.TokenRequest) { r.Code = code + "x" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			req := codeRequest(code, p)
			edit(req)
			assertOAuth(t, e.token(req), http.StatusBadRequest, "invalid_grant")
		})
	}
	// None of those spent the code: the right request still works.
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the code was spent by a refused request: %s", r.GetBody())
	}
}

func TestTokenCodeExpires(t *testing.T) {
	e := newEnv(t, nil)
	code, p := e.signIn()
	e.clk.advance(61 * time.Second)
	assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "invalid_grant")
	if len(e.signer.requests()) != 0 {
		t.Error("a token was signed for an expired code")
	}
}

func TestTokenRefusesWhatItDoesNotServe(t *testing.T) {
	e := newEnv(t, func(o *options) {
		o.extra = []*configv2alpha1.InstallationClient{{Id: "confidential-app", Kind: "confidential", Redirects: []string{"https://app.example.com/cb"}}}
	})
	code, p := e.signIn()
	type c struct {
		edit   func(*sessionv2alpha1.TokenRequest)
		status int32
		code   string
	}
	cases := map[string]c{
		"unknown client":       {func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "nobody" }, 401, "invalid_client"},
		"no client":            {func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "" }, 401, "invalid_client"},
		"confidential client":  {func(r *sessionv2alpha1.TokenRequest) { r.ClientId = "confidential-app" }, 401, "invalid_client"},
		"public with a secret": {func(r *sessionv2alpha1.TokenRequest) { r.ClientSecret = "x" }, 401, "invalid_client"},
		"public with basic":    {func(r *sessionv2alpha1.TokenRequest) { r.Authorization = "Basic c2x1aXMtY2xpOng=" }, 401, "invalid_client"},
		"no code":              {func(r *sessionv2alpha1.TokenRequest) { r.Code = "" }, 400, "invalid_request"},
		"no verifier":          {func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = "" }, 400, "invalid_request"},
		"short verifier":       {func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = "short" }, 400, "invalid_request"},
		"verifier with space":  {func(r *sessionv2alpha1.TokenRequest) { r.CodeVerifier = strings.Repeat("a b", 20) }, 400, "invalid_request"},
		"no redirect":          {func(r *sessionv2alpha1.TokenRequest) { r.RedirectUri = "" }, 400, "invalid_request"},
		"code with a control":  {func(r *sessionv2alpha1.TokenRequest) { r.Code = "a\nb" }, 400, "invalid_request"},
		"unsupported grant":    {func(r *sessionv2alpha1.TokenRequest) { r.GrantType = "password" }, 400, "unsupported_grant_type"},
		"no grant":             {func(r *sessionv2alpha1.TokenRequest) { r.GrantType = "" }, 400, "unsupported_grant_type"},
		"token exchange":       {func(r *sessionv2alpha1.TokenRequest) { r.GrantType = "urn:ietf:params:oauth:grant-type:token-exchange" }, 400, "unsupported_grant_type"},
	}
	var bodies []string
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := codeRequest(code, p)
			tc.edit(req)
			r := e.token(req)
			assertOAuth(t, r, tc.status, tc.code)
			if tc.code == "invalid_client" {
				bodies = append(bodies, string(r.GetBody()))
			}
			if strings.Contains(string(r.GetBody()), "nobody") || strings.Contains(string(r.GetBody()), "confidential") {
				t.Error("the answer repeats the request")
			}
		})
	}
	// An unknown client and a client session does not serve look the same.
	for _, b := range bodies {
		if b != bodies[0] {
			t.Errorf("invalid_client bodies differ: %q vs %q", b, bodies[0])
		}
	}
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("a refused request spent the code: %s", r.GetBody())
	}
}

func TestTokenPolicyDenies(t *testing.T) {
	deny := func(annotations map[string]string) func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
			// The sign-in (the first question) is allowed; the code exchange is not.
			if len(r.GetGrantKeyOps()) > 0 {
				return allowAll(r), nil
			}
			return &policyv2alpha1.DecideResponse{
				Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-deny", Digest: "digest-1",
				Reasons: []*policyv2alpha1.Reason{{PolicyId: "example-app-fresh-mfa", Annotations: annotations}},
			}, nil
		}
	}
	t.Run("a plain denial", func(t *testing.T) {
		e := newEnv(t, nil)
		e.policy.decide = deny(nil)
		code, p := e.signIn()
		b := assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "invalid_grant")
		if len(b) != 2 {
			t.Errorf("members = %v", b)
		}
		if len(e.signer.requests()) != 0 || e.store.count("session-chain", testTenant) != 0 {
			t.Error("something was issued for a denial")
		}
	})
	t.Run("a step-up", func(t *testing.T) {
		e := newEnv(t, nil)
		e.policy.decide = deny(map[string]string{"step_up": "acr_values=urn:example:acr:mfa max_age=900 redirect=evil"})
		code, p := e.signIn()
		b := assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "insufficient_user_authentication")
		if b["acr_values"] != "urn:example:acr:mfa" || b["max_age"] != "900" || len(b) != 4 {
			t.Errorf("answer = %v", b)
		}
		// The denial did not spend the code, but a client has to sign in again for the step-up; nothing was issued.
		if e.store.count("session-chain", testTenant) != 0 {
			t.Error("a chain was made")
		}
	})
	t.Run("a held person", func(t *testing.T) {
		e := newEnv(t, nil)
		code, p := e.signIn()
		e.store.putRaw("person-hold", testTenant, e.store.ids("person", testTenant)[0], []byte{1})
		var state string
		e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
			state = r.GetPerson().GetState()
			return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-held", Digest: "digest-1"}, nil
		}
		assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "invalid_grant")
		if state != "held" {
			t.Errorf("policy was told the state %q", state)
		}
	})
}

func allowAll(r *policyv2alpha1.DecideRequest) *policyv2alpha1.DecideResponse {
	g := fakeGrant{id: "d-x", tenant: r.GetTenant(), verbs: r.GetGrantStoreVerbs(), ops: r.GetGrantKeyOps(), expires: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)}
	return &policyv2alpha1.DecideResponse{
		Decision: policyv2alpha1.Decision_ALLOW, DecisionId: "d-x", Digest: "digest-1", GrantNames: []string{testGroup}, SealedGrant: []byte(g.encode()),
	}
}

func TestTokenDependenciesDownFailClosed(t *testing.T) {
	cases := map[string]func(*env){
		"policy": func(e *env) {
			e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
				if len(r.GetGrantKeyOps()) > 0 {
					return allowAll(r), nil
				}
				return nil, connect.NewError(connect.CodeUnavailable, nil)
			}
		},
		"signer": func(e *env) { e.signer.err = connect.NewError(connect.CodeUnavailable, nil) },
		"audit":  func(e *env) { e.transport.err = connect.NewError(connect.CodeUnavailable, nil) },
	}
	for name, down := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			code, p := e.signIn()
			down(e)
			res, err := e.client.Token(context.Background(), connect.NewRequest(codeRequest(code, p)))
			if err == nil {
				t.Fatalf("answered %d %s", res.Msg.GetStatus(), res.Msg.GetBody())
			}
			if connect.CodeOf(err) != connect.CodeUnavailable {
				t.Errorf("code = %v", connect.CodeOf(err))
			}
		})
	}
}

func TestTokenLifetimes(t *testing.T) {
	t.Run("the client's ttl_cap shortens", func(t *testing.T) {
		e := newEnv(t, func(o *options) { o.client.TtlCap = durationpb.New(2 * time.Minute) })
		b, _ := e.redeemed()
		_, at := tokenClaims(t, b["access_token"].(string))
		if num(at, "exp")-num(at, "iat") != 120 || num(b, "expires_in") != 120 {
			t.Errorf("exp-iat = %d, expires_in %d", num(at, "exp")-num(at, "iat"), num(b, "expires_in"))
		}
	})
	t.Run("the end of the session shortens", func(t *testing.T) {
		e := newEnv(t, func(o *options) { o.lifetime.HumanSessionAbsolute = durationpb.New(5 * time.Minute) })
		b, _ := e.redeemed()
		_, at := tokenClaims(t, b["access_token"].(string))
		if got := num(at, "exp") - num(at, "iat"); got != 300 {
			t.Errorf("exp-iat = %d, want the chain's 300", got)
		}
	})
	t.Run("the built-in maximum caps a longer setting", func(t *testing.T) {
		e := newEnv(t, func(o *options) {
			o.lifetime.IdToken, o.lifetime.AccessToken = durationpb.New(9*time.Hour), durationpb.New(9*time.Hour)
		})
		b, _ := e.redeemed()
		_, at := tokenClaims(t, b["access_token"].(string))
		if got := num(at, "exp") - num(at, "iat"); got != 3600 {
			t.Errorf("exp-iat = %d, want 3600", got)
		}
	})
}

func TestSubjectIsPairwiseUnlessThePublicSectorIsDeclared(t *testing.T) {
	sub := func(e *env) (string, string) {
		b, _ := e.redeemed()
		_, id := tokenClaims(t, b["id_token"].(string))
		return id["sub"].(string), e.store.ids("person", testTenant)[0]
	}
	e := newEnv(t, nil)
	s1, person := sub(e)
	if s1 == person {
		t.Fatal("sub is the person's own id")
	}
	// The same person at the same tenant gets the same sub every time.
	e.clk.advance(time.Second)
	s2, _ := sub(e)
	if s1 != s2 {
		t.Errorf("sub changed: %q then %q", s1, s2)
	}
	// A declared public sector gets the person's own id (0034).
	e = newEnv(t, func(o *options) {
		o.sectors = func(string) sessiond.Sector { return sessiond.Sector{Name: "public", Public: true} }
	})
	s3, person3 := sub(e)
	if s3 != person3 {
		t.Errorf("public sector: sub %q, person %q", s3, person3)
	}
	// A sector that is only called "public" is not the public sector: only a declaration makes one.
	e = newEnv(t, func(o *options) { o.sectors = func(string) sessiond.Sector { return sessiond.Sector{Name: "public"} } })
	if s4, person4 := sub(e); s4 == person4 {
		t.Error("a sector named public was taken for the public one")
	}
	// Two sectors give one person two different subjects.
	other := newEnv(t, func(o *options) { o.sectors = func(string) sessiond.Sector { return sessiond.Sector{Name: "other"} } })
	sa, _ := sub(newEnv(t, nil))
	sb, _ := sub(other)
	if sa == sb {
		t.Error("two sectors, one subject")
	}
}

func TestTokenGroupsAreNarrowedToTheAudience(t *testing.T) {
	e := newEnv(t, func(o *options) { o.client.Requires = []string{"dev:example-app:user"} })
	e.policy.grantNames = []string{"dev:example-app:admin", "dev:example-app:user", "dev:other-app:admin", "all:example-app:user", "prod:example-app:admin"}
	b, _ := e.redeemed()
	_, id := tokenClaims(t, b["id_token"].(string))
	g, _ := id["groups"].([]any)
	if len(g) != 2 || g[0] != "dev:example-app:admin" || g[1] != "dev:example-app:user" {
		t.Errorf("groups = %v (the pair dev:example-app, in any role, and nothing else)", g)
	}
	// A client that requires nothing gets no groups claim at all.
	e = newEnv(t, func(o *options) { o.client.Requires = nil })
	b, _ = e.redeemed()
	_, id = tokenClaims(t, b["id_token"].(string))
	if _, has := id["groups"]; has {
		t.Errorf("groups = %v", id["groups"])
	}
}

func TestTokenLosingRedemptionEndsTheWinnersChain(t *testing.T) {
	// Another instance redeems the code between this one's read and its write: this one's conditional update aborts,
	// it finds the code spent, and it ends the chain the winner made. The winner's chain exists by then because the
	// code is spent and the chain is created in one write.
	e := newEnv(t, nil)
	code, p := e.signIn()
	id := sha384hex(code)
	const winner = "winnerwinnerwinnerwinner26"
	var once sync.Once
	e.store.beforeWrite = func(s *fakeStore, _ []*storev2alpha1.Operation) {
		once.Do(func() {
			k := key("auth-code", testTenant, id)
			ac := protoOf(t, s.items[k].value, &sessionv2alpha1.AuthCode{})
			ac.Spent, ac.SessionId = true, winner
			ac.SealedFacts = nil
			raw, _ := proto.Marshal(ac)
			s.items[k] = &storedItem{value: raw, version: s.items[k].version + 1}
			facts, err := e.key.sealForTest("data", &typev2alpha1.Address{Kind: "session-chain", Id: winner}, &sessionv2alpha1.SignInFacts{Accounts: []string{"workforce/alice"}})
			if err != nil {
				panic(err)
			}
			chain, _ := proto.Marshal(&sessionv2alpha1.SessionChain{Subject: ac.GetSubject(), ClientId: testClient, Class: "human", SealedFacts: facts})
			s.items[key("session-chain", testTenant, winner)] = &storedItem{value: chain, version: 1}
		})
	}
	assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "invalid_grant")
	if _, _, ok := e.store.raw("session-chain", testTenant, winner); ok {
		t.Fatal("the winner's chain survives the losing redemption")
	}
	if n := e.store.count("session-chain", testTenant); n != 0 {
		t.Errorf("%d chains", n)
	}
}

func TestTokenSpendAndChainAreOneWrite(t *testing.T) {
	e := newEnv(t, nil)
	code, p := e.signIn()
	before := len(e.store.writes)
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("token: %s", r.GetBody())
	}
	writes := e.store.writes[before:]
	if len(writes) != 1 || len(writes[0]) != 2 {
		t.Fatalf("%d writes for the redemption, want one batch of two", len(writes))
	}
	if writes[0][0].GetAddress().GetKind() != "auth-code" || writes[0][1].GetAddress().GetKind() != "session-chain" {
		t.Errorf("batch = %v", writes[0])
	}
}
