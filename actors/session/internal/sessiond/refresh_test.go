//go:build sluis_test

package sessiond_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
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

// verifies: REQ-SESS-001
func TestRefreshOfASpentTokenEndsTheChain(t *testing.T) {
	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	second := body(t, e.token(refreshRequest(rt1)))
	rt2 := second["refresh_token"].(string)

	// The old token again, after the grace window (refresh_grace_test.go): refused, and the chain ends at once
	// (REQ-SESS-001), so the new token is dead as well.
	e.clk.advance(testGrace + time.Second)
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

// A refresh token of another installation names a chain this one never made: the token endpoint answers invalid_grant
// and creates nothing, as it does for a guess at the secret of a chain it knows.
//
// verifies: REQ-SEC-011
func TestRefreshWithATokenThisInstallationNeverIssuedIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.redeemed()
	before := e.store.count("session-chain", testTenant)
	// Well-formed (a 26-character sid and a 43-character secret), so that it reaches the lookup of the chain.
	foreign := strings.Repeat("b", 26) + "." + strings.Repeat("c", 43)
	assertOAuth(t, e.token(refreshRequest(foreign)), http.StatusBadRequest, "invalid_grant")
	if n := e.store.count("session-chain", testTenant); n != before {
		t.Fatalf("%d chains, want %d", n, before)
	}
}

// verifies: REQ-SEC-011
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

// verifies: REQ-SESS-002
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

// verifies: REQ-SESS-027, REQ-SESS-015
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

// verifies: REQ-SESS-003
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

// verifies: REQ-SESS-044
func TestSessionChainIsATempKindThatHoldsOnlyHashes(t *testing.T) {
	// The kind: temp, so a lost class costs a sign-in (ADR 0018), and hashed, so a copy of the store yields no token.
	kind, ok := registry.KindByName("SessionChain")
	if !ok {
		t.Fatal("no SessionChain kind in the registry")
	}
	if kind.Class != "temp" || kind.Treatment != "hashed" || kind.Writer != "session" || kind.TTLDefault <= 0 || kind.TTLMax < kind.TTLDefault {
		t.Fatalf("SessionChain = %+v", kind)
	}

	e := newEnv(t, nil)
	first, _ := e.redeemed()
	rt1 := first["refresh_token"].(string)
	sid, secret1, _ := strings.Cut(rt1, ".")
	start := e.clk.now()

	// What session wrote: one chain under the kind's segment, holding the SHA-384 of the secret and no spent marker yet.
	if ids := e.store.ids(kind.Segment, testTenant); len(ids) != 1 || ids[0] != sid {
		t.Fatalf("chains %v, want [%s]", ids, sid)
	}
	chainRaw, version, _ := e.store.raw(kind.Segment, testTenant, sid)
	chain := protoOf(t, chainRaw, &sessionv2alpha1.SessionChain{})
	if want := sha384Of(secret1); !bytes.Equal(chain.GetRefreshHash(), want) || len(chain.GetSpentHashes()) != 0 || version != 1 {
		t.Errorf("refresh_hash %x, spent %d, version %d; want %x, 0, 1", chain.GetRefreshHash(), len(chain.GetSpentHashes()), version, want)
	}
	// A temp kind has a lifetime: the chain is written with a ttl of the human session's absolute limit.
	ttlOf := func() time.Duration {
		e.store.mu.Lock()
		defer e.store.mu.Unlock()
		return e.store.ttls[key(kind.Segment, testTenant, sid)]
	}
	absolute := 12 * time.Hour
	if got := ttlOf(); got != absolute || got > kind.TTLMax {
		t.Errorf("chain ttl = %s, want %s (kind maximum %s)", got, absolute, kind.TTLMax)
	}

	// A refresh rotates: the new hash replaces the current one and the old one becomes a spent marker. Still hashes only,
	// and the ttl counts down to the same absolute end, so a rotation does not extend the chain.
	e.clk.advance(time.Hour)
	second := body(t, e.token(refreshRequest(rt1)))
	rt2 := second["refresh_token"].(string)
	_, secret2, _ := strings.Cut(rt2, ".")
	chainRaw, version, _ = e.store.raw(kind.Segment, testTenant, sid)
	chain = protoOf(t, chainRaw, &sessionv2alpha1.SessionChain{})
	if version != 2 || !bytes.Equal(chain.GetRefreshHash(), sha384Of(secret2)) ||
		len(chain.GetSpentHashes()) != 1 || !bytes.Equal(chain.GetSpentHashes()[0], sha384Of(secret1)) {
		t.Errorf("after a refresh: version %d, refresh_hash %x, spent %x", version, chain.GetRefreshHash(), chain.GetSpentHashes())
	}
	if got, want := ttlOf(), absolute-time.Hour; got != want {
		t.Errorf("chain ttl after a refresh = %s, want %s", got, want)
	}
	if end := start.Add(absolute); !chain.GetEndsAt().AsTime().Equal(end) {
		t.Errorf("ends_at = %s, want %s", chain.GetEndsAt().AsTime(), end)
	}

	// The scan: nothing session stored or wrote holds a refresh token, in whole or its secret, as the client got it or in
	// the usual encodings of the bytes: the current one, the spent one, or one of either ever shown to the client.
	chains := e.store.count(kind.Segment, testTenant)
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	// A scan of nothing proves nothing: session wrote the chain and rotated it, so it made writes and holds a chain.
	if len(e.store.writes) == 0 || chains != 1 {
		t.Fatalf("the scan saw %d writes and %d chains", len(e.store.writes), chains)
	}
	records := e.transport.records()
	if len(records) == 0 {
		t.Fatal("the scan saw no audit records")
	}
	for _, tok := range []string{rt1, rt2, secret1, secret2} {
		needles := map[string][]byte{
			"as issued": []byte(tok), "base64": []byte(base64.StdEncoding.EncodeToString([]byte(tok))),
			"base64url": []byte(base64.RawURLEncoding.EncodeToString([]byte(tok))), "hex": []byte(hex.EncodeToString([]byte(tok))),
		}
		holds := func(hay []byte) (string, bool) {
			for how, n := range needles {
				if bytes.Contains(hay, n) {
					return how, true
				}
			}
			return "", false
		}
		// What is stored: every value and every key.
		for k, it := range e.store.items {
			if how, bad := holds(it.value); bad {
				t.Errorf("a refresh token (%s) is stored in the value of %q", how, strings.ReplaceAll(k, "\x00", "/"))
			}
			if how, bad := holds([]byte(k)); bad {
				t.Errorf("a refresh token (%s) is in the key %q", how, strings.ReplaceAll(k, "\x00", "/"))
			}
		}
		// What session wrote, which is what a copy of the store's log would hold: values and addresses.
		for _, ops := range e.store.writes {
			for _, op := range ops {
				a := op.GetAddress()
				if how, bad := holds(op.GetValue()); bad {
					t.Errorf("a write of %s/%s carries a refresh token (%s) in its value", a.GetKind(), verbName[op.GetVerb()], how)
				}
				if how, bad := holds([]byte(a.GetKind() + "/" + a.GetTenant() + "/" + a.GetId())); bad {
					t.Errorf("a write of %s/%s carries a refresh token (%s) in its address", a.GetKind(), verbName[op.GetVerb()], how)
				}
			}
		}
		// And what session said to the audit log.
		for i, rec := range records {
			if how, bad := holds(rec); bad {
				t.Errorf("audit record %d carries a refresh token (%s)", i, how)
			}
		}
	}
}

func sha384Of(s string) []byte {
	sum := sha512.Sum384([]byte(s))
	return sum[:]
}

// verifies: REQ-SESS-016
func TestRefreshKeepsAcrAmrAuthTimeAndSid(t *testing.T) {
	acr := "urn:example:acr:mfa"
	cases := []struct {
		name       string
		a          *integrationv2alpha1.Assertion
		noAuthTime bool // the upstream said nothing about when the person authenticated
	}{
		{name: "acr, amr and auth_time", a: &integrationv2alpha1.Assertion{Acr: &acr, Amr: []string{"pwd", "hwk", "mfa"}, AmrPresent: true}},
		// An absent value stays absent: a refresh does not make an acr or an auth_time up (0020, 0031).
		{name: "no acr", a: &integrationv2alpha1.Assertion{Amr: []string{"pwd", "otp"}, AmrPresent: true}},
		{name: "acr, no amr", a: &integrationv2alpha1.Assertion{Acr: &acr}},
		{name: "no auth_time", a: &integrationv2alpha1.Assertion{Acr: &acr, Amr: []string{"pwd", "hwk"}, AmrPresent: true}, noAuthTime: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.a
			e := newEnv(t, nil)
			authTime := e.clk.now().Add(-90 * time.Second)
			a.Issuer, a.SubjectClaim, a.Subject = "https://idp.example.test/realms/test", "preferred_username", "alice"
			if !c.noAuthTime {
				a.AuthTime = timestampOf(authTime)
			}
			e.upstream.assertion = a

			first, _ := e.redeemed()
			rt := first["refresh_token"].(string)
			sid, _, _ := strings.Cut(rt, ".")
			_, id0 := tokenClaims(t, first["id_token"].(string))
			_, at0 := tokenClaims(t, first["access_token"].(string))
			// The sign-in itself carries what the upstream said, so that the refreshes are compared with something real:
			// a claim dropped at the sign-in and at every refresh would otherwise pass as "kept".
			if id0["sid"] != sid {
				t.Fatalf("the sign-in ID token = %v", id0)
			}
			if c.noAuthTime != (id0["auth_time"] == nil) || (!c.noAuthTime && num(id0, "auth_time") != authTime.Unix()) {
				t.Fatalf("the sign-in auth_time = %v", id0["auth_time"])
			}
			if (a.Acr != nil) != (id0["acr"] != nil) || (a.Acr != nil && id0["acr"] != acr) {
				t.Fatalf("the sign-in acr = %v", id0["acr"])
			}
			if len(a.GetAmr()) > 0 {
				got, ok := id0["amr"].([]any)
				if !ok || len(got) != len(a.GetAmr()) {
					t.Fatalf("the sign-in amr = %v, want %v", id0["amr"], a.GetAmr())
				}
			} else if id0["amr"] != nil {
				t.Fatalf("the sign-in made an amr up: %v", id0["amr"])
			}
			chainBefore, _, _ := e.store.raw("session-chain", testTenant, sid)

			// Two refreshes, an hour apart, so a refresh that took "now" for the authentication would show.
			for i := 1; i <= 2; i++ {
				e.clk.advance(time.Hour)
				r := e.token(refreshRequest(rt))
				if r.GetStatus() != http.StatusOK {
					t.Fatalf("refresh %d: %d %s", i, r.GetStatus(), r.GetBody())
				}
				out := body(t, r)
				rt = out["refresh_token"].(string)
				_, id := tokenClaims(t, out["id_token"].(string))
				_, at := tokenClaims(t, out["access_token"].(string))
				if num(id, "iat") != e.clk.now().Unix() {
					t.Fatalf("refresh %d: iat = %v, the refresh did not happen now", i, id["iat"])
				}
				for _, tk := range []struct {
					name string
					m    map[string]any
					ref  map[string]any
				}{{"ID token", id, id0}, {"access token", at, at0}} {
					for _, claim := range []string{"acr", "amr", "auth_time", "sid"} {
						if !reflect.DeepEqual(tk.m[claim], tk.ref[claim]) {
							t.Errorf("refresh %d: %s %s = %v, was %v at sign-in", i, tk.name, claim, tk.m[claim], tk.ref[claim])
						}
					}
				}
				if got, _, _ := strings.Cut(rt, "."); got != sid {
					t.Errorf("refresh %d: the session id changed to %s", i, got)
				}
				// Policy decides at every refresh on the same assurance, so a refresh cannot lift or hide it there either.
				reqs := e.policy.requests()
				if len(reqs) == 0 {
					t.Fatalf("refresh %d: policy was not asked", i)
				}
				ctx := reqs[len(reqs)-1].GetContext()
				if ctx.GetAcr() != a.GetAcr() || (ctx.Acr != nil) != (a.Acr != nil) || !reflect.DeepEqual(ctx.GetAmr(), a.GetAmr()) ||
					ctx.GetAmrPresent() != a.GetAmrPresent() {
					t.Errorf("refresh %d: policy was told %v", i, ctx)
				}
				switch {
				case c.noAuthTime && ctx.AuthAge != nil:
					t.Errorf("refresh %d: auth age = %d, but the upstream sent no auth_time", i, *ctx.AuthAge)
				case !c.noAuthTime && (ctx.AuthAge == nil || *ctx.AuthAge != e.clk.now().Unix()-authTime.Unix()):
					t.Errorf("refresh %d: auth age = %v, want the age of the sign-in's auth_time", i, ctx.AuthAge)
				}
			}
			// The chain itself, which is what carries them, still holds the same facts.
			chainAfter, _, _ := e.store.raw("session-chain", testTenant, sid)
			before := protoOf(t, chainBefore, &sessionv2alpha1.SessionChain{})
			after := protoOf(t, chainAfter, &sessionv2alpha1.SessionChain{})
			if !reflect.DeepEqual(before.Acr, after.Acr) || !reflect.DeepEqual(before.GetAmr(), after.GetAmr()) ||
				before.GetAmrPresent() != after.GetAmrPresent() || !before.GetAuthTime().AsTime().Equal(after.GetAuthTime().AsTime()) {
				t.Errorf("the chain changed: %v then %v", before, after)
			}
		})
	}
}
