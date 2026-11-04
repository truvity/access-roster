//go:build sluis_test

package sessiond_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// started runs authorize and returns what the browser would bring back from the upstream.
func (e *env) started() (cb *sessionv2alpha1.CallbackRequest, p authorizeParams) {
	e.t.Helper()
	p = newAuthorize()
	a := e.authorize(p.req)
	up := location(e.t, a)
	return &sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	}, p
}

func TestCallbackIssuesACodeForTheClient(t *testing.T) {
	e := newEnv(t, nil)
	cb, p := e.started()
	r := e.callback(cb)

	back := location(t, r)
	if got := back.Scheme + "://" + back.Host + back.Path; got != testRedirect {
		t.Fatalf("redirected to %s", got)
	}
	q := back.Query()
	if q.Get("state") != p.req.GetState() {
		t.Errorf("state = %q, want the client's", q.Get("state"))
	}
	if q.Get("iss") != testIssuer {
		t.Errorf("iss = %q (RFC 9207)", q.Get("iss"))
	}
	code := q.Get("code")
	if len(code) < 43 {
		t.Fatalf("code %q is short", code)
	}
	// The cookie is spent.
	if set := headerOf(r, "Set-Cookie"); len(set) != 1 || !strings.Contains(set[0], "Max-Age=0") || cookieValue(t, r) != "" {
		t.Errorf("Set-Cookie = %v", set)
	}

	// The adapter got what it needs, with the verifier of the begin step, and the iss the upstream sent.
	if len(e.upstream.completes) != 1 {
		t.Fatalf("%d Complete calls", len(e.upstream.completes))
	}
	c := e.upstream.completes[0]
	if c.GetUpstream() != "workforce" || c.GetRedirectUri() != testIssuer+"/callback" || c.GetIss() != cb.GetIss() || c.GetCode() != cb.GetCode() {
		t.Errorf("Complete = %v", c)
	}
	if c.GetNonce() != e.upstream.begins[0].GetNonce() || s256(c.GetCodeVerifier()) != e.upstream.begins[0].GetCodeChallenge() {
		t.Error("Complete does not carry the nonce and verifier of Begin")
	}

	// The person and the link: sealed, found by a keyed hash, in the tenant of the client.
	people := e.store.ids("person", testTenant)
	links := e.store.ids("upstream-link", testTenant)
	if len(people) != 1 || len(links) != 1 {
		t.Fatalf("people %v, links %v", people, links)
	}
	if len(people[0]) != 26 {
		t.Errorf("subject %q is not 128 bits of base32", people[0])
	}
	for _, id := range append(append([]string{}, people...), links...) {
		if strings.Contains(id, "alice") {
			t.Errorf("id %q holds personal data", id)
		}
	}
	for _, kv := range []struct{ kind, id string }{{"person", people[0]}, {"upstream-link", links[0]}} {
		raw, _, _ := e.store.raw(kv.kind, testTenant, kv.id)
		if strings.Contains(string(raw), "alice") || strings.Contains(string(raw), people[0]) {
			t.Errorf("%s is not sealed", kv.kind)
		}
		if raw[0] != 1 {
			t.Errorf("%s is not an envelope", kv.kind)
		}
	}

	// The code: the item is found by the hash of the code, and the code is not in the store.
	ids := e.store.ids("auth-code", testTenant)
	if len(ids) != 1 || ids[0] != sha384hex(code) {
		t.Fatalf("auth codes %v", ids)
	}
	raw, _, _ := e.store.raw("auth-code", testTenant, ids[0])
	if strings.Contains(string(raw), code) {
		t.Error("the code is stored in the clear")
	}
	ac := protoOf(t, raw, &sessionv2alpha1.AuthCode{})
	if ac.GetSubject() != people[0] || ac.GetClientId() != testClient || ac.GetRedirectUri() != testRedirect ||
		ac.GetCodeChallenge() != p.req.GetCodeChallenge() || ac.GetNonce() != p.req.GetNonce() || ac.GetScope() != "openid" {
		t.Errorf("AuthCode = %v", ac)
	}
	if strings.Contains(string(raw), "alice") {
		t.Error("the account value is in the AuthCode in the clear")
	}
	if ttl := e.store.ttls[key("auth-code", testTenant, ids[0])]; ttl != defaultTTL["auth-code"] {
		t.Errorf("code ttl %v", ttl)
	}
	// 0031: the upstream's methods pass through; there was no acr, so there is none.
	if ac.Acr != nil || len(ac.GetAmr()) != 3 || !ac.GetAmrPresent() {
		t.Errorf("assurance: acr %v amr %v", ac.Acr, ac.GetAmr())
	}
	if ac.GetAuthTime() == nil || ac.GetAuthenticatedAt() == nil {
		t.Error("auth_time or authenticated_at missing")
	}

	// Every key@ call that needs a tenant grant carried one (the fake refuses otherwise), and nothing used a purpose
	// that session has no rule for.
	for _, c := range e.key.called() {
		switch c {
		case "mac mac", "seal cookie", "open cookie", "seal data", "open data", "mac pseudonym":
		default:
			t.Errorf("unexpected key call %q", c)
		}
	}
}

func sha384hex(s string) string {
	return secretIDForTest(s)
}

func TestCallbackAsksPolicyWithTheFacts(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	e.callback(cb)
	reqs := e.policy.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d decisions", len(reqs))
	}
	r := reqs[0]
	if r.GetAction() != "token.issue" || r.GetTenant() != testTenant {
		t.Errorf("action %q tenant %q", r.GetAction(), r.GetTenant())
	}
	if r.GetPrincipal().GetType() != "Person" || r.GetResource().GetType() != "Client" || r.GetResource().GetId() != testClient {
		t.Errorf("principal %v resource %v", r.GetPrincipal(), r.GetResource())
	}
	// The account is the pair (upstream name, subject claim value), never an e-mail address.
	if p := r.GetPerson(); p.GetOrg() != testTenant || p.GetState() != "live" || len(p.GetAccounts()) != 1 || p.GetAccounts()[0] != "workforce/alice" || p.GetSubject() != r.GetPrincipal().GetId() {
		t.Errorf("person = %v", p)
	}
	if c := r.GetClient(); c.GetKind() != "public" || c.GetId() != testClient || len(c.GetRequires()) != 1 || c.GetRequires()[0] != testGroup {
		t.Errorf("client = %v", c)
	}
	ctx := r.GetContext()
	if ctx.Acr != nil || !ctx.GetAmrPresent() || len(ctx.GetAmr()) != 3 || ctx.AuthAge == nil || *ctx.AuthAge != 30 {
		t.Errorf("context = %v", ctx)
	}
	// What the grant must allow: creates, and seal and open under the tenant's data key.
	if strings.Join(r.GetGrantStoreVerbs(), ",") != "create" || strings.Join(r.GetGrantKeyOps(), ",") != "seal,open" {
		t.Errorf("verbs %v ops %v", r.GetGrantStoreVerbs(), r.GetGrantKeyOps())
	}
}

func TestCallbackRefusesACallbackThatIsNotOurs(t *testing.T) {
	cases := map[string]func(cb *sessionv2alpha1.CallbackRequest, e *env){
		"no cookie":      func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Cookie = "" },
		"garbage cookie": func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Cookie = "not-a-cookie" },
		"cookie with a bad id": func(cb *sessionv2alpha1.CallbackRequest, _ *env) {
			cb.Cookie = "../../../etc." + strings.SplitN(cb.Cookie, ".", 2)[1]
		},
		"flipped bit": func(cb *sessionv2alpha1.CallbackRequest, _ *env) {
			b := []byte(cb.Cookie)
			b[len(b)-3] ^= 1
			cb.Cookie = string(b)
		},
		"another id": func(cb *sessionv2alpha1.CallbackRequest, _ *env) {
			cb.Cookie = strings.Repeat("a", 26) + "." + strings.SplitN(cb.Cookie, ".", 2)[1]
		},
		"state mismatch":          func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.State = "another-state" },
		"state missing":           func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.State = "" },
		"state is a prefix":       func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.State = cb.State[:10] },
		"state with the client's": func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.State = "client-state-1" },
		"pending past its end": func(_ *sessionv2alpha1.CallbackRequest, e *env) {
			e.clk.advance(10*time.Minute + 1)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			cb, _ := e.started()
			edit(cb, e)
			r := e.callback(cb)
			assertErrorPage(t, r)
			if len(headerOf(r, "Location")) != 0 {
				t.Error("a callback that is not ours was redirected")
			}
			if set := headerOf(r, "Set-Cookie"); len(set) != 1 || !strings.Contains(set[0], "Max-Age=0") {
				t.Errorf("Set-Cookie = %v", set)
			}
			if len(e.upstream.completes) != 0 {
				t.Error("the upstream's code was exchanged for a callback that is not ours")
			}
			if len(e.policy.requests()) != 0 || e.store.count("person", testTenant) != 0 || e.store.count("auth-code", testTenant) != 0 {
				t.Error("something was decided or written")
			}
		})
	}
}

func TestCallbackStateFromAnotherBrowser(t *testing.T) {
	// Two sign-ins start; the second browser brings the first one's state with its own cookie (login CSRF): refused.
	e := newEnv(t, nil)
	first, _ := e.started()
	second, _ := e.started()
	second.State = first.State
	assertErrorPage(t, e.callback(second))
	if len(e.upstream.completes) != 0 {
		t.Error("the upstream's code was exchanged")
	}
}

func TestCallbackReplayIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	first := e.callback(cb)
	if location(t, first).Query().Get("code") == "" {
		t.Fatal("the first callback failed")
	}
	// The browser still has the cookie (it was told to clear it), and the URL is replayed: the upstream refuses its
	// code a second time, so the client gets an error and no second code is made.
	second := e.callback(cb)
	if got := location(t, second).Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q", got)
	}
	if n := e.store.count("auth-code", testTenant); n != 1 {
		t.Errorf("%d codes after a replay", n)
	}
}

func TestCallbackTheUpstreamRefuses(t *testing.T) {
	cases := map[string]struct {
		edit func(cb *sessionv2alpha1.CallbackRequest, e *env)
		code string
	}{
		"person refused": {func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Error = "access_denied" }, "access_denied"},
		"upstream error": {func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Error = "server_error" }, "access_denied"},
		"upstream busy":  {func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Error = "temporarily_unavailable" }, "temporarily_unavailable"},
		"error text is not repeated": {func(cb *sessionv2alpha1.CallbackRequest, _ *env) {
			cb.Error, cb.ErrorDescription = "<script>", "<script>alert(1)</script>"
		}, "access_denied"},
		"no code": {func(cb *sessionv2alpha1.CallbackRequest, _ *env) { cb.Code = "" }, "invalid_request"},
		"adapter rejects the code": {func(_ *sessionv2alpha1.CallbackRequest, e *env) {
			e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
				return nil, refusal.New(connect.CodeFailedPrecondition, "REJECTED", "code")
			}
		}, "access_denied"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			cb, p := e.started()
			c.edit(cb, e)
			r := e.callback(cb)
			q := location(t, r).Query()
			if q.Get("error") != c.code {
				t.Errorf("error = %q, want %q", q.Get("error"), c.code)
			}
			if q.Get("state") != p.req.GetState() || q.Get("iss") != testIssuer || q.Get("code") != "" {
				t.Errorf("redirect = %v", q)
			}
			if strings.Contains(r.GetHeaders()[0].GetValue(), "%3Cscript") {
				t.Error("the upstream's text was repeated")
			}
			if e.store.count("person", testTenant) != 0 || e.store.count("auth-code", testTenant) != 0 {
				t.Error("something was written for a refused sign-in")
			}
		})
	}
}

func TestCallbackAdapterDownIsUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}
	_, err := e.client.Callback(context.Background(), connect.NewRequest(cb))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestCallbackPolicyDeniesAndNothingIsCreated(t *testing.T) {
	e := newEnv(t, nil)
	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{
			Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-deny", Digest: "digest-1",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "example-app-fresh-mfa", Layer: "config"}},
		}, nil
	}
	cb, p := e.started()
	r := e.callback(cb)
	q := location(t, r).Query()
	if q.Get("error") != "access_denied" || q.Get("state") != p.req.GetState() || q.Get("code") != "" {
		t.Errorf("redirect = %v", q)
	}
	// Nothing is created for a refused sign-in (0019): no person, no link, no code, and no write at all.
	if len(e.store.writes) != 0 {
		t.Errorf("%d writes", len(e.store.writes))
	}
	// The audit record is a failure that names the decision.
	var found bool
	for _, rec := range e.records() {
		md := rec["metadata"].(map[string]any)
		if md["event_code"] == "session.signin" {
			found = true
			if rec["status_code"] != "denied" {
				t.Errorf("status_code = %v", rec["status_code"])
			}
			if !strings.Contains(string(mustJSON(rec)), "d-deny") {
				t.Error("the record does not name the decision")
			}
		}
	}
	if !found {
		t.Error("no session.signin record")
	}
}

func TestCallbackPolicyUnavailableFailsClosed(t *testing.T) {
	cases := map[string]error{
		"unavailable":  connect.NewError(connect.CodeUnavailable, nil),
		"bad question": refusal.New(connect.CodeInvalidArgument, "schema", "person.org"),
	}
	for name, perr := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) { return nil, perr }
			cb, _ := e.started()
			_, err := e.client.Callback(context.Background(), connect.NewRequest(cb))
			if connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("err = %v", err)
			}
			if len(e.store.writes) != 0 {
				t.Error("something was written")
			}
		})
	}
}

func TestCallbackAllowWithoutAGrantFailsClosed(t *testing.T) {
	e := newEnv(t, nil)
	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_ALLOW, DecisionId: "d-1"}, nil
	}
	cb, _ := e.started()
	_, err := e.client.Callback(context.Background(), connect.NewRequest(cb))
	if connect.CodeOf(err) != connect.CodeUnavailable || len(e.store.writes) != 0 {
		t.Fatalf("err = %v, writes %d", err, len(e.store.writes))
	}
}

func TestCallbackFindsTheSamePersonAgain(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	first := location(t, e.callback(cb)).Query().Get("code")
	e.clk.advance(5 * time.Second)
	cb2, _ := e.started()
	cb2.Code = "second-code-0001"
	second := location(t, e.callback(cb2)).Query().Get("code")
	if first == second {
		t.Fatal("two sign-ins got one code")
	}
	if n := e.store.count("person", testTenant); n != 1 {
		t.Fatalf("%d people for one account", n)
	}
	// Both codes name the same subject.
	var subjects []string
	for _, id := range e.store.ids("auth-code", testTenant) {
		raw, _, _ := e.store.raw("auth-code", testTenant, id)
		subjects = append(subjects, protoOf(t, raw, &sessionv2alpha1.AuthCode{}).GetSubject())
	}
	if len(subjects) != 2 || subjects[0] != subjects[1] {
		t.Errorf("subjects = %v", subjects)
	}
}

func TestCallbackLinksByTheSubjectClaimNotByEmail(t *testing.T) {
	// Two accounts that differ in the subject claim value are two people, whatever else they share (0019: no linking
	// by e-mail, no merging). A subject claim of another name is a different account too.
	subjects := map[string]*integrationv2alpha1.Assertion{}
	for name, a := range map[string]*integrationv2alpha1.Assertion{
		"alice":        {Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"},
		"alice2":       {Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice2"},
		"other claim":  {Issuer: "https://idp.example.test/realms/test", SubjectClaim: "sub", Subject: "alice"},
		"other issuer": {Issuer: "https://idp2.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"},
	} {
		subjects[name] = a
	}
	e := newEnv(t, nil)
	for name, a := range subjects {
		a := a
		e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) { return a, nil }
		cb, _ := e.started()
		if got := location(t, e.callback(cb)).Query().Get("code"); got == "" {
			t.Fatalf("%s: no code", name)
		}
	}
	if n := e.store.count("person", testTenant); n != len(subjects) {
		t.Fatalf("%d people for %d accounts", n, len(subjects))
	}
	if n := e.store.count("upstream-link", testTenant); n != len(subjects) {
		t.Fatalf("%d links", n)
	}
}

func TestCallbackRaceOnFirstSignInMakesOnePerson(t *testing.T) {
	// A second first sign-in of the same account wins the create between this one's read and write. This one's batch
	// fails with already exists, reads the link and continues as the winner: one person.
	e := newEnv(t, nil)
	cb, _ := e.started()
	var once sync.Once
	var winner string
	e.store.beforeWrite = func(s *fakeStore, ops []*storev2alpha1.Operation) {
		once.Do(func() {
			for _, op := range ops {
				a := op.GetAddress()
				if a.GetKind() != "upstream-link" {
					continue
				}
				// The winner sealed its own subject under the same address.
				winner = "winnerwinnerwinnerwinner26"
				env, err := sealAsWinner(e, a.GetTenant(), a.GetId(), winner)
				if err != nil {
					panic(err)
				}
				s.items[key(a.GetKind(), a.GetTenant(), a.GetId())] = &storedItem{value: env, version: 1}
			}
		})
	}
	r := e.callback(cb)
	if location(t, r).Query().Get("code") == "" {
		t.Fatalf("no code: %s", location(t, r))
	}
	if n := e.store.count("person", testTenant); n != 0 {
		t.Errorf("%d Person items written by the loser", n)
	}
	ids := e.store.ids("auth-code", testTenant)
	if len(ids) != 1 {
		t.Fatalf("%d codes", len(ids))
	}
	raw, _, _ := e.store.raw("auth-code", testTenant, ids[0])
	if got := protoOf(t, raw, &sessionv2alpha1.AuthCode{}).GetSubject(); got != winner {
		t.Errorf("subject %q, want the winner's %q", got, winner)
	}
}

func TestCallbackAHeldPersonIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	first := location(t, e.callback(cb)).Query().Get("code")
	if first == "" {
		t.Fatal("no code")
	}
	subject := e.store.ids("person", testTenant)[0]
	e.store.putRaw("person-hold", testTenant, subject, []byte{1, 2, 3})
	e.clk.advance(5 * time.Second)
	cb2, _ := e.started()
	q := location(t, e.callback(cb2)).Query()
	if q.Get("error") != "access_denied" || q.Get("code") != "" {
		t.Errorf("redirect = %v", q)
	}
	if n := e.store.count("auth-code", testTenant); n != 1 {
		t.Errorf("%d codes; the held person got one", n)
	}
}

func TestCallbackStoreWriteFailureIsUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	e.store.failWrites = connect.NewError(connect.CodeUnavailable, nil)
	_, err := e.client.Callback(context.Background(), connect.NewRequest(cb))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestSignInIsAudited(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	e.callback(cb)
	codes := e.eventCodes()
	if len(codes) != 2 || codes[0] != "session.authorize" || codes[1] != "session.signin" {
		t.Fatalf("records = %v", codes)
	}
	signin := e.records()[1]
	raw := string(mustJSON(signin))
	for _, secret := range []string{"alice", "upstream-code", "client-nonce", "client-state"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the record holds %q", secret)
		}
	}
	// The subject is a person, named by a pseudonym, and the record names the decision that gated it.
	if !strings.Contains(raw, `"d-1"`) {
		t.Errorf("the record does not name the decision: %s", raw)
	}
}
