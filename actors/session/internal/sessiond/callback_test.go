//go:build sluis_test

package sessiond_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	storev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/store/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
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

// The id of an upstream link is a keyed hash made at key@: the Mac of the boundary's mac key under the link label,
// over the length-prefixed issuer and subject (the fake key computes the HMAC the real one does), and the upstream
// subject is nowhere in it. Another subject of the same issuer, and the same subject of another issuer, give other ids.
//
// verifies: REQ-SUBJ-057
func TestTheIdOfAnUpstreamLinkIsAMacOutputUnderTheLinkLabel(t *testing.T) {
	e := newEnv(t, nil)
	cb, _ := e.started()
	e.callback(cb)
	links := e.store.ids("upstream-link", testTenant)
	if len(links) != 1 {
		t.Fatalf("links %v", links)
	}
	prefixed := func(parts ...string) []byte {
		var out []byte
		for _, p := range parts {
			out = binary.BigEndian.AppendUint32(out, uint32(len(p))) //nolint:gosec // short test strings
			out = append(out, p...)
		}
		return out
	}
	// The fake key's formula (fakes_test.go): HMAC-SHA384 under the key of the purpose, over the label length, the label
	// and the input. The label is the one session gives to link ids, which is versioned on purpose.
	mac := func(issuer, subject string) string {
		h := hmac.New(sha512.New384, []byte("test mac key|mac|"))
		const label = "sluis-upstream-link-v2"
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(label))))
		h.Write([]byte(label))
		h.Write(prefixed(issuer, subject))
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil)[:32]))
	}
	const issuer = "https://idp.example.test/realms/test"
	if want := mac(issuer, "alice"); links[0] != want {
		t.Errorf("link id = %s, want the Mac output %s", links[0], want)
	}
	if links[0] == mac(issuer, "bob") || links[0] == mac("https://other.example.test", "alice") {
		t.Error("the link id does not depend on both the issuer and the subject")
	}
	if len(links[0]) != 52 || strings.Contains(links[0], "alice") {
		t.Errorf("link id %q is not 256 bits of base32 free of the subject", links[0])
	}
	e.key.mu.Lock()
	macs := slices.Contains(e.key.calls, "mac mac")
	e.key.mu.Unlock()
	if !macs {
		t.Error("the link id was not made by a Mac at key@")
	}
}

// verifies: REQ-AUTHN-005
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
	// What the grant must allow: creates, seal and open under the tenant's data key, and mac for the pairwise key of the
	// subject (the tenant's first pairwise key is made only under a grant).
	if strings.Join(r.GetGrantStoreVerbs(), ",") != "create" || strings.Join(r.GetGrantKeyOps(), ",") != "seal,open,mac" {
		t.Errorf("verbs %v ops %v", r.GetGrantStoreVerbs(), r.GetGrantKeyOps())
	}
}

// verifies: REQ-SESS-049, REQ-FED-017
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

// verifies: REQ-SUBJ-037
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

// verifies: REQ-SUBJ-037
func TestCallbackLinksByTheSubjectClaimNotByEmail(t *testing.T) {
	// Two accounts that differ in the subject claim value are two people, whatever else they share (0019: no linking
	// by e-mail, no merging). Another issuer is another account too. (Another claim name for one issuer is refused by
	// the pin: TestCallbackRefusesASubjectClaimThatContradictsThePin.)
	subjects := map[string]*integrationv2alpha1.Assertion{}
	for name, a := range map[string]*integrationv2alpha1.Assertion{
		"alice":        {Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"},
		"alice2":       {Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice2"},
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

// verifies: REQ-SUBJ-041
func TestCallbackRefusesASubjectClaimThatContradictsThePin(t *testing.T) {
	// 0019: the first link of an issuer pins its subject claim; a later sign-in through the issuer with another claim
	// is refused, never linked again as a new person. The test links by sub, changes the claim to oid, and signs in.
	const issuer = "https://idp.example.test/realms/test"
	e := newEnv(t, nil)
	signIn := func(a *integrationv2alpha1.Assertion) url.Values {
		t.Helper()
		e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) { return a, nil }
		cb, _ := e.started()
		return location(t, e.callback(cb)).Query()
	}
	first := &integrationv2alpha1.Assertion{Issuer: issuer, SubjectClaim: "sub", Subject: "11111111-2222-3333-4444-555555555555"}
	if q := signIn(first); q.Get("code") == "" {
		t.Fatalf("first sign-in: %v", q)
	}
	pins := e.store.ids("upstream-pin", testTenant)
	if len(pins) != 1 {
		t.Fatalf("%d pins after the issuer's first link", len(pins))
	}
	raw, _, _ := e.store.raw("upstream-pin", testTenant, pins[0])
	if p := protoOf(t, raw, &sessionv2alpha1.UpstreamPin{}); p.GetIssuer() != issuer || p.GetSubjectClaim() != "sub" {
		t.Fatalf("pin = %v", p)
	}
	for name, a := range map[string]*integrationv2alpha1.Assertion{
		"the claim changed to oid":          {Issuer: issuer, SubjectClaim: "oid", Subject: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		"another claim with the same value": {Issuer: issuer, SubjectClaim: "oid", Subject: first.GetSubject()},
	} {
		before := len(e.records())
		q := signIn(a)
		if q.Get("error") != "access_denied" || q.Get("code") != "" {
			t.Errorf("%s: %v", name, q)
		}
		if n := e.store.count("person", testTenant); n != 1 {
			t.Errorf("%s: %d people; a contradicted pin made a person", name, n)
		}
		if n := e.store.count("upstream-link", testTenant); n != 1 {
			t.Errorf("%s: %d links", name, n)
		}
		recs := e.records()[before:]
		if len(recs) == 0 || recs[len(recs)-1]["status_code"] != "subject_claim" {
			t.Errorf("%s: records = %v", name, recs)
		}
	}
	// The pinned claim still signs the same person in; another issuer pins its own claim.
	if q := signIn(first); q.Get("code") == "" {
		t.Fatalf("the pinned claim: %v", q)
	}
	if q := signIn(&integrationv2alpha1.Assertion{Issuer: "https://idp2.example.test/realms/test", SubjectClaim: "oid", Subject: "x-1"}); q.Get("code") == "" {
		t.Fatalf("another issuer: %v", q)
	}
	if n, p := e.store.count("person", testTenant), e.store.count("upstream-pin", testTenant); n != 2 || p != 2 {
		t.Errorf("%d people and %d pins, want 2 and 2", n, p)
	}
}

// verifies: REQ-SUBJ-041
func TestCallbackRaceOnAnIssuersFirstPin(t *testing.T) {
	// Two people sign in through a new issuer at once. The other one's batch writes the pin between this one's read and
	// write: this batch fails with already exists, reads the pin again and makes its person without it. When the pin
	// the winner wrote names another claim, this sign-in is refused.
	const issuer = "https://idp.example.test/realms/test"
	for name, c := range map[string]struct {
		winnerClaim string
		ok          bool
	}{"the same claim": {"preferred_username", true}, "another claim": {"sub", false}} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
				return &integrationv2alpha1.Assertion{Issuer: issuer, SubjectClaim: "preferred_username", Subject: "alice"}, nil
			}
			cb, _ := e.started()
			var once sync.Once
			e.store.beforeWrite = func(s *fakeStore, ops []*storev2alpha1.Operation) {
				for _, op := range ops {
					if a := op.GetAddress(); a.GetKind() == "upstream-pin" {
						once.Do(func() {
							b, err := proto.Marshal(&sessionv2alpha1.UpstreamPin{Issuer: issuer, SubjectClaim: c.winnerClaim})
							if err != nil {
								panic(err)
							}
							s.items[key(a.GetKind(), a.GetTenant(), a.GetId())] = &storedItem{value: b, version: 1}
						})
					}
				}
			}
			q := location(t, e.callback(cb)).Query()
			people := e.store.count("person", testTenant)
			if c.ok && (q.Get("code") == "" || people != 1) {
				t.Errorf("code %q, %d people; want a code and one person", q.Get("code"), people)
			}
			if !c.ok && (q.Get("error") != "access_denied" || people != 0) {
				t.Errorf("error %q, %d people; want access_denied and none", q.Get("error"), people)
			}
			if n := e.store.count("upstream-pin", testTenant); n != 1 {
				t.Errorf("%d pins", n)
			}
		})
	}
}

// verifies: REQ-SUBJ-041
func TestCallbackRaceBetweenThePinReadAndTheLinkRead(t *testing.T) {
	// B signs in with the claim oid and the value X and finds no pin. Before B reads the link, A's first sign-in with
	// the claim sub and the same value X commits its person, its link and the pin. The link id leaves the claim name
	// out, so B finds A's link: B is refused, never signed in as A's person.
	const issuer, value = "https://idp.example.test/realms/test", "same-value-x"
	e := newEnv(t, nil)
	e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
		return &integrationv2alpha1.Assertion{Issuer: issuer, SubjectClaim: "oid", Subject: value}, nil
	}
	cb, _ := e.started()
	const winner = "winnerwinnerwinnerwinner26"
	var pinAt *typev2alpha1.Address
	var once sync.Once
	e.store.beforeGet = func(s *fakeStore, a *typev2alpha1.Address) {
		switch a.GetKind() {
		case "upstream-pin":
			pinAt = a
		case "upstream-link":
			once.Do(func() {
				if pinAt == nil {
					panic("the link was read before the pin")
				}
				pin, err := proto.Marshal(&sessionv2alpha1.UpstreamPin{Issuer: issuer, SubjectClaim: "sub"})
				if err != nil {
					panic(err)
				}
				link, err := sealAsWinner(e, a.GetTenant(), a.GetId(), winner, issuer, "sub")
				if err != nil {
					panic(err)
				}
				s.items[key("upstream-pin", pinAt.GetTenant(), pinAt.GetId())] = &storedItem{value: pin, version: 1}
				s.items[key("upstream-link", a.GetTenant(), a.GetId())] = &storedItem{value: link, version: 1}
				s.items[key("person", a.GetTenant(), winner)] = &storedItem{value: []byte{1}, version: 1}
			})
		}
	}
	before := len(e.records())
	q := location(t, e.callback(cb)).Query()
	if q.Get("error") != "access_denied" || q.Get("code") != "" {
		t.Fatalf("B was not refused: %v", q)
	}
	if n := e.store.count("person", testTenant); n != 1 {
		t.Errorf("%d people, want A's only", n)
	}
	if n := len(e.store.ids("auth-code", testTenant)); n != 0 {
		t.Errorf("%d codes: B signed in", n)
	}
	recs := e.records()[before:]
	if len(recs) == 0 || recs[len(recs)-1]["status_code"] != "subject_claim" {
		t.Errorf("records = %v", recs)
	}
}

// verifies: REQ-SUBJ-042
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

// verifies: REQ-TOKEN-031, REQ-AUTHN-008
func TestCallbackMaxAge(t *testing.T) {
	signedAgo := func(d time.Duration) func(*env) {
		return func(e *env) {
			e.upstream.completeFn = func(_ *integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
				return &integrationv2alpha1.Assertion{
					Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
					AuthTime: timestampOf(e.clk.now().Add(-d)),
				}, nil
			}
		}
	}
	noAuthTime := func(e *env) {
		e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
			return &integrationv2alpha1.Assertion{Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"}, nil
		}
	}
	cases := map[string]struct {
		setup  func(*env)
		maxAge string
		ok     bool
	}{
		"fresh enough":             {signedAgo(30 * time.Second), "60", true},
		"exactly at the limit":     {signedAgo(60 * time.Second), "60", true},
		"older than allowed":       {signedAgo(61 * time.Second), "60", false},
		"an old session":           {signedAgo(8 * time.Hour), "300", false},
		"no auth_time":             {noAuthTime, "60", false},
		"no max_age, no auth_time": {noAuthTime, "", true},
		"no max_age, an old one":   {signedAgo(8 * time.Hour), "", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			c.setup(e)
			p := newAuthorize()
			p.req.MaxAge = c.maxAge
			a := e.authorize(p.req)
			up := location(t, a)
			cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: up.Query().Get("state"), Cookie: cookieValue(t, a)})
			q := location(t, cb).Query()
			if c.ok {
				if q.Get("code") == "" {
					t.Fatalf("refused: %v", q)
				}
				// The ID token carries auth_time when the client asked for max_age.
				if c.maxAge != "" {
					tr := e.token(codeRequest(q.Get("code"), p))
					_, id := tokenClaims(t, body(t, tr)["id_token"].(string))
					if id["auth_time"] == nil {
						t.Error("no auth_time in the ID token of a max_age request")
					}
				}
				return
			}
			if q.Get("error") != "login_required" || q.Get("code") != "" || q.Get("state") != p.req.GetState() {
				t.Errorf("redirect = %v", q)
			}
			if len(e.store.writes) != 0 || len(e.policy.requests()) != 0 {
				t.Error("something was decided or written for a stale authentication")
			}
		})
	}
}

// A callback that carries no cookie of ours knows no client, and its record names nobody: `unknown` with type_id 0. It is not
// the pseudonym of a client called "unknown", which would look like the constant and stand for nothing (0030, "The OCSF
// attributes a class requires").
//
// verifies: REQ-AUDIT-188
func TestACallbackThatKnowsNoClientNamesNobody(t *testing.T) {
	e := newEnv(t, nil)
	e.callback(&sessionv2alpha1.CallbackRequest{Code: "c", State: "s", Cookie: "not-a-cookie"})
	rec := e.lastRecord("session.signin")
	if rec == nil {
		t.Fatal("no record of the refused callback")
	}
	user, _ := rec["user"].(map[string]any)
	if user["uid"] != "unknown" || user["type_id"] != float64(0) {
		t.Errorf("user = %v, want unknown with type_id 0", user)
	}
	for _, c := range e.key.called() {
		if c == "mac pseudonym" {
			t.Errorf("a pseudonym was asked of key@ for a step that knows nobody: %v", e.key.called())
		}
	}
}
