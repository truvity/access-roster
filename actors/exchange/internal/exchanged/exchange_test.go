//go:build sluis_test

package exchanged_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/actors/exchange/internal/exchanged"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	exchangev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/exchange/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/refusal"
	"github.com/truvity/sluis/v2/kits/go/subject"
)

// verifies: REQ-EXCH-010
func TestExchangeForExampleAppReturnsAnAccessTokenNarrowedToThatAudience(t *testing.T) {
	e := newEnv(t, envOptions{requires: []string{"dev:example-app:user"}})
	// The person holds the full set after the ladder; the audience asks for the pair dev:example-app only.
	e.policy.decide = allow("dev:example-app:user", "dev:example-app:operator", "dev:other-app:admin", "acme:example-app:admin", "prod:example-app:admin")
	subject := e.mint(subjectClaims(nil))

	r := e.exchange(request(subject))
	if r.GetStatus() != 200 {
		t.Fatalf("status = %d: %s", r.GetStatus(), r.GetBody())
	}
	hdr := map[string]string{}
	for _, h := range r.GetHeaders() {
		hdr[h.GetName()] = h.GetValue()
	}
	if hdr["Content-Type"] != "application/json" || hdr["Cache-Control"] != "no-store" || hdr["Pragma"] != "no-cache" {
		t.Errorf("headers = %v", hdr)
	}
	b := body(t, r)
	if b["token_type"] != "Bearer" || b["issued_token_type"] != accessType {
		t.Errorf("body = %v", b)
	}
	if _, ok := b["refresh_token"]; ok {
		t.Error("an exchange returned a refresh token (REQ-EXCH-010)")
	}
	// 10 minutes is not set, so the built-in hour is the cap, and the subject token ends in 30 minutes.
	if b["expires_in"] != float64(30*60) {
		t.Errorf("expires_in = %v, want 1800", b["expires_in"])
	}

	claims, typ := claimsOf(t, b["access_token"].(string))
	if typ != "at+jwt" {
		t.Errorf("typ = %q", typ)
	}
	if claims["iss"] != testIssuer || claims["aud"] != "example-app" || claims["client_id"] != "sluis-cli" {
		t.Errorf("claims = %v", claims)
	}
	// groups is narrowed to the pair dev:example-app, in any role: no other app, no other scope.
	if got := strings.Join(toStrings(claims["groups"]), ","); got != "dev:example-app:operator,dev:example-app:user" {
		t.Errorf("groups = %v", claims["groups"])
	}
	// acr, amr, auth_time and sid pass from the subject token.
	if claims["acr"] != "urn:example:acr:mfa" || claims["sid"] != "sid-1" || claims["auth_time"] != float64(t0.Add(-10*time.Minute).Unix()) {
		t.Errorf("assurance claims = %v", claims)
	}
	if got := strings.Join(toStrings(claims["amr"]), ","); got != "pwd,mfa" {
		t.Errorf("amr = %v", claims["amr"])
	}
	if claims["jti"] == "" || claims["jti"] == "j-subject" {
		t.Errorf("jti = %v", claims["jti"])
	}
	// The token does not outlive the token it was made from, and does not claim an earlier start (REQ-EXCH-004).
	if claims["iat"] != float64(t0.Unix()) || claims["exp"] != float64(t0.Add(30*time.Minute).Unix()) {
		t.Errorf("iat/exp = %v/%v", claims["iat"], claims["exp"])
	}
	for _, c := range []string{"scope", "act", "cnf", "azp", "email", "name"} {
		if _, ok := claims[c]; ok {
			t.Errorf("claim %s is outside the set of ADR 0020", c)
		}
	}
	if n := len(e.signer.requests()); n != 1 || e.signer.requests()[0].GetTyp() != "at+jwt" {
		t.Errorf("signer asked %d times", n)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestSubIsThePairwiseSubjectOfTheTargetTenantNotTheOneOfTheSubjectToken(t *testing.T) {
	e := newEnv(t, envOptions{})
	r := e.exchange(request(e.mint(subjectClaims(nil))))
	claims, _ := claimsOf(t, body(t, r)["access_token"].(string))

	// ADR 0034: Mac(the tenant's pairwise key, length-prefixed sector, the person's id), truncated to 256 bits and
	// written as base64url without padding. The sector is the tenant's until Tenant items exist (D-4).
	input := subject.PairwiseInput(testTenant, testPerson.ID)
	want := base64.RawURLEncoding.EncodeToString(macOf("pairwise", testTenant, "pairwise", input)[:32])
	if claims["sub"] != want {
		t.Errorf("sub = %v, want %s", claims["sub"], want)
	}
	if claims["sub"] == "pairwise-of-the-sign-in" || claims["sub"] == testPerson.ID {
		t.Error("sub is the subject of the subject token or the person's own id")
	}
	macs := e.key.pairwise()
	if len(macs) != 1 || macs[0].GetTenant() != testTenant || string(macs[0].GetGrant()) != "sealed-grant" {
		t.Errorf("pairwise Mac requests = %v", macs)
	}
}

func TestPolicyIsAskedTokenExchangeWithTheFactsOfThePersonAndTheClient(t *testing.T) {
	e := newEnv(t, envOptions{requires: []string{"dev:example-app:user"}})
	r := e.exchange(request(e.mint(subjectClaims(nil))))
	if r.GetStatus() != 200 {
		t.Fatalf("%s", r.GetBody())
	}
	reqs := e.policy.requests()
	if len(reqs) != 1 {
		t.Fatalf("policy asked %d times", len(reqs))
	}
	q := reqs[0]
	if q.GetAction() != "token.exchange" || q.GetTenant() != testTenant {
		t.Errorf("action/tenant = %q/%q", q.GetAction(), q.GetTenant())
	}
	if q.GetPrincipal().GetType() != "Person" || q.GetPrincipal().GetId() != testPerson.ID || q.GetResource().GetType() != "Client" || q.GetResource().GetId() != "example-app" {
		t.Errorf("principal/resource = %v / %v", q.GetPrincipal(), q.GetResource())
	}
	p := q.GetPerson()
	if p.GetSubject() != testPerson.ID || p.GetOrg() != testTenant || p.GetState() != "live" || len(p.GetAccounts()) != 1 || p.GetAccounts()[0] != "workforce/u-1001" {
		t.Errorf("person = %v", p)
	}
	c := q.GetClient()
	if c.GetId() != "example-app" || c.GetKind() != "confidential" || len(c.GetRequires()) != 1 {
		t.Errorf("client = %v", c)
	}
	// auth_age is counted by the asker from auth_time: 10 minutes. amr is present, acr is the token's.
	ctx := q.GetContext()
	if ctx.GetAcr() != "urn:example:acr:mfa" || !ctx.GetAmrPresent() || len(ctx.GetAmr()) != 2 || ctx.AuthAge == nil || ctx.GetAuthAge() != 600 {
		t.Errorf("context = %v", ctx)
	}
	if got := e.dir.tenant; got != testTenant {
		t.Errorf("directory asked for tenant %q", got)
	}
}

func TestAnAbsentAcrAmrAndAuthTimeStayUnknownToPolicyAndAbsentFromTheToken(t *testing.T) {
	e := newEnv(t, envOptions{})
	r := e.exchange(request(e.mint(subjectClaims(map[string]any{"acr": nil, "amr": nil, "auth_time": nil, "sid": nil}))))
	if r.GetStatus() != 200 {
		t.Fatalf("%s", r.GetBody())
	}
	ctx := e.policy.requests()[0].GetContext()
	if ctx.Acr != nil || ctx.GetAmrPresent() || len(ctx.GetAmr()) != 0 || ctx.AuthAge != nil {
		t.Errorf("context = %v: exchange filled in what the upstream did not send", ctx)
	}
	claims, _ := claimsOf(t, body(t, r)["access_token"].(string))
	for _, c := range []string{"acr", "amr", "auth_time", "sid"} {
		if _, ok := claims[c]; ok {
			t.Errorf("claim %s appeared from nothing", c)
		}
	}
}

func TestAnEmptyAmrIsStillPresent(t *testing.T) {
	e := newEnv(t, envOptions{})
	r := e.exchange(request(e.mint(subjectClaims(map[string]any{"amr": []string{}}))))
	if r.GetStatus() != 200 {
		t.Fatalf("%s", r.GetBody())
	}
	if ctx := e.policy.requests()[0].GetContext(); !ctx.GetAmrPresent() {
		t.Error("an empty amr list became unknown")
	}
	claims, _ := claimsOf(t, body(t, r)["access_token"].(string))
	if a, ok := claims["amr"].([]any); !ok || len(a) != 0 {
		t.Errorf("amr = %v", claims["amr"])
	}
}

// verifies: REQ-EXCH-009
func TestAnUnknownAudienceAndARefusedAudienceAreTheSameAnswer(t *testing.T) {
	e := newEnv(t, envOptions{})
	subject := e.mint(subjectClaims(nil))

	unknown := request(subject)
	unknown.Audience = "no-such-app"
	ru := e.exchange(unknown)
	failure(t, ru, "invalid_target")

	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000002", Digest: "d",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "example-app-fresh-mfa"}}}, nil
	}
	rr := e.exchange(request(subject))
	failure(t, rr, "invalid_target")

	// An audience that cannot be a client id, and a resource indicator, look the same too (REQ-EXCH-003).
	badID := request(subject)
	badID.Audience = "Not/A Client"
	rb := e.exchange(badID)
	res := request(subject)
	res.Audience, res.Resource = "", "https://api.example.com/"
	rres := e.exchange(res)
	for name, other := range map[string]*typev2alpha1.HttpReply{"refused": rr, "bad id": rb, "resource": rres} {
		if other.GetStatus() != ru.GetStatus() || string(other.GetBody()) != string(ru.GetBody()) || len(other.GetHeaders()) != len(ru.GetHeaders()) {
			t.Errorf("%s answers differently from unknown: %s vs %s", name, other.GetBody(), ru.GetBody())
		}
	}
	// The operator still learns the real reason (REQ-EXCH-009).
	recs := e.transport.records(t)
	var reasons []string
	for _, r := range recs {
		reasons = append(reasons, get(r, "status_code").(string))
	}
	if strings.Join(reasons, ",") != "audience,policy,audience,resource" {
		t.Errorf("audit reasons = %v", reasons)
	}
	// An unknown audience takes the path of a known one: policy is asked (about a stand-in client, and its answer is
	// not used), so the calls are the same. Neither reaches signer.
	reqs := e.policy.requests()
	if len(reqs) != 3 {
		t.Fatalf("policy asked %d times, want 3 (unknown, refused, malformed)", len(reqs))
	}
	if reqs[0].GetClient().GetId() != "unknown-audience" || reqs[1].GetClient().GetId() != "example-app" || reqs[2].GetClient().GetId() != "unknown-audience" {
		t.Errorf("policy was asked about %q, %q, %q", reqs[0].GetClient().GetId(), reqs[1].GetClient().GetId(), reqs[2].GetClient().GetId())
	}
	if n := len(e.signer.requests()); n != 0 {
		t.Errorf("signer signed %d tokens for refused exchanges", n)
	}
}

// answer is what a caller sees of a call: the reply, or the Connect error.
func (e *env) answer(r *exchangev2alpha1.TokenExchangeRequest) string {
	e.t.Helper()
	res, err := e.client.Token(context.Background(), connect.NewRequest(r))
	if err != nil {
		reason, _ := refusal.Reason(err)
		return "error " + connect.CodeOf(err).String() + " " + reason
	}
	b, _ := json.Marshal(res.Msg.GetHeaders())
	return string(res.Msg.GetBody()) + string(b)
}

// With a valid subject token, a caller meets the same answer whatever audience it names, unless the audience itself
// is what is refused (REQ-EXCH-003): a known and an unknown audience differ only in the final invalid_target.
func TestEveryRefusalThatDoesNotDependOnTheAudienceIsTheSameForAKnownAndAnUnknownAudience(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(*env)
	}{
		{"the directory is unbound", func(e *env) { e.dir.err = exchanged.ErrUnbound }},
		{"the directory is down", func(e *env) { e.dir.err = context.DeadlineExceeded }},
		{"the session has ended", func(e *env) { e.dir.err = exchanged.ErrSessionEnded }},
		{"nobody has this subject", func(e *env) { e.dir.err = exchanged.ErrUnknownPerson }},
		{"policy is down", func(e *env) {
			e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
				return nil, refusal.New(connect.CodeUnavailable, "key", "")
			}
		}},
		{"policy denies", func(e *env) {
			e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
				return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000005"}, nil
			}
		}},
		{"the store is down", func(e *env) { e.store.fail = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			subject := e.mint(subjectClaims(nil))
			c.setup(e)
			known := e.answer(request(subject))
			unknownReq := request(subject)
			unknownReq.Audience = "no-such-app"
			unknown := e.answer(unknownReq)
			if known != unknown {
				t.Errorf("a known audience answers %s, an unknown one %s", known, unknown)
			}
		})
	}

}

// verifies: REQ-EXCH-009
func TestEveryExchangeAndEveryRefusalIsAudited(t *testing.T) {
	e := newEnv(t, envOptions{})
	subject := e.mint(subjectClaims(nil))
	e.exchange(request(subject))
	rec := e.lastRecord()
	if get(rec, "metadata", "event_code") != "exchange.token" || get(rec, "status_id") != float64(1) || get(rec, "class_uid") != float64(3002) || get(rec, "activity_id") != float64(99) {
		t.Errorf("success record = %v", rec)
	}
	if get(rec, "unmapped", "sluis", "token", "audience") != "example-app" {
		t.Errorf("audience missing: %v", rec["unmapped"])
	}
	if get(rec, "unmapped", "sluis", "assurance", "acr") != "urn:example:acr:mfa" {
		t.Errorf("assurance missing: %v", rec["unmapped"])
	}
	if uid, _ := get(rec, "user", "uid").(string); !strings.HasPrefix(uid, "p1.") || strings.Contains(uid, testPerson.ID) {
		t.Errorf("user.uid = %v, want a pseudonym", get(rec, "user", "uid"))
	}
	if get(rec, "policy", "uid") != "0192a000-0000-7000-8000-000000000001" {
		t.Errorf("policy = %v", rec["policy"])
	}
	if get(rec, "metadata", "tenant_uid") != testTenant {
		t.Errorf("tenant_uid = %v", get(rec, "metadata", "tenant_uid"))
	}

	bad := request(subject)
	bad.Scope = "openid"
	failure(t, e.exchange(bad), "invalid_scope")
	rec = e.lastRecord()
	if get(rec, "metadata", "event_code") != "exchange.refused" || get(rec, "status_id") != float64(2) || get(rec, "status_code") != "scope" {
		t.Errorf("refusal record = %v", rec)
	}

	// No record holds a token, the person's id, or the subject of any token.
	for _, r := range e.transport.records(t) {
		raw, _ := json.Marshal(r)
		for _, secret := range []string{subject, testPerson.ID, "workforce/u-1001", "pairwise-of-the-sign-in"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("a record carries %q", secret)
			}
		}
	}
}

func TestARefusedExchangeRecordsTheDecisionThatDeniedIt(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000003", Digest: "d9",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "person-not-live"}}}, nil
	}
	failure(t, e.exchange(request(e.mint(subjectClaims(nil)))), "invalid_target")
	rec := e.lastRecord()
	if get(rec, "status_code") != "policy" || get(rec, "policy", "uid") != "0192a000-0000-7000-8000-000000000003" {
		t.Errorf("record = %v", rec)
	}
}

// verifies: REQ-EXCH-002, REQ-EXCH-008
func TestTheRequestIsChecked(t *testing.T) {
	e := newEnv(t, envOptions{})
	subject := e.mint(subjectClaims(nil))
	cases := []struct {
		name   string
		mutate func(*exchangev2alpha1.TokenExchangeRequest)
		code   string
		reason string
	}{
		{"another grant", func(r *exchangev2alpha1.TokenExchangeRequest) { r.GrantType = "authorization_code" }, "unsupported_grant_type", "grant_type"},
		{"no subject token", func(r *exchangev2alpha1.TokenExchangeRequest) { r.SubjectToken = "" }, "invalid_request", "subject_token"},
		{"no subject token type", func(r *exchangev2alpha1.TokenExchangeRequest) { r.SubjectTokenType = "" }, "invalid_request", "subject_token_type"},
		{"an id token type", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.SubjectTokenType = "urn:ietf:params:oauth:token-type:id_token"
		}, "invalid_request", "subject_token_type"},
		{"an actor token (REQ-EXCH-002)", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ActorToken = subject }, "invalid_request", "actor_token"},
		{"an actor token type", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ActorTokenType = accessType }, "invalid_request", "actor_token"},
		{"a refresh token wanted (REQ-EXCH-008)", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.RequestedTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
		}, "invalid_request", "requested_token_type"},
		{"a scope", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Scope = "openid" }, "invalid_scope", "scope"},
		{"a resource", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Resource = "https://api.example.com" }, "invalid_target", "resource"},
		{"no audience", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Audience = "" }, "invalid_target", "audience"},
		{"a long audience", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Audience = strings.Repeat("a", 200) }, "invalid_target", "audience"},
		// A client that names itself, is not the client of the token and sends no credentials is not authenticated.
		{"another client with no credentials", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "example-app" }, "invalid_client", "client_authentication"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := request(subject)
			c.mutate(r)
			rep := e.exchange(r)
			if c.code == "invalid_client" {
				if rep.GetStatus() != 401 || body(t, rep)["error"] != c.code {
					t.Fatalf("status %d: %s", rep.GetStatus(), rep.GetBody())
				}
			} else {
				failure(t, rep, c.code)
			}
			if got := get(e.lastRecord(), "status_code"); got != c.reason {
				t.Errorf("reason = %v, want %s", got, c.reason)
			}
		})
	}
	if n := len(e.policy.requests()) + len(e.signer.requests()); n != 0 {
		t.Errorf("a refused request reached policy or signer %d times", n)
	}
	// The client of the request may be named when it is the client of the token.
	ok := request(subject)
	ok.ClientId = "sluis-cli"
	if r := e.exchange(ok); r.GetStatus() != 200 {
		t.Errorf("the client of the token was refused: %s", r.GetBody())
	}
}

// verifies: REQ-SEC-011, REQ-SEC-012
func TestASubjectTokenThatIsNotAcceptableIsInvalidRequest(t *testing.T) {
	e := newEnv(t, envOptions{})
	other := newSigner(t)
	headerAndPayload := func(header, claims string) string {
		enc := base64.RawURLEncoding.EncodeToString
		return enc([]byte(header)) + "." + enc([]byte(claims)) + "."
	}
	valid := e.mint(subjectClaims(nil))
	cases := []struct {
		name, token, reason string
	}{
		{"not a JWS", "not-a-token", "signature"},
		{"alg none", headerAndPayload(`{"alg":"none","typ":"at+jwt"}`, `{"iss":"`+testIssuer+`"}`), "signature"},
		{"HS256", headerAndPayload(`{"alg":"HS256","typ":"at+jwt"}`, `{"iss":"`+testIssuer+`"}`) + "AAAA", "signature"},
		{"signed by another key", mintWith(t, other.key, "at+jwt", subjectClaims(nil)), "signature"},
		{"a tampered payload", tamper(valid), "signature"},
		{"an ID token (typ JWT)", mintWith(t, e.signer.key, "JWT", subjectClaims(nil)), "signature"},
		{"no typ", mintWith(t, e.signer.key, "", subjectClaims(nil)), "signature"},
		{"expired", e.mint(subjectClaims(map[string]any{"exp": t0.Add(-time.Second).Unix()})), "expired"},
		{"issued in the future", e.mint(subjectClaims(map[string]any{"iat": t0.Add(time.Hour).Unix()})), "claims"},
		{"another issuer", e.mint(subjectClaims(map[string]any{"iss": "https://sluis.other.example.com"})), "issuer"},
		{"no sub", e.mint(subjectClaims(map[string]any{"sub": nil})), "claims"},
		{"no exp", e.mint(subjectClaims(map[string]any{"exp": nil})), "claims"},
		{"a float exp", e.mint(subjectClaims(map[string]any{"exp": float64(t0.Unix()) + 0.5})), "claims"},
		{"no jti", e.mint(subjectClaims(map[string]any{"jti": nil})), "claims"},
		{"no client_id", e.mint(subjectClaims(map[string]any{"client_id": nil})), "claims"},
		// A token for another audience than its client: a relying party's token, or an exchange for another client.
		{"an exchanged token", e.mint(subjectClaims(map[string]any{"aud": "example-app"})), "claims"},
		// Until private_key_jwt lands, only a native public client's token is a subject (REQ-EXCH-020).
		{"a confidential relying party's own sign-in token", e.mint(subjectClaims(map[string]any{"aud": "example-app", "client_id": "example-app"})), "client_kind"},
		{"a browser client's token", e.mint(subjectClaims(map[string]any{"aud": "browser-app", "client_id": "browser-app"})), "client_kind"},
		{"a machine client's token", e.mint(subjectClaims(map[string]any{"aud": "machine-app", "client_id": "machine-app"})), "client_kind"},
		{"a client nobody registered", e.mint(subjectClaims(map[string]any{"aud": "ghost", "client_id": "ghost"})), "client"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			failure(t, e.exchange(request(c.token)), "invalid_request")
			if got := get(e.lastRecord(), "status_code"); got != c.reason {
				t.Errorf("reason = %v, want %s", got, c.reason)
			}
		})
	}
	if n := len(e.policy.requests()) + len(e.signer.requests()) + len(e.key.pairwise()); n != 0 {
		t.Errorf("a refused subject token reached policy, signer or key@ %d times", n)
	}
}

// tamper changes a claim of the payload and keeps the signature.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	payload = []byte(strings.Replace(string(payload), "example-app", "example-apx", 1))
	payload = []byte(strings.Replace(string(payload), `"sid":"sid-1"`, `"sid":"sid-2"`, 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}

func TestANativePublicClientsTokenMayBeExchanged(t *testing.T) {
	e := newEnv(t, envOptions{})
	for _, client := range []string{"sluis-cli", "native-app"} { // the installation's CLI and another native client
		req := request(e.mint(subjectClaims(map[string]any{"aud": client, "client_id": client})))
		req.ClientId = client
		r := e.exchange(req)
		if r.GetStatus() != 200 {
			t.Errorf("%s: %s", client, r.GetBody())
		}
	}
	// The relying party's own sign-in token, a public client with no profile and a browser client's are refused
	// before policy, signer or the directory.
	n := len(e.policy.requests())
	for _, client := range []string{"example-app", "bare-app", "browser-app"} {
		req := request(e.mint(subjectClaims(map[string]any{"aud": client, "client_id": client})))
		req.ClientId = client
		failure(t, e.exchange(req), "invalid_request")
		if got := get(e.lastRecord(), "status_code"); got != "client_kind" {
			t.Errorf("%s: reason = %v", client, got)
		}
	}
	if len(e.policy.requests()) != n {
		t.Error("a token that may not be a subject reached policy")
	}
}

// verifies: REQ-EXCH-005
func TestThePersonOfTheTokenIsLookedUpAndAnEndedSessionIsRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	subject := e.mint(subjectClaims(nil))

	e.dir.err = exchanged.ErrSessionEnded
	failure(t, e.exchange(request(subject)), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "session_ended" {
		t.Errorf("reason = %v (REQ-EXCH-005)", got)
	}
	e.dir.err = exchanged.ErrUnknownPerson
	failure(t, e.exchange(request(subject)), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "person" {
		t.Errorf("reason = %v", got)
	}
	// The directory sees the verified claims, not the token.
	s := e.dir.seen[0]
	if s.Kind != exchanged.KindOwn || s.SID != "sid-1" || s.ClientID != "sluis-cli" || s.Subject != "pairwise-of-the-sign-in" {
		t.Errorf("directory saw %+v", s)
	}
	if n := len(e.policy.requests()); n != 0 {
		t.Error("policy was asked about a person nobody could find")
	}
}

func TestAHeldPersonReachesPolicyAsHeldAndIsNotIssuedATokenWhenPolicyDenies(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.dir.person.State = "held"
	e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		if r.GetPerson().GetState() == "held" {
			return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000004"}, nil
		}
		return allow("dev:example-app:user")(r)
	}
	failure(t, e.exchange(request(e.mint(subjectClaims(nil)))), "invalid_target")
	if len(e.signer.requests()) != 0 {
		t.Error("a held person was issued a token (REQ-EXCH-012)")
	}
}

func TestADependencyThatDoesNotAnswerIsAnOutageAndNoTokenIsIssued(t *testing.T) {
	subjectOf := func(e *env) *exchangev2alpha1.TokenExchangeRequest { return request(e.mint(subjectClaims(nil))) }
	cases := []struct {
		name    string
		breakIt func(*env)
		reason  string
	}{
		{"store", func(e *env) { e.store.fail = true }, "unavailable_store"},
		{"policy", func(e *env) {
			e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
				return nil, refusal.New(connect.CodeUnavailable, "key", "")
			}
		}, "unavailable_policy"},
		{"policy refuses the question", func(e *env) {
			e.policy.decide = func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
				return nil, refusal.New(connect.CodeInvalidArgument, "schema", "person.org")
			}
		}, "unavailable_policy"},
		{"signer", func(e *env) { e.signer.fail = true }, "unavailable_signer"},
		{"key@", func(e *env) { e.key.fail = true }, "unavailable_key"},
		{"directory", func(e *env) { e.dir.err = context.DeadlineExceeded }, "unavailable_directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			req := subjectOf(e)
			if c.name == "signer" {
				// The signer's key set is cached from the first call; break it after the subject is verified.
				e.exchange(request(e.mint(subjectClaims(nil))))
			}
			c.breakIt(e)
			_, err := e.client.Token(context.Background(), connect.NewRequest(req))
			if connect.CodeOf(err) != connect.CodeUnavailable {
				t.Fatalf("err = %v, want unavailable", err)
			}
			if got := get(e.lastRecord(), "status_code"); got != c.reason {
				t.Errorf("reason = %v, want %s", got, c.reason)
			}
		})
	}
}

func TestAnExchangeWhoseAuditFactWasNotAcceptedDoesNotLeave(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.transport.fail = true
	_, err := e.client.Token(context.Background(), connect.NewRequest(request(e.mint(subjectClaims(nil)))))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v, want unavailable", err)
	}
	if reason, _ := refusal.Reason(err); reason != "audit" {
		t.Errorf("reason = %q", reason)
	}
}

func TestOnlyTheCallersOfTheCallGraphMayExchange(t *testing.T) {
	e := newEnv(t, envOptions{caller: "signer"})
	_, err := e.client.Token(context.Background(), connect.NewRequest(request("x")))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("err = %v, want permission_denied", err)
	}
	if n := len(e.transport.records(t)); n != 0 {
		t.Errorf("a refused caller made %d records", n)
	}
}

// verifies: REQ-TOKEN-037
func TestTheLifetimeIsTheEarliestOfTheIssuerTheClientTheCapAndTheSubjectToken(t *testing.T) {
	for _, c := range []struct {
		name      string
		lifetime  time.Duration
		clientCap time.Duration
		subject   time.Duration // the subject token's remaining life
		want      int64
	}{
		{"the subject token is the earliest", 10 * time.Minute, 0, 90 * time.Second, 90},
		{"the issuer's lifetime", 10 * time.Minute, 0, 30 * time.Minute, 600},
		{"the client's ttl_cap", 10 * time.Minute, 2 * time.Minute, 30 * time.Minute, 120},
		{"the built-in hour when nothing is declared", 0, 0, 3 * time.Hour, 3600},
		{"an issuer value above the hour", 3 * time.Hour, 0, 3 * time.Hour, 3600},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, envOptions{lifetime: c.lifetime, clientCap: c.clientCap})
			subject := e.mint(subjectClaims(map[string]any{"exp": t0.Add(c.subject).Unix()}))
			r := e.exchange(request(subject))
			if r.GetStatus() != 200 {
				t.Fatalf("%s", r.GetBody())
			}
			claims, _ := claimsOf(t, body(t, r)["access_token"].(string))
			if got := int64(claims["exp"].(float64)) - int64(claims["iat"].(float64)); got != c.want {
				t.Errorf("lifetime = %d s, want %d", got, c.want)
			}
			if body(t, r)["expires_in"] != float64(c.want) {
				t.Errorf("expires_in = %v", body(t, r)["expires_in"])
			}
		})
	}
}

func TestASubjectTokenWithLessThanASecondLeftGivesNoToken(t *testing.T) {
	e := newEnv(t, envOptions{})
	// exp is a whole second, so a token that expires at t0+0 has already expired at the verifier, and one that
	// expires a second later leaves exactly one second.
	subject := e.mint(subjectClaims(map[string]any{"exp": t0.Unix()}))
	failure(t, e.exchange(request(subject)), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "expired" {
		t.Errorf("reason = %v", got)
	}
}

func TestTheNarrowingKeepsPairsAndNeverWidens(t *testing.T) {
	e := newEnv(t, envOptions{requires: []string{"dev:example-app:admin", "acme:billing:user", "*:x:y", "bad"}})
	e.policy.decide = allow("dev:example-app:user", "acme:billing:admin", "acme:billing:user", "dev:x:y", "prod:example-app:admin")
	r := e.exchange(request(e.mint(subjectClaims(nil))))
	claims, _ := claimsOf(t, body(t, r)["access_token"].(string))
	if got := strings.Join(toStrings(claims["groups"]), ","); got != "acme:billing:admin,acme:billing:user,dev:example-app:user" {
		t.Errorf("groups = %v", claims["groups"])
	}

	// Nothing the audience asks for is held: the claim is an empty array, not absent and not the full set.
	e.policy.decide = allow("prod:other:admin")
	r = e.exchange(request(e.mint(subjectClaims(nil))))
	claims, _ = claimsOf(t, body(t, r)["access_token"].(string))
	if g, ok := claims["groups"].([]any); !ok || len(g) != 0 {
		t.Errorf("groups = %v", claims["groups"])
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t, envOptions{})
	if bad := e.svc.Check(context.Background()); len(bad) != 0 {
		t.Errorf("check = %v", bad)
	}
	e = newEnv(t, envOptions{unbound: true})
	if bad := e.svc.Check(context.Background()); len(bad) != 1 || bad[0] != "directory" {
		t.Errorf("check with an unbound directory = %v", bad)
	}
	// An unbound directory makes every exchange unavailable.
	_, err := e.client.Token(context.Background(), connect.NewRequest(request(e.mint(subjectClaims(nil)))))
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("err = %v", err)
	}
	e = newEnv(t, envOptions{environment: "production", trust: &configv2alpha1.ExchangeTrust{Issuers: []*configv2alpha1.TrustedIssuer{
		{Issuer: "https://token.example.com", Audiences: []string{"sluis"}, ProofKind: "github-oidc", JwksUri: "http://127.0.0.1/keys"},
		{Issuer: "https://other.example.com"},
	}}})
	bad := e.svc.Check(context.Background())
	if strings.Join(bad, ",") != "exchange_trust.issuers[0].jwks_uri,exchange_trust.issuers[1]" {
		t.Errorf("check = %v", bad)
	}
}

func TestTheKeySetOfTheBoundaryComesFromSignerAndIsKeptForAMinute(t *testing.T) {
	e := newEnv(t, envOptions{})
	for range 3 {
		if r := e.exchange(request(e.mint(subjectClaims(nil)))); r.GetStatus() != 200 {
			t.Fatalf("%s", r.GetBody())
		}
	}
	if e.signer.keysets != 1 {
		t.Errorf("signer was asked for the key set %d times, want 1", e.signer.keysets)
	}

	// signer rotates: a token of the new key finds it by one fresh fetch.
	old := e.signer.key
	e.signer.key = newSigner(t).key
	if r := e.exchange(request(e.mint(subjectClaims(map[string]any{"jti": "after-rotation"})))); r.GetStatus() != 200 {
		t.Fatalf("a token of the rotated key was refused: %s", r.GetBody())
	}
	if e.signer.keysets != 2 {
		t.Errorf("key set fetches = %d, want 2", e.signer.keysets)
	}
	// A token of a key that was never in the set cannot make signer fetch again within the gap.
	for range 3 {
		failure(t, e.exchange(request(mintWith(t, old, "at+jwt", subjectClaims(nil)))), "invalid_request")
	}
	if e.signer.keysets != 2 {
		t.Errorf("key set fetches = %d after forged tokens, want 2", e.signer.keysets)
	}
}

// ---- client authentication on the exchange (REQ-EXCH-018, REQ-EXCH-019, REQ-CLIENT-001, REQ-CLIENT-002) ----

// authed is an exchange as the confidential client example-app, whose subject token was issued to the public native
// client sluis-cli (confirmation C-3: the secret authenticates the requesting client, not the subject).
func authed(e *env, mutate func(*exchangev2alpha1.TokenExchangeRequest)) *exchangev2alpha1.TokenExchangeRequest {
	r := request(e.mint(subjectClaims(nil)))
	r.Audience, r.ClientId = "example-app", "" // the confidential client names itself by its credentials
	mutate(r)
	return r
}

func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func wwwAuthenticate(r *typev2alpha1.HttpReply) string {
	for _, h := range r.GetHeaders() {
		if h.GetName() == "WWW-Authenticate" {
			return h.GetValue()
		}
	}
	return ""
}

func TestREQ_EXCH_018_AConfidentialClientExchangesWithBasicAndWithClientSecret(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(*exchangev2alpha1.TokenExchangeRequest)
	}{
		{"client_secret_basic", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.Authorization = basicHeader("example-app", appSecret)
		}},
		{"client_secret_post", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.ClientId, r.ClientSecret = "example-app", appSecret
		}},
		{"basic and the same client_id in the body", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.Authorization, r.ClientId = basicHeader("example-app", appSecret), "example-app"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, envOptions{})
			rep := e.exchange(authed(e, c.mutate))
			if rep.GetStatus() != 200 {
				t.Fatalf("status %d: %s", rep.GetStatus(), rep.GetBody())
			}
			// The client that asked is in the record, and how it authenticated; the secret is not.
			rec := e.lastRecord()
			if get(rec, "metadata", "event_code") != "exchange.token" ||
				get(rec, "unmapped", "sluis", "client", "id") != "example-app" ||
				get(rec, "unmapped", "sluis", "client", "authenticated") != true {
				t.Errorf("record = %v", rec)
			}
			assertNoSecret(t, e, rep)
		})
	}
}

// A secret never reaches a reply, a record or a log line.
func assertNoSecret(t *testing.T, e *env, rep *typev2alpha1.HttpReply) {
	t.Helper()
	enc := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("example-app") + ":" + url.QueryEscape(appSecret)))
	for _, text := range append([]string{string(rep.GetBody())}, recordsText(t, e)...) {
		if strings.Contains(text, appSecret) || strings.Contains(text, url.QueryEscape(appSecret)) || strings.Contains(text, enc) {
			t.Fatalf("a secret is in %q", text)
		}
	}
}

func recordsText(t *testing.T, e *env) []string {
	t.Helper()
	var out []string
	for _, r := range e.transport.records(t) {
		raw, _ := json.Marshal(r)
		out = append(out, string(raw))
	}
	return out
}

func TestAnExchangeAsAConfidentialClientMayCarryTheTokenOfAnotherClient(t *testing.T) {
	// The subject token was issued to sluis-cli; the request is example-app's. That is allowed only because the
	// subject is a public native client's (REQ-EXCH-020), which a relying party's own token is not (confirmation C-3).
	e := newEnv(t, envOptions{})
	rep := e.exchange(authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	}))
	if rep.GetStatus() != 200 {
		t.Fatalf("%s", rep.GetBody())
	}
	// The token is issued to the client that asked (RFC 9068 section 2.2), and carries no `act` claim.
	claims, _ := claimsOf(t, body(t, rep)["access_token"].(string))
	if claims["client_id"] != "example-app" || claims["aud"] != "example-app" {
		t.Errorf("claims = %v", claims)
	}
	if _, ok := claims["act"]; ok {
		t.Error("the token carries an act claim")
	}
	// The record names both clients: the one that asked and the one the subject token was issued to.
	rec := e.lastRecord()
	if get(rec, "unmapped", "sluis", "client", "id") != "example-app" || get(rec, "unmapped", "sluis", "token", "subject_client") != "sluis-cli" {
		t.Errorf("record = %v", rec)
	}
	// Policy decides on the person and on the requester (ADR 0022).
	q := e.policy.requests()[len(e.policy.requests())-1]
	if q.GetRequester().GetId() != "example-app" || q.GetRequester().GetKind() != "confidential" {
		t.Errorf("policy was told the requester %v", q.GetRequester())
	}

	other := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	})
	other.SubjectToken = e.mint(subjectClaims(map[string]any{"aud": "example-app", "client_id": "example-app"}))
	failure(t, e.exchange(other), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "client_kind" {
		t.Errorf("reason = %v", got)
	}
}

// ADR 0022: the exchange of an authenticated client is limited by policy on the person and on the requester. A
// confidential client that asks for an audience that policy does not grant to it is refused with the one
// invalid_target (REQ-EXCH-003), the same answer as for an audience that does not exist.
func TestAConfidentialClientIsRefusedAnAudiencePolicyDoesNotGrantToIt(t *testing.T) {
	e := newEnv(t, envOptions{})
	// The rule of the local installation (tests/installations/local/policy/local.cedar): a confidential requester
	// gets a token for itself and no other client.
	e.policy.decide = func(q *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		if q.GetRequester().GetKind() == "confidential" && q.GetRequester().GetId() != q.GetClient().GetId() {
			return &policyv2alpha1.DecideResponse{Decision: policyv2alpha1.Decision_DENY, DecisionId: "0192a000-0000-7000-8000-000000000009",
				Reasons: []*policyv2alpha1.Reason{{PolicyId: "exchange-confidential-for-itself"}}}, nil
		}
		return allow("dev:example-app:user")(q)
	}
	refusedFor := func(audience string) string {
		r := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.Authorization = basicHeader("example-app", appSecret)
		})
		r.Audience = audience
		return e.answer(r)
	}
	if rep := e.exchange(authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	})); rep.GetStatus() != 200 {
		t.Fatalf("its own audience: %s", rep.GetBody())
	}
	other := refusedFor("native-app")
	if other != refusedFor("no-such-app") || !strings.Contains(other, "invalid_target") {
		t.Errorf("a refused audience answers %s, an unknown one %s", other, refusedFor("no-such-app"))
	}
	if got := get(e.lastRecord(), "status_code"); got != "audience" {
		t.Errorf("reason = %v", got)
	}
	// The refusal by policy is recorded with the policy that denied it.
	r := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	})
	r.Audience = "native-app"
	failure(t, e.exchange(r), "invalid_target")
	rec := e.lastRecord()
	auths, _ := rec["authorizations"].([]any)
	if len(auths) != 1 || get(auths[0].(map[string]any), "policy", "uid") != "exchange-confidential-for-itself" {
		t.Errorf("authorizations = %v", rec["authorizations"])
	}
}

// verifies: REQ-EXCH-020
//
// The client's kind is the only thing that stops a token that exchange issued to a confidential client from being the
// subject of another exchange: a confidential client that exchanges for itself gets aud == client_id, the shape of a
// sign-in token, and exchange puts no marker in it that session does not. If a change lets a confidential client's
// token be a subject, this test fails, and the change must first add a structural guard (a claim or token type only
// exchange sets) and refuse on it in verifyOwn. A native public client's own token for itself is a subject by design
// and is not covered here.
func TestREQ_EXCH_020_AConfidentialClientsExchangedTokenIsNotASubjectOnlyByItsClientKind(t *testing.T) {
	e := newEnv(t, envOptions{})
	rep := e.exchange(authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	}))
	if rep.GetStatus() != 200 {
		t.Fatalf("%s", rep.GetBody())
	}
	token := body(t, rep)["access_token"].(string)
	claims, _ := claimsOf(t, token)
	if claims["aud"] != claims["client_id"] || claims["client_id"] != "example-app" {
		t.Fatalf("claims = %v; the premise of the test is a token whose audience is its client", claims)
	}
	// As the confidential client that holds it, authenticated.
	again := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization = basicHeader("example-app", appSecret)
	})
	again.SubjectToken = token
	failure(t, e.exchange(again), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "client_kind" {
		t.Errorf("reason = %v, want client_kind", got)
	}
	// As the public native client, which names itself: the token is another client's.
	pub := request(token)
	failure(t, e.exchange(pub), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "client_kind" {
		t.Errorf("the CLI's reason = %v, want client_kind", got)
	}
}

func TestREQ_EXCH_019_EveryFailureOfClientAuthenticationIsTheOneInvalidClient(t *testing.T) {
	e := newEnv(t, envOptions{})
	for _, c := range []struct {
		name   string
		mutate func(*exchangev2alpha1.TokenExchangeRequest)
	}{
		{"a wrong secret, Basic", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Authorization = basicHeader("example-app", "wrong") }},
		{"a wrong secret, post", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "example-app", "wrong" }},
		{"the secret and more", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.ClientId, r.ClientSecret = "example-app", appSecret+"x"
		}},
		{"an unknown client, Basic", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Authorization = basicHeader("nobody", appSecret) }},
		{"an unknown client, post", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "nobody", appSecret }},
		{"an id that is not an address", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "No Body/..", appSecret }},
		// REQ-CLIENT-001: a public client that presents a secret is a configuration error that must be visible.
		{"a public client presents a secret, Basic", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Authorization = basicHeader("sluis-cli", appSecret) }},
		{"a public client presents a secret, post", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.ClientId, r.ClientSecret = "native-app", appSecret
		}},
		{"a machine client holds no secret", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "machine-app", appSecret }},
		{"another scheme", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Authorization = "Bearer " + appSecret }},
		{"bad base64", func(r *exchangev2alpha1.TokenExchangeRequest) { r.Authorization = "Basic ###" }},
		{"a secret with no client", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientSecret = appSecret }},
		{"Basic names another client than the body", func(r *exchangev2alpha1.TokenExchangeRequest) {
			r.Authorization, r.ClientId = basicHeader("example-app", appSecret), "sluis-cli"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := e.exchange(authed(e, c.mutate))
			if rep.GetStatus() != 401 || body(t, rep)["error"] != "invalid_client" {
				t.Fatalf("status %d: %s", rep.GetStatus(), rep.GetBody())
			}
			// Every 401 of the token endpoint carries WWW-Authenticate (contracts.md), whatever method was used.
			if www := wwwAuthenticate(rep); !strings.HasPrefix(www, "Basic ") {
				t.Errorf("WWW-Authenticate = %q, want a Basic challenge", www)
			}
			rec := e.lastRecord()
			if get(rec, "metadata", "event_code") != "exchange.refused" || get(rec, "status_code") != "client_authentication" {
				t.Errorf("record = %v", rec)
			}
			if get(rec, "unmapped", "sluis", "client", "authenticated") == true {
				t.Errorf("a refused client is recorded as authenticated: %v", rec)
			}
		})
	}
	// Nothing past the client check ran: not the directory, policy, key@ or the signer.
	if n := len(e.policy.requests()) + len(e.signer.requests()) + len(e.key.pairwise()); n != 0 {
		t.Errorf("a refused client reached policy, signer or key@ %d times", n)
	}
	// No reply and no record holds the secret.
	for _, text := range recordsText(t, e) {
		if strings.Contains(text, appSecret) || strings.Contains(text, url.QueryEscape(appSecret)) {
			t.Fatalf("a record carries the secret: %s", text)
		}
	}
}

// An unknown client, a client with no secret and a wrong secret are indistinguishable to the caller: the same reply
// bytes, the same headers, and the same calls to store@ (REQ-EXCH-019). The comparison is in kits/go/clientauth.
func TestREQ_EXCH_019_AnUnknownClientAndAWrongSecretAreTheSameAnswerWithTheSameCalls(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.store.put("installation-client", "no-secret-app", &configv2alpha1.InstallationClient{Id: "no-secret-app", Kind: "confidential"})
	type outcome struct {
		answer string
		gets   map[string]int
	}
	measure := func(id string) outcome {
		before := map[string]int{}
		e.store.mu.Lock()
		for k, v := range e.store.gets {
			before[k] = v
		}
		e.store.mu.Unlock()
		ans := e.answer(authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = id, "wrong secret" }))
		e.store.mu.Lock()
		defer e.store.mu.Unlock()
		d := map[string]int{}
		for k, v := range e.store.gets {
			d[k] = v - before[k]
		}
		// A failed authentication stops before the subject token is read: store@ is asked for the secret and the
		// declaration of the client named, and nothing else.
		return outcome{ans, d}
	}
	wrong, unknown, none := measure("example-app"), measure("nobody"), measure("no-secret-app")
	for name, o := range map[string]outcome{"unknown": unknown, "no secret": none} {
		if o.answer != wrong.answer {
			t.Errorf("%s: answer %s differs from a wrong secret's %s", name, o.answer, wrong.answer)
		}
		if fmt.Sprint(o.gets) != fmt.Sprint(wrong.gets) {
			t.Errorf("%s: store@ was asked %v, a wrong secret asks %v", name, o.gets, wrong.gets)
		}
	}
	if wrong.gets["installation-client-secret"] != 1 || wrong.gets["installation-client"] < 1 {
		t.Errorf("a failed authentication asks %v", wrong.gets)
	}
}

func TestBothAuthenticationMethodsAreAnInvalidRequest(t *testing.T) {
	// RFC 6749 section 2.3: one method in each request. entry refuses this too; exchange does not trust that.
	e := newEnv(t, envOptions{})
	failure(t, e.exchange(authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) {
		r.Authorization, r.ClientSecret = basicHeader("example-app", appSecret), appSecret
	})), "invalid_request")
	if got := get(e.lastRecord(), "status_code"); got != "client_authentication_methods" {
		t.Errorf("reason = %v", got)
	}
}

func TestAClientIsAuthenticatedBeforeTheSubjectTokenIsRead(t *testing.T) {
	// A failure shows nothing of the subject or the audience: a bad subject and a bad audience are not reported
	// to a caller whose authentication failed.
	e := newEnv(t, envOptions{})
	bad := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "example-app", "wrong" })
	bad.SubjectToken, bad.Audience, bad.Scope = "not-a-jwt", "no-such-app", "openid"
	good := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "example-app", "wrong" })
	if e.answer(bad) != e.answer(good) {
		t.Errorf("a failed authentication shows %s for a bad request and %s for a good one", e.answer(bad), e.answer(good))
	}
}

func TestAStoreThatIsDownIsAnOutageNotInvalidClient(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.store.fail = true
	r := authed(e, func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId, r.ClientSecret = "example-app", appSecret })
	res, err := e.client.Token(context.Background(), connect.NewRequest(r))
	if err == nil || connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("got %v, %v; want unavailable (the call fails closed)", res, err)
	}
}

// The maintainer's decision of 2026-11-04, option (a) (ADR 0022; REQ-EXCH-007, REQ-EXCH-011): a public client of the
// native profile may exchange a token issued to ITSELF without a secret. Every other exchange is made by an
// authenticated confidential client. The rule is publicSelfExchange in service.go.
// verifies: REQ-EXCH-007, REQ-EXCH-011
func TestAPublicNativeClientMayExchangeItsOwnTokenAndNothingElseWithoutASecret(t *testing.T) {
	e := newEnv(t, envOptions{})
	// The rule: a native public client, naming itself, with the token it holds.
	for _, id := range []string{"sluis-cli", "native-app"} { // both public clients of the profile native
		r := request(e.mint(subjectClaims(map[string]any{"aud": id, "client_id": id})))
		r.ClientId = id
		rep := e.exchange(r)
		if rep.GetStatus() != 200 {
			t.Errorf("%s: %s", id, rep.GetBody())
		}
		rec := e.lastRecord()
		if get(rec, "unmapped", "sluis", "client", "id") != id || get(rec, "unmapped", "sluis", "client", "authenticated") != false {
			t.Errorf("%s: record = %v", id, rec)
		}
	}
	// The refusals, each invalid_client and each before anything past the client check ran.
	for _, c := range []struct {
		name   string
		mutate func(*exchangev2alpha1.TokenExchangeRequest)
	}{
		{"no client named", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "" }},
		{"another public client's token", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "native-app" }},
		{"a confidential client without credentials", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "example-app" }},
		{"an unknown client", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "nobody" }},
		{"a machine client without credentials", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "machine-app" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := request(e.mint(subjectClaims(nil))) // the token of sluis-cli
			c.mutate(r)
			n := len(e.policy.requests())
			rep := e.exchange(r)
			if rep.GetStatus() != 401 || body(t, rep)["error"] != "invalid_client" {
				t.Fatalf("status %d: %s", rep.GetStatus(), rep.GetBody())
			}
			if len(e.policy.requests()) != n {
				t.Error("a refused client reached policy")
			}
		})
	}
	// A public client that presents a secret is refused, even for its own token (REQ-CLIENT-001).
	own := request(e.mint(subjectClaims(nil)))
	own.ClientId, own.ClientSecret = "sluis-cli", appSecret
	if rep := e.exchange(own); rep.GetStatus() != 401 || body(t, rep)["error"] != "invalid_client" {
		t.Errorf("a public client with a secret: status %d: %s", rep.GetStatus(), rep.GetBody())
	}
	// A browser client's own token is not a subject at all (REQ-EXCH-020).
	br := request(e.mint(subjectClaims(map[string]any{"aud": "browser-app", "client_id": "browser-app"})))
	br.ClientId = "browser-app"
	failure(t, e.exchange(br), "invalid_request")
}
