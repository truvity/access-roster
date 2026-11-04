//go:build sluis_test

package exchanged_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
)

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
	input := append([]byte{0, 0, 0, byte(len(testTenant))}, []byte(testTenant)...)
	input = append(input, []byte(testPerson.ID)...)
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
	// An unknown audience never reaches policy or signer.
	if n := len(e.policy.requests()); n != 1 {
		t.Errorf("policy asked %d times, want 1 (the refused one)", n)
	}
	if n := len(e.signer.requests()); n != 0 {
		t.Errorf("signer signed %d tokens for refused exchanges", n)
	}
}

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
		{"another client", func(r *exchangev2alpha1.TokenExchangeRequest) { r.ClientId = "example-app" }, "invalid_request", "client"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := request(subject)
			c.mutate(r)
			failure(t, e.exchange(r), c.code)
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
		// An exchanged token names another audience than its client; it may not be exchanged again.
		{"an exchanged token", e.mint(subjectClaims(map[string]any{"aud": "example-app"})), "claims"},
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
