//go:build sluis_test

package sessiond_test

import (
	"net/http"
	"testing"
	"time"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

// A freshness rule in policy (here a fake that denies an authentication older than 15 minutes and annotates the denial
// with the step-up) makes session answer insufficient_user_authentication (RFC 9470); the client repeats the request
// with max_age; the person authenticates again at the upstream, and the token carries the new acr and auth_time.
//
// verifies: REQ-AUTHN-053, REQ-ISO-035
func TestAStepUpIsChallengedWhenTheAuthenticationIsOldAndMetByAFreshOne(t *testing.T) {
	e := newEnv(t, nil)
	const freshness = 15 * time.Minute
	e.policy.decide = func(r *policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		if len(r.GetGrantKeyOps()) > 0 { // the sign-in question
			return allowAll(r), nil
		}
		if age := r.GetContext().GetAuthAge(); r.GetContext().AuthAge != nil && time.Duration(age)*time.Second <= freshness {
			return allowAll(r), nil
		}
		return &policyv2alpha1.DecideResponse{
			Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-stale", Digest: "digest-1",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "fresh-mfa", Annotations: map[string]string{"step_up": "max_age=900"}}},
		}, nil
	}
	authenticatedAgo := func(d time.Duration, acr string) {
		e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
			return &integrationv2alpha1.Assertion{
				Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
				Acr: &acr, AuthTime: timestampOf(e.clk.now().Add(-d)),
			}, nil
		}
	}
	signIn := func(maxAge, upstreamCode string) (string, authorizeParams) {
		t.Helper()
		p := newAuthorize()
		p.req.MaxAge = maxAge
		a := e.authorize(p.req)
		up := location(t, a)
		cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: upstreamCode, State: up.Query().Get("state"), Cookie: cookieValue(t, a)})
		code := location(t, cb).Query().Get("code")
		if code == "" {
			t.Fatalf("no code: %s", location(t, cb))
		}
		return code, p
	}

	// A 20-minute-old authentication is older than the rule: the challenge names the step-up.
	authenticatedAgo(20*time.Minute, "urn:example:acr:pwd")
	code, p := signIn("", "c-stale-0001")
	b := assertOAuth(t, e.token(codeRequest(code, p)), http.StatusBadRequest, "insufficient_user_authentication")
	if b["max_age"] != "900" {
		t.Errorf("the challenge = %v", b)
	}
	if e.store.count("session-chain", testTenant) != 0 {
		t.Error("something was issued for the stale authentication")
	}

	// The client repeats with max_age; the person authenticates again, and the tokens reflect it.
	fresh := e.clk.now().Add(-30 * time.Second)
	authenticatedAgo(30*time.Second, "urn:example:acr:mfa")
	code, p = signIn("900", "c-fresh-0001")
	tr := e.token(codeRequest(code, p))
	if tr.GetStatus() != http.StatusOK {
		t.Fatalf("the met step-up was refused: %d %s", tr.GetStatus(), tr.GetBody())
	}
	for name, token := range map[string]string{"id_token": body(t, tr)["id_token"].(string), "access_token": body(t, tr)["access_token"].(string)} {
		_, claims := tokenClaims(t, token)
		if claims["acr"] != "urn:example:acr:mfa" {
			t.Errorf("%s acr = %v, want the new one", name, claims["acr"])
		}
		if claims["auth_time"] != float64(fresh.Unix()) {
			t.Errorf("%s auth_time = %v, want %d", name, claims["auth_time"], fresh.Unix())
		}
	}
}
