//go:build sluis_test

package sessiond_test

import (
	"net/url"
	"strings"
	"testing"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

const (
	acrMFA  = "urn:example:acr:mfa"
	acrPWD  = "urn:example:acr:pwd"
	acrHigh = "urn:example:acr:hardware"
)

// upstreamSays makes the upstream state acr (nil: none) with the methods mfa and otp, as Keycloak does at a second factor.
func upstreamSays(e *env, acr *string) {
	e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
		return &integrationv2alpha1.Assertion{
			Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
			Acr: acr, Amr: []string{"otp", "mfa"}, AmrPresent: true, AuthTime: timestampOf(e.clk.now().Add(-5e9)),
		}, nil
	}
}

func strp(s string) *string { return &s }

// signInWithACR runs authorize and callback for a request that asked for acrValues, with the upstream stating acr.
func signInWithACR(t *testing.T, e *env, acrValues string, acr *string) (q url.Values, p authorizeParams) {
	t.Helper()
	p = newAuthorize()
	p.req.AcrValues = acrValues
	a := e.authorize(p.req)
	if location(t, a).Query().Get("error") != "" {
		t.Fatalf("authorize refused: %v", location(t, a).Query())
	}
	upstreamSays(e, acr)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: location(t, a).Query().Get("state"), Cookie: cookieValue(t, a)})
	return location(t, cb).Query(), p
}

// The acr matrix (REQ-AUTHN-009, REQ-AUTHN-101): when acr_values are sent, the authentication is one of them or the client
// gets unmet_authentication_requirements. Known, unknown, restricted, and the upstream that states none.
//
// verifies: REQ-AUTHN-009, REQ-AUTHN-034, REQ-AUTHN-101
func TestACRValuesAreMetOrRefused(t *testing.T) {
	for _, c := range []struct {
		name, asked string
		upstream    *string
		ok          bool
	}{
		{"one value, met", acrMFA, strp(acrMFA), true},
		{"several, the second is met", acrHigh + " " + acrMFA, strp(acrMFA), true},
		{"several, the first is met", acrMFA + " " + acrHigh, strp(acrMFA), true},
		{"one value, a lower class is stated", acrMFA, strp(acrPWD), false},
		{"several, none is met", acrHigh + " " + acrMFA, strp(acrPWD), false},
		{"a value this installation does not know", "urn:example:acr:unknown", strp(acrMFA), false},
		{"restricted: a longer value that starts with the stated one", acrMFA + ":extra", strp(acrMFA), false},
		{"restricted: a shorter value that is a prefix of the stated one", "urn:example:acr", strp(acrMFA), false},
		{"restricted: a different case", strings.ToUpper(acrMFA), strp(acrMFA), false},
		{"the upstream states no acr, whatever amr says", acrMFA, nil, false},
		{"no acr_values, no acr stated", "", nil, true},
		{"no acr_values, an acr stated", "", strp(acrPWD), true},
		// A value that begins with - or _ is a real acr (a URN may), and must be accepted by the pattern and matched.
		{"a value starting with a hyphen", "-acr-1", strp("-acr-1"), true},
		{"a value starting with an underscore", "_acr_1", strp("_acr_1"), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			q, p := signInWithACR(t, e, c.asked, c.upstream)
			if c.ok {
				code := q.Get("code")
				if code == "" {
					t.Fatalf("refused: %v", q)
				}
				// The token's acr is the one stated, which is one of those asked for.
				tr := e.token(codeRequest(code, p))
				_, claims := tokenClaims(t, body(t, tr)["id_token"].(string))
				if c.asked != "" {
					if got, _ := claims["acr"].(string); !strings.Contains(" "+c.asked+" ", " "+got+" ") {
						t.Errorf("acr = %q, not one of %q", got, c.asked)
					}
				}
				return
			}
			if q.Get("error") != "unmet_authentication_requirements" || q.Get("code") != "" || q.Get("iss") != testIssuer {
				t.Fatalf("redirect = %v, want unmet_authentication_requirements and no code", q)
			}
			if q.Get("state") != p.req.GetState() {
				t.Errorf("state = %q", q.Get("state"))
			}
			// Nothing was made for a refused sign-in: no person, no link, no code.
			for _, kind := range []string{"person", "upstream-link", "auth-code"} {
				if n := e.store.count(kind, testTenant); n != 0 {
					t.Errorf("%d %s items written for a refused sign-in", n, kind)
				}
			}
			recs := e.records()
			last := recs[len(recs)-1]
			if last["status_code"] != "acr_values" {
				t.Errorf("the last record = %v, want status_code acr_values", last)
			}
		})
	}
}

// The refusal does not depend on prompt=none: a request for no interaction that the upstream answers with a lower class is
// still unmet.
//
// verifies: REQ-AUTHN-034
func TestACRValuesAreRefusedUnderPromptNone(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.AcrValues, p.req.Prompt = acrMFA, "none"
	a := e.authorize(p.req)
	upstreamSays(e, strp(acrPWD))
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: location(t, a).Query().Get("state"), Cookie: cookieValue(t, a)})
	if q := location(t, cb).Query(); q.Get("error") != "unmet_authentication_requirements" || q.Get("code") != "" {
		t.Fatalf("redirect = %v", q)
	}
}

// The client's list reaches the upstream as it was sent, in the client's order, and a request without one sends none.
//
// verifies: REQ-AUTHN-009
func TestACRValuesReachTheUpstreamAsSent(t *testing.T) {
	for _, asked := range []string{"", acrMFA, acrHigh + " " + acrMFA} {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.AcrValues = asked
		if q := location(t, e.authorize(p.req)).Query(); q.Get("error") != "" {
			t.Fatalf("refused: %v", q)
		}
		if got := e.upstream.begins[0].GetAcrValues(); got != asked {
			t.Errorf("acr_values to the upstream = %q, want %q", got, asked)
		}
	}
}

// A malformed list is refused to the client's redirect and never reaches the upstream: an empty member (a doubled,
// leading or trailing space), a quote, a backslash, a control character, more than eight values, or more than 256 bytes.
//
// verifies: REQ-AUTHN-009
func TestMalformedACRValuesAreRefused(t *testing.T) {
	long := strings.Repeat("a", 257)
	nine := strings.TrimSpace(strings.Repeat("a ", 9))
	for _, asked := range []string{" a", "a ", "a  b", "a\"b", "a\\b", "a\tb", "a\nb", "a\x00b", "é", long, nine, strings.Repeat("a", 129) + " " + strings.Repeat("b", 128)} {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.AcrValues = asked
		q := location(t, e.authorize(p.req)).Query()
		if q.Get("error") != "invalid_request" || q.Get("code") != "" {
			t.Errorf("%q: redirect = %v", asked, q)
		}
		if len(e.upstream.begins) != 0 {
			t.Errorf("%q: the upstream was asked", asked)
		}
		if recs := e.records(); len(recs) != 1 || recs[0]["status_code"] != "acr_values" {
			t.Errorf("%q: records = %v", asked, recs)
		}
	}
	// The bounds themselves are served: eight values, and 256 bytes.
	for _, asked := range []string{strings.TrimSpace(strings.Repeat("a ", 8)), strings.Repeat("a", 256)} {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.AcrValues = asked
		if q := location(t, e.authorize(p.req)).Query(); q.Get("error") != "" {
			t.Errorf("%q refused: %v", asked, q)
		}
	}
}
