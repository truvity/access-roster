//go:build sluis_test

package sessiond_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
)

const (
	acrMFA   = "urn:example:acr:mfa"
	acrLower = "urn:example:acr:pwd"
	acrHigh  = "urn:example:acr:hardware"
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

// supportedACRs is what the boundary of these tests lists (Boundary.acr_values_supported): the one list that discovery
// shows and that acr_values is enforced against. acrLower is a level the upstream can state and the boundary does not list.
var supportedACRs = []string{acrMFA, acrHigh, "-acr-1", "_acr_1"}

// acrEnv is an env whose boundary lists supportedACRs.
func acrEnv(t *testing.T) *env {
	t.Helper()
	return newEnv(t, func(o *options) { o.boundary.AcrValuesSupported = supportedACRs })
}

// The matrix of REQ-AUTHN-009, 034 and 101: a request is enforced against the values it names that the boundary lists, and
// is met when one of them is; a request with no listed value is not enforced and still succeeds; an unlisted value is
// ignored and counted, never satisfied by the upstream saying it. The token's acr is what the upstream stated.
//
// verifies: REQ-AUTHN-009, REQ-AUTHN-034, REQ-AUTHN-101
func TestACRValuesAreMetOrRefused(t *testing.T) {
	const unknown = "urn:example:acr:unknown"
	for _, c := range []struct {
		name, asked string
		upstream    *string
		ok          bool
		ignored     int // the unlisted values of the request
	}{
		// Only listed values: enforced.
		{"listed, met", acrMFA, strp(acrMFA), true, 0},
		{"listed several, the second is met", acrHigh + " " + acrMFA, strp(acrMFA), true, 0},
		{"listed several, the first is met", acrMFA + " " + acrHigh, strp(acrMFA), true, 0},
		{"listed, a lower class is stated", acrMFA, strp(acrLower), false, 0},
		{"listed several, none is met", acrHigh + " " + acrMFA, strp(acrLower), false, 0},
		{"listed, the upstream states no acr, whatever amr says", acrMFA, nil, false, 0},
		{"listed, a longer value that starts with the stated one", acrMFA, strp(acrMFA + ":extra"), false, 0},
		{"listed, a shorter value that is a prefix of the stated one", acrMFA, strp("urn:example:acr"), false, 0},
		{"listed, a different case", acrMFA, strp(strings.ToUpper(acrMFA)), false, 0},
		{"listed, begins with a hyphen", "-acr-1", strp("-acr-1"), true, 0},
		{"listed, begins with an underscore", "_acr_1", strp("_acr_1"), true, 0},
		// Only unlisted values: no enforcement, the request succeeds (OpenID Connect Core: acr_values is voluntary), and the
		// token states what happened.
		{"unlisted only, the upstream states another", unknown, strp(acrMFA), true, 1},
		{"unlisted only, the upstream states none", unknown, nil, true, 1},
		{"unlisted only, the upstream states that very value", acrLower, strp(acrLower), true, 1},
		// The match is exact: another case of a listed value is another value, not enforced, and counted.
		{"another case of a listed value is unlisted", strings.ToUpper(acrMFA), strp(acrMFA), true, 1},
		{"another case of a listed value, the upstream states a lower class", strings.ToUpper(acrMFA), strp(acrLower), true, 1},
		{"a listed value beside another case of it, met", acrMFA + " " + strings.ToUpper(acrMFA), strp(acrMFA), true, 1},
		{"a listed value beside another case of it, unmet", acrMFA + " " + strings.ToUpper(acrMFA), strp(strings.ToUpper(acrMFA)), false, 1},
		{"two unlisted numbers, as the OpenID Foundation's module sends", "1 2", nil, true, 2},
		// A mix: enforced against the listed value alone.
		{"mix, the listed one is met", unknown + " " + acrMFA, strp(acrMFA), true, 1},
		{"mix, the listed one is unmet", unknown + " " + acrMFA, strp(acrLower), false, 1},
		{"mix, the listed one is unmet and the upstream states the unlisted one", acrLower + " " + acrMFA, strp(acrLower), false, 1},
		{"mix, the listed one is unmet and the upstream states none", acrMFA + " " + unknown, nil, false, 1},
		// No request, no enforcement.
		{"no acr_values, no acr stated", "", nil, true, 0},
		{"no acr_values, an acr stated", "", strp(acrLower), true, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := acrEnv(t)
			q, p := signInWithACR(t, e, c.asked, c.upstream)
			if c.ok {
				code := q.Get("code")
				if code == "" {
					t.Fatalf("refused: %v", q)
				}
				// The token's acr is the one the upstream stated: not the first of the list, and not an unlisted one that was
				// asked for.
				tr := e.token(codeRequest(code, p))
				for _, name := range []string{"id_token", "access_token"} {
					_, claims := tokenClaims(t, body(t, tr)[name].(string))
					got, has := claims["acr"].(string)
					switch {
					case c.upstream == nil && has:
						t.Errorf("%s acr = %q, the upstream stated none", name, got)
					case c.upstream != nil && got != *c.upstream:
						t.Errorf("%s acr = %q, want the upstream's %q", name, got, *c.upstream)
					}
				}
				checkIgnoredCount(t, e, c.ignored)
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
			checkIgnoredCount(t, e, c.ignored)
		})
	}
}

// checkIgnoredCount holds the authorize record to the number of ignored values, and every record to carrying no value of the
// request: the count is the whole of what is kept.
func checkIgnoredCount(t *testing.T, e *env, want int) {
	t.Helper()
	var got any
	for _, r := range e.records() {
		if md, _ := r["metadata"].(map[string]any); md["event_code"] != "session.authorize" {
			continue
		}
		if un, _ := r["unmapped"].(map[string]any); un != nil {
			if sl, _ := un["sluis"].(map[string]any); sl != nil {
				got = sl["ignored_acr_values"]
			}
		}
		raw, _ := json.Marshal(r)
		for _, v := range []string{"urn:example:acr:unknown", acrLower, "1 2"} {
			if strings.Contains(string(raw), v) {
				t.Errorf("an audit record carries the value %q: %s", v, raw)
			}
		}
	}
	switch {
	case want == 0 && got != nil:
		t.Errorf("ignored_acr_values = %v, want none", got)
	case want > 0 && got != float64(want):
		t.Errorf("ignored_acr_values = %v, want %d", got, want)
	}
}

// The upstream is asked for the listed values alone, in the client's order: a value the boundary does not list is not
// passed on.
//
// verifies: REQ-AUTHN-009
func TestOnlyTheListedACRValuesReachTheUpstream(t *testing.T) {
	for _, c := range []struct{ asked, want string }{
		{"", ""},
		{acrMFA, acrMFA},
		{"urn:example:acr:unknown", ""},
		{"urn:example:acr:unknown " + acrMFA, acrMFA},
		{acrMFA + " " + acrLower + " " + acrHigh, acrMFA + " " + acrHigh},
		{"1 2", ""},
		{strings.ToUpper(acrMFA), ""},
		{strings.ToUpper(acrMFA) + " " + acrMFA, acrMFA},
	} {
		e := acrEnv(t)
		p := newAuthorize()
		p.req.AcrValues = c.asked
		if q := location(t, e.authorize(p.req)).Query(); q.Get("error") != "" {
			t.Fatalf("%q refused: %v", c.asked, q)
		}
		if got := e.upstream.begins[0].GetAcrValues(); got != c.want {
			t.Errorf("asked %q: the upstream got %q, want %q", c.asked, got, c.want)
		}
	}
}

// The list is read at /authorize and the values it keeps travel in the pending sign-in, so a reload of the Boundary between
// /authorize and the callback changes nothing for the request in flight: a value removed stays enforced, a value swapped for
// another keeps the old one enforced, and a value added is not enforced for a request that began before it. (Discovery shows
// the list the entry instance has read, which can lag session's by the 5 seconds of its cache.)
//
// verifies: REQ-AUTHN-009
func TestAReloadOfTheListDoesNotChangeARequestInFlight(t *testing.T) {
	boundary := func(list ...string) *configv2alpha1.Boundary {
		return &configv2alpha1.Boundary{Name: testBoundary, Environment: "development", Issuer: testIssuer, DefaultTenant: testTenant, AcrValuesSupported: list}
	}
	for _, c := range []struct {
		name         string
		before, then []string
		upstream     *string
		ok           bool
	}{
		{"removed: stays enforced, unmet", []string{acrMFA}, nil, strp(acrLower), false},
		{"removed: stays enforced, met", []string{acrMFA}, nil, strp(acrMFA), true},
		{"swapped: the old value stays enforced, unmet", []string{acrMFA}, []string{acrHigh}, strp(acrLower), false},
		{"swapped: the old value stays enforced, met", []string{acrMFA}, []string{acrHigh}, strp(acrMFA), true},
		{"swapped: the new value is not enforced for this request", []string{acrMFA}, []string{acrHigh}, strp(acrHigh), false},
		{"added: not enforced for a request that began before it", nil, []string{acrMFA}, strp(acrLower), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, func(o *options) { o.boundary = boundary(c.before...) })
			p := newAuthorize()
			p.req.AcrValues = acrMFA
			a := e.authorize(p.req)
			if location(t, a).Query().Get("error") != "" {
				t.Fatalf("authorize refused: %v", location(t, a).Query())
			}
			e.store.put("boundary", "", "default", boundary(c.then...)) // the reload
			upstreamSays(e, c.upstream)
			cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: location(t, a).Query().Get("state"), Cookie: cookieValue(t, a)})
			got := location(t, cb).Query()
			if c.ok != (got.Get("code") != "") {
				t.Fatalf("redirect = %v, want ok = %v", got, c.ok)
			}
		})
	}
	// A request that begins after the reload follows the new list.
	e := newEnv(t, func(o *options) { o.boundary = boundary(acrMFA) })
	e.store.put("boundary", "", "default", boundary())
	q, _ := signInWithACR(t, e, acrMFA, strp(acrLower))
	if q.Get("code") == "" {
		t.Errorf("a request after the list was emptied was enforced: %v", q)
	}
}

// A boundary that lists nothing enforces nothing: every value is ignored, counted, and the sign-in goes on.
//
// verifies: REQ-AUTHN-009
func TestABoundaryThatListsNoACRValueEnforcesNone(t *testing.T) {
	e := newEnv(t, nil)
	q, p := signInWithACR(t, e, acrMFA+" "+acrHigh, strp(acrLower))
	if q.Get("code") == "" {
		t.Fatalf("refused: %v", q)
	}
	_, claims := tokenClaims(t, body(t, e.token(codeRequest(q.Get("code"), p)))["id_token"].(string))
	if claims["acr"] != acrLower {
		t.Errorf("acr = %v", claims["acr"])
	}
	checkIgnoredCount(t, e, 2)
	if e.upstream.begins[0].GetAcrValues() != "" {
		t.Error("an unlisted value was passed on")
	}
}

// The refusal does not depend on prompt=none: a request for no interaction that the upstream answers with a lower class is
// still unmet.
//
// verifies: REQ-AUTHN-034
func TestACRValuesAreRefusedUnderPromptNone(t *testing.T) {
	e := acrEnv(t)
	p := newAuthorize()
	p.req.AcrValues, p.req.Prompt = acrMFA, "none"
	a := e.authorize(p.req)
	upstreamSays(e, strp(acrLower))
	cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: location(t, a).Query().Get("state"), Cookie: cookieValue(t, a)})
	if q := location(t, cb).Query(); q.Get("error") != "unmet_authentication_requirements" || q.Get("code") != "" {
		t.Fatalf("redirect = %v", q)
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

// The limits hold for the whole request, whether the values are listed or not: nine values or one of 257 bytes is refused by
// a boundary that lists them all.
//
// verifies: REQ-AUTHN-009
func TestTheLimitsOnACRValuesHoldWhateverTheBoundaryLists(t *testing.T) {
	long := strings.Repeat("a", 257)
	nine := strings.TrimSpace(strings.Repeat("a ", 9))
	for _, asked := range []string{long, nine, acrMFA + " " + long, nine + " " + acrMFA} {
		e := newEnv(t, func(o *options) { o.boundary.AcrValuesSupported = []string{"a", long, acrMFA} })
		p := newAuthorize()
		p.req.AcrValues = asked
		if q := location(t, e.authorize(p.req)).Query(); q.Get("error") != "invalid_request" {
			t.Errorf("%.30q: %v", asked, q)
		}
	}
}
