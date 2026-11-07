//go:build sluis_test

package sessiond_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

// What the client asked of the authentication is passed to the upstream as given, and a prompt that session cannot
// honour is answered before the upstream hears of it.
//
// verifies: REQ-AUTHN-007, REQ-AUTHN-008
func TestAuthorizePassesPromptAndMaxAgeToTheUpstream(t *testing.T) {
	for _, c := range []struct {
		name, prompt, maxAge string
		wantPrompt           string
		wantMaxAge           string // "" is none
	}{
		{"neither", "", "", "", ""},
		{"prompt none", "none", "", "none", ""},
		{"prompt login", "login", "", "login", ""},
		{"max_age", "", "900", "", "900"},
		{"max_age zero is a forced login and reaches the upstream as zero", "", "0", "", "0"},
		{"both", "login", "60", "login", "60"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt, p.req.MaxAge = c.prompt, c.maxAge
			r := e.authorize(p.req)
			if q := location(t, r).Query(); q.Get("error") != "" {
				t.Fatalf("refused: %v", q)
			}
			if len(e.upstream.begins) != 1 {
				t.Fatalf("%d upstream requests", len(e.upstream.begins))
			}
			b := e.upstream.begins[0]
			if b.GetPrompt() != c.wantPrompt {
				t.Errorf("prompt = %q, want %q", b.GetPrompt(), c.wantPrompt)
			}
			switch {
			case c.wantMaxAge == "" && b.MaxAge != nil:
				t.Errorf("max_age = %d, want none", b.GetMaxAge())
			case c.wantMaxAge != "" && (b.MaxAge == nil || itoa(b.GetMaxAge()) != c.wantMaxAge):
				t.Errorf("max_age = %v, want %s", b.MaxAge, c.wantMaxAge)
			}
		})
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// The prompt values that have no meaning, or that session cannot honour, are refused to the client's redirect and never
// reach the upstream (OpenID Connect Core section 3.1.2.1: none with another value is an error, and consent and an
// account choice that cannot be had are consent_required and account_selection_required).
//
// verifies: REQ-AUTHN-032
func TestPromptNoneWithAnotherValueIsRefused(t *testing.T) {
	for _, c := range []struct {
		prompt, code string
	}{
		{"none login", "invalid_request"},
		{"login none", "invalid_request"},
		{"none consent", "invalid_request"},
		{"none select_account", "invalid_request"},
		{"none login consent select_account", "invalid_request"},
		{"login login", "invalid_request"},
		{"none none", "invalid_request"},
		{"login  none", "invalid_request"},
		{" none", "invalid_request"},
		{"none ", "invalid_request"},
		{"NONE", "invalid_request"},
		{"create", "invalid_request"},
		{"consent", "consent_required"},
		{"select_account", "account_selection_required"},
		{"login consent", "consent_required"},
		{"login select_account", "account_selection_required"},
	} {
		t.Run(c.prompt, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt = c.prompt
			q := location(t, e.authorize(p.req)).Query()
			if q.Get("error") != c.code || q.Get("state") != p.req.GetState() || q.Get("iss") != testIssuer || q.Get("code") != "" {
				t.Errorf("redirect = %v, want error %s", q, c.code)
			}
			if len(e.upstream.begins) != 0 {
				t.Error("the upstream was asked")
			}
			if recs := e.records(); len(recs) != 1 || recs[0]["status_code"] != "prompt" {
				t.Errorf("records = %v, want one with status_code prompt", recs)
			}
		})
	}
}

// A request for no interaction that names a registered client and redirect_uri is answered with a redirect and nothing
// else: no page, whether the sign-in goes on to the upstream or the request is refused, and the upstream's answer at the
// callback is a redirect too. An address that cannot be redirected to is a page (RFC 6749 section 10.15), and so is a callback
// that arrives without its cookie (ADR 0025 says when that can happen to a silent request).
//
// verifies: REQ-AUTHN-031
func TestPromptNoneRendersNoPage(t *testing.T) {
	noPage := func(t *testing.T, r *typev2alpha1.HttpReply) {
		t.Helper()
		if r.GetStatus() != 302 || len(r.GetBody()) != 0 || len(headerOf(r, "Content-Type")) != 0 {
			t.Errorf("status %d, body %q, content type %v: want a bare redirect", r.GetStatus(), r.GetBody(), headerOf(r, "Content-Type"))
		}
	}
	for name, edit := range map[string]func(*sessionv2alpha1.AuthorizeRequest){
		"goes on to the upstream": func(*sessionv2alpha1.AuthorizeRequest) {},
		"with max_age":            func(r *sessionv2alpha1.AuthorizeRequest) { r.MaxAge = "60" },
		"a bad scope":             func(r *sessionv2alpha1.AuthorizeRequest) { r.Scope = "profile" },
		"no PKCE":                 func(r *sessionv2alpha1.AuthorizeRequest) { r.CodeChallenge = "" },
		"a bad response type":     func(r *sessionv2alpha1.AuthorizeRequest) { r.ResponseType = "token" },
		"a bad max_age":           func(r *sessionv2alpha1.AuthorizeRequest) { r.MaxAge = "soon" },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt = "none"
			edit(p.req)
			noPage(t, e.authorize(p.req))
		})
	}
	// The silent answer of the upstream is a redirect too, whatever the upstream says.
	for _, code := range []string{"login_required", "interaction_required", "consent_required", "account_selection_required", "access_denied", "server_error", "nonsense"} {
		t.Run("upstream "+code, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt = "none"
			a := e.authorize(p.req)
			cb := e.callback(&sessionv2alpha1.CallbackRequest{State: location(t, a).Query().Get("state"), Error: code, Cookie: cookieValue(t, a)})
			noPage(t, cb)
		})
	}
}

// A request for no interaction hears why the upstream could not answer without it: the four errors of OpenID Connect
// Core section 3.1.2.6 go back to the client as they are. Without prompt=none the same words from the upstream are an
// access_denied, as every other error of the upstream is, and nothing else the upstream says is repeated.
//
// verifies: REQ-AUTHN-007, REQ-AUTHN-031
func TestPromptNoneReportsWhatTheUpstreamNeeds(t *testing.T) {
	for _, c := range []struct {
		prompt, upstream, want, reason string
	}{
		{"none", "login_required", "login_required", "login_required"},
		{"none", "interaction_required", "interaction_required", "interaction_required"},
		{"none", "consent_required", "consent_required", "consent_required"},
		{"none", "account_selection_required", "account_selection_required", "account_selection_required"},
		{"none", "access_denied", "access_denied", "upstream"},
		{"none", "temporarily_unavailable", "temporarily_unavailable", "upstream"},
		{"none", "server_error", "access_denied", "upstream"},
		{"none", "evil\nerror", "access_denied", "upstream"},
		{"", "login_required", "access_denied", "upstream"},
		{"login", "login_required", "access_denied", "upstream"},
		{"", "interaction_required", "access_denied", "upstream"},
	} {
		t.Run(c.prompt+"/"+c.upstream, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt = c.prompt
			a := e.authorize(p.req)
			cb := e.callback(&sessionv2alpha1.CallbackRequest{State: location(t, a).Query().Get("state"), Error: c.upstream, ErrorDescription: "details of the upstream", Cookie: cookieValue(t, a)})
			q := location(t, cb).Query()
			if q.Get("error") != c.want || q.Get("state") != p.req.GetState() || q.Get("iss") != testIssuer || q.Get("code") != "" {
				t.Errorf("redirect = %v, want error %s", q, c.want)
			}
			if strings.Contains(q.Get("error_description"), "details") {
				t.Error("the upstream's text was repeated")
			}
			if len(e.upstream.completes) != 0 || len(e.store.writes) != 0 {
				t.Error("something was completed or written for an upstream error")
			}
			recs := e.records()
			if got := recs[len(recs)-1]["status_code"]; got != c.reason {
				t.Errorf("status_code = %v, want %s", got, c.reason)
			}
		})
	}
}

// prompt=login and max_age=0 ask for an authentication that happened because of this request. An upstream that answered
// from its own single sign-on session, and says so by an auth_time from before the request, is not believed; an upstream
// that says no time cannot show it. The clocks of the two differ by seconds (freshSkew, 10 s).
//
// verifies: REQ-AUTHN-007, REQ-AUTHN-008
func TestFreshAuthenticationIsHeldToTheRequest(t *testing.T) {
	assertion := func(e *env, at *time.Time) {
		e.upstream.completeFn = func(*integrationv2alpha1.CompleteRequest) (*integrationv2alpha1.Assertion, error) {
			a := &integrationv2alpha1.Assertion{Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice"}
			if at != nil {
				a.AuthTime = timestamppb.New(*at)
			}
			return a, nil
		}
	}
	for _, c := range []struct {
		name, prompt, maxAge string
		before               time.Duration // the auth_time, before the authorization request; negative is after
		noTime               bool
		ok                   bool
	}{
		{"login, authenticated after the request", "login", "", -3 * time.Second, false, true},
		{"login, authenticated within the skew", "login", "", 10 * time.Second, false, true},
		{"login, authenticated just before the skew", "login", "", 11 * time.Second, false, false},
		{"login, from the upstream's own session", "login", "", 2 * time.Hour, false, false},
		{"login, no auth_time", "login", "", 0, true, false},
		{"login, an auth_time 10 s ahead of the clock", "login", "", -15 * time.Second, false, true},
		{"login, an auth_time 11 s ahead of the clock", "login", "", -16 * time.Second, false, false},
		{"login, an auth_time 48 h ahead", "login", "", -48 * time.Hour, false, false},
		{"login, an auth_time 30 min ahead", "login", "", -30 * time.Minute, false, false},
		{"max_age zero, an auth_time 48 h ahead", "", "0", -48 * time.Hour, false, false},
		{"max_age zero, an auth_time 30 min ahead", "", "0", -30 * time.Minute, false, false},
		{"max_age zero, authenticated after the request", "", "0", -3 * time.Second, false, true},
		{"max_age zero, from the upstream's own session", "", "0", 2 * time.Hour, false, false},
		{"max_age zero, no auth_time", "", "0", 0, true, false},
		{"neither, from the upstream's own session", "", "", 2 * time.Hour, false, true},
		{"neither, no auth_time", "", "", 0, true, true},
		{"max_age within, from before the request", "", "7200", 30 * time.Minute, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			p := newAuthorize()
			p.req.Prompt, p.req.MaxAge = c.prompt, c.maxAge
			start := e.clk.now()
			a := e.authorize(p.req)
			e.clk.advance(5 * time.Second)
			at := start.Add(-c.before)
			if c.noTime {
				assertion(e, nil)
			} else {
				assertion(e, &at)
			}
			cb := e.callback(&sessionv2alpha1.CallbackRequest{Code: "c-1234567890", State: location(t, a).Query().Get("state"), Cookie: cookieValue(t, a)})
			q := location(t, cb).Query()
			if c.ok {
				if q.Get("code") == "" {
					t.Fatalf("refused: %v", q)
				}
				return
			}
			if q.Get("error") != "login_required" || q.Get("code") != "" || q.Get("state") != p.req.GetState() {
				t.Errorf("redirect = %v", q)
			}
			if len(e.store.writes) != 0 || len(e.policy.requests()) != 0 {
				t.Error("something was decided or written for a stale authentication")
			}
			recs := e.records()
			if got := recs[len(recs)-1]["status_code"]; got != "fresh" {
				t.Errorf("status_code = %v", got)
			}
		})
	}
}
