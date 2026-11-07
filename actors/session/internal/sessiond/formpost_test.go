//go:build sluis_test

package sessiond_test

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
)

var (
	formAction  = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	formInput   = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	scriptTag   = regexp.MustCompile(`(?s)<script[ >].*?</script>`)
	scriptBody  = regexp.MustCompile(`(?s)^<script>(.*)</script>$`)
	entryScript = regexp.MustCompile(`script-src 'sha256-([A-Za-z0-9+/=]+)'`)
)

// posted is what a browser would send: the form's action, and its hidden fields after the page's HTML was unescaped.
type posted struct {
	action string
	fields map[string]string
	names  []string
}

// readForm parses the form_post page, strictly: one form, the fields in the shape the page writes them, and nothing
// else in the body that is a script, a link or an image.
func readForm(t *testing.T, r *typev2alpha1.HttpReply) posted {
	t.Helper()
	page := string(r.GetBody())
	a := formAction.FindAllStringSubmatch(page, -1)
	if len(a) != 1 || strings.Count(page, "<form") != 1 {
		t.Fatalf("the page does not hold exactly one form: %q", page)
	}
	p := posted{action: html.UnescapeString(a[0][1]), fields: map[string]string{}}
	for _, m := range formInput.FindAllStringSubmatch(page, -1) {
		name, value := html.UnescapeString(m[1]), html.UnescapeString(m[2])
		if _, dup := p.fields[name]; dup {
			t.Errorf("the field %q is posted twice", name)
		}
		p.fields[name] = value
		p.names = append(p.names, name)
	}
	if strings.Count(page, "<input") != len(p.names) {
		t.Errorf("an input of the page is not a hidden field in the page's shape: %q", page)
	}
	for _, bad := range []string{"<a ", "<img", "<link", "<iframe", "<object", "<embed", "<base", "<meta http-equiv", "javascript:"} {
		if strings.Contains(page, bad) {
			t.Errorf("the page holds %q: %q", bad, page)
		}
	}
	return p
}

// A client that asks for form_post gets the code in an auto-submitting form, not in a redirect: the answer is a 200
// page, nothing is in the URL, the form posts to the registered redirect_uri alone, and the code in it is the real one.
//
// verifies: REQ-AUTHN-058
func TestFormPostAnswersTheCodeAsAForm(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.ResponseMode = "form_post"
	a := e.authorize(p.req)
	up := location(t, a) // the person goes to the upstream first, as for the query mode
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(t, a),
	})

	if cb.GetStatus() != http.StatusOK {
		t.Fatalf("status %d, want 200 (a form, not a redirect)", cb.GetStatus())
	}
	if got := headerOf(cb, "Location"); len(got) != 0 {
		t.Fatalf("the answer redirects: %v", got)
	}
	if ct := headerOf(cb, "Content-Type"); len(ct) != 1 || ct[0] != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %v", ct)
	}
	if cc := headerOf(cb, "Cache-Control"); len(cc) != 1 || cc[0] != "no-store" {
		t.Errorf("Cache-Control = %v", cc)
	}
	if pr := headerOf(cb, "Pragma"); len(pr) != 1 || pr[0] != "no-cache" {
		t.Errorf("Pragma = %v", pr)
	}
	if set := headerOf(cb, "Set-Cookie"); len(set) != 1 || !strings.Contains(set[0], "Max-Age=0") {
		t.Errorf("the sign-in cookie is not spent: %v", set)
	}
	if cb.GetFormPostOrigin() != "http://127.0.0.1:43210" {
		t.Errorf("form_post_origin = %q, want the scheme, host and port of %s", cb.GetFormPostOrigin(), testRedirect)
	}

	f := readForm(t, cb)
	if f.action != testRedirect {
		t.Errorf("the form posts to %q, want the registered %q", f.action, testRedirect)
	}
	if strings.Join(f.names, ",") != "code,iss,state" {
		t.Errorf("fields = %v, want code, iss and state in this order", f.names)
	}
	if f.fields["state"] != p.req.GetState() || f.fields["iss"] != testIssuer {
		t.Errorf("state %q and iss %q, want the client's state and the issuer (RFC 9207)", f.fields["state"], f.fields["iss"])
	}
	// The code is the one that the token endpoint takes, and it is nowhere else in the answer.
	code := f.fields["code"]
	if len(code) < 43 {
		t.Fatalf("code %q is short", code)
	}
	if strings.Contains(strings.Join(append(headerOf(cb, "Location"), headerOf(cb, "Set-Cookie")...), " "), code) {
		t.Error("the code is in a header")
	}
	if strings.Count(string(cb.GetBody()), code) != 1 {
		t.Error("the code is in the page more than once")
	}
	if r := e.token(codeRequest(code, p)); r.GetStatus() != http.StatusOK {
		t.Fatalf("the code of the form was refused by /token: %d %s", r.GetStatus(), r.GetBody())
	}

	// The same request in the query mode is unchanged: a redirect with the code in the URL, and no origin.
	q := newAuthorize()
	q.req.ResponseMode = "query"
	qa := e.authorize(q.req)
	qu := location(t, qa)
	qcb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + qu.Query().Get("state")[:8], State: qu.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(t, qa),
	})
	if location(t, qcb).Query().Get("code") == "" || qcb.GetFormPostOrigin() != "" || len(qcb.GetBody()) != 0 {
		t.Errorf("the query mode changed: %d %q origin %q", qcb.GetStatus(), qcb.GetBody(), qcb.GetFormPostOrigin())
	}
}

// An error goes to the client in the mode it asked for. The form carries error and error_description, the state and iss,
// and no code, from each place that answers the client: session at /authorize, and the callback when the person or the
// upstream refuses.
//
// verifies: REQ-AUTHN-058
func TestFormPostAnswersAnErrorAsAForm(t *testing.T) {
	check := func(t *testing.T, r *typev2alpha1.HttpReply, want, state string) {
		t.Helper()
		if r.GetStatus() != http.StatusOK || len(headerOf(r, "Location")) != 0 {
			t.Fatalf("the answer is %d with Location %v, want a form", r.GetStatus(), headerOf(r, "Location"))
		}
		f := readForm(t, r)
		if f.fields["error"] != want || f.fields["iss"] != testIssuer || f.fields["state"] != state {
			t.Errorf("fields = %v, want error %s, the issuer and the state %q", f.fields, want, state)
		}
		if _, ok := f.fields["code"]; ok {
			t.Error("an error carries a code")
		}
		if f.action != testRedirect || r.GetFormPostOrigin() != "http://127.0.0.1:43210" {
			t.Errorf("action %q, origin %q", f.action, r.GetFormPostOrigin())
		}
	}
	t.Run("authorize", func(t *testing.T) {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.ResponseMode, p.req.Scope = "form_post", "profile"
		check(t, e.authorize(p.req), "invalid_scope", p.req.GetState())
		if len(e.upstream.begins) != 0 {
			t.Error("a refused request started a sign-in")
		}
	})
	t.Run("a response type that is not served", func(t *testing.T) {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.ResponseMode, p.req.ResponseType = "form_post", "id_token"
		check(t, e.authorize(p.req), "unsupported_response_type", p.req.GetState())
	})
	t.Run("the person refuses at the upstream", func(t *testing.T) {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.ResponseMode = "form_post"
		a := e.authorize(p.req)
		up := location(t, a)
		cb := e.callback(&sessionv2alpha1.CallbackRequest{
			State: up.Query().Get("state"), Error: "access_denied", ErrorDescription: "<script>alert(1)</script>", Cookie: cookieValue(t, a),
		})
		check(t, cb, "access_denied", p.req.GetState())
		if strings.Contains(string(cb.GetBody()), "alert(1)") {
			t.Error("the upstream's text was repeated")
		}
	})
	t.Run("a mode that is not served is refused in the query", func(t *testing.T) {
		e := newEnv(t, nil)
		p := newAuthorize()
		p.req.ResponseMode = "form_post.jwt"
		if q := location(t, e.authorize(p.req)).Query(); q.Get("error") != "invalid_request" {
			t.Errorf("error = %q", q.Get("error"))
		}
	})
}

// Everything in the form comes from outside and is escaped: the client's state, the registered redirect_uri with a query
// that holds markup and quotes, and the fields. The page has one script, and it is the one the policy hashes.
//
// verifies: REQ-AUTHN-058, REQ-AUTHN-059
func TestFormPostEscapesWhatItCarriesAndHoldsOneScript(t *testing.T) {
	const redirect = `https://app.example.test:8443/cb?a=1&b=<x>"y'`
	e := newEnv(t, nil)
	e.store.put("installation-client", "", testClient, &configv2alpha1.InstallationClient{
		Id: testClient, Kind: "public", Redirects: []string{redirect}, Requires: []string{testGroup},
	})
	state := `"><script>alert(1)</script>&amp;'`
	p := newAuthorize()
	p.req.ResponseMode, p.req.RedirectUri, p.req.State = "form_post", redirect, state
	a := e.authorize(p.req)
	up := location(t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(t, a),
	})
	if cb.GetStatus() != http.StatusOK {
		t.Fatalf("status %d: %s", cb.GetStatus(), cb.GetBody())
	}
	page := string(cb.GetBody())
	f := readForm(t, cb)
	if f.action != redirect || f.fields["state"] != state {
		t.Errorf("action %q, state %q: the values did not survive the escaping", f.action, f.fields["state"])
	}
	if cb.GetFormPostOrigin() != "https://app.example.test:8443" {
		t.Errorf("form_post_origin = %q", cb.GetFormPostOrigin())
	}
	// Raw markup of the request is nowhere in the page; the redirect_uri is only in the action.
	for _, raw := range []string{`<script>alert`, `"><script`, `<x>`, `b=<`, `&amp;'`, state} {
		if strings.Contains(page, raw) {
			t.Errorf("the page holds %q unescaped:\n%s", raw, page)
		}
	}
	if n := strings.Count(page, "app.example.test"); n != 1 {
		t.Errorf("the redirect_uri is in the page %d times, want once, as the action", n)
	}
	// One script element, with the text the policy hashes.
	scripts := scriptTag.FindAllString(page, -1)
	if len(scripts) != 1 || strings.Count(page, "<script") != 1 {
		t.Fatalf("the page holds %d scripts: %q", len(scripts), scripts)
	}
	text := scriptBody.FindStringSubmatch(scripts[0])
	if text == nil {
		t.Fatalf("the script has attributes: %q", scripts[0])
	}
	if text[1] != "document.forms[0].submit();" {
		t.Errorf("script = %q", text[1])
	}
	if len(headerOf(cb, "Content-Security-Policy")) != 0 {
		t.Error("session set a Content-Security-Policy; entry does, per response")
	}
}

// The hash that entry allows in the page's policy is the hash of the script this page serves: the two packages are in
// step, or a browser would refuse the script and the page would never post.
//
// verifies: REQ-AUTHN-059
func TestFormPostScriptIsTheOneEntryAllowsByHash(t *testing.T) {
	e := newEnv(t, nil)
	p := newAuthorize()
	p.req.ResponseMode = "form_post"
	a := e.authorize(p.req)
	up := location(t, a)
	cb := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(t, a),
	})
	text := scriptBody.FindStringSubmatch(scriptTag.FindString(string(cb.GetBody())))
	if text == nil {
		t.Fatalf("no script in %q", cb.GetBody())
	}
	sum := sha256.Sum256([]byte(text[1]))
	served := base64.StdEncoding.EncodeToString(sum[:])
	src, err := os.ReadFile("../../../entry/src/headers.rs")
	if err != nil {
		t.Fatal(err)
	}
	all := entryScript.FindAllStringSubmatch(string(src), -1)
	if len(all) != 1 {
		t.Fatalf("entry's headers.rs holds %d script-src hashes, want 1", len(all))
	}
	if all[0][1] != served {
		t.Errorf("entry allows sha256-%s, the page serves a script with sha256-%s", all[0][1], served)
	}
}
