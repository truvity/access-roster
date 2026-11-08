//go:build sluis_test

package sessiond_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/truvity/sluis/v2/actors/session/internal/sessiond"
	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	policyv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/policy/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/registry"
)

// ---- the flow of a registration, the way entry and a browser drive it -------------------------------------------------

// signedUp makes the person "alice" the way a first sign-in does, and returns the subject.
func (e *env) signedUp() string {
	e.t.Helper()
	e.signIn()
	ids := e.store.ids("person", testTenant)
	if len(ids) != 1 {
		e.t.Fatalf("persons %v", ids)
	}
	return ids[0]
}

func (e *env) passkeyAdd(clientID string) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.PasskeyAdd(context.Background(), connect.NewRequest(&sessionv2alpha1.PasskeyAddRequest{ClientId: clientID}))
	if err != nil {
		e.t.Fatalf("PasskeyAdd: %v", err)
	}
	return res.Msg
}

func (e *env) passkeyRegister(response, cookie string) *typev2alpha1.HttpReply {
	e.t.Helper()
	res, err := e.client.PasskeyRegister(context.Background(), connect.NewRequest(&sessionv2alpha1.PasskeyRegisterRequest{Response: response, Cookie: cookie}))
	if err != nil {
		e.t.Fatalf("PasskeyRegister: %v", err)
	}
	return res.Msg
}

// freshAssertion is what an upstream says of a person who has just authenticated because of the request.
func (e *env) freshAssertion() *integrationv2alpha1.Assertion {
	return &integrationv2alpha1.Assertion{
		Issuer: "https://idp.example.test/realms/test", SubjectClaim: "preferred_username", Subject: "alice",
		Amr: []string{"pwd", "otp", "mfa"}, AmrPresent: true, AuthTime: timestampOf(e.clk.now()),
	}
}

// enrolBack runs PasskeyAdd and returns what the browser brings back from the upstream.
func (e *env) enrolBack(clientID string) (*sessionv2alpha1.CallbackRequest, *typev2alpha1.HttpReply) {
	e.t.Helper()
	a := e.passkeyAdd(clientID)
	up := location(e.t, a)
	return &sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(e.t, a),
	}, a
}

var optionsAttr = regexp.MustCompile(`data-options="([^"]*)"`)

// registrationPage runs the registration up to the page, and returns the options in it, the cookie and the reply.
func (e *env) registrationPage() (options []byte, cookie string, page *typev2alpha1.HttpReply) {
	e.t.Helper()
	e.upstream.assertion = e.freshAssertion()
	cb, _ := e.enrolBack(testClient)
	page = e.callback(cb)
	if page.GetStatus() != http.StatusOK || page.GetPage() != "passkey" {
		e.t.Fatalf("callback: status %d page %q body %q", page.GetStatus(), page.GetPage(), page.GetBody())
	}
	m := optionsAttr.FindSubmatch(page.GetBody())
	if m == nil {
		e.t.Fatalf("no options in %q", page.GetBody())
	}
	return []byte(html.UnescapeString(string(m[1]))), cookieValue(e.t, page), page
}

// A registration, end to end: the person is sent to the upstream again, comes back to the page, makes a passkey and posts it.
//
// verifies: REQ-AUTHN-018, REQ-REG-052
func TestARegistrationRunsFromTheRequestToThePasskey(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	issued := len(e.store.ids("auth-code", testTenant))

	a := e.passkeyAdd(testClient)
	up := location(t, a)
	if len(e.upstream.begins) != 2 {
		t.Fatalf("%d upstream requests", len(e.upstream.begins))
	}
	if got := e.upstream.begins[1].GetPrompt(); got != "login" {
		t.Errorf("prompt = %q: the person must authenticate again", got)
	}
	if e.upstream.begins[1].GetAcrValues() != "" || e.upstream.begins[1].MaxAge != nil {
		t.Errorf("the upstream was asked for more than a fresh login")
	}
	if cookieValue(t, a) == "" {
		t.Fatal("no cookie")
	}
	cookieHeader := headerOf(a, "Set-Cookie")[0]
	for _, want := range []string{"Secure", "HttpOnly", "SameSite=Lax", "Path=/"} {
		if !strings.Contains(cookieHeader, want) {
			t.Errorf("cookie %q lacks %s", cookieHeader, want)
		}
	}

	e.upstream.assertion = e.freshAssertion()
	page := e.callback(&sessionv2alpha1.CallbackRequest{
		Code: "upstream-code-" + up.Query().Get("state")[:8], State: up.Query().Get("state"),
		Iss: "https://idp.example.test/realms/test", Cookie: cookieValue(t, a),
	})
	if page.GetStatus() != http.StatusOK || page.GetPage() != "passkey" {
		t.Fatalf("callback: status %d, page %q, body %q", page.GetStatus(), page.GetPage(), page.GetBody())
	}
	if n := len(e.store.ids("auth-code", testTenant)); n != issued {
		t.Errorf("%d new codes: a registration issues none", n-issued)
	}
	cookie := cookieValue(t, page)
	if cookie == "" || cookie == cookieValue(t, a) {
		t.Fatal("the callback did not replace the cookie with the ceremony's")
	}
	m := optionsAttr.FindSubmatch(page.GetBody())
	if m == nil {
		t.Fatalf("no options in %q", page.GetBody())
	}
	opts := []byte(html.UnescapeString(string(m[1])))
	k := newSoftKey(t, 32, false)
	k.origin = passkeyOrigin
	done := e.passkeyRegister(string(k.Create(opts)), cookie)
	if done.GetStatus() != http.StatusOK || !strings.Contains(string(done.GetBody()), "Passkey added") {
		t.Fatalf("register: status %d body %q", done.GetStatus(), done.GetBody())
	}
	if c := cookieValue(t, done); c != "" {
		t.Errorf("the cookie is not cleared: %q", c)
	}
	got := e.stored(subject)
	if len(got) != 1 || got[0].GetClass() != "hardware" || !slices.Equal(got[0].GetCredentialId(), k.id) {
		t.Fatalf("stored %v", got)
	}
	// The three steps are in the audit log, each once, in order, and no sign-in is: nothing was signed in.
	var codes []string
	for _, c := range e.eventCodes() {
		if strings.HasPrefix(c, "session.passkey_") {
			codes = append(codes, c)
		}
	}
	if !slices.Equal(codes, []string{"session.passkey_add", "session.passkey_enrol", "session.passkey_register"}) {
		t.Errorf("audit actions %v", codes)
	}
	if n := countOf(e.eventCodes(), "session.signin"); n != 1 {
		t.Errorf("%d session.signin records, want the one of the first sign-in", n)
	}
	// No record holds the cookie, the challenge or the credential.
	opt := parseOptions(t, opts)
	for _, rec := range e.transport.records() {
		for _, secret := range []string{cookie, opt.Challenge, b64(k.id), string(m[1])} {
			if strings.Contains(string(rec), secret) {
				t.Errorf("a record holds %.12q", secret)
			}
		}
	}
}

func countOf(l []string, s string) int {
	n := 0
	for _, x := range l {
		if x == s {
			n++
		}
	}
	return n
}

// The page is a fixed template with the options in an attribute: one script, which is the constant one, nothing of the request
// reflected, no handler in markup, and the form posts to the route of this origin.
//
// verifies: REQ-AUTHN-018
func TestTheRegistrationPageHoldsOneConstantScriptAndTheOptionsAsText(t *testing.T) {
	e := passkeyEnv(t)
	e.signedUp()
	opts, cookie, page := e.registrationPage()
	body := string(page.GetBody())
	scripts := scriptTag.FindAllString(body, -1)
	if len(scripts) != 1 {
		t.Fatalf("%d scripts in %q", len(scripts), body)
	}
	text := scriptBody.FindStringSubmatch(scripts[0])
	if text == nil || text[1] != sessiond.PasskeyScript {
		t.Fatalf("the script is not the constant: %q", scripts[0])
	}
	if strings.Contains(text[1], parseOptions(t, opts).Challenge) || strings.Contains(text[1], cookie) {
		t.Error("the script holds data")
	}
	if strings.Contains(body, cookie) {
		t.Error("the cookie is in the page")
	}
	for _, bad := range []string{" onclick=", " onload=", " onsubmit=", "<script src", "javascript:", "<iframe", "<img", "<link", "<style"} {
		if strings.Contains(strings.ToLower(body), bad) {
			t.Errorf("the page has %q", bad)
		}
	}
	if !strings.Contains(body, `action="/passkeys/register"`) || !strings.Contains(body, `method="post"`) {
		t.Errorf("the form does not post to /passkeys/register: %q", body)
	}
	// The options are text: no raw quote or angle bracket ends the attribute.
	m := optionsAttr.FindStringSubmatch(body)
	if m == nil || strings.ContainsAny(m[1], "<>") {
		t.Errorf("options attribute %q", m)
	}
	if ct := headerOf(page, "Content-Type"); len(ct) != 1 || !strings.HasPrefix(ct[0], "text/html") {
		t.Errorf("content type %v", ct)
	}
	if cc := headerOf(page, "Cache-Control"); len(cc) != 1 || cc[0] != "no-store" {
		t.Errorf("cache control %v", cc)
	}
	// A page that is not the registration page carries no page word: entry gives the relaxed policy to the word alone.
	e2 := passkeyEnv(t)
	if r := e2.passkeyAdd("no-such-client"); r.GetPage() != "" || r.GetStatus() != http.StatusBadRequest {
		t.Errorf("the error page: status %d page %q", r.GetStatus(), r.GetPage())
	}
}

// The hash that entry allows in the policy of the page is the hash of the script this page serves.
//
// verifies: REQ-AUTHN-018
func TestThePasskeyScriptIsTheOneEntryAllowsByHash(t *testing.T) {
	sum := sha256.Sum256([]byte(sessiond.PasskeyScript))
	served := base64.StdEncoding.EncodeToString(sum[:])
	src, err := os.ReadFile("../../../entry/src/pages.rs")
	if err != nil {
		t.Fatal(err)
	}
	all := entryScript.FindAllStringSubmatch(string(src), -1)
	if len(all) != 1 {
		t.Fatalf("entry's pages.rs holds %d script-src hashes, want 1", len(all))
	}
	if all[0][1] != served {
		t.Errorf("entry allows sha256-%s, the page serves a script with sha256-%s", all[0][1], served)
	}
}

// A factor is added only after a fresh authentication of the person at the upstream (REQ-REG-052): an upstream that answers from
// its single sign-on session, one that gives no time, or one that gives a time from the future is refused, and nothing is
// written or shown.
//
// verifies: REQ-REG-052
func TestARegistrationNeedsAnAuthenticationFromThisRequest(t *testing.T) {
	for name, mutate := range map[string]func(*integrationv2alpha1.Assertion, *env){
		"an old authentication": func(a *integrationv2alpha1.Assertion, e *env) { a.AuthTime = timestampOf(e.clk.now().Add(-time.Hour)) },
		"no auth_time":          func(a *integrationv2alpha1.Assertion, _ *env) { a.AuthTime = nil },
		"a time far ahead": func(a *integrationv2alpha1.Assertion, e *env) {
			a.AuthTime = timestampOf(e.clk.now().Add(2 * time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := passkeyEnv(t)
			e.signedUp()
			before := len(e.store.writes)
			a := e.freshAssertion()
			mutate(a, e)
			e.upstream.assertion = a
			cb, _ := e.enrolBack(testClient)
			r := e.callback(cb)
			if r.GetStatus() != http.StatusBadRequest || r.GetPage() != "" || strings.Contains(string(r.GetBody()), "data-options") {
				t.Fatalf("status %d body %q", r.GetStatus(), r.GetBody())
			}
			if c := headerOf(r, "Set-Cookie"); len(c) != 1 || !strings.Contains(c[0], "Max-Age=0") {
				t.Errorf("the cookie is not cleared: %v", c)
			}
			if len(e.store.writes) != before {
				t.Errorf("%d writes for a refused registration", len(e.store.writes)-before)
			}
			if !failedWith(e, "session.passkey_enrol", "fresh") {
				t.Errorf("no failed passkey_enrol record with the reason fresh: %v", e.records())
			}
		})
	}
}

// failedWith says whether a failed record of the action with the status code is in the log.
func failedWith(e *env, action, code string) bool {
	for _, rec := range e.records() {
		md, _ := rec["metadata"].(map[string]any)
		if md["event_code"] == action && rec["status_code"] == code {
			return true
		}
	}
	return false
}

// A held person is refused at the callback, and one who is held between the page and the answer is refused at the finish, and
// in both nothing is stored.
//
// verifies: REQ-SUBJ-043
func TestAHeldPersonAddsNoPasskey(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	e.store.putRaw("person-hold", testTenant, subject, []byte{1})
	e.upstream.assertion = e.freshAssertion()
	cb, _ := e.enrolBack(testClient)
	r := e.callback(cb)
	if r.GetStatus() != http.StatusBadRequest || r.GetPage() != "" {
		t.Fatalf("callback: status %d body %q", r.GetStatus(), r.GetBody())
	}
	if !failedWith(e, "session.passkey_enrol", "held") {
		t.Errorf("no held record: %v", e.records())
	}

	e2 := passkeyEnv(t)
	subject2 := e2.signedUp()
	opts, cookie, _ := e2.registrationPage()
	e2.store.putRaw("person-hold", testTenant, subject2, []byte{1})
	k := newSoftKey(t, 32, false)
	k.origin = passkeyOrigin
	asked := len(e2.policy.requests())
	done := e2.passkeyRegister(string(k.Create(opts)), cookie)
	// The hold is the first thing the finish checks: policy is not asked about a held person, and the challenge is not spent.
	if n := len(e2.policy.requests()) - asked; n != 0 {
		t.Errorf("policy was asked %d times about a held person", n)
	}
	if n := len(e2.store.ids("web-authn-challenge", "")); n != 0 {
		t.Errorf("%d challenges spent for a held person", n)
	}
	if done.GetStatus() != http.StatusBadRequest {
		t.Fatalf("register: status %d body %q", done.GetStatus(), done.GetBody())
	}
	if n := len(e2.stored(subject2)); n != 0 {
		t.Errorf("%d passkeys of a held person", n)
	}
	if !failedWith(e2, "session.passkey_register", "held") {
		t.Errorf("no held record: %v", e2.records())
	}
}

// Policy decides twice: at the callback, and again at the finish with the facts sealed into the ceremony. A denial at either
// stores nothing.
//
// verifies: REQ-REG-052
func TestPolicyDecidesAtTheCallbackAndAgainAtTheFinish(t *testing.T) {
	deny := func(*policyv2alpha1.DecideRequest) (*policyv2alpha1.DecideResponse, error) {
		return &policyv2alpha1.DecideResponse{
			Decision: policyv2alpha1.Decision_DENY, DecisionId: "d-deny", Digest: "digest-1",
			Reasons: []*policyv2alpha1.Reason{{PolicyId: "a-rule", Layer: "config"}},
		}, nil
	}
	t.Run("at the callback", func(t *testing.T) {
		e := passkeyEnv(t)
		e.signedUp()
		e.policy.decide = deny
		e.upstream.assertion = e.freshAssertion()
		cb, _ := e.enrolBack(testClient)
		r := e.callback(cb)
		if r.GetStatus() != http.StatusBadRequest || r.GetPage() != "" {
			t.Fatalf("status %d", r.GetStatus())
		}
		if !failedWith(e, "session.passkey_enrol", "denied") {
			t.Errorf("no denied record")
		}
	})
	t.Run("at the finish", func(t *testing.T) {
		e := passkeyEnv(t)
		subject := e.signedUp()
		opts, cookie, _ := e.registrationPage()
		before := len(e.policy.requests())
		e.policy.decide = deny
		k := newSoftKey(t, 32, false)
		k.origin = passkeyOrigin
		done := e.passkeyRegister(string(k.Create(opts)), cookie)
		if done.GetStatus() != http.StatusBadRequest {
			t.Fatalf("status %d", done.GetStatus())
		}
		if len(e.policy.requests()) != before+1 {
			t.Errorf("policy was asked %d times at the finish", len(e.policy.requests())-before)
		}
		if n := len(e.stored(subject)); n != 0 {
			t.Errorf("%d passkeys after a denial", n)
		}
		if !failedWith(e, "session.passkey_register", "denied") {
			t.Errorf("no denied record")
		}
	})
	t.Run("the second decision is about the same person, client and facts", func(t *testing.T) {
		e := passkeyEnv(t)
		subject := e.signedUp()
		opts, cookie, _ := e.registrationPage()
		k := newSoftKey(t, 32, false)
		k.origin = passkeyOrigin
		e.passkeyRegister(string(k.Create(opts)), cookie)
		reqs := e.policy.requests()
		first, last := reqs[len(reqs)-2], reqs[len(reqs)-1]
		if last.GetPrincipal().GetId() != subject || last.GetResource().GetId() != testClient || first.GetResource().GetId() != testClient {
			t.Errorf("principal %q resource %q", last.GetPrincipal().GetId(), last.GetResource().GetId())
		}
		if !slices.Equal(last.GetPerson().GetAccounts(), first.GetPerson().GetAccounts()) || last.GetPerson().GetState() != "live" {
			t.Errorf("accounts %v then %v, state %q", first.GetPerson().GetAccounts(), last.GetPerson().GetAccounts(), last.GetPerson().GetState())
		}
		if !slices.Equal(last.GetContext().GetAmr(), first.GetContext().GetAmr()) || last.GetContext().GetAcr() != first.GetContext().GetAcr() {
			t.Errorf("the facts of the authentication changed")
		}
		if !slices.Equal(last.GetGrantStoreVerbs(), []string{"create", "update"}) || !slices.Equal(last.GetGrantKeyOps(), []string{"seal", "open", "mac"}) {
			t.Errorf("the grant asked for %v %v", last.GetGrantStoreVerbs(), last.GetGrantKeyOps())
		}
	})
}

// Nothing is made for a stranger: an account with no person yet gets no Person, no link and no pin, and passkeys that are off
// answer before the upstream is asked.
//
// verifies: REQ-REG-052
func TestARegistrationMakesNoPersonAndNeedsConfiguration(t *testing.T) {
	e := passkeyEnv(t)
	e.upstream.assertion = e.freshAssertion()
	cb, _ := e.enrolBack(testClient)
	r := e.callback(cb)
	if r.GetStatus() != http.StatusBadRequest || r.GetPage() != "" {
		t.Fatalf("status %d", r.GetStatus())
	}
	if len(e.store.writes) != 0 {
		t.Errorf("%d writes for an account with no person", len(e.store.writes))
	}
	if !failedWith(e, "session.passkey_enrol", "no_person") {
		t.Errorf("no no_person record")
	}

	off := newEnv(t, nil)
	r = off.passkeyAdd(testClient)
	if r.GetStatus() != http.StatusBadRequest || len(off.upstream.begins) != 0 {
		t.Errorf("passkeys off: status %d, %d upstream requests", r.GetStatus(), len(off.upstream.begins))
	}
	if !failedWith(off, "session.passkey_add", "passkeys_off") {
		t.Errorf("no passkeys_off record")
	}
}

// The client must be one the installation declares and that signs people in.
//
// verifies: REQ-REG-052
func TestARegistrationNamesAClientThatSignsPeopleIn(t *testing.T) {
	e := newEnv(t, func(o *options) {
		o.extra = []*configv2alpha1.InstallationClient{{Id: "xchg", Kind: "exchange"}}
	})
	putPasskeyConfig(e, []string{passkeyOrigin})
	for _, id := range []string{"", "no-such-client", "xchg"} {
		r := e.passkeyAdd(id)
		if r.GetStatus() != http.StatusBadRequest || len(e.upstream.begins) != 0 {
			t.Errorf("client %q: status %d, %d upstream requests", id, r.GetStatus(), len(e.upstream.begins))
		}
	}
	// The unknown id is not in the record: the client of a stranger's request is nobody's.
	for _, rec := range e.transport.records() {
		if strings.Contains(string(rec), "no-such-client") {
			t.Errorf("the record holds an unregistered client id: %s", rec)
		}
	}
}

// The cookie is the only thing the finish believes, and it is checked first. A missing, damaged or foreign cookie, a
// sign-in cookie (another kind), and an expired ceremony are the fixed page; nothing is stored.
//
// verifies: REQ-REG-052
func TestTheFinishBelievesOnlyACeremonyCookie(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	opts, cookie, _ := e.registrationPage()
	k := newSoftKey(t, 32, false)
	k.origin = passkeyOrigin
	response := string(k.Create(opts))

	signIn := e.passkeyAdd(testClient) // a pending sign-in, sealed under the same key
	pending := cookieValue(t, signIn)
	flip := []byte(cookie)
	flip[len(flip)-3] ^= 1
	for name, c := range map[string]string{
		"none": "", "garbage": "x.y", "a sign-in cookie": pending, "a flipped byte": string(flip),
		"the id alone": strings.SplitN(cookie, ".", 2)[0], "an empty envelope": strings.SplitN(cookie, ".", 2)[0] + ".",
	} {
		r := e.passkeyRegister(response, c)
		if r.GetStatus() != http.StatusBadRequest || strings.Contains(string(r.GetBody()), "Passkey added") {
			t.Errorf("%s: status %d", name, r.GetStatus())
		}
	}
	if n := len(e.stored(subject)); n != 0 {
		t.Fatalf("%d passkeys after refused cookies", n)
	}
	// A ceremony cookie is not a sign-in cookie: the callback does not take it.
	e.upstream.assertion = e.freshAssertion()
	cb := &sessionv2alpha1.CallbackRequest{Code: "upstream-code-xxxxxxxx", State: "s", Iss: "https://idp.example.test/realms/test", Cookie: cookie}
	if r := e.callback(cb); r.GetStatus() != http.StatusBadRequest {
		t.Errorf("the callback took a ceremony cookie: status %d", r.GetStatus())
	}
	// Time passes: the ceremony ends.
	e.clk.advance(6 * time.Minute)
	if r := e.passkeyRegister(response, cookie); r.GetStatus() != http.StatusBadRequest {
		t.Errorf("an expired ceremony: status %d", r.GetStatus())
	}
	if n := len(e.stored(subject)); n != 0 {
		t.Errorf("%d passkeys after an expired ceremony", n)
	}
}

// A response works once, and so does a credential: the same answer posted twice stores one passkey, and the second is a replay.
//
// verifies: REQ-AUTHN-051
func TestTheAnswerOfARegistrationWorksOnce(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	opts, cookie, _ := e.registrationPage()
	k := newSoftKey(t, 32, false)
	k.origin = passkeyOrigin
	response := string(k.Create(opts))
	if r := e.passkeyRegister(response, cookie); r.GetStatus() != http.StatusOK {
		t.Fatalf("first: status %d", r.GetStatus())
	}
	if r := e.passkeyRegister(response, cookie); r.GetStatus() != http.StatusBadRequest {
		t.Errorf("second: status %d", r.GetStatus())
	}
	if n := len(e.stored(subject)); n != 1 {
		t.Errorf("%d passkeys", n)
	}
	if !failedWith(e, "session.passkey_register", "reuse") {
		t.Errorf("no reuse record: %v", e.records())
	}
}

// An answer that is not a registration of this ceremony is refused with the fixed page and stored nothing: the wrong origin, a
// response that is not JSON, and an oversized one.
//
// verifies: REQ-AUTHN-050
func TestAnAnswerThatIsNotThisRegistrationStoresNothing(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	for name, build := range map[string]func(opts []byte, k *softKey) string{
		"a wrong origin": func(opts []byte, k *softKey) string { k.origin = "https://evil.example"; return string(k.Create(opts)) },
		"not json":       func([]byte, *softKey) string { return "not json" },
		"empty":          func([]byte, *softKey) string { return "" },
		"oversized":      func([]byte, *softKey) string { return strings.Repeat("a", 9000) },
	} {
		t.Run(name, func(t *testing.T) {
			opts, cookie, _ := e.registrationPage()
			k := newSoftKey(t, 32, false)
			k.origin = passkeyOrigin
			r := e.passkeyRegister(build(opts, k), cookie)
			if r.GetStatus() != http.StatusBadRequest || strings.Contains(string(r.GetBody()), "Passkey added") {
				t.Errorf("status %d", r.GetStatus())
			}
			if n := len(e.stored(subject)); n != 0 {
				t.Errorf("%d passkeys", n)
			}
		})
	}
}

// ---- REQ-REG-051: no token adds, changes or removes a factor ------------------------------------------------------------

// factorKinds are the kinds that hold a factor of a person: the kind of the passkey.
var factorKinds = []string{"staff-passkey"}

func factorWrites(e *env) int {
	n := 0
	for _, ops := range e.store.writes {
		for _, op := range ops {
			if slices.Contains(factorKinds, op.GetAddress().GetKind()) {
				n++
			}
		}
	}
	return n
}

// A relying-party access token, a refresh token, an exchanged token and an id_token_hint reach every route that takes one, and
// none of them adds, changes or removes a factor: the scan runs each of the routes with a valid token and counts the writes of
// the kinds that hold a factor. The two routes that add a factor take no token at all.
//
// verifies: REQ-REG-051
func TestNoTokenAddsChangesOrRemovesAFactor(t *testing.T) {
	e := passkeyEnv(t)
	subject := e.signedUp()
	code, p := e.signIn()
	tok := e.token(&sessionv2alpha1.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectUri: testRedirect, CodeVerifier: p.verifier, ClientId: testClient,
	})
	if tok.GetStatus() != http.StatusOK {
		t.Fatalf("token: %d %s", tok.GetStatus(), tok.GetBody())
	}
	fields := jsonFields(t, tok.GetBody())
	access, refresh, idToken := fields["access_token"], fields["refresh_token"], fields["id_token"]
	if access == "" || refresh == "" || idToken == "" {
		t.Fatalf("token response %s", tok.GetBody())
	}
	bearer := "Bearer " + access
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"userinfo": func() error {
			_, err := e.client.UserInfo(ctx, connect.NewRequest(&sessionv2alpha1.UserInfoRequest{Authorization: bearer}))
			return err
		},
		"refresh": func() error {
			_, err := e.client.Token(ctx, connect.NewRequest(&sessionv2alpha1.TokenRequest{GrantType: "refresh_token", RefreshToken: refresh, ClientId: testClient}))
			return err
		},
		"authorize with the id_token_hint": func() error {
			r := newAuthorize().req
			r.IdTokenHint = idToken
			_, err := e.client.Authorize(ctx, connect.NewRequest(r))
			return err
		},
		"the access token as the cookie of the finish": func() error {
			_, err := e.client.PasskeyRegister(ctx, connect.NewRequest(&sessionv2alpha1.PasskeyRegisterRequest{Response: "{}", Cookie: access}))
			return err
		},
		"the refresh token as the cookie of the finish": func() error {
			_, err := e.client.PasskeyRegister(ctx, connect.NewRequest(&sessionv2alpha1.PasskeyRegisterRequest{Response: "{}", Cookie: refresh}))
			return err
		},
		"the id token as the cookie of the callback": func() error {
			_, err := e.client.Callback(ctx, connect.NewRequest(&sessionv2alpha1.CallbackRequest{Code: "c", State: "s", Cookie: idToken}))
			return err
		},
		"revoke": func() error {
			_, err := e.client.Revoke(ctx, connect.NewRequest(&sessionv2alpha1.RevokeRequest{Token: refresh, ClientId: testClient}))
			return err
		},
	} {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if n := factorWrites(e); n != 0 {
		t.Errorf("%d writes of a factor kind by routes that take a token", n)
	}
	if n := len(e.stored(subject)); n != 0 {
		t.Errorf("%d passkeys", n)
	}
}

func jsonFields(t *testing.T, body []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"access_token", "refresh_token", "id_token"} {
		m := regexp.MustCompile(`"` + name + `"\s*:\s*"([^"]+)"`).FindSubmatch(body)
		if m != nil {
			out[name] = string(m[1])
		}
	}
	return out
}

// The routes that add a factor read no token and no client credential: the fields of their requests are the client's id (which
// names an admission, and is no secret) and the browser's answer and cookie. And a factor is written by one actor and one
// route: the registry gives the kind to session alone, and the only function that stores a passkey is called by the finish.
//
// verifies: REQ-REG-051
func TestTheRoutesThatAddAFactorTakeNoCredential(t *testing.T) {
	svc := sessionv2alpha1.File_sluis_session_v2alpha1_session_proto.Services().ByName("SessionService")
	allowed := map[string][]string{
		"PasskeyAdd":      {"client_id"},
		"PasskeyRegister": {"response", "cookie"},
	}
	for name, want := range allowed {
		m := svc.Methods().ByName(protoreflect.Name(name))
		if m == nil {
			t.Fatalf("no method %s", name)
		}
		var got []string
		for i := 0; i < m.Input().Fields().Len(); i++ {
			got = append(got, string(m.Input().Fields().Get(i).Name()))
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s takes %v, want %v", name, got, want)
		}
	}
	// No other method takes a field that could carry the cookie of the finish: the names that carry a credential are the
	// ones of the token routes, and the scan names them so a new method with one must be looked at.
	creds := map[string]bool{"authorization": true, "token": true, "refresh_token": true, "client_secret": true, "id_token_hint": true, "code": true}
	var withCreds []string
	for i := 0; i < svc.Methods().Len(); i++ {
		m := svc.Methods().Get(i)
		for j := 0; j < m.Input().Fields().Len(); j++ {
			if creds[string(m.Input().Fields().Get(j).Name())] {
				withCreds = append(withCreds, string(m.Name()))
				break
			}
		}
	}
	slices.Sort(withCreds)
	if want := []string{"Authorize", "Callback", "Revoke", "Token", "UserInfo"}; !slices.Equal(withCreds, want) {
		t.Errorf("methods that take a credential: %v, want %v: look at whether the new one can add a factor", withCreds, want)
	}
	for _, kind := range factorKinds {
		for _, a := range registry.Actors() {
			if registry.IsWriter(a.Name, kind) != (a.Name == "session") {
				t.Errorf("%s writes %s: %v", a.Name, kind, registry.IsWriter(a.Name, kind))
			}
		}
	}
}

// The callback of a registration believes the state it sealed and the upstream's own answer, and nothing else: another state, an
// error from the upstream and no code are the fixed page, and the upstream is not asked for a code it was not given.
//
// verifies: REQ-REG-052
func TestTheCallbackOfARegistrationKeepsTheRulesOfTheSignIn(t *testing.T) {
	for name, tweak := range map[string]struct {
		change func(*sessionv2alpha1.CallbackRequest)
		reason string
	}{
		"another state":     {func(r *sessionv2alpha1.CallbackRequest) { r.State = "another-state" }, "state"},
		"an upstream error": {func(r *sessionv2alpha1.CallbackRequest) { r.Error, r.Code = "access_denied", "" }, "upstream"},
		"no code":           {func(r *sessionv2alpha1.CallbackRequest) { r.Code = "" }, "request"},
		"no cookie":         {func(r *sessionv2alpha1.CallbackRequest) { r.Cookie = "" }, "cookie"},
	} {
		t.Run(name, func(t *testing.T) {
			e := passkeyEnv(t)
			e.signedUp()
			e.upstream.assertion = e.freshAssertion()
			cb, _ := e.enrolBack(testClient)
			tweak.change(cb)
			completes := len(e.upstream.completes)
			before := len(e.store.writes)
			r := e.callback(cb)
			if r.GetStatus() != http.StatusBadRequest || r.GetPage() != "" || strings.Contains(string(r.GetBody()), "data-options") {
				t.Fatalf("status %d body %q", r.GetStatus(), r.GetBody())
			}
			if len(e.upstream.completes) != completes || len(e.store.writes) != before {
				t.Errorf("the upstream was asked or something was written for a refused callback")
			}
			if tweak.reason != "cookie" && !failedWith(e, "session.passkey_enrol", tweak.reason) {
				t.Errorf("no %s record: %v", tweak.reason, e.records())
			}
		})
	}
}
