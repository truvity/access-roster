package sessiond

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	configv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/config/v2alpha1"
	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/rpc"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// The routes of a passkey registration (0017 "Passkeys"; the flow is the design D4 of the pull request).
//
//  1. GET /passkeys/add?client_id=C (PasskeyAdd) sends the person to the upstream again, with prompt=login, and keeps a pending
//     sign-in that is marked as a registration. This is the fresh own factor of REQ-REG-052: a factor is added only after the
//     person has signed in again at the upstream, and no bearer token reaches the route.
//  2. GET /callback (Callback, enrolCallback) brings the person back. The authentication must be from this request, policy
//     must admit the person for the client, the person must exist and not be held. Then the browser gets the registration page
//     and a cookie that holds the sealed ceremony.
//  3. POST /passkeys/register (PasskeyRegister) takes the browser's answer, decides again, verifies it and stores the passkey.
//
// No route that writes a StaffPasskey reads Authorization (REQ-REG-051): the only inputs are the cookie and the form field.

// enrolment is what the callback hands to the ceremony so that the finish can decide again with the same facts.
type enrolment struct {
	clientID string
	assure   assurance
}

// bind puts the facts of an enrolment into the ceremony. A nil enrolment (the tests of the core) leaves it as it is.
func (e *enrolment) bind(c *sessionv2alpha1.PasskeyCeremony, tenant string) {
	if e == nil {
		return
	}
	c.ClientId, c.Tenant = e.clientID, tenant
	if e.assure.acr != nil {
		v := *e.assure.acr
		c.Acr = &v
	}
	c.Amr, c.AmrPresent = e.assure.amr, e.assure.amrPresent
	if e.assure.hasAuthTime {
		c.AuthTime = timestamppb.New(e.assure.authTime)
	}
}

// assuranceOfCeremony is the assurance the callback sealed into the ceremony.
func assuranceOfCeremony(c *sessionv2alpha1.PasskeyCeremony) assurance {
	a := assurance{amr: c.GetAmr(), amrPresent: c.GetAmrPresent()}
	if c.Acr != nil {
		v := c.GetAcr()
		a.acr = &v
	}
	if c.GetAuthTime() != nil {
		a.authTime, a.hasAuthTime = c.GetAuthTime().AsTime(), true
	}
	return a
}

// cookieOfCeremony is the sign-in cookie value of a sealed ceremony: "<id>.<base64url envelope>", as the pending sign-in's.
func cookieOfCeremony(sealed []byte) (string, bool) {
	id, env, ok := bytes.Cut(sealed, []byte("."))
	if !ok || len(id) != cookieIDLen {
		return "", false
	}
	return string(id) + "." + base64.RawURLEncoding.EncodeToString(env), true
}

// ceremonyOfCookie is the inverse of cookieOfCeremony. A value that is not of that form is not ours.
func ceremonyOfCookie(cookie string) ([]byte, bool) {
	id, enc, ok := strings.Cut(cookie, ".")
	if !ok || len(id) != cookieIDLen || store.ValidateID(id) != nil {
		return nil, false
	}
	env, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(env) == 0 {
		return nil, false
	}
	return append([]byte(id+"."), env...), true
}

// PasskeyAdd starts the registration of a passkey: it sends the browser to the upstream with prompt=login, so that the
// person authenticates again because of this request, and remembers it in the sign-in cookie. The client names the admission
// the registration is decided on; nothing is redirected to the client, so no redirect_uri is read.
func (s *Service) PasskeyAdd(ctx context.Context, req *connect.Request[sessionv2alpha1.PasskeyAddRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	r := req.Msg
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, unavailable("boundary", err)
	}
	tenant := b.GetDefaultTenant()
	page := func(reason, clientID string, declared bool) (*connect.Response[typev2alpha1.HttpReply], error) {
		named := ""
		if declared {
			named = clientID
		}
		logRefusal(actionPasskeyAdd, "invalid_request", reason, named)
		if aerr := s.record(ctx, audited{action: actionPasskeyAdd, tenant: tenant, subject: clientSubject(tenant, clientID), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return passkeyErrorPage(ctx), nil
	}
	if _, err := s.opts.Config.Passkeys(ctx); err != nil {
		if errors.Is(err, errPasskeysOff) {
			return page(reasonPasskeysOff, "unregistered", false)
		}
		return nil, unavailable("config", err)
	}
	cl, err := s.opts.Config.Client(ctx, r.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return page(reasonClient, "unregistered", false)
	case err != nil:
		return nil, unavailable("client", err)
	}
	if k := cl.GetKind(); k != kindPublic && k != kindConfidential {
		return page(reasonClient, cl.GetId(), true)
	}
	if tenant, err = tenantOf(b, cl); err != nil {
		return nil, internal("tenant", err)
	}
	up, err := s.opts.Config.Upstream(ctx, s.opts.UpstreamName)
	if err != nil {
		return nil, unavailable("upstream", err)
	}
	upState, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	upNonce, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	pid, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	now := s.now()
	begin, err := s.opts.Upstream.Begin(ctx, connect.NewRequest(&integrationv2alpha1.BeginRequest{
		Upstream: up.GetName(), RedirectUri: callbackURL(b.GetIssuer()), State: upState, Nonce: upNonce,
		CodeChallenge: s256(verifier), Prompt: "login",
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeUnavailable || connect.CodeOf(err) == connect.CodeDeadlineExceeded {
			return nil, unavailable("upstream", err)
		}
		return page(reasonUpstream, cl.GetId(), true)
	}
	pending := &sessionv2alpha1.PendingSignIn{
		ClientId: cl.GetId(), Tenant: tenant, Upstream: up.GetName(),
		UpstreamState: upState, UpstreamNonce: upNonce, UpstreamVerifier: verifier,
		CreatedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(pendingLife)), Prompt: "login", Enrol: true,
	}
	envelope, err := s.keys.sealFlow(ctx, pendingKind, pid, pending)
	if err != nil {
		return nil, unavailable("key", err)
	}
	cookie := pid + "." + base64.RawURLEncoding.EncodeToString(envelope)
	if aerr := s.record(ctx, audited{action: actionPasskeyAdd, tenant: tenant, subject: clientSubject(tenant, cl.GetId())}); aerr != nil {
		return nil, aerr
	}
	return redirect(begin.Msg.GetAuthorizationUrl(), setCookie(cookie, cookieMaxAge)), nil
}

// enrolCallback is the callback of a pending sign-in that began as a registration. The order is the sign-in's: the cookie and
// the state first, then the upstream's code, then what the registration needs of the authentication (from this request,
// REQ-REG-052), policy's decision, the person, the hold, and last the ceremony. Every refusal is the fixed page and clears the
// cookie; nothing is written for a refusal except the ceremony's user handle after all the checks passed.
func (s *Service) enrolCallback(ctx context.Context, r *sessionv2alpha1.CallbackRequest, pending *sessionv2alpha1.PendingSignIn, b *configv2alpha1.Boundary, now time.Time) (*connect.Response[typev2alpha1.HttpReply], error) {
	tenant := pending.GetTenant()
	page := func(reason string, pol *verdict) (*connect.Response[typev2alpha1.HttpReply], error) {
		logRefusal(actionPasskeyEnrol, "access_denied", reason, pending.GetClientId())
		a := audited{action: actionPasskeyEnrol, tenant: tenant, subject: clientSubject(tenant, pending.GetClientId()), reason: reason}
		if pol != nil {
			a.policy = pol.ref()
		}
		if aerr := s.record(ctx, a); aerr != nil {
			return nil, aerr
		}
		return passkeyErrorPage(ctx, clearCookie()), nil
	}
	if !equal(r.GetState(), pending.GetUpstreamState()) {
		return page(reasonState, nil)
	}
	if r.GetError() != "" {
		return page(reasonUpstream, nil)
	}
	if r.GetCode() == "" {
		return page(reasonRequest, nil)
	}
	if _, err := s.opts.Config.Passkeys(ctx); err != nil {
		if errors.Is(err, errPasskeysOff) {
			return page(reasonPasskeysOff, nil)
		}
		return nil, unavailable("config", err)
	}
	cl, err := s.opts.Config.Client(ctx, pending.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return page(reasonClient, nil)
	case err != nil:
		return nil, unavailable("client", err)
	}
	if k := cl.GetKind(); k != kindPublic && k != kindConfidential {
		return page(reasonClient, nil)
	}
	up, err := s.opts.Config.Upstream(ctx, pending.GetUpstream())
	if err != nil {
		return nil, unavailable("upstream", err)
	}
	done, err := s.opts.Upstream.Complete(ctx, connect.NewRequest(&integrationv2alpha1.CompleteRequest{
		Upstream: up.GetName(), Code: r.GetCode(), RedirectUri: callbackURL(b.GetIssuer()),
		CodeVerifier: pending.GetUpstreamVerifier(), Nonce: pending.GetUpstreamNonce(), Iss: r.GetIss(),
	}))
	if err != nil {
		switch connect.CodeOf(err) {
		case connect.CodeUnavailable, connect.CodeDeadlineExceeded:
			return nil, unavailable("upstream", err)
		}
		return page(reasonUpstream, nil)
	}
	assertion := done.Msg.GetAssertion()
	if assertion.GetSubject() == "" || assertion.GetIssuer() == "" || assertion.GetSubjectClaim() == "" {
		return nil, internal("assertion", errors.New("empty"))
	}
	assure := assuranceOf(assertion)
	account := up.GetName() + "/" + assertion.GetSubject()
	// A factor is added after a fresh authentication of the person, by the upstream, because of this request (REQ-REG-052).
	// An upstream that does not say when, or that answered from its single sign-on session, shows no fresh factor.
	if !assure.authenticatedSince(pending.GetCreatedAt().AsTime(), now, freshSkew) {
		return page(reasonFresh, nil)
	}
	candidate, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tenant, subject: candidate, accounts: []string{account}, state: stateLive,
		client: cl, assure: assure, now: now, verbs: []string{"create", "update"}, ops: []string{"seal", "open", "mac"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		return page(reasonDenied, &v)
	}
	// The person must exist: a passkey is added to someone who has signed in before. Nothing is made here.
	subject, _, err := s.linkPerson(ctx, tenant, candidate, assertion, v.grant, now, false)
	switch {
	case errors.Is(err, errNoPerson):
		return page(reasonNoPerson, &v)
	case errors.Is(err, errPinContradicted):
		return page(reasonPin, &v)
	case err != nil:
		return nil, err
	}
	options, sealed, err := s.registerBegin(ctx, tenant, subject, account, v.grant, &enrolment{clientID: cl.GetId(), assure: assure})
	switch {
	case errors.Is(err, errPasskeyHeld):
		return page(reasonHeld, &v)
	case errors.Is(err, errPasskeysOff):
		return page(reasonPasskeysOff, &v)
	case errors.Is(err, errPasskeyTaken):
		return page(reasonPasskey, &v)
	case err != nil:
		return nil, err
	}
	cookie, ok := cookieOfCeremony(sealed)
	if !ok || len(cookie) > maxCookie {
		return nil, internal("ceremony", errors.New("cookie"))
	}
	if aerr := s.record(ctx, audited{action: actionPasskeyEnrol, tenant: tenant, subject: personSubject(tenant, subject), policy: v.ref()}); aerr != nil {
		return nil, aerr
	}
	return passkeyRegisterPage(ctx, options, setCookie(cookie, int(ceremonyLife/time.Second))), nil
}

// PasskeyRegister takes the browser's answer to the registration page. The cookie holds the sealed ceremony; policy decides
// again, on the facts the callback sealed into it, because the grant of the first decision is gone; then the answer is verified
// and the passkey stored. The only inputs are the cookie and the one form field: the route reads no Authorization.
func (s *Service) PasskeyRegister(ctx context.Context, req *connect.Request[sessionv2alpha1.PasskeyRegisterRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	r := req.Msg
	now := s.now()
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, unavailable("boundary", err)
	}
	tenant := b.GetDefaultTenant()
	fail := func(reason string, subject *audit.Subject, pol *verdict) (*connect.Response[typev2alpha1.HttpReply], error) {
		logRefusal(actionPasskeyRegister, "access_denied", reason, "")
		a := audited{action: actionPasskeyRegister, tenant: tenant, subject: subject, reason: reason}
		if pol != nil {
			a.policy = pol.ref()
		}
		if aerr := s.record(ctx, a); aerr != nil {
			return nil, aerr
		}
		return passkeyErrorPage(ctx, clearCookie()), nil
	}
	sealed, ok := ceremonyOfCookie(r.GetCookie())
	if !ok {
		return fail(reasonCookie, nil, nil)
	}
	c, err := s.openCeremony(ctx, sealed, ceremonyRegister, now)
	switch {
	case errors.Is(err, errPasskeyExpired):
		return fail(reasonCookie, nil, nil)
	case err != nil:
		return nil, err
	}
	tenant = c.GetTenant()
	person := personSubject(tenant, c.GetSubject())
	if tenant == "" || c.GetClientId() == "" || c.GetSubject() == "" {
		return fail(reasonCookie, nil, nil)
	}
	if _, err := s.opts.Config.Passkeys(ctx); err != nil {
		if errors.Is(err, errPasskeysOff) {
			return fail(reasonPasskeysOff, person, nil)
		}
		return nil, unavailable("config", err)
	}
	cl, err := s.opts.Config.Client(ctx, c.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fail(reasonClient, person, nil)
	case err != nil:
		return nil, unavailable("client", err)
	}
	// The hold first: policy is asked about a person who is live (policy.md "Entity types"), and a held person is refused
	// whatever policy would say.
	switch err := s.passkeyNotHeld(ctx, tenant, c.GetSubject()); {
	case errors.Is(err, errPasskeyHeld):
		return fail(reasonHeld, person, nil)
	case err != nil:
		return nil, err
	}
	v, err := s.decide(ctx, question{
		tenant: tenant, subject: c.GetSubject(), accounts: []string{c.GetAccount()}, state: stateLive,
		client: cl, assure: assuranceOfCeremony(c), now: now, verbs: []string{"create", "update"}, ops: []string{"seal", "open", "mac"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		return fail(reasonDenied, person, &v)
	}
	rec, err := s.registerFinish(ctx, tenant, sealed, []byte(r.GetResponse()), v.grant)
	switch {
	case errors.Is(err, errPasskeyReplay):
		return fail(reasonReuse, person, &v)
	case errors.Is(err, errPasskeyHeld):
		return fail(reasonHeld, person, &v)
	case errors.Is(err, errPasskeyResponse), errors.Is(err, errPasskeyTaken), errors.Is(err, errPasskeyBadID), errors.Is(err, errPasskeyExpired):
		return fail(reasonPasskey, person, &v)
	case err != nil:
		return nil, err
	}
	sluis := map[string]any{"passkey_class": rec.GetClass(), "attestation_format": rec.GetAttestationFormat()}
	if aerr := s.record(ctx, audited{action: actionPasskeyRegister, tenant: tenant, subject: person, policy: v.ref(), sluis: sluis}); aerr != nil {
		return nil, aerr
	}
	return passkeyDonePage(ctx, rec.GetClass(), clearCookie()), nil
}

// passkeyScript is the one inline script of the registration page, byte for byte, and it holds no data: the options are in an
// attribute of the form. The Content-Security-Policy that entry sends with the page allows exactly this text by its SHA-256
// hash (actors/entry/src/pages.rs, PASSKEY_SCRIPT), and a test of this package compares the hash of what the page serves with
// the hash in that file. The page posts a form like any other (no fetch, so connect-src stays 'none'): the script only makes the
// credential and puts its JSON in the hidden field.
const passkeyScript = `(function(){var f=document.forms[0],m=document.getElementById("message");f.addEventListener("submit",function(e){e.preventDefault();if(!window.PublicKeyCredential||!PublicKeyCredential.parseCreationOptionsFromJSON){m.textContent="This browser cannot make a passkey.";return}var o;try{o=PublicKeyCredential.parseCreationOptionsFromJSON(JSON.parse(f.dataset.options))}catch(x){m.textContent="The passkey could not be started.";return}navigator.credentials.create({publicKey:o}).then(function(c){f.elements.response.value=JSON.stringify(c.toJSON());f.submit()},function(){m.textContent="The passkey was not made. You can try again."})})})();` //nolint:gosec // a script, not a credential

// pagePasskey is the page word of HttpReply.page for the registration page.
const pagePasskey = "passkey"

// passkeyRegisterPage is the registration page. The options are the JSON of PublicKeyCredentialCreationOptions in a data
// attribute (escaped, so it is text and not markup); the script is constant. It holds nothing else of the request.
func passkeyRegisterPage(ctx context.Context, options []byte, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Add a passkey</title></head>
<body data-sluis-page="passkey-register"><h1>Add a passkey</h1>
<p>Your browser will ask you to make a passkey. The private key stays on your device or in your password manager; sluis keeps only the public key.</p>
<form method="post" action="/passkeys/register" data-sluis-action="passkey-register" data-options="` + html.EscapeString(string(options)) + `">
<input type="hidden" name="response" value="">
<button type="submit">Add a passkey</button>
</form>
<p id="message" role="status"></p>
<noscript><p>Adding a passkey needs a browser that runs scripts.</p></noscript>
` + requestRef(ctx) + `<script>` + passkeyScript + `</script>
</body></html>
`)
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	out := reply(http.StatusOK, []byte(b.String()), append(hs, h...)...)
	out.Msg.Page = pagePasskey
	return out
}

// passkeyDonePage tells the person the passkey is added, and what kind it is. It has no script, so it has no page word.
func passkeyDonePage(ctx context.Context, class string, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	kind := "a device-bound passkey, such as a security key"
	if class == classSynced {
		kind = "a synced passkey, which your password manager or your phone keeps for you"
	}
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	return reply(http.StatusOK, []byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Passkey added</title></head>
<body data-sluis-page="passkey-done"><h1>Passkey added</h1>
<p>The passkey is added. It is `+kind+`.</p>
`+requestRef(ctx)+`</body></html>
`), append(hs, h...)...)
}

// passkeyErrorPage is the fixed page of a registration that cannot continue. It holds no value of the request.
func passkeyErrorPage(ctx context.Context, h ...*typev2alpha1.Header) *connect.Response[typev2alpha1.HttpReply] {
	hs := append([]*typev2alpha1.Header{header("Content-Type", "text/html; charset=utf-8")}, noStore()...)
	return reply(http.StatusBadRequest, []byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>The passkey could not be added</title></head>
<body data-sluis-page="passkey-error"><h1>The passkey could not be added</h1>
<p>The request was not valid, or it took too long. Start again from the page that sent you here.</p>
`+requestRef(ctx)+`</body></html>
`), append(hs, h...)...)
}

// requestRef is the line with the request identifier, or nothing when there is none (as errorPageHTML).
func requestRef(ctx context.Context) string {
	id := rpc.CorrelationID(ctx)
	if id == "" {
		return ""
	}
	return "<p>If you ask for help, give this reference: <code>" + html.EscapeString(id) + "</code></p>\n"
}
