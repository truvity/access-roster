package sessiond

import (
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	integrationv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/integration/v2alpha1"
	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// A sign-in cookie is "<id>.<base64url envelope>". The id is the 26 characters randomID makes.
const cookieIDLen = 26

// Callback finishes a sign-in: the browser returns from the upstream with a code and the state session sent.
//
// The order matters (RFC 6749 section 10.12): the sign-in cookie must open, and the state must be the one sealed in
// it, before anything else is believed, so a callback that did not start in this browser is refused with the fixed
// page and neither the upstream nor the client hears of it. Then the upstream's code is exchanged through the
// adapter, which verifies the ID token and leaves the state check to session. The person is found or made by the
// upstream's subject claim and never by e-mail (0019). Policy decides whether this person may sign in to this
// client, and only then is anything written: nothing is created for a refused sign-in (0019 "Assigning a subject").
func (s *Service) Callback(ctx context.Context, req *connect.Request[sessionv2alpha1.CallbackRequest]) (*connect.Response[typev2alpha1.HttpReply], error) {
	r := req.Msg
	now := s.now()
	b, err := s.opts.Config.Boundary(ctx)
	if err != nil {
		return nil, unavailable("boundary", err)
	}
	tenant := b.GetDefaultTenant()
	// Whatever happens, this cookie is spent: it is cleared on every answer, so a second callback with it finds none.
	page := func(reason string) (*connect.Response[typev2alpha1.HttpReply], error) {
		if aerr := s.record(ctx, audited{action: actionSignin, tenant: tenant, subject: clientSubject(tenant, "unknown"), reason: reason}); aerr != nil {
			return nil, aerr
		}
		return errorPage(clearCookie()), nil
	}

	pending, err := s.openPending(ctx, r.GetCookie(), now)
	switch {
	case errors.Is(err, errNotOurs):
		return page(reasonCookie)
	case err != nil:
		return nil, unavailable("key", err)
	}
	tenant = pending.GetTenant()
	if !equal(r.GetState(), pending.GetUpstreamState()) {
		return page(reasonState)
	}

	// The cookie and the state are ours, so the redirect_uri inside is the one the client registered at authorize. The
	// client may have been changed since; if its declaration no longer allows the redirect, the page is shown.
	cl, err := s.opts.Config.Client(ctx, pending.GetClientId())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return page(reasonClient)
	case err != nil:
		return nil, unavailable("client", err)
	}
	if cl.GetKind() != "public" || !redirectRegistered(cl.GetRedirects(), pending.GetRedirectUri()) {
		return page(reasonRedirectURI)
	}
	subjectOfClient := clientSubject(tenant, cl.GetId())
	deny := func(code, desc, reason string, pol *verdict) (*connect.Response[typev2alpha1.HttpReply], error) {
		out, rerr := clientRedirect(pending.GetRedirectUri(), pending.GetState(), b.GetIssuer(), url.Values{"error": {code}, "error_description": {desc}}, clearCookie())
		if rerr != nil {
			return nil, internal("redirect", rerr)
		}
		a := audited{action: actionSignin, tenant: tenant, subject: subjectOfClient, reason: reason}
		if pol != nil {
			a.policy = pol.ref()
		}
		if aerr := s.record(ctx, a); aerr != nil {
			return nil, aerr
		}
		return out, nil
	}
	// The upstream says the sign-in failed or the person refused (RFC 6749 section 4.1.2.1): pass the refusal on.
	if r.GetError() != "" {
		return deny(upstreamErrorCode(r.GetError()), "the upstream did not sign the person in", reasonUpstream, nil)
	}
	if r.GetCode() == "" {
		return deny("invalid_request", "the upstream sent no code", reasonRequest, nil)
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
		return deny("access_denied", "the upstream did not sign the person in", reasonUpstream, nil)
	}
	assertion := done.Msg.GetAssertion()
	if assertion.GetSubject() == "" || assertion.GetIssuer() == "" || assertion.GetSubjectClaim() == "" {
		return nil, internal("assertion", errors.New("empty"))
	}
	assure := assuranceOf(assertion)
	account := up.GetName() + "/" + assertion.GetSubject()

	// max_age (OpenID Connect Core section 3.1.2.1): the authentication must be no older than the client asked, and the
	// upstream must say when it happened; an upstream that sends no auth_time cannot show it, so it is refused. This
	// is also what makes auth_time reach the ID token whenever a client asked for max_age.
	if m := pending.MaxAge; m != nil {
		if age, ok := assure.authAge(now); !ok || age > *m {
			return deny("login_required", "a fresher authentication is needed", reasonMaxAge, nil)
		}
	}

	// The decision is the sign-in's admission: may a person with this account have a token for this client, with how
	// they just authenticated. Its grant (about a minute) lets session open the link and write what follows. The
	// subject is the candidate: the person's own when the link exists, the one a new person will get when it does not.
	// Policy decides on the account and the client, so the answer is the same for either, but the record of this
	// decision names the candidate; the token endpoint decides again with the person's own subject.
	candidate, err := randomID()
	if err != nil {
		return nil, internal("random", err)
	}
	v, err := s.decide(ctx, question{
		tenant: tenant, subject: candidate, accounts: []string{account}, state: stateLive,
		client: cl, assure: assure, now: now, verbs: []string{"create"}, ops: []string{"seal", "open"},
	})
	if err != nil {
		return nil, unavailable("policy", err)
	}
	if !v.allow {
		return deny("access_denied", "the person may not sign in to this client", reasonDenied, &v)
	}

	subject, created, err := s.linkPerson(ctx, tenant, candidate, assertion, v.grant, now)
	if err != nil {
		return nil, err
	}
	hold, err := s.sealed.exists(ctx, "PersonHold", tenant, subject)
	if err != nil {
		return nil, unavailable("store", err)
	}
	if hold {
		return deny("access_denied", "the person may not sign in", reasonHeld, &v)
	}

	// The code is a secret the client holds: the item is found by its hash. The facts policy will need again at the
	// token endpoint are sealed into it.
	code, err := randomToken()
	if err != nil {
		return nil, internal("random", err)
	}
	id := secretID(code)
	facts, err := s.keys.sealFlow(ctx, authCodeKind, id, &sessionv2alpha1.SignInFacts{Accounts: []string{account}})
	if err != nil {
		return nil, unavailable("key", err)
	}
	item := &sessionv2alpha1.AuthCode{
		ClientId: cl.GetId(), RedirectUri: pending.GetRedirectUri(), Scope: pending.GetScope(), Nonce: pending.GetNonce(),
		CodeChallenge: pending.GetCodeChallenge(), Subject: subject, AuthenticatedAt: timestamppb.New(now),
		Acr: assure.acr, Amr: assure.amr, AmrPresent: assure.amrPresent, SealedFacts: facts,
	}
	if assure.hasAuthTime {
		item.AuthTime = timestamppb.New(assure.authTime)
	}
	if _, err := s.codes.Create(ctx, tenant, id, item, store.WithGrant(v.grant)); err != nil {
		return nil, unavailable("store", err)
	}
	out, err := clientRedirect(pending.GetRedirectUri(), pending.GetState(), b.GetIssuer(), url.Values{"code": {code}}, clearCookie())
	if err != nil {
		return nil, internal("redirect", err)
	}
	sluis := map[string]any{"new_person": created}
	if aerr := s.record(ctx, audited{action: actionSignin, tenant: tenant, subject: personSubject(tenant, subject), policy: v.ref(), sluis: sluis}); aerr != nil {
		return nil, aerr
	}
	return out, nil
}

// authCodeKind is the address segment of the kind AuthCode.
const authCodeKind = "auth-code"

// openPending opens the sign-in cookie. errNotOurs says it is missing, malformed, altered, from another boundary or
// kind, or past its end; any other error is key@ failing.
func (s *Service) openPending(ctx context.Context, cookie string, now time.Time) (*sessionv2alpha1.PendingSignIn, error) {
	id, enc, ok := strings.Cut(cookie, ".")
	if !ok || len(id) != cookieIDLen || store.ValidateID(id) != nil {
		return nil, errNotOurs
	}
	envelope, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(envelope) == 0 {
		return nil, errNotOurs
	}
	p := &sessionv2alpha1.PendingSignIn{}
	if err := s.keys.openFlow(ctx, pendingKind, id, envelope, p); err != nil {
		return nil, err
	}
	if p.GetExpiresAt() == nil || !now.Before(p.GetExpiresAt().AsTime()) || p.GetTenant() == "" || p.GetUpstreamState() == "" {
		return nil, errNotOurs
	}
	return p, nil
}

// upstreamErrorCode is the error session reports to the client when the upstream reported one. The upstream's own
// code is not repeated: only a refusal by the person is told apart from the rest.
func upstreamErrorCode(c string) string {
	switch c {
	case "access_denied":
		return "access_denied"
	case "temporarily_unavailable":
		return "temporarily_unavailable"
	}
	return "access_denied"
}

// linkPerson finds the person of the upstream account, or makes one. The account is the pair (issuer, subject claim
// value) and never an e-mail address (0019 "Linking an upstream account"). A new person and the link are written in
// one batch; the link is a create, so when two first sign-ins of one account race, one batch wins and the other
// fails with already exists, reads the link and continues as the winner. Two people never result.
func (s *Service) linkPerson(ctx context.Context, tenant, candidate string, a *integrationv2alpha1.Assertion, grant []byte, now time.Time) (subject string, created bool, err error) {
	id, err := s.keys.linkID(ctx, a.GetIssuer(), a.GetSubjectClaim(), a.GetSubject())
	if err != nil {
		return "", false, unavailable("key", err)
	}
	read := func() (string, error) {
		env, err := s.sealed.get(ctx, "UpstreamLink", tenant, id)
		if err != nil {
			return "", err
		}
		l := &sessionv2alpha1.UpstreamLink{}
		if err := s.keys.openData(ctx, "upstream-link", tenant, id, env, l, grant); err != nil {
			return "", err
		}
		return l.GetSubject(), nil
	}
	sub, err := read()
	switch {
	case err == nil:
		return s.checkSubject(sub)
	case !errors.Is(err, store.ErrNotFound):
		return "", false, unavailable("store", err)
	}
	err = s.sealed.createAll(ctx, tenant, grant,
		newSealed{kind: "Person", id: candidate, value: &sessionv2alpha1.Person{Subject: candidate, CreatedAt: timestamppb.New(now)}},
		newSealed{kind: "UpstreamLink", id: id, value: &sessionv2alpha1.UpstreamLink{Subject: candidate, Issuer: a.GetIssuer(), SubjectClaim: a.GetSubjectClaim()}},
	)
	switch {
	case err == nil:
		return candidate, true, nil
	case errors.Is(err, store.ErrExists):
		sub, err = read()
		if err != nil {
			return "", false, unavailable("store", err)
		}
		return s.checkSubject(sub)
	}
	return "", false, unavailable("store", err)
}

// checkSubject refuses a link whose subject is not a valid id: the item is damaged, and a damaged item is not
// something to sign a person in with.
func (s *Service) checkSubject(sub string) (string, bool, error) {
	if store.ValidateID(sub) != nil || strings.Contains(sub, "/") {
		return "", false, internal("link", errors.New("subject"))
	}
	return sub, false, nil
}
