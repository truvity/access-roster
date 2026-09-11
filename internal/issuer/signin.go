package issuer

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/logsafe"
)

// SignIn is a directory a person can prove who they are with.
//
// The issuer authenticates nobody itself: it sends the browser to a
// provider that does, and takes one thing back — an address. Everything
// that follows is decided by the hub and the policy, because a provider
// saying who somebody is must not also decide what they get.
type SignIn interface {
	// Kind names the provider: "google", "entra".
	Kind() string
	// URL is where the browser goes to prove who somebody is.
	URL(state string) (string, error)
	// Identify turns the callback's code into an address.
	Identify(ctx context.Context, code string) (string, error)
}

// Authenticated is who a sign-in established, and when.
//
// The "when" is separate from "now" on purpose: a request completed
// silently against a browser session established this morning
// authenticated this morning, and `auth_time` has to say so.
type Authenticated struct {
	Subject  string
	AuthTime time.Time
	// SSO is the browser session it was established against or by.
	SSO string
	// How this person was proved: a provider kind ("google"), or
	// "recovery". It becomes the token's `acr`, which is the one claim a
	// relying party can read to refuse a break-glass sign-in.
	How string
}

// Pending is what an authorization request asks of a sign-in, expressed
// so that the sign-in pages can answer it without knowing the protocol.
type Pending struct {
	// ForcesLogin is `prompt=login` or `prompt=select_account`: a live
	// browser session is not enough, authenticate again.
	ForcesLogin bool
	// ForbidsUI is `prompt=none`: complete silently or not at all.
	ForbidsUI bool
	// MaxAge, when set, is how old the authentication may be.
	MaxAge time.Duration
	// RedirectURI and State are the client's, for the one case that has
	// to answer the CLIENT rather than the person: `prompt=none` with
	// nobody signed in. The library validated the URI when it accepted
	// the request, so it is safe to send a browser back to it.
	RedirectURI string
	State       string
}

// Completer is the part of the storage a sign-in finishes against: an
// authorization request waiting for somebody to be established.
type Completer interface {
	Complete(id string, who Authenticated) error
	Pending(id string) (Pending, error)
}

// SignInDeps is what the sign-in routes need.
type SignInDeps struct {
	// Recovery is the way in when no directory can vouch for anybody, and
	// nil is a deployment with none. It is offered alongside the
	// providers rather than instead of them: a directory that cannot
	// answer yet is only the first of the days it exists for.
	Recovery Recovery
	Issuer   *Issuer
	// AfterSignOut is where a person lands once their sign-in has ended.
	//
	// Empty is this service's own signed-out page, which says what did
	// and did not happen. A deployment with a console sets it to the
	// console, so that signing out leads back to signing in — and it must
	// be somewhere a sign-in can actually START. `/login` is not: its
	// buttons carry the id of a pending authorization request, and
	// visiting it without one produces a page that looks like a sign-in
	// and cannot finish. The console's front page has no such problem:
	// it sends an unauthenticated browser through `/authorize`, which
	// makes the request the chooser needs.
	AfterSignOut string
	// Providers a person may choose. One button per *kind* is rendered,
	// never one per company: an anonymous page that lists the companies
	// an installation serves has published them to anyone who loads it.
	Providers []SignIn
	// Storage completes the authorization request once somebody is
	// established.
	Storage Completer
	// State signs the flow's state, which carries the authorization
	// request the browser is in the middle of.
	State *access.StateCodec
	// SSO is the browser's session with this issuer: what makes a second
	// console cost no login, and what `end_session` ends. Nil serves no
	// single sign-on at all — every authorization request then goes to a
	// provider, which is what this issuer did before it had one.
	SSO *SSO
	// ConsoleOrigin is the one origin allowed to call SessionService from
	// a browser. Empty serves it not at all, which is right for an
	// installation with no console: an endpoint nobody calls is surface
	// with no consumer.
	ConsoleOrigin string
	// ConsoleMount is where the console sits on this origin, e.g.
	// "/console". It is what an old `/account` bookmark is sent to, and
	// empty means there is no console to send anybody to, so the route is
	// not served at all.
	ConsoleMount string
	// Return is op.AuthCallbackURL(provider): where to send the browser
	// once the request is complete.
	Return func(ctx context.Context, requestID string) string
	// Secure marks the state cookie, which a deployment always sets.
	Secure bool
	Log    *slog.Logger
}

// signInWindow is how long a person has to finish signing in.
const signInWindow = 10 * time.Minute

// SignInRoutes registers the pages this service serves itself: the
// chooser, the provider round trip, and the page a person lands on after
// signing out.
//
// They are the issuer's own because each runs before there is anyone to
// authorize — there is no session yet to decide what a console would show.
func SignInRoutes(mux *http.ServeMux, deps SignInDeps) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &signIn{deps: deps, providers: map[string]SignIn{}}
	for _, provider := range deps.Providers {
		s.providers[provider.Kind()] = provider
	}
	mux.HandleFunc("GET /login", s.chooser)
	mux.HandleFunc("GET /login/{provider}/start", s.start)
	mux.HandleFunc("GET /login/{provider}/callback", s.callback)
	mux.HandleFunc("POST /login/recovery", s.recover)
	// BOTH methods. A person following a link sends GET; the console
	// sends POST, because its own sign-out was a POST — "a link that logs
	// you out would be a link anyone could put in a page" — and a
	// GET-only route answered that with 404. Serving one and not the
	// other is how sign-out was fixed once and still did not work.
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /signed-out", s.signedOut)

	// `/account` was the person's own page — their sessions, and the one
	// button that ends all of them. It lived here because it needed to be
	// same-origin with the session service, and it is not needed here any
	// more: the console is same-origin with this issuer and is now the
	// same process, and its own page for a person already shows both
	// (INF-695). One directory UI; this service's UI is the login form.
	//
	// What is left is the redirect, because the address was linked to and
	// bookmarked, and a 404 is a worse answer than the page somebody
	// wanted. With no console mounted there is nowhere to send them, so
	// the route is not served rather than sending them to a 404 of a
	// different shape.
	if deps.SSO != nil && deps.ConsoleMount != "" {
		mux.HandleFunc("GET /account", s.account)
	}
}

type signIn struct {
	deps      SignInDeps
	providers map[string]SignIn
}

// chooser asks which directory, and only when there is more than one to
// ask about: a single provider is a question with one answer, and asking
// it costs a click on every login in the estate.
func (s *signIn) chooser(w http.ResponseWriter, r *http.Request) {
	request := r.URL.Query().Get("auth")
	if request == "" {
		s.page(w, "Sign in", `<p>This page is reached from an application asking you to sign in.</p>`)
		return
	}
	// A live browser session is what makes the second console cost no
	// login, so it is tried before anything is rendered: the page below
	// is the fallback, not the normal path.
	//
	// A deployment with no storage wired can still render the chooser --
	// this is the login path, and it must not be the thing that panics.
	var pending Pending

	if s.deps.Storage != nil {
		asked, err := s.deps.Storage.Pending(request)
		if err != nil {
			http.Error(w, "this sign-in is not valid any more; start again", http.StatusBadRequest)
			return
		}

		pending = asked
	}

	if s.silent(w, r, request, pending) {
		return
	}

	if pending.ForbidsUI {
		// `prompt=none` asked for no interface and there is no session to
		// answer from, so the answer goes to the CLIENT and not to the
		// person: OpenID Connect Core 3.1.2.6 requires `login_required`
		// at the redirect URI.
		//
		// This used to render a page saying so, which is worse than it
		// sounds. The caller of `prompt=none` is usually a hidden iframe
		// doing a silent renewal: it cannot read an HTML page, has nobody
		// to show it to, and waits until it times out. Conformance failed
		// it as "expected an error but did not get one", which is the same
		// fact from the other side.
		s.refuse(w, r, pending, "login_required",
			"there is no active sign-in here to continue from")

		return
	}

	kinds := slices.Sorted(maps.Keys(s.providers))
	recovery := s.recoveryForm(request)

	// One provider and no recovery is the only case with a single way in,
	// and skipping a page with one button on it is a kindness. With
	// recovery there are two, and forwarding to a provider that may not
	// be able to help -- which is exactly the state a fresh installation
	// is in -- would hide the one that can.
	if len(kinds) == 1 && recovery == "" {
		http.Redirect(w, r, s.startURL(kinds[0], request), http.StatusFound)
		return
	}
	if len(kinds) == 0 && recovery == "" {
		s.page(w, "Nobody can sign in", `<p>This installation has no directory configured to sign in with.</p>`)
		return
	}

	var buttons strings.Builder
	// Say where this is. A person arrives here redirected from somewhere
	// else, on a hostname they may never have seen, and being asked to
	// sign in by a page that does not identify itself is the shape of
	// every phishing page there has ever been.
	buttons.WriteString(`<p class="note">Sign in to continue to the application that sent you here.</p>`)
	for _, kind := range kinds {
		fmt.Fprintf(&buttons, `<p><a class="btn" href="%s">Continue with %s</a></p>`,
			html.EscapeString(s.startURL(kind, request)), html.EscapeString(providerName(kind)))
	}
	if len(kinds) == 0 {
		buttons.WriteString(`<p>No directory is configured to sign in with yet.</p>`)
	}
	buttons.WriteString(recovery)
	s.page(w, "Sign in", buttons.String())
}

func (s *signIn) startURL(kind, request string) string {
	return "/login/" + kind + "/start?auth=" + url.QueryEscape(request)
}

// start sends the browser to the provider, with the authorization request
// it is in the middle of carried in the signed state.
func (s *signIn) start(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.providers[r.PathValue("provider")]
	if !ok {
		http.Error(w, "this issuer cannot sign in with that directory", http.StatusNotFound)
		return
	}
	request := r.URL.Query().Get("auth")
	if request == "" {
		http.Error(w, "this sign-in is not part of an application's request", http.StatusBadRequest)
		return
	}
	// The authorization request travels in the state, signed. A callback
	// carrying somebody else's request id would finish their login as
	// this person.
	state, err := s.deps.State.Issue(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	where, err := provider.URL(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusFailedDependency)
		return
	}
	http.SetCookie(w, access.LoginCookie(state, s.deps.Secure, signInWindow))
	http.Redirect(w, r, where, http.StatusFound)
}

// refuse answers the CLIENT with an OAuth error, for the cases where
// there is nobody to show a page to.
//
// Falls back to a page when the request named no redirect URI, which the
// library should not produce -- it validates the URI before the request
// exists -- but a redirect to nowhere is worse than a page.
func (s *signIn) refuse(w http.ResponseWriter, r *http.Request, pending Pending, code, why string) {
	if pending.RedirectURI == "" {
		s.page(w, "Sign-in required", `<p>This application asked to continue without prompting, and there is no active sign-in here to continue from.</p>
	<p class="note">Open the application again, or sign in first.</p>`)

		return
	}

	to, err := url.Parse(pending.RedirectURI)
	if err != nil {
		s.deps.Log.WarnContext(r.Context(), "a pending request has an unparseable redirect uri",
			"error", logsafe.Error(err))
		s.page(w, "Sign-in required", `<p>This application asked to continue without prompting.</p>`)

		return
	}

	query := to.Query()
	query.Set("error", code)
	query.Set("error_description", why)

	// Echoed when there was one, and omitted when there was not: a state
	// invented here would be one the client never sent.
	if pending.State != "" {
		query.Set("state", pending.State)
	}

	to.RawQuery = query.Encode()

	http.Redirect(w, r, to.String(), http.StatusFound)
}

// recoveryForm renders the recovery block, or nothing when a deployment
// has no recovery at all.
//
// The pending authorization request travels in a signed state, exactly as
// it does through a provider round trip: a POST carrying somebody else's
// request id would otherwise finish their sign-in as this person.
func (s *signIn) recoveryForm(request string) string {
	if s.deps.Recovery == nil {
		return ""
	}
	state, err := s.deps.State.Issue(request)
	if err != nil {
		return ""
	}
	prompt := s.deps.Recovery.Prompt()
	command := ""
	if prompt.Command != "" {
		command = "<pre>" + html.EscapeString(prompt.Command) + "</pre>"
	}
	return fmt.Sprintf(`<details><summary class="note">Recovery sign-in</summary>
	<p class="note">%s</p>%s
	<form method="post" action="/login/recovery">
		<input type="hidden" name="state" value="%s">
		<p><label>%s<br><input type="password" name="proof" autocomplete="off"></label></p>
		<p><button type="submit">Recover access</button></p>
	</form>
	<p class="warn">%s</p></details>`,
		html.EscapeString(prompt.Intro), command, html.EscapeString(state),
		html.EscapeString(prompt.Label), html.EscapeString(prompt.Caution))
}

// recover completes a sign-in with a ServiceAccount the cluster vouches
// for, when no directory can vouch for anybody.
//
// It completes as the SUBJECT, not as an address: what that subject is
// entitled to is the policy's `service_account` matchers, the same table
// that decides what a workload gets. Nothing here grants anything.
func (s *signIn) recover(w http.ResponseWriter, r *http.Request) {
	if s.deps.Recovery == nil {
		http.Error(w, "this issuer has no recovery", http.StatusNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "that form could not be read", http.StatusBadRequest)
		return
	}
	request, err := s.deps.State.Verify(r.PostFormValue("state"))
	if err != nil || request == "" {
		http.Error(w, "this sign-in is not valid any more; start again", http.StatusBadRequest)
		return
	}

	subject, err := s.deps.Recovery.Verify(r.Context(), r.PostFormValue("proof"))
	if err != nil {
		// One message for every reason, and the reason in the log: a
		// caller told which part of its proof failed is a caller helped
		// to produce a better one.
		s.deps.Log.WarnContext(r.Context(), "recovery refused", "error", logsafe.Error(err))
		http.Error(w, "that proof was not accepted", http.StatusForbidden)
		return
	}

	if err = s.deps.Storage.Complete(request, s.established(w, r, subject, RecoveryHow)); err != nil {
		http.Error(w, "that sign-in is no longer waiting to be completed", http.StatusBadRequest)
		return
	}
	// WARN, not INFO: this is the way in that bypasses the directory, and
	// it should be as loud in a log as it is rare.
	s.deps.Log.WarnContext(r.Context(), "recovery sign-in", "subject", logsafe.Value(subject))
	http.Redirect(w, r, s.deps.Return(r.Context(), request), http.StatusFound)
}

// callback finishes it: the provider says who, the hub says whether we
// serve them, and the authorization request is completed with the address.
func (s *signIn) callback(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.providers[r.PathValue("provider")]
	if !ok {
		http.Error(w, "this issuer cannot sign in with that directory", http.StatusNotFound)
		return
	}
	cookie, err := r.Cookie(access.LoginCookieName)
	state := r.URL.Query().Get("state")
	if err != nil || cookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "this sign-in did not start in this browser", http.StatusBadRequest)
		return
	}
	request, err := s.deps.State.Verify(state)
	if err != nil || request == "" {
		http.Error(w, "this sign-in is not valid any more; start again", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, access.LoginCookie("", s.deps.Secure, 0))

	email, err := provider.Identify(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.deps.Log.WarnContext(r.Context(), "sign-in exchange failed",
			"provider", provider.Kind(), "error", logsafe.Error(err))
		http.Error(w, "the sign-in could not be completed: "+err.Error(), http.StatusBadGateway)
		return
	}

	// The hub decides whether this address is anybody here. Refusing at
	// the door beats issuing a token that carries no groups: the person
	// would be signed in everywhere and admitted nowhere, with nothing to
	// read that explained it.
	standing, err := s.deps.Issuer.resolver.Resolve(r.Context(), email)
	var refused *Refused
	switch {
	case errors.As(err, &refused):
		// The directory has an opinion and it is no. Saying so here is
		// the only place a person will read it: everywhere downstream
		// they would simply find themselves admitted nowhere.
		s.deps.Log.WarnContext(r.Context(), "sign-in refused", "email", logsafe.Value(email), "reason", logsafe.Value(refused.Reason))
		http.Error(w, "signed in as "+email+", but "+refused.Reason, http.StatusForbidden)
		return
	case err != nil:
		s.deps.Log.ErrorContext(r.Context(), "the hub could not be asked", "email", logsafe.Value(email), "error", logsafe.Error(err))
		http.Error(w, "signed in as "+email+", but the directory could not be reached",
			http.StatusServiceUnavailable)
		return
	}

	if err = s.deps.Storage.Complete(request, s.established(w, r, email, provider.Kind())); err != nil {
		http.Error(w, "that sign-in is no longer waiting to be completed", http.StatusBadRequest)
		return
	}
	s.deps.Log.InfoContext(r.Context(), "signed in",
		"email", logsafe.Value(email), "provider", provider.Kind(), "groups", len(standing.Groups))
	http.Redirect(w, r, s.deps.Return(r.Context(), request), http.StatusFound)
}

// logout is the sign-out a PERSON follows, as opposed to `/end_session`,
// which is the protocol endpoint a relying party redirects to.
//
// It exists because the console's sign-out button pointed at `/logout`
// and nothing served it: the button returned 404 and the sign-in
// survived, which is how "even sign-out does not work" was reported. The
// button was not wrong — this is the address a person expects, it is
// what they type, and `/end_session` is a name from a specification.
//
// Both end the same thing. This one needs no `id_token_hint`, which the
// console could not supply anyway: it never redeems the code it gets
// back, so it holds no ID token. That it takes a GET is the same posture
// `end_session` has — ending a session is not a change somebody else can
// exploit by making your browser visit it, only annoy you with.
func (s *signIn) logout(w http.ResponseWriter, r *http.Request) {
	SignOut(s.deps, w, r)

	where := strings.TrimSpace(s.deps.AfterSignOut)
	if where == "" {
		where = signedOutPath
	}

	http.Redirect(w, r, where, http.StatusFound)
}

// SignOut ends EVERYTHING this browser opened, and then the sign-in
// itself. It is what both doors do, because there is only one thing a
// person means by signing out.
//
// Ending the sign-in alone stops the next silent `/authorize` and
// nothing else. The design leaned on the other sessions dying "at their
// next refresh" — they do not, because nothing revoked the refresh
// tokens. Reported from hubble: signed out at the issuer, and its proxy
// went on refreshing successfully and serving pages for hours.
//
// The two doors did not agree about this, and the one that had the weaker
// half was the one a PROXY uses. `/logout` revoked; `/end_session`, which
// is what oauth2-proxy chains to, only ended the sign-in — so every
// console behind a proxy had exactly the failure the fix was written for.
//
// Sessions first, sign-in second. If the first half fails the sign-in is
// still there and the person can try again; the other order would leave
// sessions running with nothing listing them. Narrowed by identity, which
// the sign-in record carries: an SSO-only query reads every session in
// the installation and filters, and this runs on an ordinary sign-out.
func SignOut(deps SignInDeps, w http.ResponseWriter, r *http.Request) {
	if deps.SSO == nil {
		return
	}

	if id := SSOFromRequest(r); id != "" {
		record, live, err := deps.SSO.Get(r.Context(), id)
		if deps.Issuer != nil && err == nil && live {
			ended, err := deps.Issuer.Sessions().Revoke(r.Context(),
				Query{Identity: record.Identity, SSO: id})
			switch {
			case err != nil:
				deps.log().WarnContext(r.Context(), "sign-out could not end what this browser opened",
					"error", logsafe.Error(err))
			case ended > 0:
				deps.log().InfoContext(r.Context(), "sign-out ended the sessions this browser opened",
					"ended", ended)
			}
		}

		if err := deps.SSO.End(r.Context(), id); err != nil {
			deps.log().WarnContext(r.Context(), "sign-out could not end the session",
				"error", logsafe.Error(err))
		}
	}

	// Cleared whatever the record said: a cookie naming a session that is
	// already gone still makes the next request look signed in until it
	// is checked, and clearing it costs nothing.
	http.SetCookie(w, deps.SSO.Cookie("", deps.Secure))
}

// log is the deps' logger, or the default one. SignOut is reached from
// the provider middleware as well as from this handler, and that path
// has never been required to carry a logger.
func (d SignInDeps) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}

	return slog.Default()
}

// signedOut is where sign-out lands, whichever door was used. It says
// what did and did not happen, because "signed out" on a page that ended
// one session and left three others running is the kind of half-truth
// people plan around.
func (s *signIn) signedOut(w http.ResponseWriter, _ *http.Request) {
	s.page(w, "Signed out", `<p>Your sign-in here has ended. The next application you open will ask again.</p>
	<p class="note">Applications you already opened keep their OWN sessions until those expire —
	ending a sign-in here cannot reach into them. To end one now, revoke its session from the
	console's Sessions page.</p>`)
}

// providerName is what a person calls the directory, rather than what the
// code calls the backend.
func providerName(kind string) string {
	switch kind {
	case "google":
		return "Google"
	case "entra":
		return "Microsoft"
	default:
		return kind
	}
}

func (s *signIn) page(w http.ResponseWriter, title, body string) {
	if err := writePage(w, http.StatusOK, title, body); err != nil {
		s.deps.Log.Warn("page could not be written", "error", err)
	}
}

// writePage renders one of this service's pages. It is a function rather
// than only a method because `/end_session` is served by the LIBRARY and
// still has to answer a browser in the same voice -- see
// [endSessionForPeople].
func writePage(w http.ResponseWriter, status int, title, body string) error {
	// Headers first, then the status: anything set after WriteHeader is
	// dropped, and a page served without its content type is left to the
	// browser to guess at.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err := fmt.Fprintf(w, pageHTML, html.EscapeString(title), html.EscapeString(title), body)
	return err
}

// pageHTML is the whole of this service's own UI: three pages, no
// JavaScript, no console. Each runs before there is anyone to authorize,
// which is exactly why they cannot be part of one.
const pageHTML = `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>
 body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f3f5f8;color:#1b2230}
 main{background:#fff;padding:32px 36px;border-radius:8px;border:1px solid #d9dee6;max-width:26rem}
 h1{font-size:20px;margin:0 0 4px} p{margin:12px 0}
 input{width:100%%;padding:8px;border:1px solid #d9dee6;border-radius:4px;font:inherit}
 button,.btn{display:inline-block;padding:8px 14px;border:0;border-radius:4px;background:#0e7c7b;color:#fff;font:inherit;text-decoration:none;cursor:pointer}
 .note{font-size:14px;color:#6b7383}
 .warn{font-size:13px;color:#8a4b21;background:#fdf3e7;border:1px solid #f0d9c0;border-radius:4px;padding:8px 10px}
 pre{font-size:13px;background:#f3f5f8;border:1px solid #d9dee6;border-radius:4px;padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
 details{margin-top:20px;border-top:1px solid #e6eaef;padding-top:12px}
 summary{cursor:pointer}
</style>
<main><h1>%s</h1>%s</main>`

// silent completes the authorization request from a browser session that
// already exists, and reports whether it did.
//
// This is single sign-on, and it is one function: the second console's
// request completes here instead of making a round trip to the corporate
// directory. Everything it will not do is as important as what it will.
func (s *signIn) silent(w http.ResponseWriter, r *http.Request, request string, pending Pending) bool {
	if s.deps.SSO == nil || s.deps.Storage == nil || pending.ForcesLogin {
		return false
	}

	session, live, err := s.deps.SSO.Get(r.Context(), SSOFromRequest(r))
	if err != nil || !live || !session.Fresh(time.Now(), pending.MaxAge) {
		return false
	}

	// The browser proved who it is; the DIRECTORY still decides whether
	// that account is live. Without this a suspended person would keep
	// signing in silently for as long as their browser session lasted --
	// the one failure single sign-on can introduce that the login path
	// does not have, and the one an identity service least wants. A
	// ServiceAccount subject (a recovery sign-in) has no directory to ask:
	// the policy's matchers decide it at token time, exactly as they do
	// for a workload.
	if strings.Contains(session.Identity, "@") {
		if _, err = s.deps.Issuer.resolver.Resolve(r.Context(), session.Identity); err != nil {
			s.deps.Log.WarnContext(r.Context(), "browser session is no longer admitted",
				"identity", logsafe.Value(session.Identity), "error", logsafe.Error(err))
			_ = s.deps.SSO.End(r.Context(), session.ID)
			http.SetCookie(w, s.deps.SSO.Cookie("", s.deps.Secure))

			return false
		}
	}

	if err = s.deps.Storage.Complete(request, Authenticated{
		Subject:  session.Identity,
		AuthTime: session.AuthTime,
		SSO:      session.ID,
		// The session's own, not this request's: completing silently
		// does not re-prove anybody, so the token must say how they were
		// proved in the first place.
		How: session.How,
	}); err != nil {
		return false
	}

	s.deps.Log.InfoContext(r.Context(), "signed in from an existing browser session",
		"identity", logsafe.Value(session.Identity), "how", session.How)
	http.Redirect(w, r, s.deps.Return(r.Context(), request), http.StatusFound)

	return true
}

// established records a fresh authentication as a browser session and
// hands the browser its cookie.
//
// A deployment with no SSO store still signs people in; it just asks the
// provider every time, which is what this issuer did before it had one.
func (s *signIn) established(w http.ResponseWriter, r *http.Request, identity, how string) Authenticated {
	who := Authenticated{Subject: identity, AuthTime: time.Now(), How: how}
	if s.deps.SSO == nil {
		return who
	}

	session, err := s.deps.SSO.Begin(r.Context(), identity, how)
	if err != nil {
		// A sign-in that worked must not fail because the browser session
		// could not be filed. The person is authenticated either way; the
		// only cost is that the next console asks again.
		s.deps.Log.WarnContext(r.Context(), "browser session could not be recorded",
			"identity", logsafe.Value(identity), "error", logsafe.Error(err))

		return who
	}

	http.SetCookie(w, s.deps.SSO.Cookie(session.ID, s.deps.Secure))
	who.AuthTime, who.SSO = session.AuthTime, session.ID

	return who
}

// account sends an old bookmark to the console's page for the person.
//
// The page itself is gone (INF-695). It lived here because it had to be
// same-origin with the session service; the console is same-origin with
// this issuer and now the same process, and its own page for a person
// already lists their sessions and offers *sign out everywhere*. Two
// pages showing the same thing is two things to keep true of each other.
//
// A person not signed in here is sent to the console's root rather than
// to a page about themselves, because there is no themselves to name.
func (s *signIn) account(w http.ResponseWriter, r *http.Request) {
	to := s.deps.ConsoleMount + "/"

	session, live, err := s.deps.SSO.Get(r.Context(), SSOFromRequest(r))
	if err == nil && live && session.Identity != "" {
		// The console routes in the FRAGMENT, so the path is the console
		// itself and the page is what follows the hash.
		to += "#/people/" + url.PathEscape(session.Identity)
	}

	http.Redirect(w, r, to, http.StatusFound)
}
