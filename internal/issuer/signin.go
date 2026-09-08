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

// Completer is the part of the storage a sign-in finishes against: an
// authorization request waiting for somebody to be established.
type Completer interface {
	Complete(id, subject string) error
}

// SignInDeps is what the sign-in routes need.
type SignInDeps struct {
	Issuer *Issuer
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
	mux.HandleFunc("GET /signed-out", s.signedOut)
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
	kinds := slices.Sorted(maps.Keys(s.providers))
	switch len(kinds) {
	case 0:
		s.page(w, "Nobody can sign in", `<p>This installation has no directory configured to sign in with.</p>`)
		return
	case 1:
		http.Redirect(w, r, s.startURL(kinds[0], request), http.StatusFound)
		return
	}
	var buttons strings.Builder
	for _, kind := range kinds {
		fmt.Fprintf(&buttons, `<p><a class="btn" href="%s">Continue with %s</a></p>`,
			html.EscapeString(s.startURL(kind, request)), html.EscapeString(providerName(kind)))
	}
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
			"provider", provider.Kind(), "error", err)
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
		s.deps.Log.WarnContext(r.Context(), "sign-in refused", "email", email, "reason", refused.Reason)
		http.Error(w, "signed in as "+email+", but "+refused.Reason, http.StatusForbidden)
		return
	case err != nil:
		s.deps.Log.ErrorContext(r.Context(), "the hub could not be asked", "email", email, "error", err)
		http.Error(w, "signed in as "+email+", but the directory could not be reached",
			http.StatusServiceUnavailable)
		return
	}

	if err = s.deps.Storage.Complete(request, email); err != nil {
		http.Error(w, "that sign-in is no longer waiting to be completed", http.StatusBadRequest)
		return
	}
	s.deps.Log.InfoContext(r.Context(), "signed in",
		"email", email, "provider", provider.Kind(), "groups", len(standing.Groups))
	http.Redirect(w, r, s.deps.Return(r.Context(), request), http.StatusFound)
}

// signedOut is where RP-initiated logout lands. It says what did and did
// not happen, because "signed out" on a page that ended one session and
// left three others running is the kind of half-truth people plan around.
func (s *signIn) signedOut(w http.ResponseWriter, _ *http.Request) {
	s.page(w, "Signed out", `<p>This application has signed you out.</p>
	<p class="note">Other applications you signed into keep their own sessions until they expire.
	To end every one of them, sign out everywhere from your own page in the directory console.</p>`)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := fmt.Fprintf(w, pageHTML, html.EscapeString(title), html.EscapeString(title), body); err != nil {
		s.deps.Log.Warn("page could not be written", "error", err)
	}
}

// pageHTML is the whole of this service's own UI: three pages, no
// JavaScript, no console. Each runs before there is anyone to authorize,
// which is exactly why they cannot be part of one.
const pageHTML = `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>
 body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f3f5f8;color:#1b2230}
 main{background:#fff;padding:32px 36px;border-radius:8px;border:1px solid #d9dee6;max-width:26rem}
 h1{font-size:20px;margin:0 0 4px} p{margin:12px 0}
 .btn{display:inline-block;padding:8px 14px;border-radius:4px;background:#0e7c7b;color:#fff;text-decoration:none}
 .note{font-size:14px;color:#6b7383}
</style>
<main><h1>%s</h1>%s</main>`
