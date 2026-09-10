package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/logsafe"
	"github.com/truvity/access-roster/internal/version"
)

// ForwardedIdentity configures how a bearer forwarded by an authenticating
// gateway becomes a principal.
//
// Two paths, and they are not equals. VERIFYING the bearer against the
// issuer's published keys is the one to use: it answers "who signed this"
// rather than "who can reach this port". TRUSTING a header is the fallback
// for a gateway that forwards no token, and it is only ever as good as the
// promise that nothing else can reach the listener -- a promise one
// NetworkPolicy edit, one port-forward or one sidecar away from false.
type ForwardedIdentity struct {
	// Issuer the bearer is verified against, as a URL. Set with Audience,
	// this turns on the verified path.
	Issuer string
	// Audience the token must name -- the console's client id at the
	// issuer. Empty accepts any audience the issuer mints, which makes
	// every other service it serves a way in here.
	Audience string
	// EmailHeader is the header the proxy puts the caller's address in.
	// Empty turns the trusted-header path off, which is the right setting
	// wherever the verified path is configured.
	EmailHeader string
}

// ConsoleServer is the console listener: the operator services, the login
// routes, the consent callback and the identity middleware that feeds them.
type ConsoleServer struct {
	console    *Console
	authz      *access.Authorizer
	sessions   *access.Sessions
	state      *access.StateCodec
	connectors map[string]Connector
	hub        *hub.Hub
	recovery   Recovery
	signIn     bool
	signOutURL string
	forwarded  ForwardedIdentity
	bearer     *forwardedBearer
	log        *slog.Logger
	consoleUI  fs.FS
}

// ConsoleServerDeps is what the console listener needs.
type ConsoleServerDeps struct {
	Console    *Console
	Authorizer *access.Authorizer
	Sessions   *access.Sessions
	State      *access.StateCodec
	Connectors []Connector
	Hub        *hub.Hub
	// Recovery is the way in when the ordinary one is broken. Nil is a
	// deployment with no recovery path at all.
	Recovery Recovery
	// SignIn offers the hub's own sign-in page. A console reached only
	// through a gateway that has already run the login wants one door,
	// not two. It does not affect connecting a directory, which is an
	// operator granting this hub access rather than a way in.
	SignIn bool
	// SignOutURL is where the console's sign-out control goes. Empty is
	// this hub's own `/logout`, which is right only where this hub's own
	// cookie is what signed the person in. Behind a proxy it is the
	// proxy's sign-out path.
	SignOutURL string
	Forwarded  ForwardedIdentity
	Log        *slog.Logger
	// UI is the built console. Nil serves no UI, which is what a
	// deployment that only wants the API does.
	UI fs.FS
}

// NewConsoleServer assembles the console listener.
func NewConsoleServer(deps ConsoleServerDeps) *ConsoleServer {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	s := &ConsoleServer{
		console:    deps.Console,
		authz:      deps.Authorizer,
		sessions:   deps.Sessions,
		state:      deps.State,
		connectors: map[string]Connector{},
		hub:        deps.Hub,
		recovery:   deps.Recovery,
		signIn:     deps.SignIn,
		signOutURL: deps.SignOutURL,
		forwarded:  deps.Forwarded,
		bearer:     newForwardedBearer(deps.Forwarded, deps.Log),
		log:        deps.Log,
		consoleUI:  deps.UI,
	}
	for _, c := range deps.Connectors {
		s.connectors[c.Kind()] = c
	}
	return s
}

// Handler returns the console listener's HTTP handler.
func (s *ConsoleServer) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.Handle(directoryrosterv1connect.NewWorkspaceServiceHandler(s.console))
	mux.Handle(directoryrosterv1connect.NewSettingsServiceHandler(s.console))
	mux.Handle(directoryrosterv1connect.NewAccessServiceHandler(s.console))

	if s.consoleUI != nil {
		mux.Handle("GET /assets/", http.FileServerFS(s.consoleUI))
		mux.HandleFunc("GET /{$}", s.index)
		mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	}

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /login/{backend}/start", s.signInStart)
	mux.HandleFunc("GET /login/{backend}/callback", s.signInCallback)
	mux.HandleFunc("POST /login/recovery", s.recoveryLogin)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /connect/{backend}/callback", s.connectCallback)
	mux.HandleFunc("GET /.access/whoami", s.whoami)

	return s.withIdentity(mux)
}

// index serves the console shell. Views live in the URL fragment, so one
// route is enough: no catch-all, and every API path stays clean.
func (s *ConsoleServer) index(w http.ResponseWriter, r *http.Request) {
	if _, ok := IdentityFrom(r.Context()); !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	page, err := fs.ReadFile(s.consoleUI, "index.html")
	if err != nil {
		http.Error(w, "the console is not built into this binary", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err = w.Write(page); err != nil {
		s.log.WarnContext(r.Context(), "console shell could not be written", "error", err)
	}
}

// withIdentity resolves the caller once per request and puts the identity
// in the context. It never rejects: a request with no identity simply has
// none, and the handler that needs one says so.
func (s *ConsoleServer) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.principal(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		id, err := s.authz.Authorize(r.Context(), principal)
		if err != nil {
			// The address is the point of the line — an audit record that
			// does not say who was refused is not one — and it is safe to
			// write by construction rather than by the handler's choice.
			s.log.InfoContext(r.Context(), "authorization refused",
				"email", logsafe.Value(principal.Email),
				"source", principal.Source, "error", logsafe.Error(err))
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// principal reads whichever source established the caller.
func (s *ConsoleServer) principal(r *http.Request) (access.Principal, bool) {
	if p, err := s.sessions.Read(r); err == nil {
		return p, true
	}
	// Verified before trusted: where both are configured, a signature
	// decides and a header is never consulted.
	if s.bearer != nil {
		if p, ok := s.bearer.identity(r); ok {
			return p, true
		}
	}
	if s.forwarded.EmailHeader != "" {
		email := strings.ToLower(strings.TrimSpace(r.Header.Get(s.forwarded.EmailHeader)))
		// An identity arriving in a header is only as trustworthy as the
		// gateway that sets it, and the hub cannot check that. What it can
		// check is that the value is an address at all: everything above
		// routes by the domain after the '@', so a header carrying a
		// bare word, a whole log line, or a stray newline is not an
		// identity this hub could answer about — it is a misconfigured
		// gateway, and taking it as a principal would put unvalidated
		// header content into the policy and the audit log alike.
		if _, ok := emailaddr.Domain(email); ok && !strings.ContainsFunc(email, unwritable) {
			return access.Principal{
				Email:   email,
				Subject: email,
				Source:  access.SourceForwarded,
				Issuer:  s.forwarded.Issuer,
			}, true
		}
		if email != "" {
			s.log.WarnContext(r.Context(), "the forwarded identity header is not an address; ignoring it",
				"header", s.forwarded.EmailHeader, "length", len(email))
		}
	}
	return access.Principal{}, false
}

// unwritable reports a rune that has no business in an address: a control
// character, or the space that would let one header value look like two
// fields. An address is written down in audit lines and matched against
// the policy, and a value that can forge a line break in either is not an
// address however well-formed the rest of it looks.
func unwritable(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }

// loginPage is the plain page a standalone installation signs in on. Where
// a gateway fronts the console it is never reached: the proxy has already
// run the login and forwards the bearer.
func (s *ConsoleServer) loginPage(w http.ResponseWriter, r *http.Request) {
	if id, ok := IdentityFrom(r.Context()); ok && id.Role != access.RoleNone {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// One button per directory kind, never one per company: an anonymous
	// page that lists the companies an installation serves has published
	// them to anyone who loads it. Which tenant a person belongs to is
	// answered by the address the provider gives back, not by asking them
	// first — the provider's own account chooser has already asked.
	var sources strings.Builder
	for _, kind := range slices.Sorted(maps.Keys(s.connectors)) {
		// Only a connector that can sign somebody in gets a button. One
		// that cannot would be a link to a 404 on the page a person
		// reaches when they are already having trouble.
		if _, ok := s.signInConnector(kind); !ok {
			continue
		}
		fmt.Fprintf(&sources,
			`<p><a class="btn" href="/login/%s/start">Continue with %s</a></p>`,
			html.EscapeString(kind), html.EscapeString(providerName(kind)))
	}

	// Recovery is behind a disclosure rather than on the page. It is the
	// path for the day the one above is broken, and a field sitting in
	// the open invites a password manager to fill it and everyone else to
	// treat it as the normal way in.
	recovery := ""
	if recoveryEnabled(s.recovery) {
		prompt := s.recovery.Prompt()
		command := ""
		if prompt.Command != "" {
			command = "<pre>" + html.EscapeString(prompt.Command) + "</pre>"
		}
		// The command carries this installation's own namespace and
		// account, because the alternative is an operator guessing a
		// release name during an outage — the same reason the setup steps
		// show the real redirect URI. None of it is a secret, and none of
		// it works without the cluster RBAC to mint the token.
		//
		// The warning is the part that matters. What is written here is
		// an instruction to produce a credential that grants operator on
		// this hub, on a page anyone may load, so it says plainly that
		// nobody should ever run it because they were asked to.
		recovery = fmt.Sprintf(`<details><summary class="note">Recovery sign-in</summary>
		<p class="note">For the day the directory is what is broken. %s</p>
		%s<form method="post" action="/login/recovery">
			<p><label>%s<br><input type="password" name="proof" autocomplete="off"></label></p>
			<p><button type="submit">Recover access</button></p>
		</form>
		<p class="warn">%s</p></details>`,
			html.EscapeString(prompt.Intro), command,
			html.EscapeString(prompt.Label), html.EscapeString(prompt.Caution))
	}
	// With no way in of its own, this page is otherwise a card with a
	// heading and nothing under it — which is what somebody who has just
	// signed out lands on, wondering where the button went.
	elsewhere := ""
	if sources.Len() == 0 {
		elsewhere = `<p class="note">This console does not sign anyone in itself: the gateway in
		front of it does, and sending you somewhere else to sign in would be a second door to the
		same room. <a href="/">Go to the console</a> and it will take you to the right one.</p>
		<p class="note">Recovery below is the way in when the gateway is what is broken.</p>`
	}
	s.writePage(w, r, http.StatusOK, "Sign in", `<h1>directory-roster</h1>
<p class="note">The directory hub. Sign in to connect workspaces and grant access.</p>`+
		elsewhere+sources.String()+recovery)
}

// providerName is what a person calls the directory, rather than what the
// code calls the backend.
func providerName(kind string) string {
	switch kind {
	case "google":
		return "Google"
	case "entra":
		return "Microsoft"
	case "demo":
		return "the demonstration directory"
	default:
		return kind
	}
}

// consoleCSS is the style the hub's plain pages share. It is written
// here once because a second copy is a second page that stops looking
// like this one the first time either is touched.
//
// Note the single `%` — this is a plain string, not a Printf format. The
// pages build their bodies separately and hand them to writePage, which
// is what keeps the CSS out of a format string.
const consoleCSS = `
 body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f3f5f8;color:#1b2230}
 main{background:#fff;padding:32px 36px;border-radius:8px;border:1px solid #d9dee6;max-width:34rem}
 h1{font-size:20px;margin:0 0 4px} p{margin:12px 0}
 input{width:100%;padding:8px;border:1px solid #d9dee6;border-radius:4px;font:inherit}
 button,.btn{display:inline-block;padding:8px 14px;border:0;border-radius:4px;background:#0e7c7b;color:#fff;font:inherit;text-decoration:none;cursor:pointer}
 .note{font-size:14px;color:#6b7383}
 .warn{font-size:13px;color:#8a4b21;background:#fdf3e7;border:1px solid #f0d9c0;border-radius:4px;padding:8px 10px}
 pre{font-size:13px;background:#f3f5f8;border:1px solid #d9dee6;border-radius:4px;padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
 details{margin-top:20px;border-top:1px solid #e6eaef;padding-top:12px}
 summary{cursor:pointer}
 ul{margin:12px 0;padding-left:20px} li{margin:8px 0}
`

// writePage writes one of the hub's plain pages. The body is already
// HTML: every caller escapes what it interpolates.
func (s *ConsoleServer) writePage(w http.ResponseWriter, r *http.Request, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err := io.WriteString(w, `<!doctype html><meta charset="utf-8"><title>`+
		html.EscapeString(title)+` — directory-roster</title><style>`+consoleCSS+`</style><main>`+body+`</main>`)
	if err != nil {
		s.log.WarnContext(r.Context(), "page could not be written", "title", title, "error", err)
	}
}

// signInStart sends the browser to a directory's own sign-in screen.
func (s *ConsoleServer) signInStart(w http.ResponseWriter, r *http.Request) {
	connector, ok := s.signInConnector(r.PathValue("backend"))
	if !ok {
		http.Error(w, "this hub cannot sign in with that directory", http.StatusNotFound)
		return
	}
	state, err := s.state.Issue("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	url, err := connector.SignInURL(state)
	if err != nil {
		// Almost always "no OAuth client is registered yet", which is a
		// setup step rather than a fault, so it says so instead of
		// failing with a stack of OAuth vocabulary.
		http.Error(w, err.Error(), http.StatusFailedDependency)
		return
	}
	http.SetCookie(w, access.LoginCookie(state, s.sessions.Secure(), signInWindow))
	http.Redirect(w, r, url, http.StatusFound)
}

// signInWindow is how long a person has to finish signing in.
const signInWindow = 10 * time.Minute

// signInCallback finishes a directory sign-in.
//
// The address it establishes is the whole of what is taken from the
// provider. Everything else — whether the account is live, which company
// it belongs to, what it may do here — is answered by the directory this
// hub already reads and by the policy, because a provider saying who
// somebody is must not also decide what they get.
func (s *ConsoleServer) signInCallback(w http.ResponseWriter, r *http.Request) {
	connector, ok := s.signInConnector(r.PathValue("backend"))
	if !ok {
		http.Error(w, "this hub cannot sign in with that directory", http.StatusNotFound)
		return
	}
	cookie, err := r.Cookie(access.LoginCookieName)
	state := r.URL.Query().Get("state")
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "this sign-in did not start in this browser", http.StatusBadRequest)
		return
	}
	if _, err = s.state.Verify(state); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, access.LoginCookie("", s.sessions.Secure(), 0))

	email, err := connector.Identify(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		s.log.WarnContext(r.Context(), "sign-in exchange failed",
			"backend", connector.Kind(), "error", logsafe.Error(err))
		http.Error(w, "the sign-in could not be completed: "+err.Error(), http.StatusBadGateway)
		return
	}

	// An address the hub has no opinion about is refused here rather than
	// given a session with no role. The line is not "has a role" — a
	// person of a company we do serve who is in no group signs in fine,
	// and their own page explains what they have and why. It is whether
	// this hub knows them at all: a stranger from a domain nobody here
	// serves would get a session, see nothing, and have nothing to read
	// that explained it.
	known, err := s.hub.ResolveUser(r.Context(), email, nil)
	switch {
	case err != nil:
		s.log.ErrorContext(r.Context(), "sign-in could not be resolved", "email", logsafe.Value(email), "error", logsafe.Error(err))
		http.Error(w, "signed in as "+email+", but the directory could not be read: "+err.Error(),
			http.StatusServiceUnavailable)
		return
	case !known.InDomain:
		http.Error(w, "signed in as "+email+", but no directory connected to this hub serves that domain",
			http.StatusForbidden)
		return
	case !known.Found && known.Authoritative:
		http.Error(w, "signed in as "+email+", but that account is not in the directory",
			http.StatusForbidden)
		return
	}

	identity, err := s.authz.Authorize(r.Context(),
		access.Principal{Email: email, Subject: email, Source: access.SourceDirectory, Issuer: connector.Kind()})
	if err != nil {
		// The one Authorize refuses outright is an account the directory
		// authoritatively says is not live.
		s.log.WarnContext(r.Context(), "sign-in refused", "email", logsafe.Value(email), "error", logsafe.Error(err))
		http.Error(w, "signed in as "+email+", but this hub cannot serve that address: "+err.Error(),
			http.StatusForbidden)
		return
	}

	if err = s.sessions.Issue(w, access.Principal{
		Email: email, Subject: email, Source: access.SourceDirectory, Issuer: connector.Kind(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.InfoContext(r.Context(), "signed in",
		"email", logsafe.Value(email), "backend", connector.Kind(), "role", identity.Role)
	redirectOrOK(w, r, "/")
}

// signInConnector is the connector for a kind, if it can sign a person in
// and this deployment offers its own sign-in at all.
func (s *ConsoleServer) signInConnector(kind string) (SignInConnector, bool) {
	connector, ok := s.connectors[kind]
	if !ok || !s.signIn {
		return nil, false
	}
	signIn, ok := connector.(SignInConnector)
	return signIn, ok
}

// recoveryLogin is the way in when the ordinary one is broken.
//
// The proof may come in the form, as JSON, or as a bearer — the last so
// that a runbook can be one curl, which matters on the day this is
// reached at all.
func (s *ConsoleServer) recoveryLogin(w http.ResponseWriter, r *http.Request) {
	if !recoveryEnabled(s.recovery) {
		http.Error(w, "this deployment has no recovery sign-in", http.StatusForbidden)
		return
	}
	proof := r.FormValue("proof")
	if proof == "" {
		proof = jsonField(r, "proof")
	}
	if proof == "" {
		proof = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	subject, err := s.recovery.Verify(r.Context(), strings.TrimSpace(proof))
	switch {
	case errors.Is(err, ErrRecoveryThrottled):
		s.log.WarnContext(r.Context(), "recovery refused: too many attempts", "remote", r.RemoteAddr)
		http.Error(w, "too many attempts; wait a minute", http.StatusTooManyRequests)
		return
	case errors.Is(err, ErrRecoveryRefused):
		s.log.WarnContext(r.Context(), "recovery refused", "remote", r.RemoteAddr, "reason", logsafe.Error(err))
		http.Error(w, "that proof was not accepted", http.StatusUnauthorized)
		return
	case err != nil:
		// The check did not happen — an unreachable API server, a hub
		// that may not create TokenReviews. Saying "wrong password" here
		// would send an operator hunting for the wrong thing on the worst
		// possible day.
		s.log.ErrorContext(r.Context(), "recovery could not be checked", "error", err)
		http.Error(w, "recovery could not be checked: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// The session records who recovered. A shared password made every
	// recovery look like the same person; a token names one.
	if err = s.sessions.Issue(w, access.Principal{
		Email: subject, Subject: subject, Source: access.SourceRecovery,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.WarnContext(r.Context(), "recovery sign-in", "subject", logsafe.Value(subject), "kind", s.recovery.Kind())
	redirectOrOK(w, r, "/")
}

// logout clears the session. It cannot end a session elsewhere: rotating
// the session key is what does that, and it logs everyone out at once.
func (s *ConsoleServer) logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Clear(w)
	redirectOrOK(w, r, "/login")
}

// signOut is where the console's sign-out control goes.
//
// This hub's own `/logout` clears this hub's own cookie, and behind a
// proxy that cookie is not what signed anybody in: the proxy holds the
// session and forwards a bearer. Clearing ours there ends nothing, drops
// the person on a sign-in page with no way in — the hub's own sign-in
// being off is the whole point of having a proxy — and the next request
// arrives authenticated exactly as before. So a deployment behind a proxy
// names the proxy's sign-out, and it is a value rather than something
// derived: the path belongs to the proxy, and where it should go
// afterwards — an issuer's end-session, a landing page — is the
// installation's to decide without a release here.
func (s *ConsoleServer) signOut() string {
	if s.signOutURL != "" {
		return s.signOutURL
	}
	return "/logout"
}

// consentProblem renders what went wrong on the page the operator is
// looking at, instead of a status code nobody sees.
//
// The status is deliberately NOT 5xx. The CDN in front of this console
// replaces a 502 with its own "Bad gateway" page — observed: six
// kilobytes of Cloudflare HTML where the hub had written one line naming
// the exact Google project and the exact API to enable. The diagnosis
// survived only in the log, which is the one place the person who can
// act on it was not looking. A 4xx is delivered intact, and 409 is what
// this handler already returns for the other consent that cannot be
// adopted as it stands.
//
// `detail` is whatever the provider said, verbatim. It is escaped, and
// it is the most useful line on the page: Google's own messages name the
// project, the API and the console URL that fixes it.
func (s *ConsoleServer) consentProblem(
	w http.ResponseWriter, r *http.Request, status int, summary, detail string, causes []string,
) {
	var body strings.Builder
	body.WriteString(`<h1>The consent could not be completed</h1>`)
	fmt.Fprintf(&body, `<p>%s</p>`, html.EscapeString(summary))
	if detail != "" {
		fmt.Fprintf(&body, `<p class="note">What the directory said:</p><pre>%s</pre>`,
			html.EscapeString(detail))
	}
	if len(causes) > 0 {
		body.WriteString(`<p class="note">The usual causes, most common first:</p><ul>`)
		for _, cause := range causes {
			fmt.Fprintf(&body, `<li>%s</li>`, html.EscapeString(cause))
		}
		body.WriteString(`</ul>`)
	}
	body.WriteString(`<p><a class="btn" href="/">Back to the console</a></p>`)
	s.writePage(w, r, status, "Consent", body.String())
}

// consentCauses is what to check when a directory refuses the credential
// its own consent screen has just granted. Ordered by how often each one
// is the answer, because a list read top-down is a list whose order is a
// claim about likelihood.
var consentCauses = []string{
	"The directory API is not enabled in the cloud project that owns this hub's OAuth client. " +
		"The message above names the project and the page that enables it.",
	"The API was enabled moments ago. Enabling propagates over a few minutes; try again.",
	"The account that consented is not an administrator of the workspace, or lacks the " +
		"privileges to read users and groups.",
	"The consent was granted with a personal account, or with an account in a different " +
		"workspace than the one intended. The account chooser remembers the last one used.",
}

// connectCallback finishes an admin-consent flow: it checks the state
// against the cookie, exchanges the code, and adopts the workspace.
func (s *ConsoleServer) connectCallback(w http.ResponseWriter, r *http.Request) {
	conn, ok := s.connectors[r.PathValue("backend")]
	if !ok {
		s.consentProblem(w, r, http.StatusNotFound,
			"This hub has no connector for that directory.", "", nil)
		return
	}

	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(access.ConnectCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		s.consentProblem(w, r, http.StatusBadRequest,
			"This consent did not start in this browser.", "", []string{
				"The consent was started in another browser, or another profile or private window.",
				"More than ten minutes passed between starting the consent and returning from it.",
				"The browser is refusing the cookie this flow is pinned to.",
			})
		return
	}
	binding, err := s.state.VerifyBinding(state)
	if err != nil {
		s.consentProblem(w, r, http.StatusBadRequest,
			"This consent cannot be finished.", err.Error(), []string{
				"More than ten minutes passed between starting the consent and returning from it.",
				"The hub's session key was rotated while the consent was in progress, which " +
					"invalidates every flow that was open at the time.",
			})
		return
	}
	bind := binding.Bind

	// Who authorised this consent.
	//
	// This request is a redirect from Google, and it does NOT arrive on
	// the route the gateway authenticates: the bootstrap surface exists
	// precisely so a callback is not swallowed by a login prompt, which
	// means the proxy adds no identity to it. So the operator is the one
	// the signed state names — established at the start of the flow, on a
	// request the gateway did authenticate, and pinned to this browser by
	// the cookie checked just above.
	//
	// A request that does carry an identity is still preferred, because a
	// standalone installation signs in with this hub's own session and has
	// one here.
	actor := binding.Actor
	if id, ok := IdentityFrom(r.Context()); ok && id.Can(access.RoleOperator) {
		actor = id.Who()
	}
	if actor == "" {
		s.consentProblem(w, r, http.StatusForbidden,
			"Connecting a directory needs the operator role.", "", nil)
		return
	}
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))

	ws, b, err := conn.Exchange(r.Context(), r.URL.Query().Get("code"), bind)
	if err != nil {
		s.log.WarnContext(r.Context(), "consent exchange failed", "backend", conn.Kind(), "error", err)
		s.consentProblem(w, r, http.StatusConflict,
			providerName(conn.Kind())+" granted the consent, and then refused the first read with it.",
			err.Error(), consentCauses)
		return
	}
	if bind != "" && ws.ID != bind {
		s.consentProblem(w, r, http.StatusConflict,
			"That consent is for a different tenant than the workspace being reconnected.", "", []string{
				"The account chooser offered the account last used rather than the one this " +
					"workspace belongs to.",
			})
		return
	}
	ws.ConnectedBy = actor
	if _, err = s.hub.Adopt(r.Context(), ws, b); err != nil {
		s.log.ErrorContext(r.Context(), "the workspace could not be adopted",
			"workspace", ws.ID, "error", err)
		s.consentProblem(w, r, http.StatusConflict,
			"The consent worked, but the workspace could not be saved.", err.Error(), nil)
		return
	}
	s.log.InfoContext(r.Context(), "workspace connected",
		"workspace", ws.ID, "backend", b.Kind(), "by", logsafe.Value(actor))
	// Straight to the question the connect leaves behind: which of this
	// tenant's domains this hub should answer for. Asking here, once, is
	// the difference between an operator choosing and an operator
	// discovering afterwards what was chosen for them.
	http.Redirect(w, r, "/#/directories/"+url.PathEscape(ws.ID)+"?choose=domains", http.StatusFound)
}

// whoamiBody is the shape every adapter of the Go module serves, so that a
// console UI needs no knowledge of the proxy's header names.
type whoamiBody struct {
	Status     string   `json:"status"`
	Email      string   `json:"email,omitempty"`
	Name       string   `json:"name,omitempty"`
	GivenName  string   `json:"givenName,omitempty"`
	FamilyName string   `json:"familyName,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Source     string   `json:"source,omitempty"`
	// Groups are the internal groups the policy puts the caller in.
	Groups []string `json:"groups,omitempty"`
	// Scopes are roles held over ONE workspace each, keyed by workspace
	// id. Roles above is the installation-wide answer and is not a
	// summary of these: an identity with a global role carries no scopes,
	// and a console reading this must treat "no scopes" as "everywhere"
	// only when Roles says so.
	Scopes map[string][]string `json:"scopes,omitempty"`
	// Version is the build the hub is running, so that a console can show
	// it without a second call.
	Version    string `json:"version"`
	SignOutURL string `json:"signOutUrl,omitempty"`
	// IssuerURL is where this console's shared issuer sits (INF-687),
	// same origin as the console, so the browser reaches its
	// SessionService directly with the SSO cookie. Empty for a hub
	// deployed alone with no issuer -- which is what every deployment
	// that sets nothing new here still gets -- and the console's
	// sessions sections render only when it is set.
	//
	// It is the forwarded bearer's issuer: the same URL this hub already
	// verifies a gateway-forwarded token against
	// (access.login.forwardedBearer.issuer), which on one origin IS the
	// issuer the console shares its host with.
	IssuerURL string `json:"issuerUrl,omitempty"`
}

func (s *ConsoleServer) whoami(w http.ResponseWriter, r *http.Request) {
	body := whoamiBody{Status: "signed-out", Version: version.String(), IssuerURL: s.forwarded.Issuer}
	if id, ok := IdentityFrom(r.Context()); ok {
		body = whoamiBody{
			Status:     "signed-in",
			Email:      id.Email,
			Name:       id.Name(),
			GivenName:  id.GivenName,
			FamilyName: id.FamilyName,
			Roles:      rolesOf(id.Role),
			Scopes:     scopesBody(id.Scopes),
			Source:     string(id.Source),
			Groups:     id.Groups,
			Version:    version.String(),
			SignOutURL: s.signOut(),
			IssuerURL:  s.forwarded.Issuer,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.WarnContext(r.Context(), "whoami could not be written", "error", err)
	}
}

// rolesOf expands a role into every role it implies, so that a UI can ask
// for one without knowing the hierarchy.
// scopesBody renders the per-workspace roles the same way rolesOf renders
// the global one, so a console asks the same question of both.
func scopesBody(scopes map[string]access.Role) map[string][]string {
	if len(scopes) == 0 {
		return nil
	}
	out := make(map[string][]string, len(scopes))
	for workspace, role := range scopes {
		out[workspace] = rolesOf(role)
	}
	return out
}

func rolesOf(r access.Role) []string {
	switch r {
	case access.RoleOperator:
		return []string{"operator", "viewer"}
	case access.RoleViewer:
		return []string{"viewer"}
	case access.RoleNone:
		return nil
	default:
		return nil
	}
}

// jsonField reads one string field from a JSON body, for callers that post
// JSON rather than a form.
func jsonField(r *http.Request, name string) string {
	var body map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<10)).Decode(&body); err != nil {
		return ""
	}
	return body[name]
}

// redirectOrOK sends a browser onwards and answers a programmatic caller
// with an empty 204.
func redirectOrOK(w http.ResponseWriter, r *http.Request, to string) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
