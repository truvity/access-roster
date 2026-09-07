package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/emailaddr"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/internal/version"
)

// ForwardedIdentity configures how a bearer forwarded by an authenticating
// gateway becomes a principal.
type ForwardedIdentity struct {
	// Issuer the bearer is verified against. Empty disables the source.
	Issuer string
	// EmailHeader is the header the proxy puts the caller's address in.
	// Trusting a header is only safe where nothing but the proxy can reach
	// this listener, which is what the NetworkPolicy is for; the
	// verified-bearer path replaces it in the built service.
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
	forwarded  ForwardedIdentity
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
	Recovery  Recovery
	Forwarded ForwardedIdentity
	Log       *slog.Logger
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
		forwarded:  deps.Forwarded,
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
			s.log.InfoContext(r.Context(), "authorization refused",
				"email", principal.Email, "source", principal.Source, "error", err)
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// One button per directory kind, never one per company: an anonymous
	// page that lists the companies an installation serves has published
	// them to anyone who loads it. Which tenant a person belongs to is
	// answered by the address the provider gives back, not by asking them
	// first — the provider's own account chooser has already asked.
	var sources strings.Builder
	for _, kind := range slices.Sorted(maps.Keys(s.connectors)) {
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
		recovery = fmt.Sprintf(`<details><summary class="note">Recovery sign-in</summary>
		<form method="post" action="/login/recovery">
			<p><label>%s<br><input type="password" name="proof" autocomplete="off"></label></p>
			<p><button type="submit">Recover access</button></p>
		</form>
		<p class="note">For the day the directory is what is broken. Present %s</p></details>`,
			html.EscapeString(recoveryLabel(s.recovery.Kind())), html.EscapeString(s.recovery.Prompt()))
	}
	if _, err := fmt.Fprintf(w, loginHTML, sources.String(), recovery); err != nil {
		s.log.WarnContext(r.Context(), "login page could not be written", "error", err)
	}
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

func recoveryLabel(kind string) string {
	if kind == "token" {
		return "Recovery token"
	}
	return "Recovery password"
}

const loginHTML = `<!doctype html><meta charset="utf-8"><title>Sign in — directory-roster</title>
<style>
 body{font:16px/1.5 system-ui,sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f3f5f8;color:#1b2230}
 main{background:#fff;padding:32px 36px;border-radius:8px;border:1px solid #d9dee6;max-width:26rem}
 h1{font-size:20px;margin:0 0 4px} p{margin:12px 0}
 input{width:100%%;padding:8px;border:1px solid #d9dee6;border-radius:4px;font:inherit}
 button,.btn{display:inline-block;padding:8px 14px;border:0;border-radius:4px;background:#0e7c7b;color:#fff;font:inherit;text-decoration:none;cursor:pointer}
 .note{font-size:14px;color:#6b7383}
</style>
<main><h1>directory-roster</h1>
<p class="note">The directory hub. Sign in to connect workspaces and grant access.</p>
%s%s</main>`

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
		s.log.WarnContext(r.Context(), "recovery refused", "remote", r.RemoteAddr, "reason", err)
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
	s.log.WarnContext(r.Context(), "recovery sign-in", "subject", subject, "kind", s.recovery.Kind())
	redirectOrOK(w, r, "/")
}

// logout clears the session. It cannot end a session elsewhere: rotating
// the session key is what does that, and it logs everyone out at once.
func (s *ConsoleServer) logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Clear(w)
	redirectOrOK(w, r, "/login")
}

// connectCallback finishes an admin-consent flow: it checks the state
// against the cookie, exchanges the code, and adopts the workspace.
func (s *ConsoleServer) connectCallback(w http.ResponseWriter, r *http.Request) {
	id, ok := IdentityFrom(r.Context())
	if !ok || !id.Can(access.RoleOperator) {
		http.Error(w, "this needs the operator role", http.StatusForbidden)
		return
	}
	conn, ok := s.connectors[r.PathValue("backend")]
	if !ok {
		http.Error(w, "unknown backend", http.StatusNotFound)
		return
	}

	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(access.ConnectCookieName)
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "this consent did not start in this browser", http.StatusBadRequest)
		return
	}
	bind, err := s.state.Verify(state)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, access.ConnectCookie("", s.sessions.Secure(), 0))

	ws, b, err := conn.Exchange(r.Context(), r.URL.Query().Get("code"), bind)
	if err != nil {
		s.log.WarnContext(r.Context(), "consent exchange failed", "backend", conn.Kind(), "error", err)
		http.Error(w, "the consent could not be completed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if bind != "" && ws.ID != bind {
		http.Error(w, "that consent is for a different tenant than the workspace being reconnected",
			http.StatusConflict)
		return
	}
	ws.ConnectedBy = id.Email
	if _, err = s.hub.Adopt(r.Context(), ws, b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.InfoContext(r.Context(), "workspace connected",
		"workspace", ws.ID, "backend", b.Kind(), "by", id.Email)
	http.Redirect(w, r, "/#workspaces", http.StatusFound)
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
	// Version is the build the hub is running, so that a console can show
	// it without a second call.
	Version    string `json:"version"`
	SignOutURL string `json:"signOutUrl,omitempty"`
}

func (s *ConsoleServer) whoami(w http.ResponseWriter, r *http.Request) {
	body := whoamiBody{Status: "signed-out", Version: version.String()}
	if id, ok := IdentityFrom(r.Context()); ok {
		body = whoamiBody{
			Status:     "signed-in",
			Email:      id.Email,
			Name:       id.Name(),
			GivenName:  id.GivenName,
			FamilyName: id.FamilyName,
			Roles:      rolesOf(id.Role),
			Source:     string(id.Source),
			Groups:     id.Groups,
			Version:    version.String(),
			SignOutURL: "/logout",
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
