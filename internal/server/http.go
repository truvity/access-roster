package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/hub"
	"github.com/truvity/access-roster/rules"
)

// AdminAccount is the break-glass account: a generated password, kept as a
// digest. The password is 32 bytes of machine-generated entropy and never
// chosen by a person, so a fast digest is the right tool — there is
// nothing to brute-force and no password to reuse elsewhere.
type AdminAccount struct {
	Enabled bool
	digest  [32]byte
}

// NewAdminAccount returns an enabled admin account for a password.
func NewAdminAccount(password string) AdminAccount {
	return AdminAccount{Enabled: true, digest: sha256.Sum256([]byte(password))}
}

// verify reports whether the password is the one.
func (a AdminAccount) verify(password string) bool {
	got := sha256.Sum256([]byte(password))
	return a.Enabled && subtle.ConstantTimeCompare(got[:], a.digest[:]) == 1
}

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
	admin      AdminAccount
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
	Admin      AdminAccount
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
		admin:      deps.Admin,
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
	mux.HandleFunc("POST /admin/login", s.adminLogin)
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
		if email := strings.TrimSpace(r.Header.Get(s.forwarded.EmailHeader)); email != "" {
			return access.Principal{
				Email:   email,
				Subject: email,
				Source:  access.SourceForwarded,
				Issuer:  s.forwarded.Issuer,
			}, true
		}
	}
	return access.Principal{}, false
}

// loginPage is the plain page a standalone installation signs in on. Where
// a gateway fronts the console it is never reached: the proxy has already
// run the login and forwards the bearer.
func (s *ConsoleServer) loginPage(w http.ResponseWriter, r *http.Request) {
	if id, ok := IdentityFrom(r.Context()); ok && id.Role != rules.RoleNone {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	var sources strings.Builder
	for kind := range s.connectors {
		fmt.Fprintf(&sources,
			`<p><a class="btn" href="/login/%s/start">Sign in with the %s directory</a></p>`, kind, kind)
	}
	admin := ""
	if s.admin.Enabled {
		admin = `<form method="post" action="/admin/login">
			<p><label>Break-glass admin password<br><input type="password" name="password" autofocus></label></p>
			<p><button type="submit">Sign in as admin</button></p>
		</form>
		<p class="note">The admin account is for day one and for the day the directory
		is what is broken. Turn it off once a rule grants operator to a real identity.</p>`
	}
	if _, err := fmt.Fprintf(w, loginHTML, sources.String(), admin); err != nil {
		s.log.WarnContext(r.Context(), "login page could not be written", "error", err)
	}
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

// adminLogin signs the break-glass account in.
func (s *ConsoleServer) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !s.admin.Enabled {
		http.Error(w, "the admin account is disabled", http.StatusForbidden)
		return
	}
	password := r.FormValue("password")
	if password == "" {
		password = jsonField(r, "password")
	}
	if !s.admin.verify(password) {
		s.log.WarnContext(r.Context(), "admin sign-in refused", "remote", r.RemoteAddr)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	if err := s.sessions.Issue(w, access.Principal{Email: "admin", Subject: "admin", Source: access.SourceAdmin}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.InfoContext(r.Context(), "admin signed in")
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
	if !ok || !id.Can(rules.RoleOperator) {
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
	http.SetCookie(w, &http.Cookie{Name: access.ConnectCookieName, Path: "/", MaxAge: -1})

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
	Status     string    `json:"status"`
	Email      string    `json:"email,omitempty"`
	Name       string    `json:"name,omitempty"`
	Roles      []string  `json:"roles,omitempty"`
	Source     string    `json:"source,omitempty"`
	Matched    []string  `json:"matchedRules,omitempty"`
	ExpiresAt  time.Time `json:"expiresAt,omitzero"`
	SignOutURL string    `json:"signOutUrl,omitempty"`
}

func (s *ConsoleServer) whoami(w http.ResponseWriter, r *http.Request) {
	body := whoamiBody{Status: "signed-out"}
	if id, ok := IdentityFrom(r.Context()); ok {
		body = whoamiBody{
			Status:     "signed-in",
			Email:      id.Email,
			Roles:      rolesOf(id.Role),
			Source:     string(id.Source),
			Matched:    id.Matched,
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
func rolesOf(r rules.Role) []string {
	switch r {
	case rules.RoleOperator:
		return []string{"operator", "viewer"}
	case rules.RoleViewer:
		return []string{"viewer"}
	case rules.RoleNone:
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
