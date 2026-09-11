package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// login runs the browser flow once and caches what came back.
//
// Authorization code with PKCE on a LOOPBACK port, which is the only
// browser flow left: the device flow was withdrawn (INF-693) because
// nobody signs in from a machine with no browser here. A loopback
// redirect is what makes a public client safe without a secret — the
// code comes back to a port only this process is listening on, and PKCE
// means a code seen by anything else cannot be redeemed.
func login(args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	issuer := flags.String("issuer", "", "the access-roster issuer, e.g. https://access.example")
	clientID := flags.String("client", "", "the client to sign in as (default "+DefaultClientID+")")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}

	cfg, err := loadConfig(*issuer, *clientID)
	if err != nil {
		return err
	}

	// Port zero: the kernel picks, so two laptops and two shells do not
	// fight over one number, and the redirect is registered as a pattern
	// rather than an exact port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on loopback: %w", err)
	}
	defer func() { _ = listener.Close() }()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	verifier := random()
	state := random()
	query := url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"scope":                 {"openid offline_access"},
		"redirect_uri":          {redirect},
		"state":                 {state},
		"code_challenge":        {challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	where := cfg.Issuer + "/authorize?" + query.Encode()

	_, _ = fmt.Fprintln(stdout, "Opening your browser to sign in.")
	_, _ = fmt.Fprintln(stdout, "If it does not open, go to:")
	_, _ = fmt.Fprintln(stdout, "  "+where)
	openBrowser(where)

	code, err := waitForCode(listener, state)
	if err != nil {
		return err
	}

	session, err := redeem(context.Background(), cfg, code, verifier, redirect)
	if err != nil {
		return err
	}
	if err = saveConfig(cfg); err != nil {
		return err
	}
	if err = saveSession(session); err != nil {
		return err
	}

	who := session.Email
	if who == "" {
		who = session.Subject
	}
	_, _ = fmt.Fprintf(stdout, "Signed in as %s.\n", who)
	return nil
}

// waitForCode serves the one request the browser is about to make.
//
// It answers with a page rather than closing the connection, because a
// browser left on a failed request is how somebody concludes the sign-in
// did not work when it did.
func waitForCode(listener net.Listener, state string) (string, error) {
	type result struct {
		code string
		err  error
	}
	answers := make(chan result, 1)

	server := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			if failure := query.Get("error"); failure != "" {
				detail := query.Get("error_description")
				if detail == "" {
					detail = failure
				}
				page(w, "Sign-in refused", detail)
				answers <- result{err: fmt.Errorf("the issuer refused the sign-in: %s", detail)}
				return
			}
			// The state is checked before the code is used: a callback
			// somebody else caused is not one to redeem.
			if query.Get("state") != state {
				page(w, "Sign-in refused", "That response does not belong to this sign-in.")
				answers <- result{err: errors.New("the callback did not match this sign-in")}
				return
			}
			code := query.Get("code")
			if code == "" {
				page(w, "Sign-in refused", "No authorization code came back.")
				answers <- result{err: errors.New("no authorization code came back")}
				return
			}
			page(w, "Signed in", "You can close this tab and go back to the terminal.")
			answers <- result{code: code}
		}),
	}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	select {
	case answer := <-answers:
		return answer.code, answer.err
	case <-time.After(3 * time.Minute):
		// Long enough for a password manager, a second factor and a
		// consent screen; short enough that a forgotten terminal does
		// not hold a port all afternoon.
		return "", errors.New("timed out waiting for the browser")
	}
}

// redeem trades the code for tokens.
func redeem(ctx context.Context, cfg Config, code, verifier, redirect string) (Session, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Issuer+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return Session{}, fmt.Errorf("build the token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %w", errUnreachable, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf("the issuer refused the code: %s", strings.TrimSpace(string(body)))
	}

	var granted struct {
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &granted); err != nil {
		return Session{}, fmt.Errorf("parse the token response: %w", err)
	}
	if granted.RefreshToken == "" {
		// Without one, every later command would open a browser. The
		// scope asked for offline_access, so this means the client is
		// declared without it.
		return Session{}, errors.New("the issuer returned no refresh token: this client cannot stay signed in")
	}

	session := Session{RefreshToken: granted.RefreshToken}
	// The ID token is read for the person's own name only, and is not
	// verified here: it was just received over TLS from the issuer this
	// process chose, and nothing is authorized on it.
	if subject, email, ok := readIDToken(granted.IDToken); ok {
		session.Subject, session.Email = subject, email
	}
	return session, nil
}

// readIDToken reads `sub` and `email` for display. Unverified, and used
// for nothing else.
func readIDToken(token string) (subject, email string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return "", "", false
	}
	return claims.Subject, claims.Email, true
}

// page is the one thing the browser sees from this process.
//
// Everything is escaped, and the message especially: it carries the
// issuer's `error_description` straight off the query string, so it is
// attacker-controlled by anyone who can make a browser visit this
// loopback port while a sign-in is running. Reflecting it unescaped was
// a reflected XSS, and CodeQL was right to say so.
func page(w http.ResponseWriter, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Nothing on this page loads a script, so the policy says exactly
	// that. It costs one header and closes the whole class rather than
	// this one instance of it.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	safeTitle, safeMessage := html.EscapeString(title), html.EscapeString(message)
	_, _ = fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:4rem auto;max-width:32rem;padding:0 1rem}</style>
<h1>%s</h1><p>%s</p>`, safeTitle, safeTitle, safeMessage)
}

// openBrowser asks the desktop to open a URL, and does not care whether
// it worked: the address is printed above either way, which is the only
// thing that has to be true on a machine with no desktop at all.
func openBrowser(where string) {
	var command string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		command = "open"
	case "windows":
		command, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		command = "xdg-open"
	}
	_ = exec.Command(command, append(args, where)...).Start() //nolint:gosec // a URL this process built
}

func random() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
