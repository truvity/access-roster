package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

// defaultClientID is the client the CLI signs in as unless --client-id names another. The installation declares the
// client (an InstallationClient, ADR 0021); until the CLI reads that declaration, the flag names it.
const defaultClientID = "sluis-cli"

type loginFlags struct {
	issuer, clientID string
	noBrowser        bool
	secretFd         int
	timeout          time.Duration
}

func (f *loginFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&f.issuer, "issuer", "", "the issuer URL; from the cache when signed in before")
	fs.StringVar(&f.clientID, "client-id", defaultClientID, "the client the CLI signs in as")
	fs.BoolVar(&f.noBrowser, "no-browser", false, "print the sign-in URL and do not open a browser")
	fs.IntVar(&f.secretFd, "secret-fd", -1, "read the client secret from this descriptor, for an issuer that registers the CLI as a confidential client")
	fs.DurationVar(&f.timeout, "timeout", 5*time.Minute, "how long to wait for the browser")
}

// readSecret reads the client secret from the descriptor, or returns "" when none is named.
func (a *app) readSecret(fd int) (string, error) {
	if fd < 0 {
		return "", nil
	}
	r := a.secretFd(fd)
	if r == nil {
		return "", cli.Usage(errors.New("--secret-fd: not an open descriptor"))
	}
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return "", fmt.Errorf("--secret-fd: %w", err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func (a *app) loginCommand() command {
	var f loginFlags
	return command{
		name:  "login",
		flags: f.add,
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) > 0 {
				return cli.Usage(errors.New("login takes no argument"))
			}
			return a.login(ctx, f, res)
		},
	}
}

// login is the authorization code flow with PKCE S256 and a loopback redirect (RFC 6749 section 4.1; RFC 7636; RFC 8252 section 7.3).
func (a *app) login(ctx context.Context, f loginFlags, res *result) error {
	issuer := f.issuer
	if issuer == "" {
		_, s, err := a.loadSet("")
		if err != nil {
			return err
		}
		issuer = s.Issuer
	}
	secret, err := a.readSecret(f.secretFd)
	if err != nil {
		return err
	}
	dir, err := a.cacheDir()
	if err != nil {
		return err
	}
	prov, err := discover(ctx, a.hc, issuer)
	if err != nil {
		return err
	}
	k, err := newPKCE()
	if err != nil {
		return err
	}
	state, err := randomString(24)
	if err != nil {
		return err
	}
	nonce, err := randomString(24)
	if err != nil {
		return err
	}

	// RFC 8252 section 7.3: a loopback redirect on the IP literal, with a port the operating system picks.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("loopback listener: %w", err)
	}
	redirect := fmt.Sprintf("http://%s/callback", ln.Addr().String())
	cb := make(chan callback, 1)
	srv := &http.Server{Handler: callbackHandler(state, cb), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	target, err := authURL(prov, f.clientID, redirect, state, nonce, k)
	if err != nil {
		return err
	}
	opened := false
	if !f.noBrowser {
		opened = a.openBrowser(target) == nil
	}
	if !opened {
		_, _ = fmt.Fprintf(a.stderr, "Open this URL in a browser to sign in:\n%s\n", target)
	}

	wait, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	var got callback
	select {
	case got = <-cb:
	case <-wait.Done():
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("timed out waiting for the browser")
	}
	if got.errCode != "" {
		return refused("login." + got.errCode)
	}

	c := &client{hc: a.hc, id: f.clientID, secret: secret, endpoint: prov.TokenEndpoint}
	tr, err := c.post(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {got.code},
		"redirect_uri":  {redirect},
		"code_verifier": {k.verifier},
	})
	if err != nil {
		return tokenError(err, "login.token")
	}
	if tr.IDToken == "" {
		return refused("login.id_token")
	}
	sub, err := idTokenClaims(tr.IDToken, issuer, f.clientID, nonce, a.now())
	if err != nil {
		return err
	}
	set := &tokenSet{
		Issuer:        issuer,
		ClientID:      f.clientID,
		TokenEndpoint: prov.TokenEndpoint,
		Subject:       sub,
		AccessToken:   tr.AccessToken,
		RefreshToken:  tr.RefreshToken,
		ExpiresAt:     a.now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC(),
	}
	if err := writeSet(dir, set); err != nil {
		return fmt.Errorf("token cache: %w", err)
	}
	res.Login = &loginOut{Issuer: issuer, ClientID: f.clientID, Subject: sub, ExpiresAt: set.ExpiresAt.Format(time.RFC3339)}
	res.Text = fmt.Sprintf("signed in at %s as %s; the access token is valid until %s", issuer, sub, res.Login.ExpiresAt)
	return nil
}

// tokenError maps an error of the token endpoint: a refusal of the issuer is exit 3, anything else exit 1. The
// reason never carries the issuer's error code, so an unknown and a refused audience look the same.
func tokenError(err error, reason string) error {
	var oe *oauthError
	if errors.As(err, &oe) && oe.status >= 400 && oe.status < 500 {
		return refused(reason)
	}
	return err
}

// callback is what the browser brought back to the loopback redirect.
type callback struct{ code, errCode string }

// callbackHandler takes the first request to /callback that carries the state, and ignores the rest (RFC 6749
// section 10.12: a redirect without the expected state is not ours).
func callbackHandler(state string, out chan<- callback) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "unexpected state", http.StatusBadRequest)
			return
		}
		cb := callback{code: q.Get("code")}
		if e := q.Get("error"); e != "" {
			cb.errCode = "error"
			if validErrorCode(e) {
				cb.errCode = e
			}
		} else if cb.code == "" {
			http.Error(w, "no code", http.StatusBadRequest)
			return
		}
		select {
		case out <- cb:
		default:
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if cb.errCode != "" {
			_, _ = io.WriteString(w, "Sign-in was not completed. You can close this window.\n")
			return
		}
		_, _ = io.WriteString(w, "Signed in to sluis. You can close this window.\n")
	})
	return mux
}
