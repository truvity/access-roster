package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/truvity/sluis/v2/tools/harness/kclogin"
)

// session is one run's browser, CLI home and proxy.
type session struct {
	cfg    *config
	hc     *http.Client
	driver *kclogin.Driver
	proxy  *proxy
	home   string // XDG_CONFIG_HOME and HOME of the CLI: the token cache is below it
	user   string
	creds  kclogin.Credentials
}

// newSession prepares the sign-in of a user of the identity provider: the secrets are read here, from the file, and
// held in the Credentials only.
func newSession(cfg *config, user string) (*session, error) {
	u := strings.ToUpper(user)
	sec, err := secretsOf(cfg.secrets, u+"_PASSWORD", u+"_TOTP_BASE32")
	if err != nil {
		return nil, err
	}
	px, err := cfg.startProxy()
	if err != nil {
		return nil, err
	}
	home, err := os.MkdirTemp("", "person-home-")
	if err != nil {
		px.Close()
		return nil, err
	}
	hc := cfg.httpClient()
	s := &session{
		cfg: cfg, hc: hc, proxy: px, home: home, user: strings.ToLower(user),
		creds: kclogin.Credentials{Username: strings.ToLower(user), Password: sec[u+"_PASSWORD"], TOTPSecret: sec[u+"_TOTP_BASE32"]},
	}
	// The sign-in ends at the CLI's loopback redirect: the request is handed to the CLI, as the browser would.
	s.driver = &kclogin.Driver{Client: hc, Stop: func(x *url.URL) bool { return x.Hostname() == "127.0.0.1" && x.Port() != "8180" }}
	if os.Getenv("PERSON_TRACE") != "" {
		s.driver.Trace = func(l string) { fmt.Fprintln(os.Stderr, "trace:", l) }
	}
	return s, nil
}

func (s *session) close() {
	s.proxy.Close()
	_ = os.RemoveAll(s.home) //nolint:gosec // G703: the directory this process made
}

// cliCmd is the sluis executable with the environment of a person's workstation: the harness CA, the proxy to the
// forwarder, and a home of its own for the token cache.
func (s *session) cliCmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, s.cfg.cli, args...) //nolint:gosec // the CLI of this build
	c.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + s.home, "XDG_CONFIG_HOME=" + s.home,
		"SSL_CERT_FILE=" + s.cfg.caFile, "HTTPS_PROXY=" + s.proxy.URL(), "NO_PROXY=",
	}
	return c
}

// login runs `sluis login`, drives the identity provider's forms, hands the redirect to the CLI, and returns what the CLI
// printed. The CLI prints the sign-in URL on its standard error because it is told not to open a browser.
func (s *session) login(ctx context.Context) (string, error) {
	cmd := s.cliCmd(ctx, "login", "--issuer", issuer, "--no-browser", "--timeout", "3m")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	urls := make(chan string, 1)
	var stderr bytes.Buffer
	go func() {
		sc := bufio.NewScanner(errPipe)
		for sc.Scan() {
			l := sc.Text()
			if strings.HasPrefix(l, "https://") {
				urls <- l
			} else {
				stderr.WriteString(l + "\n")
			}
		}
		close(urls)
	}()
	fail := func(err error) (string, error) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", err
	}
	var authURL string
	select {
	case authURL = <-urls:
	case <-time.After(30 * time.Second):
		return fail(errors.New("sluis login printed no sign-in URL"))
	}
	if authURL == "" {
		return fail(fmt.Errorf("sluis login printed no sign-in URL: %s", firstLine(stderr.String())))
	}
	back, err := s.driver.Authorize(ctx, authURL, s.creds)
	if err != nil {
		return fail(err)
	}
	res, err := s.hc.Get(back.String()) //nolint:gosec // the CLI's own loopback redirect, as printed by the identity provider's flow
	if err != nil {
		return fail(fmt.Errorf("the CLI's loopback redirect: %w", err))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	_ = res.Body.Close()
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("sluis login: %w: %s", err, firstLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// token runs `sluis token --audience`. The CLI prints the access token on its standard output and nothing else.
func (s *session) token(ctx context.Context, aud string) (string, error) {
	cmd := s.cliCmd(ctx, "token", "--issuer", issuer, "--audience", aud)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("sluis token: %w: %s", err, firstLine(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// idToken signs the same user in again, as a protocol client of sluis-cli, to read the ID token: the CLI keeps the access
// token and the refresh token and drops the ID token after it has checked it. The identity provider's own session
// answers the second sign-in, so the form is not shown again.
func (s *session) idToken(ctx context.Context) (string, error) {
	var disc struct {
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, s.hc, issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return "", err
	}
	ver, err := randomB64(32)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(ver))
	state, _ := randomB64(12)
	nonce, _ := randomB64(12)
	const redirect = "http://127.0.0.1:49152/callback" // the loopback redirect of the installation's client, any port
	au, err := url.Parse(disc.Authorization)
	if err != nil {
		return "", err
	}
	q := url.Values{"response_type": {"code"}, "client_id": {cliID}, "redirect_uri": {redirect}, "scope": {"openid"}, "state": {state},
		"nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	au.RawQuery = q.Encode()
	back, err := s.driver.Authorize(ctx, au.String(), s.creds)
	if err != nil {
		return "", err
	}
	if back.Query().Get("state") != state || back.Query().Get("code") == "" {
		return "", errors.New("the second sign-in did not return a code for this state")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")}, "redirect_uri": {redirect},
		"code_verifier": {ver}, "client_id": {cliID}}
	res, err := s.hc.PostForm(disc.Token, form)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	var tr struct {
		IDToken string `json:"id_token"`
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK || json.Unmarshal(b, &tr) != nil || tr.IDToken == "" {
		return "", fmt.Errorf("the token endpoint answered %d with no ID token", res.StatusCode)
	}
	// nonce: the ID token must carry the one this request sent (OpenID Connect Core section 3.1.3.7).
	_, claims, err := parseToken(tr.IDToken)
	if err != nil {
		return "", err
	}
	if claims["nonce"] != nonce {
		return "", errors.New("the ID token does not carry the nonce of the request")
	}
	return tr.IDToken, nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", req.URL.Path, err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK || json.Unmarshal(b, into) != nil {
		return fmt.Errorf("GET %s: status %d", req.URL.Path, res.StatusCode)
	}
	return nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// parseToken returns the header and the claims of a compact JWS. The signature is never decoded or shown.
func parseToken(token string) (header, claims map[string]any, err error) {
	p := strings.Split(token, ".")
	if len(p) != 3 {
		return nil, nil, errors.New("the token is not a compact JWS")
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(p[i])
		if err != nil || json.Unmarshal(b, dst) != nil {
			return nil, nil, errors.New("the token is not base64url JSON")
		}
	}
	return header, claims, nil
}

// verifyToken checks the signature of an ES384 JWS against the issuer's key set at /jwks (RFC 7515 section 5.2).
func verifyToken(token string, set *jose.JSONWebKeySet) (kid string, err error) {
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil || len(jws.Signatures) != 1 {
		return "", errors.New("the token is not a single ES384 signature")
	}
	kid = jws.Signatures[0].Header.KeyID
	keys := set.Key(kid)
	if len(keys) == 0 {
		return "", fmt.Errorf("the key set has no key %q", kid)
	}
	if _, err := jws.Verify(keys[0]); err != nil {
		return "", errors.New("the signature does not verify with the key set at /jwks")
	}
	return kid, nil
}

// loginCommand is `person login USER`: the CLI's sign-in alone, headless. It leaves nothing behind: the token cache is
// in a directory that goes with the process.
func loginCommand(args []string) error {
	user := "alice"
	if len(args) > 0 {
		user = args[0]
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	s, err := newSession(cfg, user)
	if err != nil {
		return err
	}
	defer s.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := s.login(ctx)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}
