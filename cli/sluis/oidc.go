package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const maxBody = 1 << 20

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		// A redirect from an issuer endpoint is not followed: it would carry a request body, or a code, elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// checkEndpoint accepts an https URL, or an http URL on a loopback host (decision D-11: an http issuer is for
// development on one machine). The trust roots are the system's; SSL_CERT_FILE extends them for a harness CA, and there
// is no flag that turns verification off.
func checkEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("not an absolute URL without credentials or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("an http URL is accepted only on a loopback host")
		}
	default:
		return nil, errors.New("not an https URL")
	}
	return u, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// provider is the part of the issuer's metadata that the CLI uses (OpenID Connect Discovery 1.0 section 3).
type provider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

// discover reads the issuer's metadata. The issuer in the document must equal the one asked for (OpenID Connect
// Discovery 1.0 section 4.3; RFC 8414 section 3.3).
func discover(ctx context.Context, hc *http.Client, issuer string) (*provider, error) {
	if _, err := checkEndpoint(issuer); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	// Discovery section 4: the well-known path is appended after any terminating slash is removed.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil) //nolint:gosec // the issuer is checked by checkEndpoint above
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req) //nolint:gosec // the issuer is checked by checkEndpoint
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", urlErrorWithoutURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: the issuer answered %d", resp.StatusCode)
	}
	var p provider
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&p); err != nil {
		return nil, errors.New("discovery: the metadata is not JSON")
	}
	if p.Issuer != issuer {
		return nil, refused("discovery.issuer")
	}
	for field, ep := range map[string]string{"authorization_endpoint": p.AuthorizationEndpoint, "token_endpoint": p.TokenEndpoint} {
		if _, err := checkEndpoint(ep); err != nil {
			return nil, refused("discovery." + field)
		}
	}
	if len(p.CodeChallengeMethods) > 0 && !contains(p.CodeChallengeMethods, "S256") {
		return nil, refused("discovery.code_challenge_methods_supported")
	}
	return &p, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// urlErrorWithoutURL drops the URL from a transport error: a URL may carry a query, and an error names a path, not a value.
func urlErrorWithoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkce is a code verifier and its S256 challenge (RFC 7636 sections 4.1 and 4.2).
type pkce struct{ verifier, challenge string }

func newPKCE() (pkce, error) {
	// 32 random octets encode to 43 characters, the shortest verifier RFC 7636 section 4.1 allows.
	v, err := randomString(32)
	if err != nil {
		return pkce{}, err
	}
	sum := sha256.Sum256([]byte(v))
	return pkce{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// authURL is the authorization request of RFC 6749 section 4.1.1 with PKCE (RFC 7636 section 4.3).
func authURL(p *provider, clientID, redirect, state, nonce string, k pkce) (string, error) {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", k.challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// tokenResponse is a successful answer of the token endpoint (RFC 6749 section 5.1; RFC 8693 section 2.2.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

// oauthError is an error answer of the token endpoint (RFC 6749 section 5.2). It keeps the code, which is a short
// registered word, and drops the description, which the issuer writes freely.
type oauthError struct {
	status int
	code   string
}

func (e *oauthError) Error() string {
	if e.code != "" {
		return fmt.Sprintf("the token endpoint refused the request (%s)", e.code)
	}
	return fmt.Sprintf("the token endpoint answered %d", e.status)
}

// client is the CLI as a client of the issuer. A public client sends client_id in the body; a confidential one
// (an installation whose issuer registers the CLI with a secret) authenticates with HTTP Basic (RFC 6749 section 2.3.1).
type client struct {
	hc       *http.Client
	id       string
	secret   string
	endpoint string
}

func (c *client) post(ctx context.Context, form url.Values) (*tokenResponse, error) {
	if c.secret == "" {
		form.Set("client_id", c.id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.secret != "" {
		// RFC 6749 section 2.3.1: both parts are form-encoded before the Basic encoding.
		req.SetBasicAuth(url.QueryEscape(c.id), url.QueryEscape(c.secret))
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", urlErrorWithoutURL(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		oe := &oauthError{status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && validErrorCode(e.Error) {
			oe.code = e.Error
		}
		return nil, oe
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return nil, errors.New("token endpoint: the answer holds no access token")
	}
	return &tr, nil
}

// validErrorCode accepts the characters of RFC 6749 section 5.2's error codes.
func validErrorCode(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// idTokenClaims checks the identity token of the code exchange and returns its subject. The token comes straight
// from the token endpoint of the issuer over the connection that was just checked, so the signature is not checked
// (OpenID Connect Core 1.0 section 3.1.3.7, item 6); the issuer, the audience, the expiry and the nonce are
// (items 2, 3, 9 and 11).
func idTokenClaims(raw, issuer, clientID, nonce string, now time.Time) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("id_token: not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("id_token: the payload is not base64url")
	}
	var c struct {
		Iss   string          `json:"iss"`
		Sub   string          `json:"sub"`
		Aud   json.RawMessage `json:"aud"`
		Exp   int64           `json:"exp"`
		Nonce string          `json:"nonce"`
		Azp   string          `json:"azp"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", errors.New("id_token: the payload is not JSON")
	}
	var aud []string
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		aud = []string{one}
	} else if json.Unmarshal(c.Aud, &aud) != nil {
		return "", errors.New("id_token: aud is neither a string nor a list")
	}
	switch {
	case c.Iss != issuer:
		return "", refused("id_token.iss")
	case !contains(aud, clientID):
		return "", refused("id_token.aud")
	case len(aud) > 1 && c.Azp != clientID:
		return "", refused("id_token.azp")
	case c.Exp == 0 || !time.Unix(c.Exp, 0).After(now):
		return "", refused("id_token.exp")
	case c.Nonce != nonce:
		return "", refused("id_token.nonce")
	}
	return c.Sub, nil
}

// openBrowser asks the desktop to open a URL. It returns once the helper has started.
func openBrowser(u string) error {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "linux", "freebsd", "openbsd", "netbsd":
		name = "xdg-open"
	default:
		return errors.New("no browser opener on this system")
	}
	cmd := exec.Command(name, u) //nolint:gosec // the helper is fixed by the system and the URL is built by this program
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
