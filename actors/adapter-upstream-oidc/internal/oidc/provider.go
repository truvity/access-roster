package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxBody = 1 << 20

	// metadataTTL is how long a discovery document and a key set are kept. The adapter holds nothing at rest: this is
	// memory, and a restart forgets it. A key id that the set does not hold makes one early refetch, at most once in
	// refetchGap, so a rotation shows within the gap and an unknown kid cannot be used to flood the upstream.
	metadataTTL = 10 * time.Minute
	refetchGap  = 30 * time.Second
)

// Provider is the part of an upstream's metadata that the adapter uses (OpenID Connect Discovery 1.0 section 3;
// RFC 9207 section 3 for authorization_response_iss_parameter_supported).
type Provider struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	// S256 is true unless the upstream lists its code challenge methods and S256 is not one of them.
	S256 bool
	// IssParameter is true when the upstream says it sends the iss parameter in its authorization response.
	IssParameter bool
	authority    string
}

type document struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	IssParameter          bool     `json:"authorization_response_iss_parameter_supported"`
}

type cachedProvider struct {
	p       *Provider
	fetched time.Time
}

type cachedKeys struct {
	set     *jose.JSONWebKeySet
	fetched time.Time
}

// Directory fetches and keeps, in memory, the discovery documents and key sets of the upstreams, and makes the calls
// to them. It is safe for concurrent use.
type Directory struct {
	dev, strict *http.Client
	now         func() time.Time

	mu        sync.Mutex
	providers map[string]cachedProvider
	keys      map[string]cachedKeys
}

// NewDirectory returns a Directory. now is the clock; nil means time.Now.
func NewDirectory(now func() time.Time) *Directory {
	if now == nil {
		now = time.Now
	}
	return &Directory{
		dev: newHTTPClient(true), strict: newHTTPClient(false), now: now,
		providers: map[string]cachedProvider{}, keys: map[string]cachedKeys{},
	}
}

func (d *Directory) client(development bool) *http.Client {
	if development {
		return d.dev
	}
	return d.strict
}

// get makes a GET to an endpoint of the upstream, and reads at most maxBody bytes of a 200 answer. The host is
// checked against the upstream's declared authority before the request leaves (REQ-ISO-110).
func (d *Directory) get(ctx context.Context, development bool, authority, raw, path string) ([]byte, error) {
	u, err := CheckURL(raw, development)
	if err != nil {
		return nil, Unsupported(path)
	}
	if Authority(u) != authority {
		return nil, Unsupported(path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, Unavailable(path)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.client(development).Do(req)
	if err != nil {
		return nil, transport(path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, statusRefusal(path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, Unavailable(path)
	}
	return body, nil
}

func statusRefusal(path string, status int) error {
	if status == http.StatusTooManyRequests {
		return RateLimited(path)
	}
	if status >= 500 {
		return Unavailable(path)
	}
	return Rejected(path)
}

// Provider returns the metadata of the issuer, from the memory or from discovery. The issuer in the document must equal
// the one asked for (OpenID Connect Discovery 1.0 section 4.3; RFC 8414 section 3.3), and every endpoint must be at
// the issuer's host.
func (d *Directory) Provider(ctx context.Context, issuer string, development bool) (*Provider, error) {
	iu, err := CheckURL(issuer, development)
	if err != nil {
		return nil, Unsupported("upstream.issuer")
	}
	key := issuer
	if development {
		key = "dev " + issuer
	}
	d.mu.Lock()
	c, ok := d.providers[key]
	d.mu.Unlock()
	if ok && d.now().Sub(c.fetched) < metadataTTL {
		return c.p, nil
	}
	authority := Authority(iu)
	// Discovery section 4: the well-known path is appended after any terminating slash is removed.
	body, err := d.get(ctx, development, authority, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", "discovery")
	if err != nil {
		return nil, err
	}
	var doc document
	if json.Unmarshal(body, &doc) != nil {
		return nil, Rejected("discovery")
	}
	if doc.Issuer != issuer {
		return nil, Rejected("discovery.issuer")
	}
	for field, ep := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI,
	} {
		eu, err := CheckURL(ep, development)
		if err != nil || Authority(eu) != authority {
			// An endpoint at another host is outside what the Upstream declares.
			return nil, Unsupported("discovery." + field)
		}
	}
	p := &Provider{
		Issuer: issuer, AuthorizationEndpoint: doc.AuthorizationEndpoint, TokenEndpoint: doc.TokenEndpoint, JWKSURI: doc.JWKSURI,
		S256:         len(doc.CodeChallengeMethods) == 0 || contains(doc.CodeChallengeMethods, "S256"),
		IssParameter: doc.IssParameter, authority: authority,
	}
	d.mu.Lock()
	d.providers[key] = cachedProvider{p: p, fetched: d.now()}
	d.mu.Unlock()
	return p, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// AuthorizationURL is the authorization request of RFC 6749 section 4.1.1 with PKCE (RFC 7636 section 4.3) and the
// nonce of OpenID Connect Core 1.0 section 3.1.2.1. The state, the nonce and the challenge are session's.
func (p *Provider) AuthorizationURL(clientID, redirectURI, state, nonce, challenge string, scopes []string) (string, error) {
	u, err := url.Parse(p.AuthorizationEndpoint)
	if err != nil {
		return "", Rejected("discovery.authorization_endpoint")
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// CodeRequest is the token request of RFC 6749 section 4.1.3 with the verifier of RFC 7636 section 4.5.
type CodeRequest struct {
	ClientID, ClientSecret, Code, RedirectURI, CodeVerifier string
}

// Exchange sends the code to the token endpoint and returns the ID token of the answer. The client authenticates with
// HTTP Basic (RFC 6749 section 2.3.1). The access token and the refresh token of the answer are not read: the adapter
// asks for an identity, and keeps nothing.
func (d *Directory) Exchange(ctx context.Context, p *Provider, development bool, r CodeRequest) (string, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {r.Code}, "redirect_uri": {r.RedirectURI}, "code_verifier": {r.CodeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", Unavailable("token_endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 section 2.3.1: both parts are form-encoded before the Basic encoding.
	req.SetBasicAuth(url.QueryEscape(r.ClientID), url.QueryEscape(r.ClientSecret))
	u, err := CheckURL(p.TokenEndpoint, development)
	if err != nil || Authority(u) != p.authority {
		return "", Unsupported("token_endpoint")
	}
	resp, err := d.client(development).Do(req)
	if err != nil {
		return "", transport("token_endpoint", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", Unavailable("token_endpoint")
	}
	if resp.StatusCode != http.StatusOK {
		return "", tokenRefusal(resp.StatusCode, body)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if json.Unmarshal(body, &tr) != nil || tr.IDToken == "" {
		// OpenID Connect Core 1.0 section 3.1.3.3: an authentication response holds an ID token.
		return "", Invalid("token_endpoint.id_token")
	}
	return tr.IDToken, nil
}

// tokenRefusal maps an error answer of the token endpoint (RFC 6749 section 5.2). Only the registered code is read;
// the description is free text of the upstream and is dropped.
func tokenRefusal(status int, body []byte) error {
	if status >= 500 || status == http.StatusTooManyRequests {
		return statusRefusal("token_endpoint", status)
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	switch e.Error {
	case "invalid_grant":
		return Rejected("code")
	case "invalid_client", "unauthorized_client":
		return Rejected("client")
	}
	return Rejected("token_endpoint")
}

// keySet returns the upstream's key set. force asks for a fresh copy, which is honoured at most once in refetchGap.
func (d *Directory) keySet(ctx context.Context, p *Provider, development, force bool) (*jose.JSONWebKeySet, error) {
	d.mu.Lock()
	c, ok := d.keys[p.JWKSURI]
	d.mu.Unlock()
	age := d.now().Sub(c.fetched)
	if ok && age < metadataTTL && (!force || age < refetchGap) {
		return c.set, nil
	}
	body, err := d.get(ctx, development, p.authority, p.JWKSURI, "jwks")
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if json.Unmarshal(body, &set) != nil {
		return nil, Rejected("jwks")
	}
	d.mu.Lock()
	d.keys[p.JWKSURI] = cachedKeys{set: &set, fetched: d.now()}
	d.mu.Unlock()
	return &set, nil
}
