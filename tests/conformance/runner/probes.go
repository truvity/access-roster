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
	"net/http"
	"net/url"
	"strings"
)

// A probe is a request of the runner's own, made as the public client of the plans, for what the suite does not ask: the
// suite sends a valid PKCE request or none at all, so it cannot show that a wrong or missing verifier, or the method plain,
// is refused; and it reads a token response as JSON without looking at the content type or at an error response. The probes
// are the proof of those parts of REQ-AUTHN-002, REQ-AUTHN-005 and REQ-TOKEN-010. They stay true when a confidential client
// that may skip PKCE joins the plans, because they use a public client, which always needs PKCE.
//
// A probe that fails fails the run (results.json holds every probe, with what it saw).
type probeResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Seen   string `json:"seen"`
}

type prober struct {
	who       *person
	authorize string
	token     string
	redirect  string
	issuer    string
}

func newProber(ctx context.Context, who *person, redirectAlias string) (*prober, error) {
	var disc struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	res, err := who.plain.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&disc); err != nil || disc.Authorization == "" || disc.Token == "" {
		return nil, errors.New("discovery names no authorization or token endpoint")
	}
	return &prober{who: who, authorize: disc.Authorization, token: disc.Token, issuer: disc.Issuer,
		redirect: "https://" + suiteHost + ":8443/test/a/" + redirectAlias + "/callback"}, nil
}

func b64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ask makes an authorization request and returns the query of the redirect to the client.
func (p *prober) ask(ctx context.Context, extra url.Values) (url.Values, string, error) {
	state := b64(12)
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {p.redirect}, "scope": {"openid"},
		"state": {state}, "nonce": {b64(12)}}
	for k, v := range extra {
		if len(v) == 0 {
			q.Del(k)
			continue
		}
		q[k] = v
	}
	back, err := p.who.drv.Authorize(ctx, p.authorize+"?"+q.Encode(), p.who.creds)
	if err != nil {
		return nil, state, err
	}
	return back.Query(), state, nil
}

type tokenAnswer struct {
	Status      int
	ContentType string
	CacheCtl    string
	Body        map[string]any
}

func (p *prober) redeem(ctx context.Context, form url.Values) (*tokenAnswer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.token, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.who.plain.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	a := &tokenAnswer{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), CacheCtl: res.Header.Get("Cache-Control")}
	_ = json.Unmarshal(b, &a.Body)
	return a, nil
}

func (a *tokenAnswer) isJSON() bool {
	return a.Body != nil && strings.HasPrefix(strings.ToLower(a.ContentType), "application/json") && strings.Contains(strings.ToLower(a.CacheCtl), "no-store")
}

// run makes every probe and returns what each saw.
func (p *prober) run(ctx context.Context) ([]probeResult, error) {
	var out []probeResult
	add := func(name string, ok bool, seen string) { out = append(out, probeResult{name, ok, seen}) }

	// Refused at the authorization endpoint: an error at the client's redirect, with the issuer and the client's state.
	refusals := []struct {
		name  string
		extra url.Values
		code  string
		words string
	}{
		{"no code_challenge", url.Values{"code_challenge": nil, "code_challenge_method": nil}, "invalid_request", "PKCE"},
		{"code_challenge_method=plain", url.Values{"code_challenge": {b64(32)}, "code_challenge_method": {"plain"}}, "invalid_request", "PKCE"},
		{"an unsupported response_type", url.Values{"response_type": {"token"}, "code_challenge": {challengeOf(b64(32))}, "code_challenge_method": {"S256"}}, "unsupported_response_type", ""},
		{"no response_type", url.Values{"response_type": nil, "code_challenge": {challengeOf(b64(32))}, "code_challenge_method": {"S256"}}, "invalid_request", ""},
	}
	for _, r := range refusals {
		q, state, err := p.ask(ctx, r.extra)
		if err != nil {
			add("authorize: "+r.name, false, err.Error())
			continue
		}
		ok := q.Get("error") == r.code && q.Get("code") == "" && q.Get("iss") == p.issuer && q.Get("state") == state &&
			strings.Contains(q.Get("error_description"), r.words)
		add("authorize: "+r.name+" is refused at the redirect with the issuer and the state", ok,
			fmt.Sprintf("error=%q iss=%q state matches=%v code present=%v", q.Get("error"), q.Get("iss"), q.Get("state") == state, q.Get("code") != ""))
	}

	// Redeemed at the token endpoint: a verifier that is not the one of the challenge, none at all, and the right one.
	code := func() (string, string, error) {
		verifier := b64(32)
		q, state, err := p.ask(ctx, url.Values{"code_challenge": {challengeOf(verifier)}, "code_challenge_method": {"S256"}})
		if err != nil {
			return "", "", err
		}
		if q.Get("code") == "" || q.Get("iss") != p.issuer || q.Get("state") != state {
			return "", "", fmt.Errorf("a valid S256 request got error=%q, code present=%v", q.Get("error"), q.Get("code") != "")
		}
		return q.Get("code"), verifier, nil
	}
	form := func(code, verifier string) url.Values {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirect}, "client_id": {clientID}}
		if verifier != "" {
			f.Set("code_verifier", verifier)
		}
		return f
	}
	cases := []struct {
		name   string
		mutate func(verifier string) string
		status int
		code   string
	}{
		{"a wrong code_verifier", func(string) string { return b64(32) }, 400, "invalid_grant"},
		{"no code_verifier", func(string) string { return "" }, 400, "invalid_request"},
		{"the verifier that is the challenge itself", challengeOf, 400, "invalid_grant"},
		{"the right code_verifier", func(v string) string { return v }, 200, ""},
	}
	for _, c := range cases {
		cd, verifier, err := code()
		if err != nil {
			add("token: "+c.name, false, err.Error())
			continue
		}
		a, err := p.redeem(ctx, form(cd, c.mutate(verifier)))
		if err != nil {
			add("token: "+c.name, false, err.Error())
			continue
		}
		ok := a.Status == c.status && a.isJSON()
		seen := fmt.Sprintf("status %d, content-type %q, cache-control %q, JSON body %v", a.Status, a.ContentType, a.CacheCtl, a.Body != nil)
		if c.code != "" {
			ok = ok && a.Body["error"] == c.code
			seen += fmt.Sprintf(", error %v", a.Body["error"])
		} else {
			_, hasAccess := a.Body["access_token"].(string)
			_, hasID := a.Body["id_token"].(string)
			ok = ok && hasAccess && hasID
			seen += fmt.Sprintf(", access_token %v, id_token %v", hasAccess, hasID)
		}
		add("token: "+c.name+" gives "+fmt.Sprint(c.status)+" as JSON that is not cached", ok, seen)
	}
	return out, nil
}
