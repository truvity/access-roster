package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// confidentialClient is the confidential client of the local installation (tests/installations/local/config), whose
// secret `just local-up` makes and keeps in the run's state directory.
const confidentialClient = "example-app"

// clientSecret reads the secret of the confidential client from the state directory of the run. It is returned to the
// caller only; it is never printed.
func (c *config) clientSecret() (string, error) {
	b, err := os.ReadFile(filepath.Join(c.root, ".cache", "local", "client-"+confidentialClient))
	if err != nil {
		return "", fmt.Errorf("the secret of %s: %w (run `just local-up`)", confidentialClient, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("the secret of " + confidentialClient + " is empty")
	}
	return s, nil
}

// tokenCall posts one exchange to the token endpoint through the forwarder and returns the status, the challenge
// header and the JSON body. The secret is in the Authorization header only; nothing here prints it.
func tokenCall(ctx context.Context, hc *http.Client, form url.Values, authorization string) (status int, www string, body map[string]any, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	res, err := hc.Do(req)
	if err != nil {
		return 0, "", nil, fmt.Errorf("POST /token: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = json.Unmarshal(raw, &body)
	return res.StatusCode, res.Header.Get("WWW-Authenticate"), body, nil
}

// confidentialExchange proves client authentication on the exchange (ADR 0022, REQ-EXCH-018, REQ-EXCH-019): the
// confidential client exchanges the person's sign-in token, which was issued to sluis-cli, for a token for itself.
// A wrong secret is refused first; the right one, by HTTP Basic, is served. It returns the claims of the new token.
func (s *session) confidentialExchange(ctx context.Context, subjectToken string) (map[string]any, map[string]any, error) {
	secret, err := s.cfg.clientSecret()
	if err != nil {
		return nil, nil, err
	}
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {audience},
	}
	basic := func(id, sec string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(sec)))
	}

	status, www, body, err := tokenCall(ctx, s.hc, form, basic(confidentialClient, "not-the-secret"))
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" || !strings.HasPrefix(www, "Basic") {
		return nil, nil, fmt.Errorf("a wrong secret gave status %d error %v (WWW-Authenticate %q), want 401 invalid_client with a Basic challenge", status, body["error"], www)
	}
	fmt.Println("wrong secret:  401 invalid_client, WWW-Authenticate: Basic (the same for an unknown client)")

	status, _, body, err = tokenCall(ctx, s.hc, form, basic(confidentialClient, secret))
	if err != nil {
		return nil, nil, err
	}
	at, _ := body["access_token"].(string)
	if status != http.StatusOK || at == "" {
		return nil, nil, fmt.Errorf("the confidential client's exchange gave status %d error %v, want 200", status, body["error"])
	}
	hdr, claims, err := parseToken(at)
	return hdr, claims, err
}
