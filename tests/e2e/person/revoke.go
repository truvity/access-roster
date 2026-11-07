package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// post sends a form to an endpoint of the installation and returns the status and the body.
func (s *session) post(ctx context.Context, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return res.StatusCode, b, nil
}

// signInAgain signs the same user in once more as a protocol client of sluis-cli and returns the answer of the token endpoint:
// a session of its own, next to the one the CLI holds, for the revocation to end.
func (s *session) signInAgain(ctx context.Context, a *authRequest) (map[string]any, error) {
	back, err := s.driver.Authorize(ctx, a.url, s.creds)
	if err != nil {
		return nil, err
	}
	if back.Query().Get("state") != a.state || back.Query().Get("code") == "" {
		return nil, errors.New("the sign-in did not return a code for this state")
	}
	status, b, err := s.post(ctx, a.token, url.Values{"grant_type": {"authorization_code"}, "code": {back.Query().Get("code")},
		"redirect_uri": {a.redirect}, "code_verifier": {a.verifier}, "client_id": {cliID}})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if status != http.StatusOK || json.Unmarshal(b, &out) != nil {
		return nil, fmt.Errorf("the token endpoint answered %d", status)
	}
	return out, nil
}

// revocation runs the revocation endpoint of the discovery document (RFC 7009; REQ-TOKEN-009, 025, 026) against a session
// made for it, while the CLI's own session stays: the refresh token ends exactly its grant; the same request again, an unknown
// token and an access token each get the answer the standard gives; the revoked token no longer refreshes; and the CLI,
// which signed in before, still gets a token.
func (s *session) revocation(ctx context.Context) error {
	var disc struct {
		Revocation string `json:"revocation_endpoint"`
		Token      string `json:"token_endpoint"`
	}
	if err := getJSON(ctx, s.hc, issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return err
	}
	if disc.Revocation == "" {
		return errors.New("the discovery document names no revocation_endpoint")
	}
	a, err := s.newAuthRequest(ctx, nil)
	if err != nil {
		return err
	}
	toks, err := s.signInAgain(ctx, a)
	if err != nil {
		return fmt.Errorf("the second session: %w", err)
	}
	rt, _ := toks["refresh_token"].(string)
	at, _ := toks["access_token"].(string)
	if rt == "" || at == "" {
		return errors.New("the token endpoint gave no refresh token or no access token")
	}
	refresh := func(token string) (int, error) {
		st, _, err := s.post(ctx, disc.Token, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {cliID}})
		return st, err
	}

	// An access token is not revoked, and the answer says so (RFC 7009 section 2.2.1).
	st, b, err := s.post(ctx, disc.Revocation, url.Values{"token": {at}, "token_type_hint": {"access_token"}, "client_id": {cliID}})
	if err != nil {
		return err
	}
	if st != http.StatusBadRequest || !strings.Contains(string(b), "unsupported_token_type") {
		return fmt.Errorf("revoking an access token answered %d %s, want 400 unsupported_token_type", st, b)
	}
	// A token that is not a token of this installation is answered as one that was revoked.
	st, _, err = s.post(ctx, disc.Revocation, url.Values{"token": {strings.Repeat("b", 26) + "." + strings.Repeat("c", 43)}, "client_id": {cliID}})
	if err != nil || st != http.StatusOK {
		return fmt.Errorf("revoking an unknown token answered %d, want 200: %w", st, err)
	}
	// A client that sends a secret it was never given is refused, as at the token endpoint.
	st, _, err = s.post(ctx, disc.Revocation, url.Values{"token": {rt}, "client_id": {cliID}, "client_secret": {"x"}})
	if err != nil || st != http.StatusUnauthorized {
		return fmt.Errorf("revoking with a secret answered %d, want 401: %w", st, err)
	}
	if st, err := refresh(rt); err != nil || st != http.StatusOK {
		return fmt.Errorf("the token to revoke does not refresh before the revocation: %d: %w", st, err)
	}
	// The refresh above rotated the token: the first is spent, and the successor is in the answer of the endpoint, which we
	// did not keep. A spent token of the chain proves its holder had one, and ends the chain all the same.
	st, ok, err := s.post(ctx, disc.Revocation, url.Values{"token": {rt}, "token_type_hint": {"refresh_token"}, "client_id": {cliID}})
	if err != nil || st != http.StatusOK {
		return fmt.Errorf("revoking the refresh token answered %d, want 200: %w", st, err)
	}
	st, again, err := s.post(ctx, disc.Revocation, url.Values{"token": {rt}, "client_id": {cliID}})
	if err != nil || st != http.StatusOK || string(again) != string(ok) {
		return fmt.Errorf("revoking it again answered %d %q, want the same 200 %q: %w", st, again, ok, err)
	}
	if st, err := refresh(rt); err != nil || st != http.StatusBadRequest {
		return fmt.Errorf("the revoked token refreshed or was not refused as invalid_grant: %d: %w", st, err)
	}
	// Exactly that grant: the CLI's own session, from the sign-in of step 1, still gets a token.
	viaCLI, err := s.token(ctx, audience)
	if err != nil || viaCLI == "" {
		return fmt.Errorf("the CLI's session ended with the other one: %w", err)
	}
	fmt.Println("revocation:    200 for the refresh token, the same 200 again and for an unknown token, 400 unsupported_token_type for an access token, 401 with a secret;")
	fmt.Println("               the revoked token no longer refreshes, and the CLI's session is untouched")
	return nil
}
