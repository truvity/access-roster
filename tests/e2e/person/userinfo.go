package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// bearerCall sends a request to a bearer endpoint with the Authorization header given (empty: none) and returns the
// status, the WWW-Authenticate challenge and the body.
func (s *session) bearerCall(ctx context.Context, method, endpoint, authorization string) (status int, challenge string, body []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, http.NoBody)
	if err != nil {
		return 0, "", nil, err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	res, err := s.hc.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	return res.StatusCode, res.Header.Get("WWW-Authenticate"), b, nil
}

// userinfo runs the UserInfo endpoint of the discovery document against a live access token (REQ-TOKEN-008, REQ-SEC-038):
// it answers the sub of the ID token and nothing else, by GET and by POST; and it refuses what is not a live access token
// of the client in the same words: the ID token of the same sign-in, and no token.
func (s *session) userinfo(ctx context.Context, accessToken, idToken string, idClaims map[string]any) error {
	var disc struct {
		UserInfo string `json:"userinfo_endpoint"`
	}
	if err := getJSON(ctx, s.hc, issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return err
	}
	if disc.UserInfo == "" {
		return errors.New("the discovery document names no userinfo_endpoint")
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		status, _, b, err := s.bearerCall(ctx, method, disc.UserInfo, "Bearer "+accessToken)
		if err != nil {
			return err
		}
		var got map[string]any
		if status != http.StatusOK || json.Unmarshal(b, &got) != nil {
			return fmt.Errorf("UserInfo by %s answered %d", method, status)
		}
		if len(got) != 1 || got["sub"] != idClaims["sub"] {
			return fmt.Errorf("UserInfo by %s released %d claims, want the sub of the ID token alone", method, len(got))
		}
	}
	fmt.Println("userinfo:      200 by GET and POST, the sub of the ID token and no other claim")
	for what, auth := range map[string]string{"the ID token": "Bearer " + idToken, "no token": ""} {
		status, challenge, _, err := s.bearerCall(ctx, http.MethodGet, disc.UserInfo, auth)
		if err != nil {
			return err
		}
		if status != http.StatusUnauthorized || !strings.HasPrefix(challenge, "Bearer ") {
			return fmt.Errorf("UserInfo with %s answered %d %q, want 401 with a Bearer challenge", what, status, challenge)
		}
		if auth != "" && !strings.Contains(challenge, `error="invalid_token"`) {
			return fmt.Errorf("UserInfo with %s: the challenge %q does not say invalid_token", what, challenge)
		}
	}
	// A token in the query is not taken, even a good one.
	status, _, _, err := s.bearerCall(ctx, http.MethodGet, disc.UserInfo+"?access_token="+accessToken, "")
	if err != nil {
		return err
	}
	if status != http.StatusBadRequest {
		return fmt.Errorf("UserInfo with the token in the query answered %d, want 400", status)
	}
	fmt.Println("userinfo:      401 invalid_token for the ID token, 401 for no token, 400 for a token in the query")
	return nil
}
