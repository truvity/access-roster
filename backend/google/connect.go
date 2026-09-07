package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/oauth2"
	googleauth "golang.org/x/oauth2/google"
)

// revokeURL is where a refresh token is handed back.
const revokeURL = "https://oauth2.googleapis.com/revoke" //nolint:gosec // an endpoint, not a credential

// CallbackPath is where the consent screen returns, appended to the
// console's own base URL. It is fixed because an operator has to type the
// whole redirect URI into a cloud console by hand, and the one thing that
// must not vary between installations is the part nobody can look up.
const CallbackPath = "/connect/google/callback"

// ConsentScopes are what admin consent asks for: the four the hub reads
// with, plus the two that say who consented.
//
// The identity pair is not decoration. A refresh token acts as whoever
// granted it, and a console that cannot name that account can only show
// "someone at this company" beside a credential with directory-wide read
// — which is exactly the fact an operator needs when deciding whether it
// is still the right one. They are standard scopes: no consent-screen
// entry, no verification, nothing to justify.
var ConsentScopes = append([]string{"openid", "email"}, Scopes...)

// OAuthClient is the client an installation registered once with Google.
// One per installation, never one per company: the tenants a hub reads
// are the ones whose administrators consented to this client.
type OAuthClient struct {
	ID     string
	Secret string
	// RedirectURL must match one registered with the client exactly.
	RedirectURL string
}

func (c OAuthClient) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Endpoint:     googleauth.Endpoint,
		RedirectURL:  c.RedirectURL,
		Scopes:       ConsentScopes,
	}
}

// AuthURL is where the browser goes to consent.
//
// Offline access is what makes a refresh token arrive at all, and forcing
// the screen is what makes one arrive *every* time: Google returns a
// refresh token only on a grant the administrator actually saw, so a
// second consent that silently reuses the first would hand back an access
// token good for an hour and nothing to renew it with. Reconnecting a
// workspace is precisely the case where that would be a silent failure.
func (c OAuthClient) AuthURL(state string) string {
	return c.config().AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

// Consent turns a callback code into an open backend.
//
// The returned backend acts as the administrator who consented, and
// carries the refresh token as its credential so that a store can write
// it down.
func Consent(ctx context.Context, client OAuthClient, code string) (*Backend, error) {
	if code == "" {
		return nil, errors.New("google: the consent returned no code")
	}
	token, err := client.config().Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google: exchange the consent code: %w", err)
	}
	if token.RefreshToken == "" {
		// Without one, the connection would work for an hour and then
		// quietly stop. Refusing now, while an operator is watching the
		// screen that caused it, is the only honest moment to say so.
		return nil, errors.New("google: the consent returned no refresh token; " +
			"the grant must be offline and freshly approved, so press Connect again and complete the consent screen")
	}
	admin := consentingAccount(token)
	if admin == "" {
		return nil, errors.New("google: the consent did not say which account granted it; " +
			"the OAuth client must be allowed the openid and email scopes")
	}
	return OpenWithToken(ctx, client, token.RefreshToken, admin)
}

// consentingAccount reads the address out of the id token that came back
// with the grant.
//
// The token is not verified here, and does not need to be: it did not
// arrive from a browser but from Google's own token endpoint over TLS, in
// the response to a request carrying this client's secret. Nothing but
// Google could have produced it, and nothing about the grant is decided
// from it — it names the account for a human to read.
func consentingAccount(token *oauth2.Token) string {
	raw, _ := token.Extra("id_token").(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err = json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(claims.Email))
}
