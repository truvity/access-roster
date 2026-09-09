package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	googleauth "golang.org/x/oauth2/google"
)

// revokeURL is where a refresh token is handed back.
const revokeURL = "https://oauth2.googleapis.com/revoke" //nolint:gosec // an endpoint, not a credential

// The two paths a Google flow returns to, appended to the console's own
// base URL. They are fixed because an operator types the whole redirect
// URI into a cloud console by hand, and the one thing that must not vary
// between installations is the part nobody can look up.
//
// Two, not one, because the two flows are answered by endpoints with
// opposite authorisation: the consent callback adopts a workspace and so
// demands an operator, while the sign-in callback is how a person becomes
// anyone at all and must be reachable by nobody. Sharing a path would
// mean one endpoint deciding which of those it was, from a parameter, at
// the moment it matters most.
const (
	CallbackPath       = "/connect/google/callback"
	SignInCallbackPath = "/login/google/callback"
)

// SignInScopes are what signing a person in asks for: who they are, and
// nothing else. The directory scopes belong to the consent flow, which an
// administrator grants once per company; a person signing in grants
// nothing on their company's behalf.
var SignInScopes = []string{"openid", "email", "profile"}

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
	// BaseURL is where a browser reaches this console, with no trailing
	// slash. Both redirect URIs are derived from it rather than given
	// separately, so the two cannot disagree — and a mismatched redirect
	// is the failure that arrives late, in a cloud console's own words,
	// naming nothing useful.
	BaseURL string
}

// ConsentRedirect is where the consent flow returns; one of the two URIs
// to register with the client.
func (c OAuthClient) ConsentRedirect() string { return c.BaseURL + CallbackPath }

// SignInRedirect is where the sign-in flow returns; the other one.
func (c OAuthClient) SignInRedirect() string { return c.BaseURL + SignInCallbackPath }

func (c OAuthClient) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Endpoint:     googleauth.Endpoint,
		RedirectURL:  c.ConsentRedirect(),
		Scopes:       ConsentScopes,
	}
}

func (c OAuthClient) signInConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Endpoint:     googleauth.Endpoint,
		RedirectURL:  c.SignInRedirect(),
		Scopes:       SignInScopes,
	}
}

// SignInURL is where the browser goes to prove who somebody is.
//
// No offline access and no forced screen: nothing here is stored, so
// there is no refresh token to want, and a person who signed in a minute
// ago should not be asked again. The account chooser is Google's, which
// is why this hub asks nobody for an address first.
func (c OAuthClient) SignInURL(state string) string {
	return c.signInConfig().AuthCodeURL(state)
}

// Identify turns a sign-in callback's code into the address that
// authenticated. It is the whole of what the flow is for: the hub decides
// everything else from the address, through the directory it already
// reads.
func Identify(ctx context.Context, client OAuthClient, code string) (string, error) {
	if code == "" {
		return "", errors.New("google: the sign-in returned no code")
	}
	token, err := client.signInConfig().Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("google: exchange the sign-in code: %w", err)
	}
	email := consentingAccount(token)
	if email == "" {
		return "", errors.New("google: the sign-in did not say which account it was; " +
			"the OAuth client must be allowed the openid and email scopes")
	}
	return email, nil
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

// VerifyClient reports whether this OAuth client's id and secret are the
// ones Google holds, without needing a person.
//
// It exists because the alternative is finding out after an administrator
// has already consented: a wrong secret fails at the exchange, which is
// the step AFTER the consent screen, so a real Super Admin has granted a
// real credential to an installation that cannot collect it.
//
// The method is the one OAuth actually offers. There is no "check my
// client" endpoint, so this presents a code that cannot be valid and
// reads which complaint comes back: `invalid_client` is about the client,
// and anything else — `invalid_grant`, for the code — means the client
// itself was accepted. Nothing is minted either way.
//
// Everything inconclusive passes. A refusal here stops an operator from
// connecting, so it is made only when Google has named the client as the
// problem; a timeout, a proxy, an unexpected shape are all "proceed".
func VerifyClient(ctx context.Context, client OAuthClient) error {
	if client.ID == "" || client.Secret == "" {
		return errors.New("google: the OAuth client id and secret are both required")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"access-roster-client-check"},
		"client_id":     {client.ID},
		"client_secret": {client.Secret},
		"redirect_uri":  {client.ConsentRedirect()},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		googleauth.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil //nolint:nilerr // inconclusive is not a refusal
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil //nolint:nilerr // inconclusive is not a refusal
	}
	defer func() { _ = response.Body.Close() }()

	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body); err != nil {
		return nil //nolint:nilerr // inconclusive is not a refusal
	}
	if body.Error != "invalid_client" {
		return nil
	}
	detail := body.Description
	if detail == "" {
		detail = "Google did not recognise this client id and secret"
	}
	return fmt.Errorf("google: the OAuth client was refused (%s). "+
		"Check the client id and secret against the Google Cloud project that owns them, "+
		"and that the client is a Web application with %s among its authorised redirect URIs",
		detail, client.ConsentRedirect())
}
