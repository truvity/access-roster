package slackapp

import (
	"context"
	"net/http"
	"net/url"
)

// Setup is the calls that are made before a workspace has a bot token —
// the console's connect flow. None uses one: creating and updating the
// App takes an app configuration token, and the OAuth exchange takes the
// App's own client credentials.
type Setup struct{ t *transport }

// NewSetup returns the setup calls, against Slack or a test's fake.
func NewSetup(opts ...Option) *Setup { return &Setup{t: newTransport(opts)} }

func bearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// AppCredentials is what creating an App returns.
type AppCredentials struct {
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	SigningSecret string `json:"signing_secret"`
}

// App is a created App.
type App struct {
	AppID             string         `json:"app_id"`
	Credentials       AppCredentials `json:"credentials"`
	OAuthAuthorizeURL string         `json:"oauth_authorize_url"`
}

// CreateApp creates an App from a manifest (JSON text) with an app
// configuration token. The owner then installs it from the returned
// authorize URL, which is what makes connecting a workspace two clicks.
// A refused manifest is an [*APIError] "invalid_manifest" whose Details
// say where.
func (s *Setup) CreateApp(ctx context.Context, configToken, manifest string) (App, error) {
	var out App
	err := s.t.call(ctx, "apps.manifest.create", bearer(configToken), url.Values{"manifest": {manifest}}, &out)
	return out, err
}

// UpdateApp replaces an App's manifest — unmodified fields included, as
// Slack requires — which is how an App installed earlier gets the scopes
// a later release needs. permissionsUpdated is true when the owner must
// reinstall for them to take effect.
func (s *Setup) UpdateApp(ctx context.Context, configToken, appID, manifest string) (permissionsUpdated bool, err error) {
	var out struct {
		PermissionsUpdated bool `json:"permissions_updated"`
	}
	err = s.t.call(ctx, "apps.manifest.update", bearer(configToken),
		url.Values{"app_id": {appID}, "manifest": {manifest}}, &out)
	return out.PermissionsUpdated, err
}

// Installation is the result of an owner installing the App.
type Installation struct {
	// BotToken is the workspace's credential. The caller keeps it; this
	// package never logs it.
	BotToken  string
	TeamID    string
	TeamName  string
	BotUserID string
	// Scope is the granted scopes, comma-separated; compare it with
	// [MissingScopes].
	Scope string
}

// OAuthAccess exchanges the code Slack sent back to the redirect URI for
// the bot token, using the App's client credentials (as HTTP Basic, which
// Slack recommends over form fields).
func (s *Setup) OAuthAccess(ctx context.Context, clientID, clientSecret, code, redirectURI string) (Installation, error) {
	var out struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		BotUserID   string `json:"bot_user_id"`
		Team        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"team"`
	}
	params := url.Values{"code": {code}}
	if redirectURI != "" {
		params.Set("redirect_uri", redirectURI)
	}
	err := s.t.call(ctx, "oauth.v2.access", func(r *http.Request) {
		r.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}, params, &out)
	if err != nil {
		return Installation{}, err
	}
	return Installation{BotToken: out.AccessToken, TeamID: out.Team.ID, TeamName: out.Team.Name,
		BotUserID: out.BotUserID, Scope: out.Scope}, nil
}
