// Package githubapp is the part of GitHub's App API that connecting an
// organisation needs — creating an App from a manifest, finding where it is
// installed, and uninstalling it — and the part linking a person's GitHub
// account needs: authorizing the link App as themselves, and reading back
// who they are and which addresses GitHub verified for them.
//
// An App is created by an organisation's owner in two clicks — Create,
// then Install — and nothing about it is typed or pasted. This is how the
// GitHub controller gets a credential, and it is the same verb as
// connecting a directory: the operator grants access once, in a browser,
// and the credential is kept by this service rather than delivered by a
// deployment.
//
// Ported from github-roster 0.x (`pkg/githubapp`) onto the JWT library
// access-roster already uses. A conversion's webhook secret is dropped on
// the floor, because nothing here receives a webhook; its client secret is
// kept only for the link App, which is the one App people authorize.
package githubapp

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
)

// The hosts every call goes to. Variables rather than constants for one
// reason: a test points them at a fake. Production never moves them, and
// nothing reads them from configuration.
var (
	// WebBase is where a browser is sent to create and install an App.
	WebBase = "https://github.com"
	// APIBase is where the API calls go.
	APIBase = "https://api.github.com"
)

// apiVersion is the REST API version every call pins.
const apiVersion = "2022-11-28"

// Manifest is what an App is created from. See
// https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
type Manifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	HookAttributes     HookAttributes    `json:"hook_attributes"`
	RedirectURL        string            `json:"redirect_url"`
	SetupURL           string            `json:"setup_url"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	// CallbackURLs are where GitHub may send somebody back after they
	// authorize the App as themselves. Only the link App has one.
	CallbackURLs []string `json:"callback_urls,omitempty"`
	// Description is shown on the App's page. Only a catalogue App has
	// one.
	Description string `json:"description,omitempty"`
	// DefaultEvents are the webhook events the App subscribes to. The
	// webhook stays inactive whatever they are.
	DefaultEvents []string `json:"default_events,omitempty"`
}

// HookAttributes is an App's webhook. The controller polls, so it is
// never active; GitHub still wants a URL beside it.
type HookAttributes struct {
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

// nameLimit is GitHub's length limit on an App's name.
const nameLimit = catalogue.NameLimit

// ManifestFor is the one manifest builder: every App this service creates,
// its own and a catalogue's, is an entry of the catalogue's shape turned
// into what GitHub's create page takes.
//
// homepage is where the App's page links; redirect and setup are the two
// callbacks, after Create and after Install (setup empty for an App that
// is installed nowhere); callbacks are where a person authorizing the App
// as themselves may be sent back to.
//
// The webhook is never active: nothing here receives one, so no endpoint
// of ours has to be reachable from GitHub, whatever events are declared.
func ManifestFor(app catalogue.App, homepage, redirect, setup string, callbacks []string) Manifest {
	return Manifest{
		Name:               app.DisplayName(),
		URL:                homepage,
		HookAttributes:     HookAttributes{URL: homepage, Active: false},
		RedirectURL:        redirect,
		SetupURL:           setup,
		Public:             app.Public,
		DefaultPermissions: maps.Clone(app.Permissions),
		CallbackURLs:       slices.Clone(callbacks),
		Description:        app.Description,
		DefaultEvents:      slices.Clone(app.Events),
	}
}

// OrganisationApp is the App the GitHub controller acts through in one
// organisation, as a catalogue entry.
//
// Private, because a public App can be installed by anybody on anything,
// and one App per organisation is what a private App forces anyway: it
// installs only on the account that owns it. One permission, `members:
// write`, which is enough to invite, add to and remove from teams, change
// a team role, and read who is a member — and nothing about any
// repository. No webhook: the controller asks, so nothing needs to be
// delivered to it and no endpoint of ours has to be reachable from
// GitHub.
func OrganisationApp(org string) catalogue.App {
	name := org + "-access-roster"
	if len(name) > nameLimit {
		// GitHub refuses a longer name on the create page. Cut rather than
		// let the owner meet that refusal: they can still rename it there.
		name = strings.TrimRight(name[:nameLimit], "-")
	}
	return catalogue.App{
		ID:   "access-roster",
		Org:  org,
		Name: name,
		// Organisation administration, read-only, for one thing: the plan's
		// seats. Without it the controller cannot tell a full organisation
		// from one with room, and it never invites into a paid seat blind.
		Permissions:  map[string]string{"members": "write", "organization_administration": "read"},
		Installation: catalogue.InstallationAll,
	}
}

// NewManifest is [OrganisationApp]'s manifest: redirect and setup are the
// two callbacks, after Create and after Install.
func NewManifest(org, homepage, redirect, setup string) Manifest {
	return ManifestFor(OrganisationApp(org), homepage, redirect, setup, nil)
}

// CreateURL is where the owner is sent to create the App, by a form POST
// carrying the manifest. The state comes back on the redirect.
func CreateURL(org, state string) string {
	return WebBase + "/organizations/" + url.PathEscape(org) + "/settings/apps/new?state=" + url.QueryEscape(state)
}

// InstallURL is where the owner is sent to install an App they created.
// The state comes back on the setup redirect.
func InstallURL(slug, state string) string {
	return WebBase + "/apps/" + url.PathEscape(slug) + "/installations/new?state=" + url.QueryEscape(state)
}

// Registration is what creating an App returns, minus what nothing here
// keeps.
type Registration struct {
	ID    int64
	Slug  string
	Owner string
	// PEM is the App's private key. GitHub hands it over exactly once,
	// here; losing it means reconnecting.
	PEM     string
	HTMLURL string
	// ClientID and ClientSecret are what a person's authorization of the
	// App is redeemed and refreshed with. An organisation's App ignores
	// them.
	ClientID     string
	ClientSecret string
}

// Convert exchanges the code GitHub returns after Create for the App's
// credentials. The code is the only authority the request carries and it
// is single-use, so a replay finds nothing.
func Convert(ctx context.Context, client *http.Client, code string) (Registration, error) {
	if code == "" {
		return Registration{}, errors.New("github: no code on the callback")
	}
	// Escaped: the code arrives in a query string a browser controls, and
	// one carrying a path would otherwise address some other endpoint.
	endpoint := APIBase + "/app-manifests/" + url.PathEscape(code) + "/conversions"
	var body struct {
		ID           int64  `json:"id"`
		Slug         string `json:"slug"`
		PEM          string `json:"pem"`
		URL          string `json:"html_url"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Owner        struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if err := call(ctx, client, http.MethodPost, endpoint, "", http.StatusCreated, &body); err != nil {
		return Registration{}, fmt.Errorf("github: create the App: %w", err)
	}
	if body.ID == 0 || body.PEM == "" || body.Slug == "" {
		return Registration{}, errors.New("github: the App was created and GitHub returned no id, slug or key for it")
	}
	return Registration{
		ID: body.ID, Slug: body.Slug, Owner: body.Owner.Login, PEM: body.PEM, HTMLURL: body.URL,
		ClientID: body.ClientID, ClientSecret: body.ClientSecret,
	}, nil
}

// AppToken is the short-lived JWT an App authenticates App-level calls
// with, signed by its private key.
func AppToken(appID int64, privateKey string, now time.Time) (string, error) {
	key, err := parseKey(privateKey)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("github: a signer for the App key: %w", err)
	}
	// Backdated a minute for clock skew, and valid for nine: GitHub refuses
	// anything longer than ten.
	return jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   strconv.FormatInt(appID, 10),
		IssuedAt: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:   jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}).Serialize()
}

// ErrNotInstalled is an App with no installation on the organisation yet:
// the owner created it and has not clicked Install.
var ErrNotInstalled = errors.New("github: the App is not installed on the organisation")

// FindInstallation returns where the App is installed on an organisation.
//
// The setup redirect carries an installation id, and it is not what is
// kept: it arrives in a query a browser controls. This asks GitHub, as
// the App, which of its installations belongs to that organisation.
func FindInstallation(ctx context.Context, client *http.Client, appToken, org string) (int64, error) {
	next := APIBase + "/app/installations?per_page=100"
	for next != "" {
		var page []struct {
			ID      int64 `json:"id"`
			Account struct {
				Login string `json:"login"`
			} `json:"account"`
		}
		link, err := callPage(ctx, client, next, appToken, &page)
		if err != nil {
			return 0, fmt.Errorf("github: list the App's installations: %w", err)
		}
		for _, installation := range page {
			if strings.EqualFold(installation.Account.Login, org) {
				return installation.ID, nil
			}
		}
		// The next page is followed with the App's token attached, so only
		// to the API it came from: a Link header naming anywhere else would
		// otherwise be handed a credential.
		if link != "" && !strings.HasPrefix(link, APIBase+"/") {
			return 0, fmt.Errorf("github: the next page of installations is not on %s", APIBase)
		}
		next = link
	}
	return 0, fmt.Errorf("%w: %s", ErrNotInstalled, org)
}

// InstallationToken is what the App acts in one installation with: an
// hour-long token GitHub mints on request, signed for by the App JWT.
func InstallationToken(ctx context.Context, client *http.Client, appToken string, installation int64) (string, time.Time, error) {
	minted, err := InstallationTokenFor(ctx, client, appToken, installation, Narrowing{})
	if err != nil {
		return "", time.Time{}, err
	}
	return minted.Token, minted.ExpiresAt, nil
}

// Narrowing is what an installation token is cut down to: some of the
// installation's repositories, some of its permissions. Empty fields
// narrow nothing, and GitHub then grants everything the installation has.
type Narrowing struct {
	// Repositories are names within the installation's account, without
	// the owner.
	Repositories []string `json:"repositories,omitempty"`
	// Permissions are GitHub permission names to read, write or admin.
	Permissions map[string]string `json:"permissions,omitempty"`
}

// MintedToken is an installation token and what GitHub says it carries,
// which is what was granted rather than what was asked for.
type MintedToken struct {
	Token     string
	ExpiresAt time.Time
	// Repositories are the repositories the token is narrowed to, by name.
	// Empty is every repository the installation can reach.
	Repositories []string
	// Permissions are what the token carries.
	Permissions map[string]string
}

// InstallationTokenFor mints an installation token narrowed to some
// repositories and permissions. GitHub refuses a narrowing wider than the
// installation with a 422, returned as a [StatusError].
func InstallationTokenFor(
	ctx context.Context, client *http.Client, appToken string, installation int64, narrowing Narrowing,
) (MintedToken, error) {
	endpoint := APIBase + "/app/installations/" + strconv.FormatInt(installation, 10) + "/access_tokens"
	var body struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
	}
	var request any
	if len(narrowing.Repositories) > 0 || len(narrowing.Permissions) > 0 {
		request = narrowing
	}
	if err := send(ctx, client, http.MethodPost, endpoint, appToken, request, http.StatusCreated, &body); err != nil {
		return MintedToken{}, fmt.Errorf("github: an installation token: %w", err)
	}
	if body.Token == "" {
		return MintedToken{}, errors.New("github: GitHub minted an empty installation token")
	}
	out := MintedToken{Token: body.Token, ExpiresAt: body.ExpiresAt, Permissions: body.Permissions}
	for _, repository := range body.Repositories {
		out.Repositories = append(out.Repositories, repository.Name)
	}
	return out, nil
}

// DeleteInstallation uninstalls the App from wherever that installation
// is. It is Disconnect's revoke: the App registration stays on GitHub —
// the API cannot delete one — but nothing can act through it any more.
func DeleteInstallation(ctx context.Context, client *http.Client, appToken string, installation int64) error {
	endpoint := APIBase + "/app/installations/" + strconv.FormatInt(installation, 10)
	if err := call(ctx, client, http.MethodDelete, endpoint, appToken, http.StatusNoContent, nil); err != nil {
		return fmt.Errorf("github: uninstall the App: %w", err)
	}
	return nil
}

func parseKey(privateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return nil, errors.New("github: the App key is not PEM")
	}
	// GitHub issues PKCS#1; PKCS#8 is accepted too, so a key converted by
	// hand still works.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: the App key does not parse: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: the App key is not an RSA key")
	}
	return key, nil
}

// call makes one request and decodes the answer, refusing any status but
// the one expected.
func call(ctx context.Context, client *http.Client, method, endpoint, bearer string, want int, out any) error {
	return send(ctx, client, method, endpoint, bearer, nil, want, out)
}

// send is call with a JSON body.
func send(ctx context.Context, client *http.Client, method, endpoint, bearer string, body any, want int, out any) error {
	response, err := do(ctx, client, method, endpoint, bearer, body)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	if response.StatusCode != want {
		return statusError(response)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(out)
}

// callPage is call for a paginated GET, returning the next page's URL.
func callPage(ctx context.Context, client *http.Client, endpoint, bearer string, out any) (string, error) {
	response, err := do(ctx, client, http.MethodGet, endpoint, bearer, nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	if response.StatusCode != http.StatusOK {
		return "", statusError(response)
	}
	if err = json.NewDecoder(response.Body).Decode(out); err != nil {
		return "", err
	}
	return nextLink(response.Header.Get("Link")), nil
}

func do(ctx context.Context, client *http.Client, method, endpoint, bearer string, body any) (*http.Response, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	return client.Do(request) //nolint:gosec // the host is one of the two above, never configuration
}

// statusError keeps GitHub's own message, which names the problem more
// precisely than a status can, and bounds how much of it is read.
func statusError(response *http.Response) error {
	var body struct {
		Message string `json:"message"`
	}
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	text := response.Status
	if json.Unmarshal(raw, &body) == nil && body.Message != "" {
		text = fmt.Sprintf("%s: %s", response.Status, body.Message)
	}
	return &StatusError{Code: response.StatusCode, text: text}
}

// StatusError is GitHub answering with a status other than the one a call
// expected, in GitHub's own words.
type StatusError struct {
	Code int
	text string
}

func (e *StatusError) Error() string { return e.text }

// nextLink reads the `rel="next"` URL out of a Link header.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		if len(fields) < 2 {
			continue
		}
		for _, param := range fields[1:] {
			if strings.TrimSpace(param) == `rel="next"` {
				return strings.Trim(strings.TrimSpace(fields[0]), "<>")
			}
		}
	}
	return ""
}
