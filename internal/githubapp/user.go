package githubapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubapp/catalogue"
)

// linkNameSuffix names the link App after the organisation that owns it.
const linkNameSuffix = "-access-roster-link"

// LinkApp is the App a person authorizes to link their GitHub account to
// their work identity, as a catalogue entry.
//
// It is a different App from an organisation's, on purpose. A person's
// token for an App carries that App's permissions, so a token for the
// organisation's App could manage members; this App asks for one thing —
// reading the person's own email addresses — and is installed nowhere, so
// a token for it reads one person's address list and nothing else.
//
// PUBLIC, because a private App can only be authorized by members of the
// organisation that owns it: a new hire who is not in the organisation
// yet, and a partner company's people who never will be, could not link.
// Anybody may install a public App, and installing this one grants
// nothing — it has no permission on any organisation or repository.
func LinkApp(owner string) catalogue.App {
	name := owner + linkNameSuffix
	if len(name) > nameLimit {
		name = strings.TrimRight(owner[:nameLimit-len(linkNameSuffix)], "-") + linkNameSuffix
	}
	return catalogue.App{
		ID:          "access-roster-link",
		Org:         owner,
		Name:        name,
		Public:      true,
		Permissions: map[string]string{"emails": "read"},
	}
}

// NewLinkManifest is [LinkApp]'s manifest: no setup callback, because it
// is installed nowhere, and the one callback a person's authorization
// returns to.
func NewLinkManifest(owner, homepage, redirect, callback string) Manifest {
	return ManifestFor(LinkApp(owner), homepage, redirect, "", []string{callback})
}

// AuthorizeURL is where a person is sent to authorize the link App.
func AuthorizeURL(clientID, redirect, state string) string {
	query := url.Values{"client_id": {clientID}, "redirect_uri": {redirect}, "state": {state}}
	return WebBase + "/login/oauth/authorize?" + query.Encode()
}

// UserTokens are what a person's authorization of the link App leaves: a
// token to read with, and one to renew it by.
//
// GitHub rotates the refresh token on every use — the old refresh token
// and the old access token stop working the moment a new pair is issued —
// so a pair that was issued and not kept is a link that can never be
// checked again.
type UserTokens struct {
	AccessToken   string
	AccessExpires time.Time
	// RefreshToken is empty for an App whose tokens do not expire, and
	// then AccessExpires is zero too.
	RefreshToken   string
	RefreshExpires time.Time
}

// ErrAuthorizationRefused is GitHub refusing a code or a refresh token.
// It is an answer, not an outage: the grant is spent, expired or revoked.
var ErrAuthorizationRefused = errors.New("github: GitHub refused the authorization")

// ExchangeCode redeems the code a person's authorization returned.
func ExchangeCode(ctx context.Context, client *http.Client, clientID, secret, code, redirect string, now time.Time) (UserTokens, error) {
	if code == "" {
		return UserTokens{}, errors.New("github: no code on the callback")
	}
	return tokenRequest(ctx, client, url.Values{
		"client_id": {clientID}, "client_secret": {secret}, "code": {code}, "redirect_uri": {redirect},
	}, now)
}

// RefreshUserTokens trades a refresh token for a new pair. The pair it was
// called with is dead once this returns successfully.
func RefreshUserTokens(ctx context.Context, client *http.Client, clientID, secret, refresh string, now time.Time) (UserTokens, error) {
	return tokenRequest(ctx, client, url.Values{
		"client_id": {clientID}, "client_secret": {secret}, "grant_type": {"refresh_token"}, "refresh_token": {refresh},
	}, now)
}

func tokenRequest(ctx context.Context, client *http.Client, form url.Values, now time.Time) (UserTokens, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, WebBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return UserTokens{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request) //nolint:gosec // the host is GitHub's, never configuration
	if err != nil {
		return UserTokens{}, fmt.Errorf("github: token request: %w", err)
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	if response.StatusCode != http.StatusOK {
		return UserTokens{}, fmt.Errorf("github: token request: %w", statusError(response))
	}
	var body struct {
		AccessToken           string `json:"access_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshToken          string `json:"refresh_token"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
		Error                 string `json:"error"`
		ErrorDescription      string `json:"error_description"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&body); err != nil {
		return UserTokens{}, fmt.Errorf("github: token response: %w", err)
	}
	// GitHub answers a refused grant with a 200 and the reason inside. Only
	// a spent, expired or revoked grant is a refusal; anything else — the
	// App's own credentials wrong, say — is a fault of ours, and must never
	// read as the person's grant being gone.
	switch body.Error {
	case "":
	case "bad_refresh_token", "bad_verification_code":
		return UserTokens{}, fmt.Errorf("%w: %s: %s", ErrAuthorizationRefused, body.Error, body.ErrorDescription)
	default:
		return UserTokens{}, fmt.Errorf("github: token request: %s: %s", body.Error, body.ErrorDescription)
	}
	if body.AccessToken == "" {
		return UserTokens{}, errors.New("github: the token response carried no token")
	}
	out := UserTokens{AccessToken: body.AccessToken, RefreshToken: body.RefreshToken}
	if body.ExpiresIn > 0 {
		out.AccessExpires = now.Add(time.Duration(body.ExpiresIn) * time.Second)
	}
	if body.RefreshTokenExpiresIn > 0 {
		out.RefreshExpires = now.Add(time.Duration(body.RefreshTokenExpiresIn) * time.Second)
	}
	return out, nil
}

// User is a GitHub account. The id is what a link is kept by: a login can
// be renamed, and a renamed login can be taken by somebody else.
type User struct {
	ID    int64
	Login string
}

// ErrTokenRefused is GitHub refusing a person's token outright (401).
// Whether that is a revoked authorization or something else is a second
// question — [CheckUserToken] answers it.
var ErrTokenRefused = errors.New("github: GitHub refused the token")

// CurrentUser is the account a person's token belongs to.
func CurrentUser(ctx context.Context, client *http.Client, token string) (User, error) {
	var body struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := userCall(ctx, client, APIBase+"/user", token, &body); err != nil {
		return User{}, fmt.Errorf("github: who the token belongs to: %w", err)
	}
	if body.ID == 0 || body.Login == "" {
		return User{}, errors.New("github: the account has no id or login")
	}
	return User{ID: body.ID, Login: body.Login}, nil
}

// VerifiedEmails are the addresses GitHub has verified for the token's
// account, lowercased. Unverified ones are left out: anybody can add an
// address to their account, and only verifying it proves they receive
// mail there.
func VerifiedEmails(ctx context.Context, client *http.Client, token string) ([]string, error) {
	var out []string
	next := APIBase + "/user/emails?per_page=100"
	for next != "" {
		var page []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		}
		link, err := userPage(ctx, client, next, token, &page)
		if err != nil {
			return nil, fmt.Errorf("github: the account's addresses: %w", err)
		}
		for _, entry := range page {
			if entry.Verified && entry.Email != "" {
				out = append(out, strings.ToLower(strings.TrimSpace(entry.Email)))
			}
		}
		if link != "" && !strings.HasPrefix(link, APIBase+"/") {
			return nil, fmt.Errorf("github: the next page of addresses is not on %s", APIBase)
		}
		next = link
	}
	return out, nil
}

// CheckUserToken asks GitHub, as the App, whether a person's token is
// still valid. False with no error is GitHub's own answer that it is not:
// the authorization was revoked, or the account is gone.
func CheckUserToken(ctx context.Context, client *http.Client, clientID, secret, token string) (bool, error) {
	raw, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		return false, err
	}
	endpoint := APIBase + "/applications/" + url.PathEscape(clientID) + "/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(raw)))
	if err != nil {
		return false, err
	}
	request.SetBasicAuth(clientID, secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := client.Do(request) //nolint:gosec // the host is GitHub's, never configuration
	if err != nil {
		return false, fmt.Errorf("github: check a token: %w", err)
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	switch response.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("github: check a token: %w", statusError(response))
	}
}

func userCall(ctx context.Context, client *http.Client, endpoint, token string, out any) error {
	response, err := do(ctx, client, http.MethodGet, endpoint, token, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	if err = userStatus(response); err != nil {
		return err
	}
	return json.NewDecoder(response.Body).Decode(out)
}

func userPage(ctx context.Context, client *http.Client, endpoint, token string, out any) (string, error) {
	response, err := do(ctx, client, http.MethodGet, endpoint, token, nil)
	if err != nil {
		return "", err
	}
	defer response.Body.Close() //nolint:errcheck // a read body's close has nothing to report
	if err = userStatus(response); err != nil {
		return "", err
	}
	if err = json.NewDecoder(response.Body).Decode(out); err != nil {
		return "", err
	}
	return nextLink(response.Header.Get("Link")), nil
}

func userStatus(response *http.Response) error {
	switch response.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrTokenRefused, statusError(response))
	default:
		return statusError(response)
	}
}

// FormatID is a GitHub id as the string it is kept under.
func FormatID(id int64) string { return strconv.FormatInt(id, 10) }
