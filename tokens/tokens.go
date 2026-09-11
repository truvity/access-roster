// Package tokens trades one token for another, and writes the two
// shapes a credential helper has to speak.
//
// It is what `accessctl` runs on and what a workload uses directly. The
// exchange is RFC 8693 and carries no secret: a caller presents a token
// something else already gave it — a GitHub Actions token, a
// ServiceAccount token, or its own from a sign-in — and receives one
// audienced at what it is trying to reach.
//
// The two encoders exist because the tools that consume a credential
// disagree about the envelope and about nothing else. `kubectl` reads an
// ExecCredential on stdout; the AWS SDKs read a credential-process
// document. Both wrap the same exchanged token, and getting either shape
// slightly wrong fails in a way that names neither this package nor the
// token.
package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The RFC 8693 constants, spelled once.
const (
	GrantTypeExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

// ErrRefused is an exchange the issuer declined: the proof did not carry
// a group the requested audience admits. It is separated from a
// transport failure because a caller should retry one and not the other.
var ErrRefused = errors.New("tokens: the exchange was refused")

// Exchanger trades a subject token for one audienced elsewhere.
type Exchanger struct {
	// Issuer is the access-roster issuer, e.g. https://access.example.
	Issuer string
	// ClientID is the client this caller presents itself as. The library
	// on the other side reads the exchange's client from HTTP Basic
	// alone — never from a posted client_id — so a public client sends
	// its id with an empty password, which is what this does.
	ClientID string
	// ClientSecret is empty for a public client.
	ClientSecret string
	// Client is the transport. Nil uses one with a thirty-second
	// timeout: an exchange is one round trip and should not be the thing
	// that hangs a CI job.
	Client *http.Client
}

// Token is what an exchange returns.
type Token struct {
	AccessToken string
	// Expires is when it stops being accepted. A caller that caches must
	// honour it: a token used past expiry fails at the relying party,
	// where the error names neither this package nor the exchange.
	Expires time.Time
}

// Exchange trades subject for a token audienced at audience.
//
// subjectType says what is being presented. Both RFC 8693 spellings are
// accepted by the issuer, and an empty value means [TypeJWT], which is
// what every subject this family deals in actually is.
func (e *Exchanger) Exchange(ctx context.Context, subject, subjectType, audience string) (Token, error) {
	switch {
	case e == nil || strings.TrimSpace(e.Issuer) == "":
		return Token{}, errors.New("tokens: no issuer is configured")
	case strings.TrimSpace(subject) == "":
		return Token{}, errors.New("tokens: no subject token to exchange")
	case strings.TrimSpace(audience) == "":
		// An exchange with no audience would mint a token for nothing in
		// particular, which is the one thing an audience exists to stop.
		return Token{}, errors.New("tokens: no audience was asked for")
	}
	if subjectType == "" {
		subjectType = TypeJWT
	}

	form := url.Values{
		"grant_type":         {GrantTypeExchange},
		"subject_token":      {subject},
		"subject_token_type": {subjectType},
		"audience":           {audience},
		"scope":              {"openid"},
	}
	endpoint := strings.TrimSuffix(e.Issuer, "/") + "/token"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("tokens: build the exchange: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(e.ClientID, e.ClientSecret)

	httpClient := e.Client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return Token{}, fmt.Errorf("tokens: exchange at %s: %w", endpoint, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return Token{}, fmt.Errorf("tokens: read the exchange: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		var failure struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &failure)
		// The description is the issuer's own sentence — it names the
		// audience and the groups the proof holds — and it is the whole
		// value of the error to whoever is reading a build log.
		detail := strings.TrimSpace(failure.Description)
		if detail == "" {
			detail = strings.TrimSpace(failure.Error)
		}
		if detail == "" {
			detail = response.Status
		}
		return Token{}, fmt.Errorf("%w: %s", ErrRefused, detail)
	}

	var granted struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &granted); err != nil {
		return Token{}, fmt.Errorf("tokens: parse the exchange: %w", err)
	}
	if granted.AccessToken == "" {
		return Token{}, errors.New("tokens: the exchange returned no token")
	}

	out := Token{AccessToken: granted.AccessToken}
	if granted.ExpiresIn > 0 {
		out.Expires = time.Now().Add(time.Duration(granted.ExpiresIn) * time.Second)
	}
	return out, nil
}
