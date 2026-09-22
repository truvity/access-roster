package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/truvity/access-roster/tokens"
)

// sessionTokenMargin is how long before expiry the session's own access
// token stops being reused. It is handed straight to an exchange, so this
// only has to cover that one round trip.
const sessionTokenMargin = time.Minute

// refresh returns the issuer's own access token for this sign-in, minting
// one only when the last is spent.
//
// Every command starts here, which is why a laptop signs in once a week
// rather than once a morning: the refresh token is the long-lived half and
// the access token is minted for the moment it is used.
//
// IT REFUSES TO REFRESH NEEDLESSLY, and that is a correctness property
// rather than thrift. A refresh SPENDS the refresh token -- the issuer
// rotates it and refuses the old one, deliberately, so that a stolen one
// is good for a single use (internal/issuer/storage.go). Two commands
// refreshing at the same instant therefore end with one of them holding a
// token the issuer refuses, and this command reports that as "not signed
// in": the operator is signed out of everything by a pair of ordinary
// commands. Reusing the token already in hand removes the occasion
// entirely, and the lock below makes the moment it IS spent a moment only
// one caller is in.
func refresh(ctx context.Context, cfg Config) (tokens.Token, error) {
	session, err := loadSession()
	if err != nil {
		return tokens.Token{}, err
	}
	if token, ok := liveSessionToken(session); ok {
		return token, nil
	}

	path, err := sessionPath()
	if err != nil {
		return tokens.Token{}, err
	}

	var minted tokens.Token
	err = withCacheLock(path, func() error {
		// Re-read under the lock: a caller that waited here while another
		// minted finds the answer already written, which is the whole
		// point -- one refresh, not one per command.
		if current, loadErr := loadSession(); loadErr == nil {
			if token, ok := liveSessionToken(current); ok {
				minted = token

				return nil
			}
			session = current
		}

		var mintErr error
		minted, mintErr = mintSessionToken(ctx, cfg, session)

		return mintErr
	})
	if err != nil {
		return tokens.Token{}, err
	}

	return minted, nil
}

// liveSessionToken returns the session's own access token while it is
// still worth presenting.
//
// A session written by an older version of this command carries no token
// and no expiry, which reads as spent: the next refresh fills both in.
func liveSessionToken(session Session) (tokens.Token, bool) {
	if session.AccessToken == "" || session.AccessExpires.IsZero() {
		return tokens.Token{}, false
	}
	if time.Until(session.AccessExpires) <= sessionTokenMargin {
		return tokens.Token{}, false
	}

	return tokens.Token{AccessToken: session.AccessToken, Expires: session.AccessExpires}, true
}

// mintSessionToken spends the refresh token for a new pair and stores
// both. Called with the session lock held.
func mintSessionToken(ctx context.Context, cfg Config, session Session) (tokens.Token, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {session.RefreshToken},
		"client_id":     {cfg.ClientID},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Issuer+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return tokens.Token{}, fmt.Errorf("build the refresh: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return tokens.Token{}, fmt.Errorf("%w: %w", errUnreachable, err)
	}
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK {
		// A refused refresh means the session ended: revoked, expired,
		// or the account suspended. Signing in again is the only answer,
		// so it reads as not signed in rather than as a failure.
		return tokens.Token{}, errNotSignedIn
	}

	var granted struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err = json.Unmarshal(body, &granted); err != nil {
		return tokens.Token{}, fmt.Errorf("parse the refresh: %w", err)
	}
	token := tokens.Token{AccessToken: granted.AccessToken}
	if granted.ExpiresIn > 0 {
		token.Expires = time.Now().Add(time.Duration(granted.ExpiresIn) * time.Second)
	}

	// A rotated refresh token must be kept or the next command signs in
	// again — and the old one is dead the moment this one is issued. The
	// access token is kept for the same reason in reverse: so the next
	// command is not made to spend a refresh token to be given one just
	// like it.
	rotated := granted.RefreshToken != "" && granted.RefreshToken != session.RefreshToken
	if rotated {
		session.RefreshToken = granted.RefreshToken
	}

	// The access token is kept only when its lifetime is known, and
	// CLEARED otherwise: a token nothing can judge is one this file would
	// hold as a secret at rest for no reader, since a cache that cannot
	// tell when it stops being true must never serve it.
	held, heldUntil := session.AccessToken, session.AccessExpires
	session.AccessToken, session.AccessExpires = "", time.Time{}
	if !token.Expires.IsZero() {
		session.AccessToken, session.AccessExpires = granted.AccessToken, token.Expires
	}
	if rotated || session.AccessToken != held || !session.AccessExpires.Equal(heldUntil) {
		if err = saveSession(session); err != nil {
			return tokens.Token{}, err
		}
	}

	return token, nil
}

// grantsOf asks the issuer what this identity's groups open.
func grantsOf(ctx context.Context, cfg Config, token string) ([]grant, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Issuer+"/.access/grants", nil)
	if err != nil {
		return nil, fmt.Errorf("build the grants request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnreachable, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized {
		return nil, errNotSignedIn
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the issuer answered %s asking what you are granted", response.Status)
	}

	var answer struct {
		Grants []grant `json:"grants"`
	}
	if err = json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return nil, fmt.Errorf("parse the grants: %w", err)
	}
	return answer.Grants, nil
}

// grant is one client this identity may be issued a token for.
type grant struct {
	Audience string   `json:"audience"`
	Kind     string   `json:"kind"`
	Through  []string `json:"through"`
}

// whoami says who this is and what it opens.
func whoami(args []string) error {
	cfg, token, err := signedIn(args, "whoami")
	if err != nil {
		return err
	}

	session, _ := loadSession()
	who := session.Email
	if who == "" {
		who = session.Subject
	}
	if who != "" {
		_, _ = fmt.Fprintln(stdout, who)
	}

	grants, err := grantsOf(context.Background(), cfg, token.AccessToken)
	if err != nil {
		return err
	}
	if len(grants) == 0 {
		_, _ = fmt.Fprintln(stdout, "\nYour groups open nothing yet.")
		return nil
	}
	_, _ = fmt.Fprintln(stdout, "\nYou are granted:")
	for _, one := range grants {
		_, _ = fmt.Fprintf(stdout, "  %-28s through %s\n", one.Audience, strings.Join(one.Through, ", "))
	}
	return nil
}

// exchange is the raw exchange, for a script.
//
// The subject token comes in on stdin rather than as an argument,
// because an argument is in the process list and in a shell history.
func exchange(args []string) error {
	flags := flag.NewFlagSet("exchange", flag.ContinueOnError)
	audience := flags.String("audience", "", "what the token should be for")
	issuer := flags.String("issuer", "", "the issuer, when not configured")
	clientID := flags.String("client", "", "the client to present")
	if err := flags.Parse(args); err != nil {
		return usageError{err}
	}
	if strings.TrimSpace(*audience) == "" {
		return badUsage("--audience is required: a token for nothing in particular is what an audience prevents")
	}
	cfg, err := loadConfig(*issuer, *clientID)
	if err != nil {
		return err
	}

	subject, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return fmt.Errorf("read the subject token from stdin: %w", err)
	}
	if strings.TrimSpace(string(subject)) == "" {
		return badUsage("no subject token on stdin")
	}

	token, err := exchangeFor(context.Background(), cfg, strings.TrimSpace(string(subject)), *audience)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, token.AccessToken)
	return nil
}

// exchangeFor trades a subject token for one audienced elsewhere, and
// turns the issuer's refusal into this tool's exit code.
func exchangeFor(ctx context.Context, cfg Config, subject, audience string) (tokens.Token, error) {
	return exchangeAs(ctx, cfg.Issuer, cfg.ClientID, subject, tokens.TypeJWT, audience)
}

// exchangeAs is the exchange with the presented client named, which a
// job's proof needs: it presents the audience, never a sign-in client.
func exchangeAs(ctx context.Context, issuer, client, subject, subjectType, audience string) (tokens.Token, error) {
	exchanger := &tokens.Exchanger{Issuer: issuer, ClientID: client, Client: retryingClient()}
	token, err := exchanger.Exchange(ctx, subject, subjectType, audience)
	switch {
	case errors.Is(err, tokens.ErrRefused):
		// The issuer's own sentence names the audience and the groups
		// the proof holds, so it is carried through rather than replaced
		// with something shorter and less useful.
		return tokens.Token{}, fmt.Errorf("%w: %w", errNotGranted, err)
	case err != nil:
		return tokens.Token{}, fmt.Errorf("%w: %w", errUnreachable, err)
	}
	return token, nil
}

// signedIn is the opening of every command that needs a token.
func signedIn(args []string, name string) (Config, tokens.Token, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	issuer := flags.String("issuer", "", "the issuer, when not configured")
	clientID := flags.String("client", "", "the client to present")
	if err := flags.Parse(args); err != nil {
		return Config{}, tokens.Token{}, usageError{err}
	}
	cfg, err := loadConfig(*issuer, *clientID)
	if err != nil {
		return Config{}, tokens.Token{}, err
	}
	token, err := refresh(context.Background(), cfg)
	if err != nil {
		return Config{}, tokens.Token{}, err
	}
	return cfg, token, nil
}
