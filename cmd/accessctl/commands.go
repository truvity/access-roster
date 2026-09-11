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

	"github.com/truvity/access-roster/tokens"
)

// refresh trades the cached refresh token for a fresh access token.
//
// Every command below starts here, which is why a laptop signs in once a
// week rather than once a morning: the refresh token is the long-lived
// half and the access token is minted for the moment it is used.
func refresh(ctx context.Context, cfg Config) (tokens.Token, error) {
	session, err := loadSession()
	if err != nil {
		return tokens.Token{}, err
	}

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
	}
	if err = json.Unmarshal(body, &granted); err != nil {
		return tokens.Token{}, fmt.Errorf("parse the refresh: %w", err)
	}
	// A rotated refresh token must be kept or the next command signs in
	// again — and the old one is dead the moment this one is issued.
	if granted.RefreshToken != "" && granted.RefreshToken != session.RefreshToken {
		session.RefreshToken = granted.RefreshToken
		if err = saveSession(session); err != nil {
			return tokens.Token{}, err
		}
	}
	return tokens.Token{AccessToken: granted.AccessToken}, nil
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
	exchanger := &tokens.Exchanger{Issuer: cfg.Issuer, ClientID: cfg.ClientID}
	token, err := exchanger.Exchange(ctx, subject, tokens.TypeJWT, audience)
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
