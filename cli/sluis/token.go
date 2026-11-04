package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"time"

	"github.com/truvity/sluis/v2/kits/go/cli"
)

//nolint:gosec // G101: these are the registered names of RFC 8693, not credentials
const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"
	// leeway is how long before its expiry a cached token stops being used.
	leeway = 30 * time.Second
)

func (a *app) tokenCommand() command {
	var issuer, audience string
	var secretFd int
	return command{
		name: "token",
		flags: func(fs *flag.FlagSet) {
			fs.StringVar(&issuer, "issuer", "", "the issuer URL; from the cache when only one is signed in")
			fs.StringVar(&audience, "audience", "", "the client id of the audience (required)")
			fs.IntVar(&secretFd, "secret-fd", -1, "read the client secret from this descriptor")
		},
		run: func(ctx context.Context, positional []string, res *result) error {
			if len(positional) > 0 {
				return cli.Usage(errors.New("token takes no argument"))
			}
			if audience == "" {
				return cli.Usage(errors.New("--audience is required"))
			}
			secret, err := a.readSecret(secretFd)
			if err != nil {
				return err
			}
			return a.token(ctx, issuer, audience, secret, res)
		},
	}
}

// token prints an access token for the audience: from the cache while it is valid, otherwise by an RFC 8693 token
// exchange whose subject token is the cached access token, refreshed first when it has expired (RFC 6749 section 6).
func (a *app) token(ctx context.Context, issuer, audience, secret string, res *result) error {
	dir, set, err := a.loadSet(issuer)
	if err != nil {
		return err
	}
	key := exchangeKey(a.boundary, audience)
	if e, ok := set.Exchanged[key]; ok && e.AccessToken != "" && e.ExpiresAt.After(a.now().Add(leeway)) {
		return a.tokenResult(res, e, audience, set.Issuer)
	}
	if _, err := checkEndpoint(set.TokenEndpoint); err != nil {
		return refused("cache.token_endpoint")
	}
	c := &client{hc: a.hc, id: set.ClientID, secret: secret, endpoint: set.TokenEndpoint}

	if !set.ExpiresAt.After(a.now().Add(leeway)) {
		if set.RefreshToken == "" {
			return refused("cache.login")
		}
		tr, err := c.post(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {set.RefreshToken}})
		if err != nil {
			// A refresh token the issuer refuses means the person has to sign in again.
			return tokenError(err, "cache.login")
		}
		set.AccessToken = tr.AccessToken
		set.ExpiresAt = a.now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()
		if tr.RefreshToken != "" {
			set.RefreshToken = tr.RefreshToken
		}
		set.Exchanged = nil // issued against the old subject token
		if err := writeSet(dir, set); err != nil {
			return fmt.Errorf("token cache: %w", err)
		}
	}

	// RFC 8693 section 2.1. The refusal looks the same for an unknown and a refused audience (contracts.md).
	tr, err := c.post(ctx, url.Values{
		"grant_type":           {grantTokenExchange},
		"subject_token":        {set.AccessToken},
		"subject_token_type":   {tokenTypeAccess},
		"requested_token_type": {tokenTypeAccess},
		"audience":             {audience},
	})
	if err != nil {
		return tokenError(err, "token.exchange")
	}
	// RFC 8693 section 2.2.1: issued_token_type is REQUIRED, and this request asked for an access token.
	if tr.IssuedTokenType != tokenTypeAccess {
		return refused("token.issued_token_type")
	}
	e := exchanged{AccessToken: tr.AccessToken, ExpiresAt: a.now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC()}
	if set.Exchanged == nil {
		set.Exchanged = map[string]exchanged{}
	}
	set.Exchanged[key] = e
	if err := writeSet(dir, set); err != nil {
		return fmt.Errorf("token cache: %w", err)
	}
	return a.tokenResult(res, e, audience, set.Issuer)
}

func (a *app) tokenResult(res *result, e exchanged, audience, issuer string) error {
	res.Token = &tokenOut{AccessToken: e.AccessToken, ExpiresAt: e.ExpiresAt.UTC().Format(time.RFC3339), Audience: audience, Issuer: issuer}
	res.Text = e.AccessToken
	return nil
}
