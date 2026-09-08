// Package connector turns a directory's own sign-in screen into a
// workspace the hub can read.
//
// It sits between the console, which knows about consent flows and
// nothing about directories, and a backend, which knows about a directory
// and nothing about browsers. Keeping it out of both is what lets the
// backend packages stay free of the hub's vocabulary.
package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/backend/google"
	"github.com/truvity/access-roster/internal/hub"
)

// Google connects a Google Workspace, both ways in: an administrator's
// consent, or a service-account key an operator already holds.
//
// The client is read at each use rather than captured, because it is a
// console setting on a fresh installation: the connector exists before
// anyone has registered a client, and offering "Connect" only after a
// restart would make day one worse for no reason.
type Google struct {
	client func() (google.OAuthClient, error)
}

// NewGoogle returns a connector reading its OAuth client from client.
func NewGoogle(client func() (google.OAuthClient, error)) *Google {
	return &Google{client: client}
}

// Kind implements the console's connector contract.
func (g *Google) Kind() string { return "google" }

// AuthURL implements the console's connector contract.
func (g *Google) AuthURL(state string) (string, error) {
	client, err := g.client()
	if err != nil {
		return "", err
	}
	return client.AuthURL(state), nil
}

// SignInURL implements the console's sign-in contract.
func (g *Google) SignInURL(state string) (string, error) {
	client, err := g.client()
	if err != nil {
		return "", err
	}
	return client.SignInURL(state), nil
}

// Identify implements the console's sign-in contract.
func (g *Google) Identify(ctx context.Context, code string) (string, error) {
	client, err := g.client()
	if err != nil {
		return "", err
	}
	return google.Identify(ctx, client, code)
}

// Exchange implements the console's connector contract: the callback's
// code becomes a workspace and the backend that reads it.
//
// The tenant id is read here rather than left to adoption because the
// console needs it one step earlier — a reconnection has to be refused
// when the administrator who consented belongs to a different company
// than the workspace being reconnected, and by the time the hub adopts,
// that question has already been answered wrongly.
func (g *Google) Exchange(ctx context.Context, code, _ string) (hub.Workspace, backend.Backend, error) {
	client, err := g.client()
	if err != nil {
		return hub.Workspace{}, nil, err
	}
	reader, err := google.Consent(ctx, client, code)
	if err != nil {
		return hub.Workspace{}, nil, err
	}
	tenant, err := reader.Tenant(ctx)
	if err != nil {
		return hub.Workspace{}, nil, fmt.Errorf("read the tenant that consented: %w", err)
	}
	return hub.Workspace{
		ID:         tenant.ID,
		Admin:      reader.Admin(),
		Credential: hub.CredentialOAuth,
	}, reader, nil
}

// FromKey implements the console's key-upload contract.
//
// The id is left for adoption to discover: the tenant knows it, and an id
// nobody typed cannot be mistyped.
func (g *Google) FromKey(ctx context.Context, key []byte, admin string) (hub.Workspace, backend.Backend, error) {
	admin = strings.ToLower(strings.TrimSpace(admin))
	if admin == "" {
		return hub.Workspace{}, nil, errors.New("the admin account to impersonate is required")
	}
	reader, err := google.Open(ctx, key, admin)
	if err != nil {
		return hub.Workspace{}, nil, err
	}
	return hub.Workspace{
		Admin:      admin,
		Credential: hub.CredentialServiceAccountKey,
	}, reader, nil
}
