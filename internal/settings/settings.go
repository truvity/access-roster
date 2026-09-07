// Package settings keeps the two things an operator can change from the
// console: the OAuth client used for admin consent and for sign-in, and
// the memberships added there.
//
// Everything else an operator sees — the internal groups, what they add,
// the lifetimes, the clients, the intervals — is deployment
// configuration, shown read-only.
package settings

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// ErrDeclared is returned when the deployment owns what is being changed.
var ErrDeclared = errors.New("settings: declared by the deployment")

// OAuthClient is the client an installation registered once with its
// directory backend: it drives both admin consent and operator sign-in.
type OAuthClient struct {
	ID     string
	Secret string
	// Declared marks a client the chart named, which the console shows
	// but cannot change.
	Declared bool
}

// Configured reports whether both halves are present.
func (c OAuthClient) Configured() bool { return c.ID != "" && c.Secret != "" }

// Store keeps the console-writable settings.
type Store interface {
	// OAuthClient returns the client, which may be unconfigured.
	OAuthClient(ctx context.Context) (OAuthClient, error)
	// SetOAuthClient stores one; ErrDeclared when the chart declared it.
	SetOAuthClient(ctx context.Context, id, secret string) error
	// Memberships returns the console layer of the policy.
	Memberships(ctx context.Context) (map[string][]string, error)
	// SetMemberships replaces it.
	SetMemberships(ctx context.Context, memberships map[string][]string) error
}

// Memory is a Store in process memory: the prototype's, and the fake
// behind tests of the one that persists.
type Memory struct {
	mu          sync.RWMutex
	client      OAuthClient
	memberships map[string][]string
}

var _ Store = (*Memory)(nil)

// NewMemory returns a store, optionally seeded with a declared client.
func NewMemory(declared OAuthClient) *Memory {
	return &Memory{client: declared, memberships: map[string][]string{}}
}

// OAuthClient implements [Store].
func (m *Memory) OAuthClient(_ context.Context) (OAuthClient, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.client, nil
}

// SetOAuthClient implements [Store].
func (m *Memory) SetOAuthClient(_ context.Context, id, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client.Declared {
		return ErrDeclared
	}
	if id == "" || secret == "" {
		return errors.New("settings: both the client id and the secret are required")
	}
	m.client = OAuthClient{ID: id, Secret: secret}
	return nil
}

// Memberships implements [Store].
func (m *Memory) Memberships(_ context.Context) (map[string][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string][]string, len(m.memberships))
	for name, members := range m.memberships {
		out[name] = slices.Clone(members)
	}
	return out, nil
}

// SetMemberships implements [Store].
func (m *Memory) SetMemberships(_ context.Context, memberships map[string][]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.memberships = make(map[string][]string, len(memberships))
	for name, members := range memberships {
		m.memberships[name] = slices.Clone(members)
	}
	return nil
}
