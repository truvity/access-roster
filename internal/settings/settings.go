// Package settings keeps the two things an operator can change from the
// console: the OAuth client used for admin consent and for sign-in, and
// the access rules added there.
//
// Everything else an operator sees — the intervals, the cache backend, the
// declared rules — is deployment configuration, shown read-only.
package settings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/truvity/access-roster/rules"
)

// ErrDeclared is returned when the deployment owns what is being changed.
var ErrDeclared = errors.New("settings: declared by the deployment")

// ErrNotFound is returned for a rule id the store does not hold.
var ErrNotFound = errors.New("settings: not found")

// OAuthClient is the client an installation registered once with its
// directory backend: it drives both admin consent and operator sign-in.
type OAuthClient struct {
	ID     string
	Secret string
	// Declared marks a client the chart named, which the console shows but
	// cannot change.
	Declared bool
}

// Configured reports whether both halves are present.
func (c OAuthClient) Configured() bool { return c.ID != "" && c.Secret != "" }

// Store keeps the console-writable settings.
type Store interface {
	// OAuthClient returns the client, which may be unconfigured.
	OAuthClient(ctx context.Context) (OAuthClient, error)
	// SetOAuthClient stores one; it returns ErrDeclared when the chart
	// declared the client.
	SetOAuthClient(ctx context.Context, id, secret string) error
	// Rules returns the rules added through the console, in order.
	Rules(ctx context.Context) ([]rules.Rule, error)
	// AddRule appends one.
	AddRule(ctx context.Context, rule rules.Rule) error
	// RemoveRule deletes one by id; ErrNotFound when there is none.
	RemoveRule(ctx context.Context, id string) error
}

// Memory is a Store in process memory: the prototype's, and the fake
// behind tests of the one that persists.
type Memory struct {
	mu     sync.RWMutex
	client OAuthClient
	added  []rules.Rule
}

var _ Store = (*Memory)(nil)

// NewMemory returns a store, optionally seeded with a declared client.
func NewMemory(declared OAuthClient) *Memory { return &Memory{client: declared} }

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

// Rules implements [Store].
func (m *Memory) Rules(_ context.Context) ([]rules.Rule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.added), nil
}

// AddRule implements [Store].
func (m *Memory) AddRule(_ context.Context, rule rules.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.added {
		if m.added[i].ID == rule.ID {
			return fmt.Errorf("settings: rule %q already exists", rule.ID)
		}
	}
	m.added = append(m.added, rule)
	return nil
}

// RemoveRule implements [Store].
func (m *Memory) RemoveRule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.added {
		if m.added[i].ID == id {
			m.added = slices.Delete(m.added, i, i+1)
			return nil
		}
	}
	return fmt.Errorf("%w: rule %q", ErrNotFound, id)
}
