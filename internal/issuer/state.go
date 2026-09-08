package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"time"
)

// State is where a login in progress lives: the authorization request a
// browser is part-way through, the code it comes back with, the tokens
// that follow, the device flow a CLI is polling.
//
// It is an interface because none of it may live in one process. A
// browser starts at /authorize on one replica, comes back from the
// provider at another, and the client redeems the code at a third; a CLI
// polls the device endpoint at whichever answers. Kept in memory, each of
// those is a coin toss that looks like an intermittent failure — the same
// shape of bug as a per-process signing key, and harder to see, because
// it only appears at more than one replica and only sometimes.
//
// Everything here expires on its own. Nothing in a login flow is worth
// keeping past its lifetime, and a store that needs sweeping is a store
// that grows when the sweeper stops.
type State interface {
	// Get returns the value, or false when there is none. An expired
	// value is absent, not an error.
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// Set stores it for ttl.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// SetIfAbsent stores it only if the key is free, and reports whether
	// it did. It is how a user code is claimed: two replicas minting the
	// same short code at the same moment must not both believe they own
	// it.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// Delete removes it. Deleting what is not there is not an error.
	Delete(ctx context.Context, key string) error
}

// getJSON reads a value and decodes it.
func getJSON[T any](ctx context.Context, state State, key string) (*T, error) {
	raw, found, err := state.Get(ctx, key)
	if err != nil || !found {
		return nil, err
	}
	var out T
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("issuer: %s is not readable: %w", key, err)
	}
	return &out, nil
}

// setJSON encodes a value and stores it.
func setJSON(ctx context.Context, state State, key string, value any, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("issuer: encode %s: %w", key, err)
	}
	return state.Set(ctx, key, raw, ttl)
}

// MemoryState keeps it in one process: right for a local run and for one
// replica, and wrong for more.
type MemoryState struct {
	mu     sync.Mutex
	values map[string]memoryValue
	now    func() time.Time
}

type memoryValue struct {
	value   []byte
	expires time.Time
}

var _ State = (*MemoryState)(nil)

// NewMemoryState returns an empty store.
func NewMemoryState() *MemoryState {
	return &MemoryState{values: map[string]memoryValue{}, now: time.Now}
}

// SetClock replaces the clock. For tests.
func (m *MemoryState) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// Get implements [State].
func (m *MemoryState) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.get(key)
}

func (m *MemoryState) get(key string) ([]byte, bool, error) {
	held, ok := m.values[key]
	if !ok {
		return nil, false, nil
	}
	// Expiry is checked on read rather than swept: a value nobody asks
	// for costs a little memory, and a sweeper that stops is a store that
	// grows without anyone noticing.
	if !held.expires.IsZero() && !m.now().Before(held.expires) {
		delete(m.values, key)
		return nil, false, nil
	}
	return held.value, true, nil
}

// Set implements [State].
func (m *MemoryState) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set(key, value, ttl)
	return nil
}

func (m *MemoryState) set(key string, value []byte, ttl time.Duration) {
	held := memoryValue{value: value}
	if ttl > 0 {
		held.expires = m.now().Add(ttl)
	}
	m.values[key] = held
}

// SetIfAbsent implements [State].
func (m *MemoryState) SetIfAbsent(
	_ context.Context, key string, value []byte, ttl time.Duration,
) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken, _ := m.get(key); taken {
		return false, nil
	}
	m.set(key, value, ttl)
	return true, nil
}

// Delete implements [State].
func (m *MemoryState) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
	return nil
}

// Keys returns what is held, for a test that wants to see it.
func (m *MemoryState) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.values))
	for key := range maps.Keys(m.values) {
		out = append(out, key)
	}
	return out
}
