package valkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/internal/issuer"
)

// State is a login in progress, shared by every replica: the
// authorization request a browser is part-way through, the code it comes
// back with, the tokens that follow, the device flow a CLI is polling.
//
// It is here rather than in the issuer because the issuer must not know
// what a cache is, and here rather than beside the snapshots because the
// two have nothing to do with each other beyond the address they dial.
// Everything carries its own expiry, so nothing sweeps.
type State struct {
	client redis.UniversalClient
	prefix string
}

var _ issuer.State = (*State)(nil)

// OpenState connects and proves it can talk, so that a misconfigured
// address is a startup failure rather than a failed login.
func OpenState(ctx context.Context, cfg Config) (*State, error) {
	client, prefix, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &State{client: client, prefix: prefix}, nil
}

// NewState wraps a client that is already open. For tests.
func NewState(client redis.UniversalClient, prefix string) *State {
	return &State{client: client, prefix: prefix}
}

// Close releases the connections.
func (s *State) Close() error { return s.client.Close() }

func (s *State) key(key string) string { return s.prefix + ":" + key }

// Get implements [issuer.State].
func (s *State) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := s.client.Get(ctx, s.key(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		// Expired or never written, and those are the same answer: there
		// is nothing to continue.
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("valkey: read %s: %w", key, err)
	}
	return value, true, nil
}

// Set implements [issuer.State].
func (s *State) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if ttl <= 0 {
		// Everything in a login flow has a lifetime. A value with none
		// would sit here until somebody noticed, which is how a cache
		// becomes a database nobody meant to run.
		return fmt.Errorf("valkey: %s was stored with no lifetime", key)
	}
	if err := s.client.Set(ctx, s.key(key), value, ttl).Err(); err != nil {
		return fmt.Errorf("valkey: store %s: %w", key, err)
	}
	return nil
}

// SetIfAbsent implements [issuer.State].
func (s *State) SetIfAbsent(
	ctx context.Context, key string, value []byte, ttl time.Duration,
) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("valkey: %s was stored with no lifetime", key)
	}
	// One round trip that both checks and claims: two replicas minting
	// the same short user code at the same moment must not both believe
	// they own it, and a check followed by a write leaves exactly that
	// gap.
	taken, err := s.client.SetNX(ctx, s.key(key), value, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("valkey: claim %s: %w", key, err)
	}
	return taken, nil
}

// Delete implements [issuer.State].
func (s *State) Delete(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, s.key(key)).Err(); err != nil {
		return fmt.Errorf("valkey: delete %s: %w", key, err)
	}
	return nil
}

// Add implements [issuer.State].
//
// SADD then EXPIRE, and the expiry is refreshed on every add: a set of
// sessions should outlive its newest member, not its oldest. Without the
// refresh an identity that signs in daily would have its whole index
// vanish on the anniversary of its first login.
func (s *State) Add(ctx context.Context, key, member string, ttl time.Duration) error {
	if err := s.client.SAdd(ctx, s.key(key), member).Err(); err != nil {
		return fmt.Errorf("valkey: add to %s: %w", key, err)
	}

	if ttl > 0 {
		if err := s.client.Expire(ctx, s.key(key), ttl).Err(); err != nil {
			return fmt.Errorf("valkey: expire %s: %w", key, err)
		}
	}

	return nil
}

// Remove implements [issuer.State].
func (s *State) Remove(ctx context.Context, key, member string) error {
	if err := s.client.SRem(ctx, s.key(key), member).Err(); err != nil {
		return fmt.Errorf("valkey: remove from %s: %w", key, err)
	}

	return nil
}

// Members implements [issuer.State].
func (s *State) Members(ctx context.Context, key string) ([]string, error) {
	members, err := s.client.SMembers(ctx, s.key(key)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("valkey: read %s: %w", key, err)
	}

	return members, nil
}
