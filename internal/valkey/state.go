package valkey

import (
	"context"
	"crypto/sha1" //nolint:gosec // see Revision
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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

// retry runs one command, once more if its node was lost. See
// [retryAfterFailover]. Nothing State does consumes what it reads -- a
// redemption is a Get followed by a separate Delete, issued by the
// issuer -- so no read here is unsafe to repeat.
func (s *State) retry(ctx context.Context, name, key string, idempotent bool, op func() error) error {
	return retryAfterFailover(ctx, s.client, name, s.key(key), idempotent, op)
}

// Get implements [issuer.State].
func (s *State) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var value []byte
	err := s.retry(ctx, "get", key, true, func() (err error) {
		value, err = s.client.Get(ctx, s.key(key)).Bytes()
		return err
	})
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
	if err := s.retry(ctx, "set", key, true, func() error {
		return s.client.Set(ctx, s.key(key), value, ttl).Err()
	}); err != nil {
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
	var taken bool
	err := s.retry(ctx, "setnx", key, false, func() (err error) {
		taken, err = s.client.SetNX(ctx, s.key(key), value, ttl).Result()
		return err
	})
	if err != nil {
		return false, fmt.Errorf("valkey: claim %s: %w", key, err)
	}
	return taken, nil
}

// Delete implements [issuer.State].
func (s *State) Delete(ctx context.Context, key string) error {
	if err := s.retry(ctx, "del", key, true, func() error {
		return s.client.Del(ctx, s.key(key)).Err()
	}); err != nil {
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
	if err := s.retry(ctx, "sadd", key, true, func() error {
		return s.client.SAdd(ctx, s.key(key), member).Err()
	}); err != nil {
		return fmt.Errorf("valkey: add to %s: %w", key, err)
	}

	if ttl > 0 {
		if err := s.retry(ctx, "expire", key, true, func() error {
			return s.client.Expire(ctx, s.key(key), ttl).Err()
		}); err != nil {
			return fmt.Errorf("valkey: expire %s: %w", key, err)
		}
	}

	return nil
}

// Remove implements [issuer.State].
func (s *State) Remove(ctx context.Context, key, member string) error {
	if err := s.retry(ctx, "srem", key, true, func() error {
		return s.client.SRem(ctx, s.key(key), member).Err()
	}); err != nil {
		return fmt.Errorf("valkey: remove from %s: %w", key, err)
	}

	return nil
}

// Members implements [issuer.State].
func (s *State) Members(ctx context.Context, key string) ([]string, error) {
	var members []string
	err := s.retry(ctx, "smembers", key, true, func() (err error) {
		members, err = s.client.SMembers(ctx, s.key(key)).Result()
		return err
	})
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("valkey: read %s: %w", key, err)
	}

	return members, nil
}

// Ping reports whether the store answers. See [Snapshots.Ping] for why
// this is readiness and never liveness.
func (s *State) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Revision is what [State] calls a value's version: the SHA-1 of its bytes,
// as Valkey's own Lua computes it. It is a content tag, not a counter, and
// not a security measure -- Valkey keeps no version of a key, and adding one
// would change what is written.
func Revision(value []byte) string {
	sum := sha1.Sum(value) //nolint:gosec // a content tag compared by equality, not a hash anyone trusts
	return hex.EncodeToString(sum[:])
}

// The two compare-and-swap scripts. Both answer -1 when the key is gone
// (absent or expired), 0 when its bytes are not the ones expected and 1
// when they acted.
var (
	swapScript = redis.NewScript(`
local cur = redis.call("get", KEYS[1])
if not cur then return -1 end
if redis.sha1hex(cur) ~= ARGV[1] then return 0 end
redis.call("set", KEYS[1], ARGV[2], "PX", ARGV[3])
return 1`)
	dropScript = redis.NewScript(`
local cur = redis.call("get", KEYS[1])
if not cur then return -1 end
if redis.sha1hex(cur) ~= ARGV[1] then return 0 end
redis.call("del", KEYS[1])
return 1`)
)

// Outcome is what a conditional write did.
type Outcome int

// The outcomes of [State.Swap] and [State.DropIf].
const (
	// Gone: there was no live value to compare.
	Gone Outcome = -1
	// Moved: the value's revision was not the one expected.
	Moved Outcome = 0
	// Done: the condition held and the command ran.
	Done Outcome = 1
)

// Swap replaces the value at key with a new one for ttl, only if the
// current value's [Revision] is expected. It is one script, so two replicas
// swapping from one revision cannot both win.
func (s *State) Swap(ctx context.Context, key, expected string, value []byte, ttl time.Duration) (Outcome, error) {
	if ttl <= 0 {
		return Moved, fmt.Errorf("valkey: %s was stored with no lifetime", key)
	}
	var out int64
	err := s.retry(ctx, "swap", key, false, func() (err error) {
		out, err = swapScript.Run(ctx, s.client, []string{s.key(key)}, expected, value, ttl.Milliseconds()).Int64()
		return err
	})
	if err != nil {
		return Moved, fmt.Errorf("valkey: swap %s: %w", key, err)
	}
	return Outcome(out), nil
}

// DropIf deletes the value at key only if its [Revision] is expected.
func (s *State) DropIf(ctx context.Context, key, expected string) (Outcome, error) {
	var out int64
	err := s.retry(ctx, "dropif", key, false, func() (err error) {
		out, err = dropScript.Run(ctx, s.client, []string{s.key(key)}, expected).Int64()
		return err
	})
	if err != nil {
		return Moved, fmt.Errorf("valkey: delete %s if unchanged: %w", key, err)
	}
	return Outcome(out), nil
}

// Keys lists the keys that start with prefix, sorted, without this State's
// own namespace. It is a SCAN of every primary: right for a listing an
// operator or a watcher asks for, and not a path a request takes.
func (s *State) Keys(ctx context.Context, prefix string) ([]string, error) {
	match := globEscape(s.key(prefix)) + "*"
	var (
		mu  sync.Mutex
		out []string
	)
	scan := func(ctx context.Context, c redis.Cmdable) error {
		var cursor uint64
		for {
			keys, next, err := c.Scan(ctx, cursor, match, 512).Result()
			if err != nil {
				return err
			}
			mu.Lock()
			for _, k := range keys {
				out = append(out, strings.TrimPrefix(k, s.prefix+":"))
			}
			mu.Unlock()
			if cursor = next; cursor == 0 {
				return nil
			}
		}
	}
	var err error
	if cluster, ok := s.client.(*redis.ClusterClient); ok {
		err = cluster.ForEachMaster(ctx, func(ctx context.Context, node *redis.Client) error { return scan(ctx, node) })
	} else {
		err = scan(ctx, s.client)
	}
	if err != nil {
		return nil, fmt.Errorf("valkey: list %s: %w", prefix, err)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func globEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`).Replace(s)
}
