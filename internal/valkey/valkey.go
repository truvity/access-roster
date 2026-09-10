// Package valkey keeps the hub's snapshots where every replica can see
// the same one.
//
// A snapshot is a whole directory read at a moment: every account with
// its liveness, every group with its members. Two replicas each holding
// their own would answer the same question two ways and read the same
// directory twice, and a directory's API quota is per tenant, not per
// reader. So the snapshot is shared, and so is the lease that decides
// which replica does the reading.
//
// Nothing here is a source of truth. Everything in this store can be
// rebuilt by reading the directory again, which is what makes it safe to
// lose: an empty cache is a hub with no snapshots, which answers "not
// authoritative" until the next refresh, and a non-authoritative answer
// removes nobody's access.
package valkey

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/backend"
	"github.com/truvity/access-roster/internal/hub"
)

// DefaultTTL is how long a snapshot outlives its last write.
//
// It is not the freshness window — that is the hub's, and much shorter.
// This is only so that a workspace disconnected while a replica was down
// does not leave a copy of a company's directory sitting in a cache for
// ever.
const DefaultTTL = 7 * 24 * time.Hour

// Config is how to reach the Valkey the deployment points at.
type Config struct {
	// Address is host:port. Empty means "no Valkey": the caller keeps
	// snapshots in memory instead.
	Address string
	// Password is optional.
	Password string
	// TLS turns on TLS to the server.
	TLS bool
	// Cluster speaks the cluster protocol. The fleet's Valkeys are
	// ValkeyClusters even at one shard, so this is the usual answer; a
	// plain single server needs it off, and a mismatch shows up as a
	// refused command at start rather than as a subtle failure later.
	Cluster bool
	// Prefix namespaces every key, so that one Valkey can serve more than
	// one installation.
	Prefix string
	// TTL overrides DefaultTTL.
	TTL time.Duration
}

// Snapshots is a shared [hub.SnapshotStore] with a shared refresh lease.
type Snapshots struct {
	client redis.UniversalClient
	prefix string
	ttl    time.Duration
}

var (
	_ hub.SnapshotStore = (*Snapshots)(nil)
	_ hub.Locker        = (*Snapshots)(nil)
)

// dial connects and proves it can talk, so that a misconfigured address
// is a startup failure rather than a first-request one.
func dial(ctx context.Context, cfg Config) (redis.UniversalClient, string, error) {
	if cfg.Address == "" {
		return nil, "", errors.New("valkey: no address")
	}
	options := &redis.UniversalOptions{
		Addrs:    []string{cfg.Address},
		Password: cfg.Password,
	}
	if cfg.TLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// UniversalClient picks a cluster client from the shape of the
	// options, not by asking the server, so the choice is stated.
	var client redis.UniversalClient
	if cfg.Cluster {
		client = redis.NewClusterClient(options.Cluster())
	} else {
		client = redis.NewClient(options.Simple())
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, "", fmt.Errorf("valkey: %s does not answer: %w", cfg.Address, err)
	}
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "directory-roster"
	}
	return client, prefix, nil
}

// Open connects a snapshot store.
func Open(ctx context.Context, cfg Config) (*Snapshots, error) {
	client, prefix, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Snapshots{client: client, prefix: prefix, ttl: ttl}, nil
}

// NewSnapshots wraps a client that is already open. For tests.
func NewSnapshots(client redis.UniversalClient, prefix string, ttl time.Duration) *Snapshots {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Snapshots{client: client, prefix: prefix, ttl: ttl}
}

// Close releases the connections.
func (s *Snapshots) Close() error { return s.client.Close() }

// key names one workspace's snapshot. The braces make every key of one
// workspace hash to one slot, so that a future multi-key operation on a
// cluster stays legal.
func (s *Snapshots) key(kind, workspace string) string {
	return fmt.Sprintf("%s:{%s}:%s", s.prefix, workspace, kind)
}

// wire is what a snapshot looks like on the way to Valkey.
//
// The reverse index is deliberately not stored: it is derived from the
// groups, so writing it would double the payload and make a corrupted
// copy possible — an index that disagrees with the memberships it came
// from would answer questions about people wrongly, quietly.
type wire struct {
	Workspace string            `json:"workspace"`
	TakenAt   time.Time         `json:"takenAt"`
	Accounts  []backend.Account `json:"accounts"`
	Groups    []backend.Group   `json:"groups"`
	// Discovered is every group the read held before narrowing. It is
	// omitempty so that a snapshot written by an older replica during a
	// rollout decodes into "the kept groups are all there were", which is
	// what it meant.
	Discovered []string `json:"discovered,omitempty"`
}

// Get implements [hub.SnapshotStore].
func (s *Snapshots) Get(ctx context.Context, workspace string) (*hub.Snapshot, error) {
	blob, err := s.client.Get(ctx, s.key("snapshot", workspace)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil //nolint:nilnil // absence is not an error: there is simply no snapshot yet
	}
	if err != nil {
		return nil, fmt.Errorf("valkey: read the snapshot of %s: %w", workspace, err)
	}
	return decode(blob)
}

// Put implements [hub.SnapshotStore].
func (s *Snapshots) Put(ctx context.Context, snap *hub.Snapshot) error {
	blob, err := encode(snap)
	if err != nil {
		return err
	}
	if err = s.client.Set(ctx, s.key("snapshot", snap.Workspace), blob, s.ttl).Err(); err != nil {
		return fmt.Errorf("valkey: store the snapshot of %s: %w", snap.Workspace, err)
	}
	return nil
}

// Delete implements [hub.SnapshotStore].
func (s *Snapshots) Delete(ctx context.Context, workspace string) error {
	if err := s.client.Del(ctx, s.key("snapshot", workspace)).Err(); err != nil {
		return fmt.Errorf("valkey: delete the snapshot of %s: %w", workspace, err)
	}
	return nil
}

// releaseScript deletes the lease only if it is still the one this caller
// took. Without the comparison, a replica whose lease had already expired
// would delete the lease of whoever took it next.
var releaseScript = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
end
return 0`)

// Lock implements [hub.Locker].
func (s *Snapshots) Lock(
	ctx context.Context, name string, ttl time.Duration,
) (func(context.Context), bool, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, false, fmt.Errorf("valkey: %w", err)
	}
	held := hex.EncodeToString(token)
	// The lease always expires. A replica killed mid-refresh must not
	// stop every other replica from ever refreshing that workspace again.
	key := s.leaseKey(name)
	taken, err := s.client.SetNX(ctx, key, held, ttl).Result()
	if err != nil {
		return nil, false, fmt.Errorf("valkey: take the %s lease: %w", name, err)
	}
	if !taken {
		return nil, false, nil
	}
	return func(ctx context.Context) {
		_ = releaseScript.Run(ctx, s.client, []string{key}, held).Err()
	}, true, nil
}

// leaseKey keeps a workspace's lease in the same slot as its snapshot.
func (s *Snapshots) leaseKey(name string) string {
	kind, workspace, found := strings.Cut(name, ":")
	if !found {
		return fmt.Sprintf("%s:lease:%s", s.prefix, name)
	}
	return s.key("lease:"+kind, workspace)
}

// encode writes a snapshot compressed. A directory of any size is mostly
// repeated domain names and repeated addresses, which gzip takes down by
// roughly an order of magnitude — worth it for something written once per
// refresh interval and read on every miss.
func encode(snap *hub.Snapshot) ([]byte, error) {
	if snap == nil {
		return nil, errors.New("valkey: nothing to store")
	}
	out := wire{Workspace: snap.Workspace, TakenAt: snap.TakenAt, Discovered: snap.Discovered}
	for _, email := range sortedKeys(snap.Accounts) {
		out.Accounts = append(out.Accounts, snap.Accounts[email])
	}
	for _, email := range sortedKeys(snap.Groups) {
		out.Groups = append(out.Groups, snap.Groups[email])
	}

	var buf bytes.Buffer
	zip := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zip).Encode(out); err != nil {
		return nil, fmt.Errorf("valkey: encode the snapshot of %s: %w", snap.Workspace, err)
	}
	if err := zip.Close(); err != nil {
		return nil, fmt.Errorf("valkey: encode the snapshot of %s: %w", snap.Workspace, err)
	}
	return buf.Bytes(), nil
}

// decode rebuilds a snapshot, index and all.
func decode(blob []byte) (*hub.Snapshot, error) {
	zip, err := gzip.NewReader(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("valkey: the stored snapshot is not readable: %w", err)
	}
	defer func() { _ = zip.Close() }()

	var in wire
	if err = json.NewDecoder(io.LimitReader(zip, maxSnapshotBytes)).Decode(&in); err != nil {
		return nil, fmt.Errorf("valkey: the stored snapshot is not readable: %w", err)
	}
	// Rebuilt through the ordinary constructor, so a snapshot read back
	// is indexed exactly like one just taken.
	return hub.NewSnapshot(in.Workspace, in.TakenAt, in.Accounts, in.Groups, in.Discovered), nil
}

// maxSnapshotBytes bounds what one decompression may produce. The value
// is far above any real directory; it is here so that a corrupt or
// hostile value in the cache cannot be turned into unbounded memory.
const maxSnapshotBytes = 512 << 20

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Sorted so that two encodings of the same snapshot are identical,
	// which makes a stored value diffable by a human debugging one.
	slices.Sort(out)
	return out
}

// Ping reports whether the store answers.
//
// Readiness calls it. A process that cannot reach its Valkey cannot do
// the thing it exists to do -- the hub cannot read a snapshot, the
// issuer cannot mint or find a session -- and saying "ready" through
// that is how a fault becomes a fifteen-second hang at the gateway
// instead of a fast refusal and a red line in `kubectl get pods`.
//
// Deliberately NOT wired to liveness. A Valkey blip would then restart
// every consumer at once, turning a degraded minute into an outage.
// Readiness stops traffic; liveness kills processes; only the first
// should follow a dependency.
func (s *Snapshots) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}
