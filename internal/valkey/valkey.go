// Package valkey is the Valkey driver of the legacy adapter
// (internal/port/legacy): the connection, its failover handling, and the
// one [State] that the issuer's logins in progress, the hub's snapshots and
// the refresh leases are all kept in.
//
// Business code does not import it: it names the ports of internal/port.
//
// Nothing here is a source of truth. Everything in this store can be
// rebuilt by reading the directory again, which is what makes it safe to
// lose: an empty cache is a hub with no snapshots, which answers "not
// authoritative" until the next refresh, and a non-authoritative answer
// removes nobody's access.
package valkey

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
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

// dial connects and proves it can talk, so that a misconfigured address
// is a startup failure rather than a first-request one.
func dial(ctx context.Context, cfg Config) (redis.UniversalClient, string, error) {
	return dialWith(ctx, cfg, nil)
}

// dialWith is dial with the network replaced, which is how a test makes
// a pod's address go dark without a cluster to do it to. nil is the
// system's own.
func dialWith(
	ctx context.Context, cfg Config, dialer func(ctx context.Context, network, addr string) (net.Conn, error),
) (redis.UniversalClient, string, error) {
	if cfg.Address == "" {
		return nil, "", errors.New("valkey: no address")
	}
	options := &redis.UniversalOptions{
		Addrs:    []string{cfg.Address},
		Password: cfg.Password,
		Dialer:   dialer,
		// A dead node does not refuse a connection, it leaves it
		// unanswered, so every dial to it costs the whole timeout. The
		// library's default is five seconds tried five times: almost half
		// a minute spent on one node that is never coming back, during
		// which the topology reload that would have found its successor
		// waits behind it. A store on the same network answers a dial in
		// milliseconds; a second, twice, is generous.
		DialTimeout:   dialTimeout,
		DialerRetries: dialAttempts,
	}
	if cfg.TLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// UniversalClient picks a cluster client from the shape of the
	// options, not by asking the server, so the choice is stated.
	var client redis.UniversalClient
	if cfg.Cluster {
		clusterOptions := options.Cluster()
		// The backstop for a topology change nothing reported. The
		// library's default is a minute, which is a minute of refused
		// logins for every key on a shard whose primary died.
		clusterOptions.ClusterStateReloadInterval = topologyReloadInterval
		clusterOptions.ClusterSlots = seedTopology(options)
		cluster := redis.NewClusterClient(clusterOptions)
		cluster.AddHook(followFailover{cluster: cluster})
		client = cluster
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

// seedTopology reads the cluster's topology through the address the
// deployment configured, every time, instead of through the nodes the
// last topology named.
//
// CLUSTER SLOTS answers with pod addresses, and the library asks those
// addresses first when it reloads. That is right while a node is lost
// and the others are not. When a rollout replaces every pod at once it is
// the slowest possible order: each known address is dead, each costs the
// whole dial budget in turn, and only after the last has failed does the
// library fall back to the configured address -- a Service name, the one
// address that follows the pods -- by which time the reload has taken
// longer than the outage it was meant to end, and nothing asks again
// until another command fails. Asking the Service first costs one dial
// and finds a live node, whichever pods are gone.
//
// The connection is made fresh for each reload and dropped after it: a
// pooled one would be a connection to whichever pod answered last time.
func seedTopology(options *redis.UniversalOptions) func(context.Context) ([]redis.ClusterSlot, error) {
	seed := *options
	seedHost, _, _ := net.SplitHostPort(seed.Addrs[0])

	return func(ctx context.Context) ([]redis.ClusterSlot, error) {
		ctx, cancel := context.WithTimeout(ctx, 2*dialTimeout)
		defer cancel()

		client := redis.NewClient(&redis.Options{
			Addr:          seed.Addrs[0],
			Password:      seed.Password,
			TLSConfig:     seed.TLSConfig,
			Dialer:        seed.Dialer,
			DialTimeout:   dialTimeout,
			DialerRetries: 1,
			MaxRetries:    -1,
			PoolSize:      1,
		})
		defer func() { _ = client.Close() }()

		// Deprecated upstream for CLUSTER SHARDS, but it is the shape the
		// library's ClusterSlots hook returns, and the one it asks for itself.
		slots, err := client.ClusterSlots(ctx).Result() //nolint:staticcheck
		if err != nil {
			return nil, err
		}
		if len(slots) == 0 {
			// A node that has just started and knows nothing yet. Keeping
			// the topology already held beats replacing it with none.
			return nil, errors.New("valkey: the seed knows no slots yet")
		}
		// A node that does not know its own address reports it empty,
		// meaning "the one you reached me on".
		for i := range slots {
			for j := range slots[i].Nodes {
				if host, port, err := net.SplitHostPort(slots[i].Nodes[j].Addr); err == nil && host == "" {
					slots[i].Nodes[j].Addr = net.JoinHostPort(seedHost, port)
				}
			}
		}
		return slots, nil
	}
}

const (
	dialTimeout            = time.Second
	dialAttempts           = 2
	topologyReloadInterval = 5 * time.Second
)

// followFailover makes a cluster client look for a new topology the moment
// a node stops answering, rather than when it next happens to.
//
// The library re-reads the topology when a node SAYS it has moved (MOVED,
// ASK, a read-only replica) and on a timer. A primary that dies says
// nothing: its replica is promoted within a couple of seconds, but every
// command for that shard keeps going to the dead address, and each one
// fails the same way, until the timer fires. Measured against a real
// three-shard cluster with the defaults, a third of all writes were still
// failing thirty seconds after the kill -- a third of the people signing
// in, refused, with a healthy replica already serving their keys.
//
// So a failure that is not an answer from the server -- a dial that timed
// out, a connection that was reset -- asks for a reload. The reload is
// asynchronous and coalesced by the library, so a burst of failures costs
// one CLUSTER SLOTS, not one each. CLUSTERDOWN is the one server answer
// treated the same way: it is what the survivors say while the election
// is running, and the next topology is the one to ask for.
type followFailover struct {
	cluster *redis.ClusterClient
}

func (followFailover) DialHook(next redis.DialHook) redis.DialHook { return next }

func (f followFailover) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if nodeLost(err) {
			f.cluster.ReloadState(ctx)
		}
		return err
	}
}

func (f followFailover) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		err := next(ctx, cmds)
		if nodeLost(err) {
			f.cluster.ReloadState(ctx)
		}
		return err
	}
}

// nodeLost reports whether err says the node may be gone, rather than
// that the node answered. A server's answer -- including "no such key" --
// is proof the node is there.
func nodeLost(err error) bool {
	if err == nil {
		return false
	}
	if redis.IsClusterDownError(err) {
		return true
	}
	var answered redis.Error
	return !errors.As(err, &answered)
}
