package valkey

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

// failoverSettle is the least a retry waits for the topology reload that
// the failed command asked for, and failoverWait the most. The library
// reloads in the background and says nothing when it is done, so the
// wait watches the one thing that matters instead: whether the key's
// shard has a different primary than it had. Twice the dial timeout is
// the most a retry may add to a request.
const (
	failoverSettle = dialTimeout / 4
	failoverWait   = 2 * dialTimeout
)

// attempt is how a failed command is classified for a retry.
type attempt int

const (
	// final: a server's logical answer, or the caller giving up. Asking
	// again would get the same answer, or answer a question nobody asks.
	final attempt = iota
	// unsent: the command certainly did not run -- the connection was
	// never made, or the server refused to start it. Anything may be
	// retried.
	unsent
	// unknown: the connection broke after the command may have been
	// written. It ran or it did not, and only a command that gives the
	// same result twice may be sent again.
	unknown
)

// classify says whether err is a lost node and, if so, how sure we are
// that the command never reached it.
//
// The caller's own context is what says it gave up. The error alone
// cannot: the standard library's dial timeout answers errors.Is(err,
// context.DeadlineExceeded) too, and it is exactly the failure a lost
// node produces.
func classify(ctx context.Context, err error) attempt {
	switch {
	case err == nil, ctx.Err() != nil:
		return final
	case redis.IsClusterDownError(err), redis.IsTryAgainError(err):
		// The survivors' answer while an election runs: refused before
		// anything was applied.
		return unsent
	}
	var answered redis.Error
	if errors.As(err, &answered) {
		return final
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return unsent
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, net.ErrClosed) {
		return unknown
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		// A read or write timeout on a connection that was up.
		return unknown
	}
	return final
}

// retryAfterFailover runs op, and if it fails because the node it went
// to is gone, asks for a new topology and runs it once more.
//
// Only once, and only for a lost node. The cluster client already
// reloads the topology on such a failure (see followFailover), but the
// command that discovered it still fails: a sign-in that lands on the
// dying shard in the seconds before its replacement is known is refused,
// though the next one a moment later succeeds. One retry turns that
// refusal into a request a few hundred milliseconds slower.
//
// idempotent says whether the command may run twice. Every command State
// issues is -- a SET with the same value, a DEL, a SADD of a member that
// may already be there, a read -- except SETNX, which reports whether
// ITS call took the key: a first attempt that landed and lost its reply
// would, retried, answer "not yours" about a key the caller owns. That
// one is retried only when it certainly never ran.
func retryAfterFailover(
	ctx context.Context, client redis.UniversalClient, name, key string, idempotent bool, op func() error,
) error {
	cluster, _ := client.(*redis.ClusterClient)
	before := primaryOf(ctx, cluster, key)

	err := op()
	kind := classify(ctx, err)
	if kind == final || (kind == unknown && !idempotent) {
		return err
	}
	if cluster != nil {
		cluster.ReloadState(ctx)
	}
	// The key is logged by its prefix only: the rest is a request id or
	// a token.
	slog.WarnContext(ctx, "valkey: retrying once after a lost node",
		"command", name, "key", keyPrefix(key), "error", err)

	// A node that could not be dialled or that said the cluster is down
	// is in the middle of being replaced, and a retry sent before the
	// replacement is known goes to the same dead address and fails the
	// same way. A connection that merely broke is not worth waiting for.
	wait := failoverSettle
	if kind == unsent {
		wait = failoverWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	poll := time.NewTicker(25 * time.Millisecond)
	defer poll.Stop()
	settled := time.After(failoverSettle)

	for moved := false; ; {
		select {
		case <-ctx.Done():
			return err
		case <-deadline.C:
			return op()
		case <-settled:
			settled = nil
			moved = true
		case <-poll.C:
		}
		if moved && (before == "" || changed(primaryOf(ctx, cluster, key), before)) {
			return op()
		}
	}
}

// changed reports whether now is a primary other than before. An empty
// answer is "cannot say", which happens mid-election when the node the
// client asked has dropped the dead primary from its view and not yet
// listed the new one: not an answer worth retrying on.
func changed(now, before string) bool { return now != "" && now != before }

// primaryOf names the node the client currently believes holds key's
// slot, or "" if it cannot say (not a cluster, or no topology yet).
func primaryOf(ctx context.Context, cluster *redis.ClusterClient, key string) string {
	if cluster == nil {
		return ""
	}
	node, err := cluster.MasterForKey(ctx, key)
	if err != nil {
		return ""
	}
	return node.Options().Addr
}

// keyPrefix keeps the part of a key that names the kind of thing, and
// drops the identifier.
func keyPrefix(key string) string {
	if i := strings.LastIndex(key, ":"); i >= 0 {
		return key[:i+1] + "*"
	}
	return key
}
