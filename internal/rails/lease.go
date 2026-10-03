package rails

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// A tick runs under a lease on its target (docs/decisions/0029), taken from
// the State port: a Create with a lifetime, renewed by a compare-and-swap
// with the revision the holder was given, released by deleting it only if it
// is still the holder's. A holder that cannot renew stops before its next
// external write, which is what cancelling the tick's context does.
const (
	// DefaultLeaseTTL is how long a lease lasts without a renewal: a few
	// times the renewal period, so one missed renewal does not lose it, and
	// short enough that a runner that died is replaced within minutes.
	DefaultLeaseTTL = 2 * time.Minute
	// leaseKeyPrefix is the layout's `lease.<target>`. The target is
	// `<kind>:<name>`, which is the form the legacy adapter maps onto the
	// hub's `{name}:lease:kind` slot.
	leaseKeyPrefix = "lease."
)

var (
	// ErrHeld is a lease another runner holds.
	ErrHeld = errors.New("rails: the target is leased to another runner")
	// ErrLost is a lease that was taken over, or expired, under its holder.
	ErrLost = errors.New("rails: the lease was lost")
)

// Leases takes the leases of one runner.
type Leases struct {
	State port.State
	// Holder names this runner, uniquely among the runners that may share the
	// State (see [NewHolder]).
	Holder string
	// TTL is a lease's lifetime between renewals. Zero is [DefaultLeaseTTL].
	TTL time.Duration
	Log *slog.Logger
}

// NewHolder is an identifier for one runner for as long as it lives: its host
// name and a random suffix, so a restarted pod is never mistaken for the one
// before it.
func NewHolder() string {
	host, _ := os.Hostname()
	var b [4]byte
	_, _ = rand.Read(b[:])
	return host + "-" + hex.EncodeToString(b[:])
}

func (l *Leases) ttl() time.Duration {
	if l.TTL > 0 {
		return l.TTL
	}
	return DefaultLeaseTTL
}

func (l *Leases) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

// Key is the State key of the lease on a target of a kind, for instance
// `lease.slack-tick:acme`.
func Key(kind, target string) string { return leaseKeyPrefix + kind + ":" + target }

// Lease is one held lease.
type Lease struct {
	owner *Leases
	key   string

	mu  sync.Mutex
	rev port.Revision
}

// Acquire takes the lease on a target of a kind: [ErrHeld] when another
// runner has it. Any other error is the State's.
func (l *Leases) Acquire(ctx context.Context, kind, target string) (*Lease, error) {
	key := Key(kind, target)
	rev, err := l.State.Create(ctx, key, []byte(l.Holder), l.ttl())
	switch {
	case errors.Is(err, port.ErrExists):
		return nil, ErrHeld
	case err != nil:
		return nil, fmt.Errorf("take the lease on %s: %w", target, err)
	}
	return &Lease{owner: l, key: key, rev: rev}, nil
}

// Renew extends the lease by its lifetime: [ErrLost] if it moved or is gone.
func (x *Lease) Renew(ctx context.Context) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	rev, err := x.owner.State.Update(ctx, x.key, []byte(x.owner.Holder), x.owner.ttl(), x.rev)
	switch {
	case errors.Is(err, port.ErrConflict), errors.Is(err, port.ErrNotFound):
		return ErrLost
	case err != nil:
		return fmt.Errorf("renew the lease %s: %w", x.key, err)
	}
	x.rev = rev
	return nil
}

// Release gives the lease up, only if it is still this holder's: a holder
// whose lease expired must not delete the one of whoever took it next.
func (x *Lease) Release(ctx context.Context) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	err := x.owner.State.DeleteIfRevision(ctx, x.key, x.rev)
	if errors.Is(err, port.ErrConflict) || errors.Is(err, port.ErrNotFound) {
		return nil
	}
	return err
}

// Do runs fn under the lease on a target of a kind, and says whether it ran:
// false with no error when another runner holds the lease. The context fn
// gets ends when the lease is lost (or cannot be renewed for a whole
// lifetime, which is as good as lost), so a tick stops before its next
// external write. The lease is released when fn returns.
func (l *Leases) Do(ctx context.Context, kind, target string, fn func(ctx context.Context)) (ran bool, err error) {
	lease, err := l.Acquire(ctx, kind, target)
	if errors.Is(err, ErrHeld) {
		meters.contended.Add(ctx, 1, leaseAttr(kind))
		return false, nil
	}
	if err != nil {
		return false, err
	}
	meters.acquired.Add(ctx, 1, leaseAttr(kind))
	meters.held.Add(ctx, 1, leaseAttr(kind))
	defer meters.held.Add(context.WithoutCancel(ctx), -1, leaseAttr(kind))
	held, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.keep(held, cancel, lease, kind, target)
	}()
	fn(held)
	cancel(nil)
	<-done
	// Released even when the caller's context is already over.
	release, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	if err := lease.Release(release); err != nil {
		l.log().WarnContext(ctx, "a lease could not be released; it expires on its own", "target", target, "error", err)
	}
	return true, nil
}

// keep renews the lease every third of its lifetime until ctx ends. A lease
// that is lost, or that could not be renewed for a whole lifetime, cancels
// the tick.
func (l *Leases) keep(ctx context.Context, cancel context.CancelCauseFunc, lease *Lease, kind, target string) {
	every := l.ttl() / 3
	timer := time.NewTicker(every)
	defer timer.Stop()
	lastGood := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		err := lease.Renew(ctx)
		switch {
		case err == nil:
			lastGood = time.Now()
		case errors.Is(err, ErrLost):
			l.log().WarnContext(ctx, "a lease was lost; the tick stops before its next write", "target", target)
			meters.lost.Add(ctx, 1, leaseAttr(kind))
			cancel(ErrLost)
			return
		case ctx.Err() != nil:
			return
		case time.Since(lastGood) >= l.ttl():
			l.log().WarnContext(ctx, "a lease could not be renewed for its whole lifetime; the tick stops", "target", target, "error", err)
			meters.lost.Add(ctx, 1, leaseAttr(kind))
			cancel(ErrLost)
			return
		default:
			l.log().WarnContext(ctx, "a lease could not be renewed; trying again", "target", target, "error", err)
		}
	}
}
