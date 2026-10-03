package nats

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/truvity/access-roster/internal/port"
)

// Watch implements [port.State]: a KV watch on the prefix from now.
//
// A write is a put event. A delete, a purge and a limit marker (the server
// reaping an expired record) are delete events. A record this watch saw
// written with a lifetime is also reported deleted when the adapter's clock
// passes its expiry, so a watcher on a server without per-message TTL (or one
// whose clock was advanced) still sees it; a record that was already there
// when the watch began is reported by the server's marker only.
func (s *Store) Watch(ctx context.Context, prefix string) (<-chan port.Event, error) {
	// The context is the watch's life: it must not be the bounded one of a
	// call.
	w, err := s.kv.WatchFiltered(ctx, []string{filter(prefix)}, jetstream.UpdatesOnly())
	if err != nil {
		return nil, unavailable(err)
	}
	out := make(chan port.Event, 64)
	go s.pump(ctx, w, prefix, out)
	return out, nil
}

type tracked struct {
	expires time.Time
	rev     port.Revision
}

func (s *Store) pump(ctx context.Context, w jetstream.KeyWatcher, prefix string, out chan<- port.Event) {
	defer close(out)
	defer func() { _ = w.Stop() }()
	send := func(ev port.Event) bool {
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}
	seen := map[string]tracked{}
	tick := time.NewTicker(s.sweep)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			for key, t := range seen {
				if s.expired(t.expires) {
					delete(seen, key)
					if !send(port.Event{Key: key, Revision: t.rev, Deleted: true}) {
						return
					}
				}
			}
		case e, ok := <-w.Updates():
			if !ok {
				send(port.Event{Err: fmt.Errorf("%w: the watch ended", port.ErrUnavailable)})
				return
			}
			if e == nil { // the end of the initial values
				continue
			}
			key := decode(e.Key())
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			rev := revision(e.Revision())
			if _, expires, valid := open(e.Value()); e.Operation() == jetstream.KeyValuePut && valid {
				if expires.IsZero() {
					delete(seen, key)
				} else {
					seen[key] = tracked{expires: expires, rev: rev}
				}
				if !send(port.Event{Key: key, Revision: rev}) {
					return
				}
				continue
			}
			delete(seen, key)
			if !send(port.Event{Key: key, Revision: rev, Deleted: true}) {
				return
			}
		}
	}
}

// --- Index ---

const indexPrefix = "idx."

func indexKey(set, member string) string {
	return indexPrefix + encode(set) + "." + escapeDots(member)
}

// Add implements [port.Index]: the member is the key `idx.<set>.<member>`
// with an empty value and the lifetime, so the lifetime is the member's and
// an Add does not extend the other members'.
func (s *Store) Add(ctx context.Context, key, member string, ttl time.Duration) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err := s.publish(ctx, indexKey(key, member), nil, ttl, nil); err != nil {
		return unavailable(err)
	}
	return nil
}

// Remove implements [port.Index].
func (s *Store) Remove(ctx context.Context, key, member string) error {
	return s.Delete(ctx, indexKey(key, member))
}

// Members implements [port.Index]: a prefix listing.
func (s *Store) Members(ctx context.Context, key string) ([]string, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	prefix := indexPrefix + encode(key) + "."
	keys, err := s.keysUnder(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var members []string
	for _, k := range keys {
		rest := strings.TrimPrefix(k, prefix)
		if strings.Contains(rest, ".") { // another set that this one is a prefix of
			continue
		}
		if _, _, err := s.live(ctx, k); err != nil {
			if err == port.ErrNotFound {
				continue
			}
			return nil, err
		}
		members = append(members, decode(rest))
	}
	return members, nil
}

// --- Trigger ---

const (
	triggerPrefix = "notify."
	// triggerTTL is how long a notification can be picked up by a subscriber
	// that was reconnecting; a missed one is covered by the periodic pass.
	triggerTTL = time.Minute
	retryEvery = time.Second
)

// Notify implements [port.Trigger]: it writes `notify.<target>`, which every
// subscribing process is watching.
func (s *Store) Notify(ctx context.Context, target string) error {
	_, err := s.Put(ctx, triggerPrefix+escapeDots(target), []byte(s.clock().Format(time.RFC3339Nano)), triggerTTL)
	return err
}

// Subscribe implements [port.Trigger]: it watches the notification prefix
// and runs the handler for each target, a target notified again while its
// handler is waiting to run being delivered once. The first watch is
// established before Subscribe returns, so a notification made after it is
// seen; a watch that fails is re-established every second, and what was
// notified while it was down is left to the periodic pass.
func (s *Store) Subscribe(handler func(target string)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var (
		mu      sync.Mutex
		pending = map[string]struct{}{}
		wake    = make(chan struct{}, 1)
	)
	go func() { // the dispatcher
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
			}
			mu.Lock()
			batch := pending
			pending = map[string]struct{}{}
			mu.Unlock()
			for target := range batch {
				handler(target)
			}
		}
	}()
	ch, err := s.Watch(ctx, triggerPrefix)
	go func() {
		for ctx.Err() == nil {
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(retryEvery):
				}
				ch, err = s.Watch(ctx, triggerPrefix)
				continue
			}
			for ev := range ch {
				if ev.Err != nil || ev.Deleted {
					continue
				}
				mu.Lock()
				pending[decode(strings.TrimPrefix(ev.Key, triggerPrefix))] = struct{}{}
				mu.Unlock()
				select {
				case wake <- struct{}{}:
				default:
				}
			}
			err = fmt.Errorf("the watch ended")
		}
	}()
	return cancel
}
