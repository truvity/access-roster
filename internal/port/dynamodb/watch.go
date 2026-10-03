package dynamodb

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// snapshot is every live key under the prefix and its revision.
func (s *Store) snapshot(ctx context.Context, prefix string) (map[string]port.Revision, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := map[string]port.Revision{}
	err := s.iterate(ctx, prefix, "", 0, func(it item) bool {
		out[it.key] = it.rev
		return true
	})
	return out, err
}

// failures is how many polls in a row may fail before a Watch gives up and ends
// with the error.
const failures = 3

// Watch implements [port.State] by polling: the prefix is listed now, and again
// every poll interval, and what differs is the event: a key whose revision moved
// is a put, and a key that is gone, deleted or expired by the adapter's clock, a
// delete. The first listing is made before Watch returns, so a change made after
// it is seen. Changes to one key between two polls are one event.
func (s *Store) Watch(ctx context.Context, prefix string) (<-chan port.Event, error) {
	last, err := s.snapshot(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(chan port.Event, 64)
	go s.pump(ctx, prefix, last, out)
	return out, nil
}

func (s *Store) pump(ctx context.Context, prefix string, last map[string]port.Revision, out chan<- port.Event) {
	defer close(out)
	send := func(ev port.Event) bool {
		select {
		case out <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}
	tick := time.NewTicker(s.poll)
	defer tick.Stop()
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		cur, err := s.snapshot(ctx, prefix)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if failed++; failed >= failures {
				send(port.Event{Err: err})
				return
			}
			continue
		}
		failed = 0
		keys := make([]string, 0, len(cur)+len(last))
		for k := range cur {
			keys = append(keys, k)
		}
		for k := range last {
			if _, ok := cur[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			rev, now := cur[k]
			switch old, was := last[k]; {
			case now && (!was || old != rev):
				if !send(port.Event{Key: k, Revision: rev}) {
					return
				}
			case !now:
				if !send(port.Event{Key: k, Revision: old, Deleted: true}) {
					return
				}
			}
		}
		last = cur
	}
}

// --- Trigger ---

const (
	triggerPrefix = "notify."
	// triggerTTL is how long a notification can be picked up by a subscriber
	// that was away; a missed one is covered by the periodic pass.
	triggerTTL = time.Minute
	retryEvery = time.Second
)

// Notify implements [port.Trigger]: it writes `notify.<target>`, which every
// subscribing process polls for.
func (s *Store) Notify(ctx context.Context, target string) error {
	_, err := s.Put(ctx, triggerPrefix+target, []byte(s.clock().Format(time.RFC3339Nano)), triggerTTL)
	return err
}

// Subscribe implements [port.Trigger]: it watches the notification prefix and
// runs the handler for each target, a target notified again while its handler
// is waiting to run being delivered once. The first listing is made before
// Subscribe returns, so a notification made after it is seen (within a poll
// interval); a watch that fails is re-established every second, and what was
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
				pending[strings.TrimPrefix(ev.Key, triggerPrefix)] = struct{}{}
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
