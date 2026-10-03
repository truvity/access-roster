package legacy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/valkey"
)

// State is [port.State] over the Valkey and ConfigMap objects of today; see
// the package documentation for the mapping and the gaps.
type State struct {
	b     *Backend
	every time.Duration
}

var _ port.State = (*State)(nil)

func (s *State) orgs() (*kube.Entries, error) {
	if s.b.Kube == nil {
		return nil, unsupported("this process is not in a cluster, so there are no ConfigMaps")
	}
	return kube.GitHubOrgEntries(s.b.Kube), nil
}

func (s *State) cache() (*valkey.State, error) {
	if s.b.Valkey == nil {
		return nil, unsupported("no Valkey is configured")
	}
	return s.b.Valkey, nil
}

// Get implements [port.State].
func (s *State) Get(ctx context.Context, key string) (port.Record, error) {
	t, err := route(key)
	if err != nil {
		return port.Record{}, err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return port.Record{}, err
		}
		value, found, err := cache.Get(ctx, t.valkey)
		if err != nil {
			return port.Record{}, unavailable(err)
		}
		if !found {
			return port.Record{}, port.ErrNotFound
		}
		return port.Record{Key: key, Value: value, Revision: port.Revision(valkey.Revision(value))}, nil
	}
	entries, err := s.orgs()
	if err != nil {
		return port.Record{}, err
	}
	all, err := entries.All(ctx)
	if err != nil {
		return port.Record{}, unavailable(err)
	}
	raw, ok := all[t.entry]
	if !ok {
		return port.Record{}, port.ErrNotFound
	}
	return port.Record{Key: key, Value: []byte(raw), Revision: port.Revision(valkey.Revision([]byte(raw)))}, nil
}

func (s *State) check(key string, value []byte, ttl time.Duration) (target, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return target{}, err
	}
	t, err := route(key)
	if err != nil {
		return target{}, err
	}
	if t.valkey == "" && ttl > 0 {
		return target{}, unsupported("a ConfigMap entry has no lifetime")
	}
	return t, nil
}

// Put implements [port.State].
func (s *State) Put(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	t, err := s.check(key, value, ttl)
	if err != nil {
		return "", err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return "", err
		}
		if err = cache.Set(ctx, t.valkey, value, ttl); err != nil {
			return "", unavailable(err)
		}
		return port.Revision(valkey.Revision(value)), nil
	}
	return s.edit(ctx, t, value, func(string, bool) error { return nil })
}

// Create implements [port.State].
func (s *State) Create(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	t, err := s.check(key, value, ttl)
	if err != nil {
		return "", err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return "", err
		}
		won, err := cache.SetIfAbsent(ctx, t.valkey, value, ttl)
		if err != nil {
			return "", unavailable(err)
		}
		if !won {
			return "", port.ErrExists
		}
		return port.Revision(valkey.Revision(value)), nil
	}
	return s.edit(ctx, t, value, func(_ string, exists bool) error {
		if exists {
			return port.ErrExists
		}
		return nil
	})
}

// Update implements [port.State].
func (s *State) Update(
	ctx context.Context, key string, value []byte, ttl time.Duration, rev port.Revision,
) (port.Revision, error) {
	t, err := s.check(key, value, ttl)
	if err != nil {
		return "", err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return "", err
		}
		outcome, err := cache.Swap(ctx, t.valkey, string(rev), value, ttl)
		if err != nil {
			return "", unavailable(err)
		}
		if err = outcomeError(outcome); err != nil {
			return "", err
		}
		return port.Revision(valkey.Revision(value)), nil
	}
	return s.edit(ctx, t, value, func(old string, exists bool) error {
		return compare(old, exists, rev)
	})
}

// edit writes one ConfigMap entry if guard allows, under the ConfigMap's
// version: a guard that fails because the entry moved is retried against the
// fresh entry by the version check, so the compare and the write are one.
func (s *State) edit(
	ctx context.Context, t target, value []byte, guard func(old string, exists bool) error,
) (port.Revision, error) {
	entries, err := s.orgs()
	if err != nil {
		return "", err
	}
	err = entries.Edit(ctx, t.entry, func(old string, exists bool) (string, bool, error) {
		if err := guard(old, exists); err != nil {
			return "", false, err
		}
		return string(value), true, nil
	})
	if err != nil {
		return "", entryError(err)
	}
	return port.Revision(valkey.Revision(value)), nil
}

func compare(old string, exists bool, rev port.Revision) error {
	switch {
	case !exists:
		return port.ErrNotFound
	case port.Revision(valkey.Revision([]byte(old))) != rev:
		return port.ErrConflict
	}
	return nil
}

func outcomeError(o valkey.Outcome) error {
	switch o {
	case valkey.Gone:
		return port.ErrNotFound
	case valkey.Moved:
		return port.ErrConflict
	default:
		return nil
	}
}

func entryError(err error) error {
	switch {
	case errors.Is(err, port.ErrNotFound), errors.Is(err, port.ErrExists), errors.Is(err, port.ErrConflict):
		return err
	case errors.Is(err, kube.ErrEntryConflict):
		return fmt.Errorf("%w: %w", port.ErrConflict, err)
	}
	return unavailable(err)
}

// Delete implements [port.State].
func (s *State) Delete(ctx context.Context, key string) error {
	t, err := route(key)
	if err != nil {
		return err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return err
		}
		return unavailable(cache.Delete(ctx, t.valkey))
	}
	entries, err := s.orgs()
	if err != nil {
		return err
	}
	err = entries.Edit(ctx, t.entry, func(string, bool) (string, bool, error) { return "", false, nil })
	if errors.Is(err, kube.ErrNoObject) {
		return nil
	}
	return entryError(err)
}

// DeleteIfRevision implements [port.State].
func (s *State) DeleteIfRevision(ctx context.Context, key string, rev port.Revision) error {
	t, err := route(key)
	if err != nil {
		return err
	}
	if t.valkey != "" {
		cache, err := s.cache()
		if err != nil {
			return err
		}
		outcome, err := cache.DropIf(ctx, t.valkey, string(rev))
		if err != nil {
			return unavailable(err)
		}
		return outcomeError(outcome)
	}
	entries, err := s.orgs()
	if err != nil {
		return err
	}
	err = entries.Edit(ctx, t.entry, func(old string, exists bool) (string, bool, error) {
		return "", false, compare(old, exists, rev)
	})
	if errors.Is(err, kube.ErrNoObject) {
		return port.ErrNotFound
	}
	return entryError(err)
}

// keys lists the port keys under a prefix, sorted.
func (s *State) keys(ctx context.Context, prefix string) ([]string, error) {
	if strings.HasPrefix(prefix, orgPrefix) || prefix == "gh." {
		entries, err := s.orgs()
		if err != nil {
			return nil, err
		}
		all, err := entries.All(ctx)
		if err != nil {
			return nil, unavailable(err)
		}
		var out []string
		for entry := range all {
			if org, ok := connection.OrgOfKey(entry); ok && strings.HasPrefix(orgPrefix+org, prefix) {
				out = append(out, orgPrefix+org)
			}
		}
		slices.Sort(out)
		return out, nil
	}
	t, err := route(prefix)
	if err != nil {
		return nil, err
	}
	cache, err := s.cache()
	if err != nil {
		return nil, err
	}
	found, err := cache.Keys(ctx, t.valkey)
	if err != nil {
		return nil, unavailable(err)
	}
	var out []string
	for _, v := range found {
		if key, ok := t.back(v); ok && strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out, nil
}

// List implements [port.State]. The whole prefix is enumerated and the page
// cut from it, so a listing is a scan: for an operator and a watcher, not a
// request path.
func (s *State) List(ctx context.Context, prefix, page string, limit int) (port.Page, error) {
	after, err := port.PageStart(prefix, page)
	if err != nil {
		return port.Page{}, err
	}
	if limit <= 0 {
		limit = port.DefaultPage
	}
	all, err := s.keys(ctx, prefix)
	if err != nil {
		return port.Page{}, err
	}
	var out port.Page
	for _, key := range all {
		if key <= after {
			continue
		}
		record, err := s.Get(ctx, key)
		if errors.Is(err, port.ErrNotFound) {
			continue // it expired or went between the scan and the read
		}
		if err != nil {
			return port.Page{}, err
		}
		if len(out.Records) == limit {
			out.Next = port.PageToken(prefix, out.Records[len(out.Records)-1].Key)
			break
		}
		out.Records = append(out.Records, record)
	}
	return out, nil
}

// Watch implements [port.State] by polling: see the package documentation.
func (s *State) Watch(ctx context.Context, prefix string) (<-chan port.Event, error) {
	seen, err := s.snapshot(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make(chan port.Event, 256)
	go func() {
		defer close(out)
		tick := time.NewTicker(s.every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			now, err := s.snapshot(ctx, prefix)
			if err != nil {
				if ctx.Err() == nil {
					out <- port.Event{Err: err}
				}
				return
			}
			var events []port.Event
			for key, rev := range now {
				if seen[key] != rev {
					events = append(events, port.Event{Key: key, Revision: rev})
				}
			}
			for key, rev := range seen {
				if _, ok := now[key]; !ok {
					events = append(events, port.Event{Key: key, Revision: rev, Deleted: true})
				}
			}
			seen = now
			for _, ev := range events {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (s *State) snapshot(ctx context.Context, prefix string) (map[string]port.Revision, error) {
	out := map[string]port.Revision{}
	for token := ""; ; {
		page, err := s.List(ctx, prefix, token, 0)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Records {
			out[r.Key] = r.Revision
		}
		if token = page.Next; token == "" {
			return out, nil
		}
	}
}

// Index is [port.Index] over Valkey sets, under their own keys.
type Index struct{ b *Backend }

var _ port.Index = Index{}

func (i Index) cache() (*valkey.State, error) {
	if i.b.Valkey == nil {
		return nil, unsupported("no Valkey is configured")
	}
	return i.b.Valkey, nil
}

// Add implements [port.Index].
func (i Index) Add(ctx context.Context, key, member string, ttl time.Duration) error {
	cache, err := i.cache()
	if err != nil {
		return err
	}
	return unavailable(cache.Add(ctx, key, member, ttl))
}

// Remove implements [port.Index].
func (i Index) Remove(ctx context.Context, key, member string) error {
	cache, err := i.cache()
	if err != nil {
		return err
	}
	return unavailable(cache.Remove(ctx, key, member))
}

// Members implements [port.Index].
func (i Index) Members(ctx context.Context, key string) ([]string, error) {
	cache, err := i.cache()
	if err != nil {
		return nil, err
	}
	members, err := cache.Members(ctx, key)
	return members, unavailable(err)
}
