// Package memory is the in-memory adapter: every port, in process memory,
// with the semantics of docs/design/ports.md and nothing more. It is what
// tests and the demonstration run on, and the reference the conformance
// suite is first written against.
package memory

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/truvity/access-roster/internal/port"
)

// Store implements [port.State], [port.Index], [port.Trigger], [port.Sealer]
// and [port.Identity]; its blobs are [Store.Blobs], a separate type because
// State and Blob both have a Delete. Every port shares one lock.
type Store struct {
	mu     sync.Mutex
	now    func() time.Time
	offset time.Duration
	rev    uint64

	records map[string]*entry
	sets    map[string]*set
	blobs   map[string]blob
	watches map[int]*watch
	nextW   int

	*Trigger

	kek    cipher.AEAD
	tokens map[string]grant
}

type entry struct {
	value   []byte
	rev     port.Revision
	expires time.Time // zero: permanent
}

type set struct {
	members map[string]struct{}
	expires time.Time
}

type blob struct {
	body    []byte
	version string
}

type watch struct {
	prefix string
	ch     chan port.Event
}

type grant struct {
	subject   string
	audiences []string
}

var (
	_ port.State     = (*Store)(nil)
	_ port.Index     = (*Store)(nil)
	_ port.Blob      = (*Blobs)(nil)
	_ port.Replacer  = (*Blobs)(nil)
	_ port.ReaderAll = (*Blobs)(nil)
	_ port.Trigger   = (*Trigger)(nil)
	_ port.Trigger   = (*Store)(nil)
	_ port.Sealer    = (*Store)(nil)
	_ port.Identity  = (*Store)(nil)
)

// Option configures [New].
type Option func(*Store)

// WithClock replaces the clock expiry is judged by.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// New returns an empty store.
func New(opts ...Option) *Store {
	s := &Store{
		now:     time.Now,
		records: map[string]*entry{},
		sets:    map[string]*set{},
		blobs:   map[string]blob{},
		watches: map[int]*watch{},
		Trigger: NewTrigger(),
		tokens:  map[string]grant{},
	}
	for _, opt := range opts {
		opt(s)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err) // the system's randomness is gone; nothing here can continue
	}
	block, _ := aes.NewCipher(key)
	s.kek, _ = cipher.NewGCM(block)
	return s
}

// Set returns every port of the store.
func (s *Store) Set() port.Set {
	return port.Set{State: s, Index: s, Blob: s.Blobs(), Trigger: s, Sealer: s, Identity: s}
}

// Advance moves the store's clock forward and sweeps what expired, so a
// test can cross a lifetime without sleeping.
func (s *Store) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offset += d
	s.sweepLocked()
}

func (s *Store) clock() time.Time { return s.now().Add(s.offset) }

func (s *Store) live(e *entry) bool { return e.expires.IsZero() || s.clock().Before(e.expires) }

func (s *Store) next() port.Revision {
	s.rev++
	return port.Revision(strconv.FormatUint(s.rev, 10))
}

func (s *Store) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.clock().Add(ttl)
}

// sweepLocked removes expired records and announces them. Reads filter on
// expiry whether or not this has run.
func (s *Store) sweepLocked() {
	for key, e := range s.records {
		if !s.live(e) {
			delete(s.records, key)
			s.emitLocked(port.Event{Key: key, Revision: e.rev, Deleted: true})
		}
	}
	for key, st := range s.sets {
		if !st.expires.IsZero() && !s.clock().Before(st.expires) {
			delete(s.sets, key)
		}
	}
}

func (s *Store) emitLocked(ev port.Event) {
	for id, w := range s.watches {
		if !strings.HasPrefix(ev.Key, w.prefix) {
			continue
		}
		select {
		case w.ch <- ev:
		default:
			// The watcher fell behind: say so and end the stream, so it
			// lists and reconciles rather than assuming it saw everything.
			<-w.ch // make room for the last event
			w.ch <- port.Event{Err: fmt.Errorf("%w: the watcher fell behind", port.ErrUnavailable)}
			close(w.ch)
			delete(s.watches, id)
		}
	}
}

func (s *Store) liveEntry(key string) (*entry, bool) {
	e, ok := s.records[key]
	if !ok || !s.live(e) {
		return nil, false
	}
	return e, true
}

func (s *Store) write(key string, value []byte, ttl time.Duration) port.Revision {
	rev := s.next()
	s.records[key] = &entry{value: slices.Clone(value), rev: rev, expires: s.expiry(ttl)}
	s.emitLocked(port.Event{Key: key, Revision: rev})
	return rev
}

// Get implements [port.State].
func (s *Store) Get(_ context.Context, key string) (port.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.liveEntry(key)
	if !ok {
		return port.Record{}, port.ErrNotFound
	}
	return port.Record{Key: key, Value: slices.Clone(e.value), Revision: e.rev}, nil
}

// Put implements [port.State].
func (s *Store) Put(_ context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(key, value, ttl), nil
}

// Create implements [port.State].
func (s *Store) Create(_ context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.liveEntry(key); ok {
		return "", port.ErrExists
	}
	return s.write(key, value, ttl), nil
}

// Update implements [port.State].
func (s *Store) Update(_ context.Context, key string, value []byte, ttl time.Duration, rev port.Revision) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.liveEntry(key)
	if !ok {
		return "", port.ErrNotFound
	}
	if e.rev != rev {
		return "", port.ErrConflict
	}
	return s.write(key, value, ttl), nil
}

// Delete implements [port.State].
func (s *Store) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(key)
	return nil
}

func (s *Store) deleteLocked(key string) {
	if e, ok := s.records[key]; ok {
		delete(s.records, key)
		s.emitLocked(port.Event{Key: key, Revision: e.rev, Deleted: true})
	}
}

// DeleteIfRevision implements [port.State].
func (s *Store) DeleteIfRevision(_ context.Context, key string, rev port.Revision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.liveEntry(key)
	if !ok {
		return port.ErrNotFound
	}
	if e.rev != rev {
		return port.ErrConflict
	}
	s.deleteLocked(key)
	return nil
}

// List implements [port.State].
func (s *Store) List(_ context.Context, prefix, page string, limit int) (port.Page, error) {
	after, err := port.PageStart(prefix, page)
	if err != nil {
		return port.Page{}, err
	}
	if limit <= 0 {
		limit = port.DefaultPage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for key, e := range s.records {
		if strings.HasPrefix(key, prefix) && key > after && s.live(e) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	var out port.Page
	for i, key := range keys {
		if i == limit {
			out.Next = port.PageToken(prefix, keys[i-1])
			break
		}
		e := s.records[key]
		out.Records = append(out.Records, port.Record{Key: key, Value: slices.Clone(e.value), Revision: e.rev})
	}
	return out, nil
}

// Watch implements [port.State].
func (s *Store) Watch(ctx context.Context, prefix string) (<-chan port.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextW
	s.nextW++
	w := &watch{prefix: prefix, ch: make(chan port.Event, 256)}
	s.watches[id] = w
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.watches[id]; ok {
			delete(s.watches, id)
			close(w.ch)
		}
	}()
	return w.ch, nil
}

// Add implements [port.Index].
func (s *Store) Add(_ context.Context, key, member string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sets[key]
	if !ok || (!st.expires.IsZero() && !s.clock().Before(st.expires)) {
		st = &set{members: map[string]struct{}{}}
		s.sets[key] = st
	}
	st.members[member] = struct{}{}
	if ttl > 0 {
		st.expires = s.expiry(ttl)
	}
	return nil
}

// Remove implements [port.Index].
func (s *Store) Remove(_ context.Context, key, member string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.sets[key]; ok {
		delete(st.members, member)
	}
	return nil
}

// Members implements [port.Index].
func (s *Store) Members(_ context.Context, key string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.sets[key]
	if !ok || (!st.expires.IsZero() && !s.clock().Before(st.expires)) {
		return nil, nil
	}
	out := make([]string, 0, len(st.members))
	for m := range st.members {
		out = append(out, m)
	}
	sort.Strings(out)
	return out, nil
}

// Blobs is the store's [port.Blob].
type Blobs struct{ s *Store }

// Blobs returns the store's blobs.
func (s *Store) Blobs() *Blobs { return &Blobs{s: s} }

// Read implements [port.Blob].
func (b *Blobs) Read(_ context.Context, name string) (port.Object, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	o, ok := b.s.blobs[name]
	if !ok {
		return port.Object{}, port.ErrNotFound
	}
	return port.Object{Body: slices.Clone(o.body), Version: o.version}, nil
}

// Write implements [port.Blob].
func (b *Blobs) Write(_ context.Context, name string, body []byte) (string, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	return b.s.putBlob(name, body), nil
}

func (s *Store) putBlob(name string, body []byte) string {
	version := string(s.next())
	s.blobs[name] = blob{body: slices.Clone(body), version: version}
	return version
}

// WriteIfVersion implements [port.Blob].
func (b *Blobs) WriteIfVersion(_ context.Context, name string, body []byte, version string) (string, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	o, ok := b.s.blobs[name]
	if !ok {
		return "", port.ErrNotFound
	}
	if o.version != version {
		return "", port.ErrConflict
	}
	return b.s.putBlob(name, body), nil
}

// Delete implements [port.Blob].
func (b *Blobs) Delete(_ context.Context, name string) error {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	delete(b.s.blobs, name)
	return nil
}

// List implements [port.Blob].
func (b *Blobs) List(_ context.Context, prefix string) ([]string, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	var out []string
	for name := range b.s.blobs {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Replace implements [port.Replacer].
func (b *Blobs) Replace(_ context.Context, prefix string, objects map[string][]byte) error {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	for name := range b.s.blobs {
		if _, keep := objects[strings.TrimPrefix(name, prefix)]; strings.HasPrefix(name, prefix) && !keep {
			delete(b.s.blobs, name)
		}
	}
	for name, body := range objects {
		b.s.putBlob(prefix+name, body)
	}
	return nil
}

// KeyID names the store's key-encryption key.
const KeyID = "memory"

// Wrap implements [port.Sealer] with a key that lives and dies with the
// store.
func (s *Store) Wrap(_ context.Context, dataKey []byte, binding string) (port.Wrapped, error) {
	nonce := make([]byte, s.kek.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return port.Wrapped{}, fmt.Errorf("%w: %w", port.ErrUnavailable, err)
	}
	return port.Wrapped{KeyID: KeyID, Blob: s.kek.Seal(nonce, nonce, dataKey, []byte(binding))}, nil
}

// Unwrap implements [port.Sealer].
func (s *Store) Unwrap(_ context.Context, w port.Wrapped, binding string) ([]byte, error) {
	n := s.kek.NonceSize()
	if w.KeyID != KeyID || len(w.Blob) < n {
		return nil, port.ErrUnwrap
	}
	key, err := s.kek.Open(nil, w.Blob[:n], w.Blob[n:], []byte(binding))
	if err != nil {
		return nil, port.ErrUnwrap
	}
	return key, nil
}

// Allow makes a token prove subject for any of the audiences.
func (s *Store) Allow(token, subject string, audiences ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = grant{subject: subject, audiences: audiences}
}

// Verify implements [port.Identity].
func (s *Store) Verify(_ context.Context, token string, audiences []string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.tokens[token]
	if !ok || !slices.ContainsFunc(audiences, func(a string) bool { return slices.Contains(g.audiences, a) }) {
		return "", port.ErrUnauthenticated
	}
	return g.subject, nil
}

// ReadAll implements [port.ReaderAll].
func (b *Blobs) ReadAll(_ context.Context, prefix string) (map[string][]byte, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	out := map[string][]byte{}
	for name, o := range b.s.blobs {
		if strings.HasPrefix(name, prefix) {
			out[strings.TrimPrefix(name, prefix)] = slices.Clone(o.body)
		}
	}
	return out, nil
}
