// Package nats is the NATS JetStream adapter of the State, Index and Trigger
// ports (docs/design/ports.md, ADR 0027): one JetStream KV bucket, shared by
// every replica and every process, so a lease is exclusive across pods and a
// notification crosses processes.
//
// # Mapping
//
//   - Get is kv.Get, and Create is kv.Create. Put and Update are a publish to
//     the bucket's subject with the expected-last-sequence header, which is
//     what kv.Put and kv.Update send, because the KV client offers no TTL on
//     either (kv.Update would clear the key's TTL).
//   - A revision is the stream sequence of the record's message, so it moves on
//     every write, identical bytes included, and a record that went A, B, A is
//     not mistaken for one that never moved.
//   - DeleteIfRevision is kv.Delete (kv.Purge when the bucket has limit
//     markers, so the delete marker itself expires) with the last-revision
//     option.
//   - List is the stream's own subject listing under the prefix (answered by
//     the leader, so it sees every acknowledged write), sorted, paged by a token
//     that names the last key (port.PageToken), then one kv.Get per key of the
//     page. It scans every key of the prefix on every page: it is for the
//     operator and the watcher and the small per-person prefixes, not for a
//     hot path over a large one.
//   - Watch is a KV watch on the prefix, from now.
//   - A key is mapped onto a NATS subject by escaping every byte a subject or
//     the KV client does not allow (a ':' of the legacy names, say) as =XX; the
//     dots stay, so the dotted layout is the subject hierarchy.
//
// # Reads
//
// A KV bucket answers a Get from any replica, which can be behind a write the
// caller was just acknowledged for. New turns direct gets off on the bucket, so
// the leader answers and a revoked session reads as revoked.
//
// # Lifetimes
//
// Every value carries its expiry, nine bytes in front of it, and every read
// judges it by the adapter's clock: Get and List never return an expired
// record, whether or not the server has removed it, Create succeeds over one
// (by writing against its revision) and Update and DeleteIfRevision treat it as
// gone. That is the whole of the semantics and works on any server.
//
// On a server that supports per-message TTL (nats-server 2.11 or later, API
// level 1) the bucket is also created with limit markers enabled
// (AllowMsgTTL, SubjectDeleteMarkerTTL) and each write carries the TTL, so the
// server reaps the record and a watcher sees the expiry. On an older server
// the bucket is created without them, nothing reaps (a record is filtered, not
// removed, until it is overwritten or deleted) and a Watch reports an expiry
// from its own clock for the records it has seen written. The TTL is rounded
// up to whole seconds, which is the server's resolution.
//
// # Trigger and Index
//
// Notify writes `notify.<target>` with a one-minute lifetime and Subscribe
// watches that prefix, so a notification reaches the subscribers of every
// process. The Index is the transitional set of the port: a member is the key
// `idx.<set>.<member>` with an empty value and the set's lifetime, so Members
// is a prefix listing and the set's expiry is per member, not refreshed for
// the others by an Add.
package nats

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/truvity/access-roster/internal/port"
)

var (
	_ port.State   = (*Store)(nil)
	_ port.Index   = (*Store)(nil)
	_ port.Trigger = (*Store)(nil)
)

// DefaultBucket is the bucket the layout names (docs/design/ports.md).
const DefaultBucket = "access-roster"

// DefaultReplicas is the bucket's replica count.
const DefaultReplicas = 3

const (
	// markerTTL is how long a delete marker stays, so that a watcher that is
	// briefly away still sees an expiry.
	markerTTL = time.Minute
	// opTimeout bounds a call whose context has no deadline.
	opTimeout = 10 * time.Second
	// version is the first byte of every stored value.
	version = 1
	// header is the version byte and the expiry in Unix milliseconds.
	header = 1 + 8
)

// Config is how a bucket is reached and made.
type Config struct {
	// URL is the server list, comma separated.
	URL string
	// Bucket is the KV bucket; empty is [DefaultBucket].
	Bucket string
	// Replicas is the bucket's replica count when it is created; 0 is
	// [DefaultReplicas].
	Replicas int
	// TokenFile holds this workload's ServiceAccount token, presented as the
	// NATS token (the auth callout validates it) and read afresh on every
	// connect.
	TokenFile string
	// CredsFile is a NATS credentials file, the alternative to TokenFile.
	CredsFile string
	// CAFile is a PEM bundle of the authorities that sign the server's
	// certificate, when the system's do not.
	CAFile string
	// NoCreate binds to a bucket that exists and never creates or updates
	// one, for an identity that may not manage streams.
	NoCreate bool
	// Name is how the connection introduces itself.
	Name string
}

// Option configures [New] and [Open].
type Option func(*Store)

// WithClock replaces the clock expiry is judged by.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// WithSweepEvery sets how often a watch checks the clock for expiries it has
// seen written (one second by default).
func WithSweepEvery(d time.Duration) Option { return func(s *Store) { s.sweep = d } }

// WithoutServerTTL creates the bucket without per-message TTL, as on a server
// older than 2.11: expiry is then judged on read only.
func WithoutServerTTL() Option { return func(s *Store) { s.noServerTTL = true } }

// Store is the State, Index and Trigger over one bucket.
type Store struct {
	nc          *nats.Conn
	owned       bool
	js          jetstream.JetStream
	kv          jetstream.KeyValue
	stream      jetstream.Stream
	subject     string
	serverTTL   bool
	noServerTTL bool

	now    func() time.Time
	offset atomic.Int64
	sweep  time.Duration
}

// Open connects to the servers and binds the bucket.
func Open(ctx context.Context, cfg Config, opts ...Option) (*Store, error) {
	nc, err := Connect(cfg)
	if err != nil {
		return nil, err
	}
	s, err := New(ctx, nc, cfg, opts...)
	if err != nil {
		nc.Close()
		return nil, err
	}
	s.owned = true
	return s, nil
}

// Connect opens the connection the configuration describes.
func Connect(cfg Config) (*nats.Conn, error) {
	if cfg.URL == "" {
		return nil, errors.New("nats: no url")
	}
	if cfg.TokenFile != "" && cfg.CredsFile != "" {
		return nil, errors.New("nats: tokenFile and credsFile are alternatives; set one")
	}
	opts := []nats.Option{
		nats.Name(orDefault(cfg.Name, "access-roster")),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(false),
		nats.Timeout(5 * time.Second),
	}
	switch {
	case cfg.TokenFile != "":
		file := cfg.TokenFile
		// Read on every (re)connect: a projected token is rotated under us.
		opts = append(opts, nats.TokenHandler(func() string {
			raw, err := readFile(file)
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(raw))
		}))
	case cfg.CredsFile != "":
		opts = append(opts, nats.UserCredentials(cfg.CredsFile))
	}
	if cfg.CAFile != "" {
		opts = append(opts, nats.RootCAs(cfg.CAFile))
	}
	nc, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", port.ErrUnavailable, err)
	}
	return nc, nil
}

// New binds the bucket over a connection the caller owns, creating it unless
// the configuration says not to.
func New(ctx context.Context, nc *nats.Conn, cfg Config, opts ...Option) (*Store, error) {
	s := &Store{nc: nc, now: time.Now, sweep: time.Second}
	for _, opt := range opts {
		opt(s)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, unavailable(err)
	}
	s.js = js
	bucket := orDefault(cfg.Bucket, DefaultBucket)
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if cfg.NoCreate {
		s.kv, err = js.KeyValue(ctx, bucket)
	} else {
		s.kv, err = s.create(ctx, bucket, cfg.Replicas)
	}
	if err != nil {
		return nil, unavailable(fmt.Errorf("bucket %q: %w", bucket, err))
	}
	if s.stream, err = js.Stream(ctx, "KV_"+bucket); err != nil {
		return nil, unavailable(fmt.Errorf("bucket %q: %w", bucket, err))
	}
	status, err := s.kv.Status(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	s.serverTTL = status.LimitMarkerTTL() > 0
	s.subject = "$KV." + bucket + "."
	return s, nil
}

func (s *Store) create(ctx context.Context, bucket string, replicas int) (jetstream.KeyValue, error) {
	if replicas <= 0 {
		replicas = DefaultReplicas
	}
	kc := jetstream.KeyValueConfig{
		Bucket:         bucket,
		Replicas:       replicas,
		Storage:        jetstream.FileStorage,
		History:        1,
		MaxValueSize:   port.MaxValue + 8<<10, // the stream counts the subject and headers too
		LimitMarkerTTL: markerTTL,
	}
	if s.noServerTTL {
		kc.LimitMarkerTTL = 0
	}
	kv, err := s.js.CreateOrUpdateKeyValue(ctx, kc)
	if err != nil && kc.LimitMarkerTTL != 0 && errors.Is(err, jetstream.ErrLimitMarkerTTLNotSupported) {
		kc.LimitMarkerTTL = 0
		kv, err = s.js.CreateOrUpdateKeyValue(ctx, kc)
	}
	if err != nil {
		return nil, err
	}
	// A direct get is answered by any replica, which may not have applied a
	// write the caller was just acknowledged for. Reads here must see what
	// the store committed (a revoked session must read as revoked), so the
	// bucket is bound again with direct gets off: the leader answers.
	stream, err := s.js.Stream(ctx, "KV_"+bucket)
	if err != nil {
		return nil, err
	}
	if sc := stream.CachedInfo().Config; sc.AllowDirect {
		sc.AllowDirect = false
		if _, err = s.js.UpdateStream(ctx, sc); err != nil {
			return nil, err
		}
		return s.js.KeyValue(ctx, bucket)
	}
	return kv, nil
}

// ServerTTL reports whether the bucket reaps expired records itself.
func (s *Store) ServerTTL() bool { return s.serverTTL }

// Close closes the connection when [Open] made it.
func (s *Store) Close() {
	if s.owned {
		s.nc.Close()
	}
}

// Ping asks the bucket's stream for its state: the server is reachable, the
// bucket is there and a leader answers.
func (s *Store) Ping(ctx context.Context) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err := s.stream.Info(ctx); err != nil {
		return unavailable(err)
	}
	return nil
}

// Set returns the ports this adapter implements.
func (s *Store) Set() port.Set { return port.Set{State: s, Index: s, Trigger: s} }

// Advance moves the adapter's clock forward, so a test can cross a lifetime
// without sleeping. Only reads and watches see it: the server's own TTL runs
// on real time.
func (s *Store) Advance(d time.Duration) { s.offset.Add(int64(d)) }

func (s *Store) clock() time.Time { return s.now().Add(time.Duration(s.offset.Load())) }

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, opTimeout)
}

func unavailable(err error) error {
	if errors.Is(err, port.ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", port.ErrUnavailable, err)
}

// isMismatch is a write that expected another last sequence for its subject.
func isMismatch(err error) bool {
	if errors.Is(err, jetstream.ErrKeyExists) || errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return true
	}
	var api *jetstream.APIError
	return errors.As(err, &api) && (api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence ||
		api.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequenceConstant)
}

// --- keys ---

const hex = "0123456789ABCDEF"

// encode escapes every byte the KV client does not allow in a key, and the
// '=' that starts an escape, as =XX. Dots stay.
func encode(key string) string {
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '/', c == '.':
			b.WriteByte(c)
		default:
			b.WriteByte('=')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// escapeDots is [encode] for a segment that must hold no dot.
func escapeDots(s string) string {
	return strings.ReplaceAll(encode(s), ".", "=2E")
}

func decode(key string) string {
	if !strings.Contains(key, "=") {
		return key
	}
	var b strings.Builder
	for i := 0; i < len(key); i++ {
		if key[i] == '=' && i+2 < len(key) {
			if hi, lo := strings.IndexByte(hex, key[i+1]), strings.IndexByte(hex, key[i+2]); hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		b.WriteByte(key[i])
	}
	return b.String()
}

// filter is the subject filter that covers every key with the prefix: the
// prefix up to its last dot, then everything below. The caller keeps what
// really has the prefix.
func filter(prefix string) string {
	enc := encode(prefix)
	base := enc[:strings.LastIndexByte(enc, '.')+1]
	return base + ">"
}

// --- values ---

func seal(value []byte, expires time.Time) []byte {
	out := make([]byte, header)
	out[0] = version
	if !expires.IsZero() {
		binary.BigEndian.PutUint64(out[1:], uint64(expires.UnixMilli()))
	}
	return append(out, value...)
}

// open reads a stored value; ok is false for what this adapter did not write
// (a limit marker, say), which reads as absent.
func open(data []byte) (value []byte, expires time.Time, ok bool) {
	if len(data) < header || data[0] != version {
		return nil, time.Time{}, false
	}
	if ms := binary.BigEndian.Uint64(data[1:header]); ms != 0 {
		expires = time.UnixMilli(int64(ms))
	}
	return data[header:], expires, true
}

func (s *Store) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.clock().Add(ttl)
}

func (s *Store) expired(expires time.Time) bool {
	return !expires.IsZero() && !s.clock().Before(expires)
}

func revision(seq uint64) port.Revision { return port.Revision(strconv.FormatUint(seq, 10)) }

func sequence(rev port.Revision) (uint64, bool) {
	n, err := strconv.ParseUint(string(rev), 10, 64)
	return n, err == nil && n != 0
}

// ttlOption is the server-side lifetime, rounded up to the server's second.
func ttlOf(ttl time.Duration) time.Duration {
	return (ttl + time.Second - 1).Truncate(time.Second)
}

// --- State ---

// live reads the record, absent or expired being [port.ErrNotFound].
func (s *Store) live(ctx context.Context, key string) (jetstream.KeyValueEntry, []byte, error) {
	e, err := s.kv.Get(ctx, encode(key))
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound), errors.Is(err, jetstream.ErrKeyDeleted):
		return nil, nil, port.ErrNotFound
	case err != nil:
		return nil, nil, unavailable(err)
	}
	if e.Operation() != jetstream.KeyValuePut {
		return nil, nil, port.ErrNotFound
	}
	value, expires, ok := open(e.Value())
	if !ok || s.expired(expires) {
		return nil, nil, port.ErrNotFound
	}
	return e, value, nil
}

// Get implements [port.State].
func (s *Store) Get(ctx context.Context, key string) (port.Record, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	e, value, err := s.live(ctx, key)
	if err != nil {
		return port.Record{}, err
	}
	return port.Record{Key: key, Value: slices.Clone(value), Revision: revision(e.Revision())}, nil
}

// publish writes a message to the key's subject, expecting the subject's last
// sequence to be expect when expect is not nil.
func (s *Store) publish(ctx context.Context, key string, value []byte, ttl time.Duration, expect *uint64) (uint64, error) {
	msg := nats.NewMsg(s.subject + encode(key))
	msg.Data = seal(value, s.expiry(ttl))
	var opts []jetstream.PublishOpt
	if expect != nil {
		opts = append(opts, jetstream.WithExpectLastSequencePerSubject(*expect))
	}
	if s.serverTTL && ttl > 0 {
		opts = append(opts, jetstream.WithMsgTTL(ttlOf(ttl)))
	}
	ack, err := s.js.PublishMsg(ctx, msg, opts...)
	if err != nil {
		return 0, err
	}
	return ack.Sequence, nil
}

// Put implements [port.State].
func (s *Store) Put(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	seq, err := s.publish(ctx, key, value, ttl, nil)
	if err != nil {
		return "", unavailable(err)
	}
	return revision(seq), nil
}

// Create implements [port.State].
func (s *Store) Create(ctx context.Context, key string, value []byte, ttl time.Duration) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var copts []jetstream.KVCreateOpt
	if s.serverTTL && ttl > 0 {
		copts = append(copts, jetstream.KeyTTL(ttlOf(ttl)))
	}
	for range 4 {
		seq, err := s.kv.Create(ctx, encode(key), seal(value, s.expiry(ttl)), copts...)
		if err == nil {
			return revision(seq), nil
		}
		if !isMismatch(err) {
			return "", unavailable(err)
		}
		// Something is stored. A live record refuses; an expired one (that
		// the server has not reaped, or the marker it left) is written over
		// against its own revision, so exactly one taker wins.
		cur, err := s.kv.Get(ctx, encode(key))
		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound), errors.Is(err, jetstream.ErrKeyDeleted):
			continue // gone meanwhile: Create again
		case err != nil:
			return "", unavailable(err)
		}
		if _, expires, ok := open(cur.Value()); ok && !s.expired(expires) && cur.Operation() == jetstream.KeyValuePut {
			return "", port.ErrExists
		}
		expect := cur.Revision()
		seq, err = s.publish(ctx, key, value, ttl, &expect)
		switch {
		case err == nil:
			return revision(seq), nil
		case isMismatch(err):
			continue
		default:
			return "", unavailable(err)
		}
	}
	return "", port.ErrExists
}

// Update implements [port.State].
func (s *Store) Update(ctx context.Context, key string, value []byte, ttl time.Duration, rev port.Revision) (port.Revision, error) {
	if err := port.CheckWrite(key, value, ttl); err != nil {
		return "", err
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	want, ok := sequence(rev)
	e, _, err := s.live(ctx, key)
	if err != nil {
		return "", err
	}
	if !ok || e.Revision() != want {
		return "", port.ErrConflict
	}
	seq, err := s.publish(ctx, key, value, ttl, &want)
	switch {
	case err == nil:
		return revision(seq), nil
	case isMismatch(err):
		if _, _, gone := s.live(ctx, key); gone != nil && errors.Is(gone, port.ErrNotFound) {
			return "", port.ErrNotFound
		}
		return "", port.ErrConflict
	}
	return "", unavailable(err)
}

// remove places the delete marker, expiring it when the bucket can.
func (s *Store) remove(ctx context.Context, key string, opts ...jetstream.KVDeleteOpt) error {
	if s.serverTTL {
		return s.kv.Purge(ctx, encode(key), append(opts, jetstream.PurgeTTL(markerTTL))...)
	}
	return s.kv.Delete(ctx, encode(key), opts...)
}

// Delete implements [port.State].
func (s *Store) Delete(ctx context.Context, key string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	if _, err := s.kv.Get(ctx, encode(key)); errors.Is(err, jetstream.ErrKeyNotFound) || errors.Is(err, jetstream.ErrKeyDeleted) {
		return nil // nothing is stored: no marker to leave
	}
	if err := s.remove(ctx, key); err != nil {
		return unavailable(err)
	}
	return nil
}

// DeleteIfRevision implements [port.State].
func (s *Store) DeleteIfRevision(ctx context.Context, key string, rev port.Revision) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	want, ok := sequence(rev)
	e, _, err := s.live(ctx, key)
	if err != nil {
		return err
	}
	if !ok || e.Revision() != want {
		return port.ErrConflict
	}
	err = s.remove(ctx, key, jetstream.LastRevision(want))
	switch {
	case err == nil:
		return nil
	case isMismatch(err):
		if _, _, gone := s.live(ctx, key); gone != nil && errors.Is(gone, port.ErrNotFound) {
			return port.ErrNotFound
		}
		return port.ErrConflict
	}
	return unavailable(err)
}

// keysUnder lists the decoded keys that have the prefix, sorted. The
// subjects come from the stream's own state, which the leader answers, so a
// listing sees every write the caller was acknowledged for.
func (s *Store) keysUnder(ctx context.Context, prefix string) ([]string, error) {
	info, err := s.stream.Info(ctx, jetstream.WithSubjectFilter(s.subject+filter(prefix)))
	if err != nil {
		return nil, unavailable(err)
	}
	keys := make([]string, 0, len(info.State.Subjects))
	for subject := range info.State.Subjects {
		if key := decode(strings.TrimPrefix(subject, s.subject)); strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// List implements [port.State].
func (s *Store) List(ctx context.Context, prefix, page string, limit int) (port.Page, error) {
	after, err := port.PageStart(prefix, page)
	if err != nil {
		return port.Page{}, err
	}
	if limit <= 0 {
		limit = port.DefaultPage
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	keys, err := s.keysUnder(ctx, prefix)
	if err != nil {
		return port.Page{}, err
	}
	var out port.Page
	for _, key := range keys {
		if key <= after {
			continue
		}
		if len(out.Records) == limit {
			out.Next = port.PageToken(prefix, out.Records[limit-1].Key)
			break
		}
		e, value, err := s.live(ctx, key)
		switch {
		case errors.Is(err, port.ErrNotFound):
			continue
		case err != nil:
			return port.Page{}, err
		}
		out.Records = append(out.Records, port.Record{Key: key, Value: slices.Clone(value), Revision: revision(e.Revision())})
	}
	return out, nil
}

func readFile(name string) ([]byte, error) { return os.ReadFile(name) }
