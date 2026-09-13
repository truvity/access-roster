// Package s3audit keeps the audit trail in S3: the durable record of what
// happened in access-roster, and the store the console's Audit page reads.
// It is an AuditSinkService writer, reached in process through
// internal/audit/sinkrpc.
//
// Events are appended in batches, one JSON-lines object per batch, under
//
//	<prefix>YYYY/MM/DD/HH/<first event's unix nanoseconds>-<writer>-<seq>.jsonl
//
// so every object holds events of one UTC hour, and a listing reads hour
// by hour, newest first. Each line is one ECS document (audit.EncodeRecord);
// objects written by access-roster 1.6.2 hold its own event lines, and both
// are read back (audit.DecodeRecord). Objects are never rewritten: the
// bucket is meant to carry Object Lock and deny deletes, and this package
// only ever puts, lists and gets.
//
// An ordinary write never waits on S3. It queues the events and returns; a
// flusher writes the queue on a short interval, at a batch size, and at
// every hour boundary, and keeps what it could not write for the next try.
// An event not yet written is still one log line, and still in listings
// from this replica. A durable write is the other kind: its events are put
// in an object of their own before it returns, and what it could not put is
// not kept at all — which is what a recovery sign-in waits for.
package s3audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"go.opentelemetry.io/otel/metric"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/logsafe"
)

// Client is the part of the S3 API the store uses.
type Client interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Config says where the trail is kept and how often it is written.
type Config struct {
	Bucket string
	// Region is the bucket's; empty takes the SDK's own resolution.
	Region string
	// Prefix is prepended to every key; "events/" when empty.
	Prefix string
	// FlushInterval is the longest an event waits to be written.
	FlushInterval time.Duration
	// BatchSize writes a batch as soon as it holds this many events.
	BatchSize int
	// Writer names this replica in object keys and event ids, so two
	// replicas never write the same key. The pod name when empty.
	Writer string
	// Meter is where the writer's metrics go; the global provider when
	// nil, which records nothing unless a collector is named.
	Meter metric.MeterProvider
}

// Defaults.
const (
	DefaultPrefix        = "events/"
	DefaultFlushInterval = 10 * time.Second
	DefaultBatchSize     = 500

	// maxPending bounds what one replica holds while S3 refuses it: past
	// it the oldest are dropped, and each drop is logged. The log lines
	// stay the copy of those.
	maxPending = 50000
	// hoursPerList and objectsPerList bound how far one listing reads, so
	// a narrow filter over a quiet year answers with a cursor rather than
	// thousands of requests.
	hoursPerList   = 24 * 7
	objectsPerList = 2000
	// cacheObjects is how many decoded objects are kept. Objects are
	// immutable, so a cached one is never stale.
	cacheObjects = 1024
)

// Store is an AuditSinkService writer in S3.
type Store struct {
	client  Client
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	metrics instruments

	mu      sync.Mutex
	pending []audit.Event // appended, not yet written, oldest first
	writing []audit.Event // taken by a flush in progress
	batch   uint64
	closed  bool

	wake    chan struct{}
	done    chan struct{}
	stopped chan struct{}

	cacheMu sync.Mutex
	cache   map[string][]audit.Event
	order   []string
	// oldestHour is the hour of the oldest object, found at oldestAt.
	oldestHour time.Time
	oldestAt   time.Time
}

// Open builds a store on the SDK's default credentials: in a cluster, the
// pod's identity.
func Open(ctx context.Context, cfg Config, log *slog.Logger) (*Store, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3audit: a bucket is required")
	}
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3audit: load AWS configuration: %w", err)
	}
	return New(s3.NewFromConfig(loaded), cfg, log, time.Now), nil
}

// New builds a store on a client and starts its flusher.
func New(client Client, cfg Config, log *slog.Logger, now func() time.Time) *Store {
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	if !strings.HasSuffix(cfg.Prefix, "/") {
		cfg.Prefix += "/"
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	cfg.Writer = audit.WriterName(cfg.Writer)
	s := &Store{
		client: client, cfg: cfg, log: log, now: now,
		wake: make(chan struct{}, 1), done: make(chan struct{}), stopped: make(chan struct{}),
		cache: map[string][]audit.Event{},
	}
	s.metrics = newInstruments(cfg.Meter, s.depth)
	go s.run()
	return s
}

// WriteAuditEvents implements the AuditSinkService handler.
func (s *Store) WriteAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.WriteAuditEventsRequest],
) (*connect.Response[directoryrosterv1.WriteAuditEventsResponse], error) {
	events := audit.EventsFromProto(req.Msg.GetEvents())
	if err := s.write(ctx, events, req.Msg.GetDurable()); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&directoryrosterv1.WriteAuditEventsResponse{
		Written: int32(len(events)), //nolint:gosec // one request's events
	}), nil
}

// write keeps events: queued, or with durable put before it returns.
func (s *Store) write(ctx context.Context, events []audit.Event, durable bool) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("s3audit: the store is closed")
	}
	now := s.now()
	for i := range events {
		events[i] = audit.Assign(events[i], s.cfg.Writer, now)
	}
	if durable {
		s.mu.Unlock()
		return s.putNow(ctx, events)
	}
	defer s.mu.Unlock()
	s.pending = append(s.pending, events...)
	if over := len(s.pending) - maxPending; over > 0 {
		s.log.Warn("the audit trail cannot be written and is full; the oldest unwritten events are dropped (their log lines remain)",
			"dropped", over)
		s.metrics.dropped.Add(context.Background(), int64(over))
		s.pending = slices.Delete(s.pending, 0, over)
	}
	if len(s.pending) >= s.cfg.BatchSize {
		s.nudge()
	}
	return nil
}

// putNow writes events in objects of their own, one per hour they span,
// bypassing the queue. It is the durable write: nothing it could not put is
// kept for later, because an event its caller refused on that failure must
// not turn up in the trail afterwards as though it had happened.
func (s *Store) putNow(ctx context.Context, events []audit.Event) error {
	slices.SortFunc(events, func(a, b audit.Event) int { return strings.Compare(a.ID, b.ID) })
	for len(events) > 0 {
		hour := hourOf(events[0].At)
		n := 1
		for n < len(events) && hourOf(events[n].At).Equal(hour) {
			n++
		}
		batch := slices.Clone(events[:n])
		events = events[n:]
		s.mu.Lock()
		s.batch++
		key := s.key(hour, batch[0].At, s.batch)
		s.mu.Unlock()
		if err := s.put(ctx, key, batch, true); err != nil {
			return err
		}
		s.remember(key, batch)
	}
	return nil
}

// key is where a batch is put: its hour, its first event's time, this
// writer, and a sequence no other batch of this writer shares.
func (s *Store) key(hour, first time.Time, batch uint64) string {
	return s.cfg.Prefix + hour.Format("2006/01/02/15") + "/" +
		fmt.Sprintf("%019d-%s-%d.jsonl", first.UnixNano(), s.cfg.Writer, batch)
}

// put writes one object of ECS records and counts the write.
func (s *Store) put(ctx context.Context, key string, batch []audit.Event, durable bool) error {
	var body bytes.Buffer
	for i := range batch {
		line, err := audit.EncodeRecord(batch[i])
		if err != nil {
			continue
		}
		body.Write(line)
		body.WriteByte('\n')
	}
	putCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := s.client.PutObject(putCtx, &s3.PutObjectInput{
		Bucket:            aws.String(s.cfg.Bucket),
		Key:               aws.String(key),
		Body:              bytes.NewReader(body.Bytes()),
		ContentType:       aws.String("application/x-ndjson"),
		ChecksumAlgorithm: types.ChecksumAlgorithmCrc32,
	})
	s.metrics.recordWrite(ctx, durable, err == nil)
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// Close stops the flusher and writes what is queued, within ctx. Called
// again after a failure, it tries the write again.
func (s *Store) Close(ctx context.Context) error {
	s.mu.Lock()
	first := !s.closed
	s.closed = true
	s.mu.Unlock()
	if first {
		close(s.done)
		s.metrics.stop()
	}
	// The flusher finishes the batch it is writing before it stops, so
	// what is left afterwards is all in pending.
	select {
	case <-s.stopped:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		written, err := s.flush(ctx)
		if err != nil {
			return err
		}
		if !written {
			return nil
		}
	}
}

func (s *Store) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) run() {
	defer close(s.stopped)
	ticker := time.NewTicker(s.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		case <-s.wake:
		}
		for {
			written, err := s.flush(context.Background())
			if err != nil {
				s.log.Warn("the audit trail could not be written to S3; tried again next interval", "error", err)
				break
			}
			if !written {
				break
			}
		}
	}
}

// flush writes one batch: the oldest pending events that share an hour, at
// most a batch size of them, and reports whether it wrote anything. Events
// gather between flushes, which the interval and the batch size pace.
func (s *Store) flush(ctx context.Context) (bool, error) {
	s.mu.Lock()
	if len(s.writing) > 0 || len(s.pending) == 0 {
		s.mu.Unlock()
		return false, nil
	}
	hour := hourOf(s.pending[0].At)
	n := 0
	for n < len(s.pending) && n < s.cfg.BatchSize && hourOf(s.pending[n].At).Equal(hour) {
		n++
	}
	s.writing = slices.Clone(s.pending[:n])
	s.pending = slices.Delete(s.pending, 0, n)
	s.batch++
	key := s.key(hour, s.writing[0].At, s.batch)
	batch := s.writing
	s.mu.Unlock()

	err := s.put(ctx, key, batch, false)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		// Back at the front, in order, for the next try.
		s.pending = append(slices.Clone(batch), s.pending...)
		s.writing = nil
		return false, err
	}
	s.writing = nil
	s.remember(key, batch)
	return true, nil
}

// ListStoredAuditEvents implements the AuditSinkService handler.
func (s *Store) ListStoredAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListStoredAuditEventsRequest],
) (*connect.Response[directoryrosterv1.ListStoredAuditEventsResponse], error) {
	events, cursor, err := s.list(ctx, audit.QueryFromProto(req.Msg.GetQuery()))
	if errors.Is(err, errCursor) {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	return connect.NewResponse(&directoryrosterv1.ListStoredAuditEventsResponse{
		Events: audit.EventsToProto(events), Cursor: cursor,
	}), nil
}

// errCursor is a cursor that is not one.
var errCursor = errors.New("s3audit: not a cursor")

// list reads newest first, including this replica's events not yet
// written.
func (s *Store) list(ctx context.Context, q audit.Query) ([]audit.Event, string, error) {
	limit := q.Limited()
	s.mu.Lock()
	unwritten := append(slices.Clone(s.writing), s.pending...)
	s.mu.Unlock()

	start := hourOf(s.now().UTC())
	if q.Cursor != "" {
		at, ok := cursorTime(q.Cursor)
		if !ok {
			return nil, "", fmt.Errorf("%w: %q", errCursor, logsafe.Value(q.Cursor))
		}
		start = hourOf(at)
	}

	// Nothing is older than the oldest object, nor than what is still
	// unwritten here: below that floor a listing is over, not paused.
	floor, err := s.oldest(ctx)
	if err != nil {
		return nil, "", err
	}
	for i := range unwritten {
		if h := hourOf(unwritten[i].At); h.Before(floor) {
			floor = h
		}
	}
	if !q.Since.IsZero() && hourOf(q.Since).After(floor) {
		floor = hourOf(q.Since)
	}

	var out []audit.Event
	objects := 0
	for hours, hour := 0, start; ; hours, hour = hours+1, hour.Add(-time.Hour) {
		if hour.Before(floor) {
			return out, "", nil
		}
		if hours == hoursPerList || objects >= objectsPerList {
			// Out of budget between hours: continue below this one.
			return out, boundary(hour.Add(time.Hour)), nil
		}
		events, read, err := s.hour(ctx, hour)
		if err != nil {
			return nil, "", err
		}
		objects += read
		events = merge(events, unwritten, hour)
		for i := range events {
			e := events[i]
			if q.Cursor != "" && e.ID >= q.Cursor {
				continue
			}
			if !q.Matches(e) {
				continue
			}
			if len(out) == limit {
				return out, out[len(out)-1].ID, nil
			}
			out = append(out, e)
		}
	}
}

// oldestTTL is how long the oldest object's hour is trusted: objects only
// ever age out of the bucket, so a stale answer reads a little too far.
const oldestTTL = time.Hour

// oldest is the hour of the oldest object in the trail, or the current hour
// when there is none. Keys sort by time, so it is one key's listing.
func (s *Store) oldest(ctx context.Context) (time.Time, error) {
	s.cacheMu.Lock()
	if !s.oldestAt.IsZero() && s.now().Sub(s.oldestAt) < oldestTTL {
		defer s.cacheMu.Unlock()
		return s.oldestHour, nil
	}
	s.cacheMu.Unlock()

	page, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.Bucket), Prefix: aws.String(s.cfg.Prefix), MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("s3audit: find the oldest object: %w", err)
	}
	hour := hourOf(s.now().UTC())
	if len(page.Contents) > 0 && page.Contents[0].Key != nil {
		stamp := strings.TrimPrefix(*page.Contents[0].Key, s.cfg.Prefix)
		if len(stamp) >= len("2006/01/02/15") {
			if parsed, perr := time.Parse("2006/01/02/15", stamp[:len("2006/01/02/15")]); perr == nil {
				hour = parsed.UTC()
			}
		}
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.oldestHour, s.oldestAt = hour, s.now()
	return hour, nil
}

// hour reads every object of one hour and returns its events newest first,
// with how many objects it had to fetch.
func (s *Store) hour(ctx context.Context, hour time.Time) ([]audit.Event, int, error) {
	prefix := s.cfg.Prefix + hour.Format("2006/01/02/15") + "/"
	var keys []string
	var token *string
	for {
		page, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(s.cfg.Bucket), Prefix: aws.String(prefix), ContinuationToken: token,
		})
		if err != nil {
			return nil, 0, fmt.Errorf("s3audit: list %s: %w", prefix, err)
		}
		for _, object := range page.Contents {
			if object.Key != nil {
				keys = append(keys, *object.Key)
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		token = page.NextContinuationToken
	}
	var events []audit.Event
	fetched := 0
	for _, key := range keys {
		batch, cached := s.cached(key)
		if !cached {
			var err error
			if batch, err = s.fetch(ctx, key); err != nil {
				return nil, 0, err
			}
			fetched++
			s.remember(key, batch)
		}
		events = append(events, batch...)
	}
	slices.SortFunc(events, func(a, b audit.Event) int { return strings.Compare(b.ID, a.ID) })
	return events, fetched, nil
}

func (s *Store) fetch(ctx context.Context, key string) ([]audit.Event, error) {
	object, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.cfg.Bucket), Key: aws.String(key)})
	if err != nil {
		return nil, fmt.Errorf("s3audit: get %s: %w", key, err)
	}
	defer func() { _ = object.Body.Close() }()
	var out []audit.Event
	lines := bufio.NewScanner(io.LimitReader(object.Body, 64<<20))
	lines.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for lines.Scan() {
		// Either format: an object holds one, and the hour it is in may
		// hold objects of both.
		if e, err := audit.DecodeRecord(lines.Bytes()); err == nil && e.ID != "" {
			out = append(out, e)
		}
	}
	if err = lines.Err(); err != nil {
		return nil, fmt.Errorf("s3audit: read %s: %w", key, err)
	}
	return out, nil
}

func (s *Store) cached(key string) ([]audit.Event, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	events, ok := s.cache[key]
	return events, ok
}

func (s *Store) remember(key string, events []audit.Event) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if _, ok := s.cache[key]; ok {
		return
	}
	s.cache[key] = events
	s.order = append(s.order, key)
	if over := len(s.order) - cacheObjects; over > 0 {
		for _, old := range s.order[:over] {
			delete(s.cache, old)
		}
		s.order = slices.Delete(s.order, 0, over)
	}
}

// merge adds the unwritten events of one hour to what S3 holds for it,
// once each, newest first.
func merge(written, unwritten []audit.Event, hour time.Time) []audit.Event {
	seen := make(map[string]bool, len(written))
	for i := range written {
		seen[written[i].ID] = true
	}
	added := false
	for i := range unwritten {
		if hourOf(unwritten[i].At).Equal(hour) && !seen[unwritten[i].ID] {
			written = append(written, unwritten[i])
			added = true
		}
	}
	if added {
		slices.SortFunc(written, func(a, b audit.Event) int { return strings.Compare(b.ID, a.ID) })
	}
	return written
}

// cursorTime reads the time a cursor or event id starts with.
func cursorTime(cursor string) (time.Time, bool) {
	digits, _, _ := strings.Cut(cursor, "-")
	if len(digits) != 19 {
		return time.Time{}, false
	}
	nanos, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, nanos).UTC(), true
}

// boundary is a cursor below every event at or after t.
func boundary(t time.Time) string { return fmt.Sprintf("%019d", t.UnixNano()) }

func hourOf(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }

// depth is how many events are accepted and not yet written.
func (s *Store) depth() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) + len(s.writing)
}
