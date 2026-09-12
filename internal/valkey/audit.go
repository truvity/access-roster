package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/truvity/access-roster/internal/audit"
)

// Audit is the event stream every replica, and both halves of the service,
// write into: one Valkey stream, capped by count on every write and trimmed
// by age.
//
// A stream rather than a list because its entry ids are times, so
// trimming by age is one command and a page is a range, and because it is
// the one key: in a cluster every write lands on the same slot, which is
// what keeps one ordered history rather than a shard each.
type Audit struct {
	client redis.UniversalClient
	prefix string
	maxLen int64
	maxAge time.Duration
	now    func() time.Time
}

var _ audit.Store = (*Audit)(nil)

// DefaultAuditEvents and DefaultAuditAge are the caps when a deployment
// sets none: enough to read back a busy month, and small enough that the
// stream is never the largest thing in the store.
const (
	DefaultAuditEvents = 50000
	DefaultAuditAge    = 30 * 24 * time.Hour
)

// OpenAudit connects an audit store.
func OpenAudit(ctx context.Context, cfg Config, maxEvents int64, maxAge time.Duration) (*Audit, error) {
	client, prefix, err := dial(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return NewAudit(client, prefix, maxEvents, maxAge), nil
}

// NewAudit wraps a client that is already open.
func NewAudit(client redis.UniversalClient, prefix string, maxEvents int64, maxAge time.Duration) *Audit {
	if maxEvents <= 0 {
		maxEvents = DefaultAuditEvents
	}
	if maxAge <= 0 {
		maxAge = DefaultAuditAge
	}
	return &Audit{client: client, prefix: prefix, maxLen: maxEvents, maxAge: maxAge, now: time.Now}
}

// Close releases the connections.
func (a *Audit) Close() error { return a.client.Close() }

func (a *Audit) key() string { return a.prefix + ":audit" }

// eventField is the one field each stream entry carries.
const eventField = "e"

// Append implements [audit.Store].
func (a *Audit) Append(ctx context.Context, e audit.Event) (string, error) {
	e.ID = "" // the stream assigns it
	raw, err := json.Marshal(e)
	if err != nil {
		return "", fmt.Errorf("valkey: encode an audit event: %w", err)
	}
	id, err := a.client.XAdd(ctx, &redis.XAddArgs{
		Stream: a.key(),
		MaxLen: a.maxLen,
		Approx: true,
		Values: map[string]any{eventField: raw},
	}).Result()
	if err != nil {
		return "", fmt.Errorf("valkey: append an audit event: %w", err)
	}
	// Age, separately: a write may not cap by both at once. Approximate,
	// like the count, so it trims whole nodes and costs nothing.
	oldest := a.now().Add(-a.maxAge).UnixMilli()
	if err = a.client.XTrimMinIDApprox(ctx, a.key(), strconv.FormatInt(oldest, 10), 0).Err(); err != nil {
		// The event is written; an untrimmed tail is trimmed by the next.
		return id, nil //nolint:nilerr // trimming is housekeeping, and the append succeeded
	}
	return id, nil
}

// scanPage is how many entries one read takes while filtering.
const scanPage = 500

// scanBudget bounds how far one listing reads looking for matches, so a
// rare filter over a full stream answers with a cursor instead of reading
// every entry in one request.
const scanBudget = 10000

// List implements [audit.Store]: newest first, filtered here.
func (a *Audit) List(ctx context.Context, q audit.Query) ([]audit.Event, string, error) {
	limit := q.Limited()
	end := "+"
	if q.Cursor != "" {
		// Exclusive: the cursor is the last entry the previous page
		// returned.
		end = "(" + q.Cursor
	}
	var out []audit.Event
	scanned, last := 0, ""
	for scanned < scanBudget {
		entries, err := a.client.XRevRangeN(ctx, a.key(), end, "-", scanPage).Result()
		if err != nil {
			return nil, "", fmt.Errorf("valkey: read the audit stream: %w", err)
		}
		for _, entry := range entries {
			scanned++
			last = entry.ID
			e, ok := decodeEvent(entry)
			if !ok {
				continue
			}
			// The stream is in time order, so an entry older than Since
			// ends the listing.
			if !q.Since.IsZero() && e.At.Before(q.Since) {
				return out, "", nil
			}
			if !q.Matches(e) {
				continue
			}
			if len(out) == limit {
				return out, out[len(out)-1].ID, nil
			}
			out = append(out, e)
		}
		if len(entries) < scanPage {
			return out, "", nil
		}
		end = "(" + entries[len(entries)-1].ID
	}
	// Out of budget with a page not yet full: say where to continue, which
	// is the last entry READ — a narrow filter over a busy stream then
	// pages through it rather than failing.
	return out, last, nil
}

func decodeEvent(entry redis.XMessage) (audit.Event, bool) {
	raw, ok := entry.Values[eventField].(string)
	if !ok {
		return audit.Event{}, false
	}
	var e audit.Event
	if json.Unmarshal([]byte(raw), &e) != nil {
		return audit.Event{}, false
	}
	e.ID = entry.ID
	return e, true
}
