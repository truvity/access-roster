// Package audit is what happened in access-roster, lately, where an
// operator can read it.
//
// One stream for the whole service. The issuer records sign-ins, refusals,
// exchanges and revokes; the directory and the console record connects
// and disconnects; a component in another process — the GitHub controller
// first — reports what it did through the console's API, and is recorded
// with the identity it proved. Status elsewhere says what is true now;
// this says what changed and who caused it.
//
// A deployment keeps it in S3 (internal/s3audit): the durable record, and
// what the console reads. Every event is also one structured log line. The
// cluster's own audit log, CloudTrail, each directory's and GitHub's
// organisation audit log stay what they are, and are not duplicated here
// beyond the events this service itself causes.
//
// Recording never fails the thing being recorded. A sign-in that could not
// be written down still happened, and refusing it because the store was
// slow would turn an audit outage into an access outage.
package audit

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// The sources this service records for itself. A component reporting
// through the API may name none of them: a reporter that could say
// `issuer` could forge a sign-in.
const (
	SourceIssuer    = "issuer"
	SourceDirectory = "directory"
	SourceConsole   = "console"
)

// Reserved reports whether a source is one only this service may record.
func Reserved(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case SourceIssuer, SourceDirectory, SourceConsole:
		return true
	default:
		return false
	}
}

// ActorSystem is the actor of something this service did on its own, with
// no caller behind it.
const ActorSystem = "system"

// The outcomes. Most events are ok; the others exist because a refusal is
// often the event worth finding.
const (
	OutcomeOK      = "ok"
	OutcomeRefused = "refused"
	OutcomeFailed  = "failed"
	OutcomeHeld    = "held"
)

// Event is one thing that happened.
type Event struct {
	// ID is assigned by the store, ordered by time.
	ID string `json:"id,omitempty"`
	// At is when; the store fills it when zero.
	At time.Time `json:"at"`
	// Source is the component: issuer, directory, console, or a
	// reporter's own name.
	Source string `json:"source"`
	// Kind is what happened, dotted: sign-in, token.exchanged,
	// workspace.connected, github.member.invited.
	Kind string `json:"kind"`
	// Actor is the verified identity that caused it, or ActorSystem.
	Actor string `json:"actor,omitempty"`
	// Reporter is the verified identity of the component that reported
	// it, stamped by the service and never taken from the report. Empty
	// for what this service recorded itself.
	Reporter string `json:"reporter,omitempty"`
	// Subject is who or what it concerns: the person signed in, the
	// member invited.
	Subject string `json:"subject,omitempty"`
	// Target is where: the client, the workspace, the organisation or
	// team.
	Target  string `json:"target,omitempty"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// Attributes are the rest, flat, for the few things worth keeping that
	// fit no field above.
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Recorder writes events down. Implementations never return an error to
// the caller and never block it for long.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// Query narrows a listing. Empty fields match everything.
type Query struct {
	Source  string
	Kind    string
	Subject string
	Target  string
	// Since keeps events at or after it.
	Since time.Time
	// Limit is how many to return, newest first; zero is a default.
	Limit int
	// Cursor continues a listing from the ID the previous page ended at.
	Cursor string
}

// DefaultLimit is how many a listing returns when asked for none.
const DefaultLimit = 100

// MaxLimit bounds one page.
const MaxLimit = 1000

// Store keeps events and lists them, newest first.
type Store interface {
	Append(ctx context.Context, e Event) (string, error)
	// List returns a page and the cursor for the next one, empty at the
	// end.
	List(ctx context.Context, q Query) ([]Event, string, error)
}

// Matches reports whether an event is one a query asks for. Stores that
// cannot filter server-side use it.
func (q Query) Matches(e Event) bool {
	return field(q.Source, e.Source) && field(q.Kind, e.Kind) &&
		field(q.Subject, e.Subject) && field(q.Target, e.Target) &&
		(q.Since.IsZero() || !e.At.Before(q.Since))
}

func field(want, have string) bool {
	return want == "" || strings.EqualFold(want, have)
}

// Limited is a query's page size, bounded.
func (q Query) Limited() int {
	switch {
	case q.Limit <= 0:
		return DefaultLimit
	case q.Limit > MaxLimit:
		return MaxLimit
	default:
		return q.Limit
	}
}

// Log records every event as a log line and then into a store, and says
// so in the log when the store refuses.
type Log struct {
	log   *slog.Logger
	store Store
	now   func() time.Time
}

// NewLog returns a recorder. A nil store records to the log alone, which
// is still the durable copy.
func NewLog(log *slog.Logger, store Store) *Log {
	if log == nil {
		log = slog.Default()
	}
	return &Log{log: log, store: store, now: time.Now}
}

// storeTimeout bounds how long a store write may hold up the caller.
const storeTimeout = 2 * time.Second

// Record implements [Recorder].
func (l *Log) Record(ctx context.Context, e Event) {
	if l == nil {
		return
	}
	if e.At.IsZero() {
		e.At = l.now().UTC()
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeOK
	}
	attrs := []any{
		"audit", true, "source", e.Source, "kind", e.Kind, "outcome", e.Outcome,
		"actor", e.Actor, "subject", e.Subject, "target", e.Target,
	}
	if e.Reporter != "" {
		attrs = append(attrs, "reporter", e.Reporter)
	}
	if e.Reason != "" {
		attrs = append(attrs, "reason", e.Reason)
	}
	for _, key := range slices.Sorted(maps.Keys(e.Attributes)) {
		attrs = append(attrs, "attr."+key, e.Attributes[key])
	}
	l.log.InfoContext(ctx, "audit", attrs...)

	if l.store == nil {
		return
	}
	// Detached from the caller's cancellation — a request that ends as
	// soon as it has signed somebody in must not take its own record with
	// it — but bounded, so a slow store costs the caller little.
	writing, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if _, err := l.store.Append(writing, e); err != nil {
		l.log.WarnContext(ctx, "an audit event was logged and not stored", "kind", e.Kind, "error", err)
	}
}

// Nop records nothing. It exists so a component with no recorder need not
// check.
type Nop struct{}

// Record implements [Recorder].
func (Nop) Record(context.Context, Event) {}

// DefaultMemoryEvents caps the in-memory store.
const DefaultMemoryEvents = 50000

// Memory is a capped store in this process: correct for one replica, a
// laptop and tests. It is not a record: a deployment keeps its trail in S3.
type Memory struct {
	mu     sync.Mutex
	cap    int
	events []Event
	next   uint64
}

// NewMemory returns a store holding at most capacity events.
func NewMemory(capacity int) *Memory {
	if capacity <= 0 {
		capacity = 10000
	}
	return &Memory{cap: capacity}
}

// Append implements [Store].
func (m *Memory) Append(_ context.Context, e Event) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	e.ID = formatID(m.next)
	m.events = append(m.events, e)
	if over := len(m.events) - m.cap; over > 0 {
		m.events = slices.Delete(m.events, 0, over)
	}
	return e.ID, nil
}

// List implements [Store].
func (m *Memory) List(_ context.Context, q Query) ([]Event, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	limit := q.Limited()
	var out []Event
	for i := len(m.events) - 1; i >= 0; i-- {
		e := m.events[i]
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
	return out, "", nil
}

// formatID is a sortable decimal: zero-padded so string order is number
// order.
func formatID(n uint64) string {
	const width = 20
	s := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}
