package audit

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
)

// DefaultMemoryEvents caps the in-memory writer.
const DefaultMemoryEvents = 50000

// MemoryWriter keeps the trail in this process: an AuditSinkService
// handler, and the one writer that checks audit works.
//
// Two uses, one implementation. A deployment without a bucket keeps its
// trail here — capped, one replica's own, gone on restart, and warned about
// at start as NOT a record — which is right for a laptop and a
// demonstration. And every test that asserts what was recorded reads it
// back from here, including whether each write asked to be durable. One
// writer for both, because a second fake of the thing whose whole job is
// to be believed would be another implementation to keep true.
//
// A test can make it refuse: every write, or only durable ones. That is how
// the fail-open rule and its one fail-closed exception are tested.
type MemoryWriter struct {
	mu          sync.Mutex
	capacity    int
	written     []Written // in the order written, oldest first
	failAll     error
	failDurable error
	now         func() time.Time
}

// Written is one event as it was written, and whether the write that
// carried it asked for it to be durable.
type Written struct {
	Event   Event
	Durable bool
}

// memoryWriterName names this writer in the ids it assigns to events that
// arrive without one.
const memoryWriterName = "memory"

// NewMemoryWriter returns a writer holding at most capacity events.
func NewMemoryWriter(capacity int) *MemoryWriter {
	if capacity <= 0 {
		capacity = 10000
	}
	return &MemoryWriter{capacity: capacity, now: time.Now}
}

// WriteAuditEvents implements the AuditSinkService handler. Memory is as
// durable as this writer gets, so a durable write and an ordinary one keep
// an event the same way; each remembers which it was.
func (m *MemoryWriter) WriteAuditEvents(
	_ context.Context, req *connect.Request[directoryrosterv1.WriteAuditEventsRequest],
) (*connect.Response[directoryrosterv1.WriteAuditEventsResponse], error) {
	durable := req.Msg.GetDurable()
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case m.failAll != nil:
		return nil, connect.NewError(connect.CodeUnavailable, m.failAll)
	case durable && m.failDurable != nil:
		return nil, connect.NewError(connect.CodeUnavailable, m.failDurable)
	}
	for _, in := range req.Msg.GetEvents() {
		m.written = append(m.written, Written{Event: Assign(FromProto(in), memoryWriterName, m.now()), Durable: durable})
	}
	if over := len(m.written) - m.capacity; over > 0 {
		m.written = slices.Delete(m.written, 0, over)
	}
	return connect.NewResponse(&directoryrosterv1.WriteAuditEventsResponse{
		Written: int32(len(req.Msg.GetEvents())), //nolint:gosec // one request's events
	}), nil
}

// ListStoredAuditEvents implements the AuditSinkService handler: newest
// first by id, filtered, paged from a cursor.
//
// Sorted at every listing rather than kept sorted, because events are
// written in the order they were recorded, not quite the order their ids
// were assigned: two requests recording at once may write in either order,
// and a cursor over the write order would skip one of them.
func (m *MemoryWriter) ListStoredAuditEvents(
	_ context.Context, req *connect.Request[directoryrosterv1.ListStoredAuditEventsRequest],
) (*connect.Response[directoryrosterv1.ListStoredAuditEventsResponse], error) {
	q := QueryFromProto(req.Msg.GetQuery())
	events := m.Events()
	slices.SortStableFunc(events, func(a, b Event) int { return strings.Compare(b.ID, a.ID) })
	limit := q.Limited()
	out := &directoryrosterv1.ListStoredAuditEventsResponse{}
	for i := range events {
		if q.Cursor != "" && events[i].ID >= q.Cursor {
			continue
		}
		if !q.Matches(events[i]) {
			continue
		}
		if len(out.Events) == limit {
			out.Cursor = out.Events[len(out.Events)-1].GetId()
			break
		}
		out.Events = append(out.Events, ToProto(events[i]))
	}
	return connect.NewResponse(out), nil
}

// FailWrites makes every write refuse with err; nil writes again.
func (m *MemoryWriter) FailWrites(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failAll = err
}

// FailDurableWrites makes only durable writes refuse with err, as S3 does
// to a put while the queue still accepts; nil writes them again.
func (m *MemoryWriter) FailDurableWrites(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failDurable = err
}

// Written is every event kept, in the order written, with whether it was
// written durably.
func (m *MemoryWriter) Written() []Written {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.written)
}

// Events is every event kept, in the order written.
func (m *MemoryWriter) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, 0, len(m.written))
	for i := range m.written {
		out = append(out, m.written[i].Event)
	}
	return out
}

// Durable is every event kept by a durable write, in the order written.
func (m *MemoryWriter) Durable() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for i := range m.written {
		if m.written[i].Durable {
			out = append(out, m.written[i].Event)
		}
	}
	return out
}

// Kinds is the kind of every event kept, in the order written.
func (m *MemoryWriter) Kinds() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.written))
	for i := range m.written {
		out = append(out, m.written[i].Event.Kind)
	}
	return out
}
