// Package audit is what happened in access-roster, where an operator can
// read it.
//
// One trail for the whole service. The issuer records sign-ins, refusals,
// exchanges and revokes; the directory and the console record connects
// and disconnects; a component in another process — the GitHub controller
// first — reports what it did through the console's API, and is recorded
// with the identity it proved. Status elsewhere says what is true now;
// this says what changed and who caused it.
//
// Where events are kept is a contract, not a type in this package: the
// generated AuditSinkService. Recording holds its client and a writer
// implements its handler — S3 for a deployment (internal/s3audit), this
// process's memory without a bucket and in every test ([MemoryWriter]) —
// joined in process by internal/audit/sinkrpc and over a network by the
// generated client, so the writing can move to another process without
// anything that records changing.
//
// Each kept record is an Elastic Common Schema document, and every event is
// also one structured log line carrying the same fields under the same
// names ([EncodeRecord], [Classify]): whoever reads the bucket and whoever
// queries the logs are reading one vocabulary. The cluster's own audit log,
// CloudTrail, each directory's and GitHub's organisation audit log stay
// what they are, and are not duplicated here beyond the events this service
// itself causes.
//
// Recording never fails the thing being recorded. A sign-in that could not
// be written down still happened, and refusing it because the writer was
// slow would turn an audit outage into an access outage. There is one
// exception, and it is deliberate: a recovery sign-in bypasses the
// directory, so it is written durably before it succeeds and refused when it
// cannot be ([Log.RecordDurable]).
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/logsafe"
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
//
// The JSON tags are the record format access-roster 1.6.2 wrote to S3, one
// event per line. Records are ECS documents now ([EncodeRecord]); the tags
// stay because those older objects are under Object Lock for longer than
// any release lives, and [DecodeRecord] reads them with these.
type Event struct {
	// ID orders by time as a string; assigned when an event is recorded.
	ID string `json:"id,omitempty"`
	// At is when; filled when zero.
	At time.Time `json:"at"`
	// Source is the component: issuer, directory, console, or a
	// reporter's own name.
	Source string `json:"source"`
	// Kind is what happened, dotted: sign-in, token.exchanged,
	// workspace.connected, github.member.invite.
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
	// ClientAddress, UserAgent and RequestID are what the event keeps of
	// the request that caused it ([Request]); empty for what no request
	// caused.
	ClientAddress string `json:"client_address,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
}

// Recorder writes events down.
type Recorder interface {
	// Record never returns an error to the caller and never blocks it for
	// long.
	Record(ctx context.Context, e Event)
	// RecordDurable returns only once the event is persisted, or says why
	// it is not. It is for the one event that must not happen without its
	// record — a recovery sign-in — and the caller refuses what it records
	// when this fails.
	RecordDurable(ctx context.Context, e Event) error
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

// Matches reports whether an event is one a query asks for. Writers that
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

// Log records every event as a log line and then through a writer, and
// says so in the log when the writer refuses.
type Log struct {
	log    *slog.Logger
	sink   directoryrosterv1connect.AuditSinkServiceClient
	writer string
	now    func() time.Time
}

// NewLog returns a recorder writing through sink, naming this process as
// writer in the ids it assigns. A nil sink records to the log alone: a
// component with nowhere to keep a trail still leaves the lines.
func NewLog(log *slog.Logger, sink directoryrosterv1connect.AuditSinkServiceClient, writer string) *Log {
	if log == nil {
		log = slog.Default()
	}
	return &Log{log: log, sink: sink, writer: WriterName(writer), now: time.Now}
}

// storeTimeout bounds how long an ordinary write may hold up the caller.
const storeTimeout = 2 * time.Second

// durableTimeout bounds how long a durable write may. It is longer, because
// the caller is waiting for the record on purpose, and still bounded,
// because a recovery sign-in that hangs is as unhelpful as one refused.
const durableTimeout = 10 * time.Second

// Record implements [Recorder].
func (l *Log) Record(ctx context.Context, e Event) {
	if l == nil {
		return
	}
	e = l.stamp(e)
	l.line(ctx, e)
	if l.sink == nil {
		return
	}
	// Detached from the caller's cancellation — a request that ends as
	// soon as it has signed somebody in must not take its own record with
	// it — but bounded, so a slow writer costs the caller little.
	writing, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := l.write(writing, e, false); err != nil {
		l.log.WarnContext(ctx, "an audit event was logged and not stored",
			"event.id", e.ID, "event.action", e.Kind, "error", logsafe.Error(err))
	}
}

// RecordDurable implements [Recorder]: the log line first, as for every
// event, then a write that answers only once the event is persisted.
//
// A log with no writer answers nil. That is a component deliberately
// keeping no trail, and refusing recovery there would make recovery
// impossible by configuration; the service itself always has a writer.
func (l *Log) RecordDurable(ctx context.Context, e Event) error {
	if l == nil {
		return nil
	}
	e = l.stamp(e)
	l.line(ctx, e)
	if l.sink == nil {
		return nil
	}
	writing, cancel := context.WithTimeout(context.WithoutCancel(ctx), durableTimeout)
	defer cancel()
	if err := l.write(writing, e, true); err != nil {
		l.log.WarnContext(ctx, "an audit event was logged and could not be written durably",
			"event.id", e.ID, "event.action", e.Kind, "error", logsafe.Error(err))
		return fmt.Errorf("audit: %s could not be written durably: %w", e.Kind, err)
	}
	return nil
}

// stamp gives an event what every record carries: a time, an outcome, and
// an id — assigned HERE, before the log line, so that the line and the
// kept record share it and one finds the other.
func (l *Log) stamp(e Event) Event {
	if e.Outcome == "" {
		e.Outcome = OutcomeOK
	}
	return Assign(e, l.writer, l.now())
}

func (l *Log) line(ctx context.Context, e Event) {
	l.log.InfoContext(ctx, "audit", append([]any{"audit", true}, LogAttrs(e)...)...)
}

func (l *Log) write(ctx context.Context, e Event, durable bool) error {
	_, err := l.sink.WriteAuditEvents(ctx, connect.NewRequest(&directoryrosterv1.WriteAuditEventsRequest{
		Events: []*directoryrosterv1.AuditEvent{ToProto(e)}, Durable: durable,
	}))
	return err
}

// Nop records nothing. It exists so a component with no recorder need not
// check.
type Nop struct{}

// Record implements [Recorder].
func (Nop) Record(context.Context, Event) {}

// RecordDurable implements [Recorder]. A component with no recorder keeps
// no trail, so there is nothing to wait for.
func (Nop) RecordDurable(context.Context, Event) error { return nil }
