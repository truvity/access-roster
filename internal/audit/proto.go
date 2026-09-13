package audit

import (
	"maps"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
)

// ToProto is an event as the wire carries it, every field of it: what a
// writer keeps is what was recorded, including the id and time it was
// recorded with.
func ToProto(e Event) *directoryrosterv1.AuditEvent {
	out := &directoryrosterv1.AuditEvent{
		Id:            e.ID,
		Source:        e.Source,
		Kind:          e.Kind,
		Actor:         e.Actor,
		Reporter:      e.Reporter,
		Subject:       e.Subject,
		Target:        e.Target,
		Outcome:       e.Outcome,
		Reason:        e.Reason,
		ClientAddress: e.ClientAddress,
		UserAgent:     e.UserAgent,
		RequestId:     e.RequestID,
	}
	if !e.At.IsZero() {
		out.At = timestamppb.New(e.At)
	}
	if len(e.Attributes) > 0 {
		out.Attributes = maps.Clone(e.Attributes)
	}
	return out
}

// FromProto is the event a wire message carries, as it carries it. Nothing
// is checked or refused here: that is the job of whatever accepts a
// message from somebody it does not trust, which a writer is not.
func FromProto(in *directoryrosterv1.AuditEvent) Event {
	e := Event{
		ID:            in.GetId(),
		Source:        in.GetSource(),
		Kind:          in.GetKind(),
		Actor:         in.GetActor(),
		Reporter:      in.GetReporter(),
		Subject:       in.GetSubject(),
		Target:        in.GetTarget(),
		Outcome:       in.GetOutcome(),
		Reason:        in.GetReason(),
		ClientAddress: in.GetClientAddress(),
		UserAgent:     in.GetUserAgent(),
		RequestID:     in.GetRequestId(),
	}
	if in.GetAt() != nil {
		e.At = in.GetAt().AsTime().UTC()
	}
	if len(in.GetAttributes()) > 0 {
		e.Attributes = maps.Clone(in.GetAttributes())
	}
	return e
}

// QueryFromProto is the query a listing request asks.
func QueryFromProto(in *directoryrosterv1.ListAuditEventsRequest) Query {
	q := Query{
		Source:  in.GetSource(),
		Kind:    in.GetKind(),
		Subject: in.GetSubject(),
		Target:  in.GetTarget(),
		Limit:   int(in.GetLimit()),
		Cursor:  in.GetCursor(),
	}
	if in.GetSince() != nil {
		q.Since = in.GetSince().AsTime()
	}
	return q
}

// Proto is the listing request a query is.
func (q Query) Proto() *directoryrosterv1.ListAuditEventsRequest {
	out := &directoryrosterv1.ListAuditEventsRequest{
		Source: q.Source, Kind: q.Kind, Subject: q.Subject, Target: q.Target,
		Limit: int32(min(q.Limit, MaxLimit)), Cursor: q.Cursor, //nolint:gosec // bounded by MaxLimit
	}
	if !q.Since.IsZero() {
		out.Since = timestamppb.New(q.Since)
	}
	return out
}

// EventsToProto is a page of events on the wire.
func EventsToProto(events []Event) []*directoryrosterv1.AuditEvent {
	out := make([]*directoryrosterv1.AuditEvent, 0, len(events))
	for i := range events {
		out = append(out, ToProto(events[i]))
	}
	return out
}

// EventsFromProto is a page of events off the wire.
func EventsFromProto(in []*directoryrosterv1.AuditEvent) []Event {
	out := make([]Event, 0, len(in))
	for _, e := range in {
		out = append(out, FromProto(e))
	}
	return out
}

// Assign fills what a writer assigns an event that arrives without it:
// the time, in UTC, and an id. An event that has them keeps them, which is
// what lets a log line and the kept record share one id.
func Assign(e Event, writer string, now time.Time) Event {
	if e.At.IsZero() {
		e.At = now
	}
	e.At = e.At.UTC()
	if e.ID == "" {
		e.ID = NewID(e.At, writer)
	}
	return e
}
