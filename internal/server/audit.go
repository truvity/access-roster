package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/policy"
)

// The bounds on what one report may carry. A reporter is a workload the
// policy trusts to say what it did, not to fill the stream: a report
// larger than this is a bug in the reporter, and refusing it whole is
// what makes the bug visible.
const (
	maxReportedEvents   = 200
	maxReportedField    = 512
	maxReportedAttrs    = 20
	maxReportedAttrSize = 256
)

// recorder is the console's own, or one that records nothing — including
// for a console server assembled without a console, which a test does and
// which recording must never be the thing to crash.
func (c *Console) recorder() audit.Recorder {
	if c != nil && c.deps.Audit != nil {
		return c.deps.Audit
	}
	return audit.Nop{}
}

// record writes down something an identity did through the console.
func (c *Console) record(ctx context.Context, e audit.Event) {
	if e.Source == "" {
		e.Source = audit.SourceConsole
	}
	if e.Actor == "" {
		if id, ok := IdentityFrom(ctx); ok {
			e.Actor = id.Who()
		}
	}
	c.recorder().Record(ctx, e)
}

// ListAuditEvents implements the audit page.
func (c *Console) ListAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListAuditEventsRequest],
) (*connect.Response[directoryrosterv1.ListAuditEventsResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if c.deps.AuditStore == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no audit stream; its events are in the log alone"))
	}
	q := audit.Query{
		Source:  req.Msg.GetSource(),
		Kind:    req.Msg.GetKind(),
		Subject: req.Msg.GetSubject(),
		Target:  req.Msg.GetTarget(),
		Limit:   int(req.Msg.GetLimit()),
		Cursor:  req.Msg.GetCursor(),
	}
	if since := req.Msg.GetSince(); since != nil {
		q.Since = since.AsTime()
	}
	events, cursor, err := c.deps.AuditStore.List(ctx, q)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	out := &directoryrosterv1.ListAuditEventsResponse{Cursor: cursor, Events: make([]*directoryrosterv1.AuditEvent, 0, len(events))}
	for i := range events {
		out.Events = append(out.Events, auditEventProto(&events[i]))
	}
	return connect.NewResponse(out), nil
}

// RecordAuditEvents implements reporting by a component.
//
// Three things are not the caller's to decide, and each is overwritten or
// refused rather than trusted: WHO reported (the verified caller), WHEN it
// was recorded (on arrival), and that the source is not one of this
// service's own — a reporter that could write `issuer` could forge a
// sign-in.
func (c *Console) RecordAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.RecordAuditEventsRequest],
) (*connect.Response[directoryrosterv1.RecordAuditEventsResponse], error) {
	id, ok := IdentityFrom(ctx)
	switch {
	case !ok:
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("sign in first"))
	// A workload, never a person: a person with the group would be able
	// to write history under a component's name from a browser.
	case id.Source != access.SourceWorkload || !slices.Contains(id.Groups, policy.GroupReporters):
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("only a workload in %s may report audit events", policy.GroupReporters))
	case len(req.Msg.GetEvents()) > maxReportedEvents:
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("a report carries at most %d events", maxReportedEvents))
	}

	events := make([]audit.Event, 0, len(req.Msg.GetEvents()))
	for i, reported := range req.Msg.GetEvents() {
		e, err := reportedEvent(reported)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("event %d: %w", i, err))
		}
		e.Reporter = id.Subject
		events = append(events, e)
	}
	// Refused whole before any is recorded, so a report is either in the
	// stream or not.
	for i := range events {
		c.recorder().Record(ctx, events[i])
	}
	return connect.NewResponse(&directoryrosterv1.RecordAuditEventsResponse{Recorded: int32(len(events))}), nil //nolint:gosec // bounded above
}

// reportedEvent reads one reported event and refuses what a reporter may
// not say.
func reportedEvent(in *directoryrosterv1.AuditEvent) (audit.Event, error) {
	e := audit.Event{
		Source:  strings.TrimSpace(in.GetSource()),
		Kind:    strings.TrimSpace(in.GetKind()),
		Actor:   in.GetActor(),
		Subject: in.GetSubject(),
		Target:  in.GetTarget(),
		Outcome: in.GetOutcome(),
		Reason:  in.GetReason(),
	}
	switch {
	case e.Source == "" || e.Kind == "":
		return audit.Event{}, errors.New("a source and a kind are required")
	case audit.Reserved(e.Source):
		return audit.Event{}, fmt.Errorf("%q is a source only this service records", e.Source)
	case in.GetReporter() != "":
		return audit.Event{}, errors.New("reporter is stamped by the service, never supplied")
	}
	switch e.Outcome {
	case "", audit.OutcomeOK, audit.OutcomeRefused, audit.OutcomeFailed, audit.OutcomeHeld:
	default:
		return audit.Event{}, fmt.Errorf("outcome %q is not one of ok, refused, failed, held", e.Outcome)
	}
	for _, value := range []string{e.Source, e.Kind, e.Actor, e.Subject, e.Target, e.Reason} {
		if len(value) > maxReportedField {
			return audit.Event{}, fmt.Errorf("a field is longer than %d bytes", maxReportedField)
		}
	}
	if len(in.GetAttributes()) > maxReportedAttrs {
		return audit.Event{}, fmt.Errorf("at most %d attributes", maxReportedAttrs)
	}
	for key, value := range in.GetAttributes() {
		if len(key)+len(value) > maxReportedAttrSize {
			return audit.Event{}, fmt.Errorf("attribute %q is longer than %d bytes", key, maxReportedAttrSize)
		}
	}
	if len(in.GetAttributes()) > 0 {
		e.Attributes = maps.Clone(in.GetAttributes())
	}
	return e, nil
}

func auditEventProto(e *audit.Event) *directoryrosterv1.AuditEvent {
	return &directoryrosterv1.AuditEvent{
		Id:         e.ID,
		At:         timestamppb.New(e.At),
		Source:     e.Source,
		Kind:       e.Kind,
		Actor:      e.Actor,
		Reporter:   e.Reporter,
		Subject:    e.Subject,
		Target:     e.Target,
		Outcome:    e.Outcome,
		Reason:     e.Reason,
		Attributes: e.Attributes,
	}
}
