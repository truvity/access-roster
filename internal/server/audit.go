package server

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/logsafe"
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
	c.recorder().Record(ctx, consoleEvent(ctx, e))
}

// recordDurable writes it down and answers only once it is persisted. It
// is for the recovery sign-in, which does not happen without its record.
func (c *Console) recordDurable(ctx context.Context, e audit.Event) error {
	return c.recorder().RecordDurable(ctx, consoleEvent(ctx, e))
}

// consoleEvent fills what the console knows of every event it records:
// that it is the source unless told otherwise, the identity signed in, and
// what the event keeps of the request, which [AuditRequests] put in the
// context.
func consoleEvent(ctx context.Context, e audit.Event) audit.Event {
	if e.Source == "" {
		e.Source = audit.SourceConsole
	}
	if e.Actor == "" {
		if id, ok := IdentityFrom(ctx); ok {
			e.Actor = id.Who()
		}
	}
	if request, ok := audit.RequestFrom(ctx); ok {
		request.Apply(&e)
	}
	return e
}

// ListAuditEvents implements the audit page: the writer's own listing,
// passed through, behind the operator check the writer does not make.
func (c *Console) ListAuditEvents(
	ctx context.Context, req *connect.Request[directoryrosterv1.ListAuditEventsRequest],
) (*connect.Response[directoryrosterv1.ListAuditEventsResponse], error) {
	if _, err := requireRole(ctx, access.RoleOperator); err != nil {
		return nil, err
	}
	if c.deps.AuditSink == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("this deployment keeps no audit trail; its events are in the log alone"))
	}
	stored, err := c.deps.AuditSink.ListStoredAuditEvents(ctx,
		connect.NewRequest(&directoryrosterv1.ListStoredAuditEventsRequest{Query: req.Msg}))
	if err != nil {
		// The writer's own words, and its code only where the caller can
		// act on it: a cursor it refused. Anything else is the trail being
		// unreadable just now.
		code, cause := connect.CodeUnavailable, err
		var refused *connect.Error
		if errors.As(err, &refused) {
			cause = errors.New(refused.Message())
			if refused.Code() == connect.CodeInvalidArgument {
				code = connect.CodeInvalidArgument
			}
		}
		return nil, connect.NewError(code, cause)
	}
	return connect.NewResponse(&directoryrosterv1.ListAuditEventsResponse{
		Events: stored.Msg.GetEvents(), Cursor: stored.Msg.GetCursor(),
	}), nil
}

// RecordAuditEvents implements reporting by a component.
//
// Three things are not the caller's to decide, and each is overwritten or
// refused rather than trusted: WHO reported (the verified caller), WHEN it
// was recorded (on arrival), and that the source is not one of this
// service's own — a reporter that could write `issuer` could forge a
// sign-in.
//
// What an event keeps of a request IS the reporter's to say, and is never
// taken from the report's own request: the reporter's connection is not
// the request that caused what it reports, and a reporter acting for a
// person may carry that person's. Recorded through the recorder directly,
// not [Console.record], for exactly that reason.
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
	// The request fields have bounds of their own, the same ones a request
	// the service reads itself is cut to. Over them is refused rather than
	// cut: a reporter sending more is a bug to see, not a value to trim.
	for _, bounded := range []struct {
		name, value string
		limit       int
	}{
		{"client_address", in.GetClientAddress(), audit.MaxClientAddress},
		{"user_agent", in.GetUserAgent(), audit.MaxUserAgent},
		{"request_id", in.GetRequestId(), audit.MaxRequestID},
	} {
		if len(bounded.value) > bounded.limit {
			return audit.Event{}, fmt.Errorf("%s is longer than %d bytes", bounded.name, bounded.limit)
		}
	}
	e.ClientAddress = logsafe.Value(in.GetClientAddress())
	e.UserAgent = logsafe.Value(in.GetUserAgent())
	e.RequestID = logsafe.Value(in.GetRequestId())
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
