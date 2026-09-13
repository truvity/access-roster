package server

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/sinkrpc"
	"github.com/truvity/access-roster/policy"
)

// auditConsole is a console recording into the in-memory writer, which is
// what the test reads back.
func auditConsole(t *testing.T) (*Console, *audit.MemoryWriter) {
	t.Helper()
	writer := audit.NewMemoryWriter(100)
	sink := sinkrpc.InProcess(writer)
	console := githubConsole(t, nil)
	console.deps.AuditSink = sink
	console.deps.Audit = audit.NewLog(slog.New(slog.DiscardHandler), sink, "test")
	return console, writer
}

func reporter(groups ...string) context.Context {
	return WithIdentity(context.Background(), access.Identity{
		Subject: "cluster:k8s:access-issuer:github-roster",
		Source:  access.SourceWorkload,
		Groups:  groups,
	})
}

func report(ctx context.Context, console *Console, events ...*directoryrosterv1.AuditEvent) error {
	_, err := console.RecordAuditEvents(ctx, connect.NewRequest(&directoryrosterv1.RecordAuditEventsRequest{Events: events}))
	return err
}

// A component reports what it did, and three things are not its to say:
// who reported, when it was recorded, and that it is the issuer.
func TestAReportIsStampedWithTheVerifiedReporter(t *testing.T) {
	t.Parallel()
	console, store := auditConsole(t)

	err := report(reporter(policy.GroupReporters), console, &directoryrosterv1.AuditEvent{
		Source: "github-roster", Kind: "github.member.invited", Actor: "system",
		Subject: "dana@south.example", Target: "example-org/team-engineering",
	})
	if err != nil {
		t.Fatalf("RecordAuditEvents: %v", err)
	}
	events := store.Events()
	if len(events) != 1 {
		t.Fatalf("stored = %+v", events)
	}
	if events[0].Reporter != "cluster:k8s:access-issuer:github-roster" || events[0].At.IsZero() || events[0].Outcome != audit.OutcomeOK {
		t.Errorf("event = %+v, want the verified reporter, an arrival time and ok", events[0])
	}

	for name, forged := range map[string]*directoryrosterv1.AuditEvent{
		"as the issuer":       {Source: "issuer", Kind: "sign-in", Subject: "ada@north.example"},
		"as the console":      {Source: "Console", Kind: "workspace.connected"},
		"naming its reporter": {Source: "github-roster", Kind: "k", Reporter: "somebody-trusted"},
		"with no kind":        {Source: "github-roster"},
		"an invented outcome": {Source: "github-roster", Kind: "k", Outcome: "approved"},
	} {
		if err = report(reporter(policy.GroupReporters), console, forged); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("a report %s = %v, want invalid argument", name, err)
		}
	}
	// Refused whole: one bad event in a batch records none of it.
	if err = report(reporter(policy.GroupReporters), console,
		&directoryrosterv1.AuditEvent{Source: "github-roster", Kind: "fine"},
		&directoryrosterv1.AuditEvent{Source: "issuer", Kind: "sign-in"},
	); err == nil {
		t.Error("a batch with a forged event was accepted")
	}
	if events = store.Events(); len(events) != 1 {
		t.Errorf("a refused batch left %d events, want only the first report's one", len(events))
	}
}

// Only a workload the policy names may report — not a workload outside
// the group, and not a person inside it.
func TestOnlyAWorkloadInTheReportersGroupMayReport(t *testing.T) {
	t.Parallel()
	console, _ := auditConsole(t)
	event := &directoryrosterv1.AuditEvent{Source: "github-roster", Kind: "k"}

	if err := report(reporter( /* no group */ ), console, event); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a workload outside the group = %v, want permission denied", err)
	}
	person := WithIdentity(context.Background(), access.Identity{
		Email: "ada@north.example", Source: access.SourceOIDC, Role: access.RoleOperator, Groups: []string{policy.GroupReporters},
	})
	if err := report(person, console, event); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a person in the group = %v, want permission denied", err)
	}
	if err := report(context.Background(), console, event); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("nobody = %v, want unauthenticated", err)
	}
}

// The stream names every sign-in, so reading it is an operator's.
func TestReadingTheAuditStreamNeedsAnOperator(t *testing.T) {
	t.Parallel()
	console, _ := auditConsole(t)
	console.deps.Audit.Record(context.Background(), audit.Event{Source: "issuer", Kind: "sign-in", Subject: "ada@north.example"})
	list := func(role access.Role) (*directoryrosterv1.ListAuditEventsResponse, error) {
		response, err := console.ListAuditEvents(WithIdentity(context.Background(), access.Identity{Role: role}),
			connect.NewRequest(&directoryrosterv1.ListAuditEventsRequest{Kind: "sign-in"}))
		if err != nil {
			return nil, err
		}
		return response.Msg, nil
	}
	if _, err := list(access.RoleViewer); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer = %v, want permission denied", err)
	}
	got, err := list(access.RoleOperator)
	if err != nil || len(got.GetEvents()) != 1 || got.GetEvents()[0].GetSubject() != "ada@north.example" {
		t.Errorf("an operator = %+v, %v", got, err)
	}
}

// What an event keeps of a request is the reporter's to say — a reporter
// acting for a person may carry that person's — and never the report's own
// connection, which caused none of it. It is bounded like any field, and
// a report over the bounds is refused whole.
func TestAReportCarriesItsOwnRequestFields(t *testing.T) {
	t.Parallel()
	console, store := auditConsole(t)
	// The reporter's own connection, as the server in front reads it.
	ctx := audit.WithRequest(reporter(policy.GroupReporters), audit.Request{ClientAddress: "10.0.0.9", UserAgent: "connect-go/1.20", RequestID: "reporter-req"})

	err := report(ctx, console,
		&directoryrosterv1.AuditEvent{Source: "github-roster", Kind: "github.link.created", Subject: "dana@south.example",
			ClientAddress: "203.0.113.7", UserAgent: "Mozilla/5.0\nforged=true", RequestId: "person-req"},
		&directoryrosterv1.AuditEvent{Source: "github-roster", Kind: "github.member.add", Actor: "system"},
	)
	if err != nil {
		t.Fatalf("RecordAuditEvents: %v", err)
	}
	events := store.Events()
	if len(events) != 2 {
		t.Fatalf("stored %v", store.Kinds())
	}
	if got := events[0]; got.ClientAddress != "203.0.113.7" || got.UserAgent != "Mozilla/5.0forged=true" || got.RequestID != "person-req" {
		t.Errorf("the reported request = %q %q %q, want the report's own, with no line break", got.ClientAddress, got.UserAgent, got.RequestID)
	}
	if got := events[1]; got.ClientAddress != "" || got.UserAgent != "" || got.RequestID != "" {
		t.Errorf("an event reported with no request took the reporter's connection: %q %q %q", got.ClientAddress, got.UserAgent, got.RequestID)
	}
	if events[0].Reporter != "cluster:k8s:access-issuer:github-roster" {
		t.Errorf("reporter = %q, want the verified caller still", events[0].Reporter)
	}

	for name, over := range map[string]*directoryrosterv1.AuditEvent{
		"a long address":    {Source: "github-roster", Kind: "k", ClientAddress: strings.Repeat("1", audit.MaxClientAddress+1)},
		"a long user agent": {Source: "github-roster", Kind: "k", UserAgent: strings.Repeat("a", audit.MaxUserAgent+1)},
		"a long request id": {Source: "github-roster", Kind: "k", RequestId: strings.Repeat("r", audit.MaxRequestID+1)},
	} {
		err = report(ctx, console, &directoryrosterv1.AuditEvent{Source: "github-roster", Kind: "fine"}, over)
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("a report with %s = %v, want invalid argument", name, err)
		}
	}
	if n := len(store.Events()); n != 2 {
		t.Errorf("refused reports left %d events, want the first report's two", n)
	}
}
