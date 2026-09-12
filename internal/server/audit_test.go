package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/policy"
)

func auditConsole(t *testing.T) (*Console, *audit.Memory) {
	t.Helper()
	store := audit.NewMemory(100)
	console := githubConsole(t, nil)
	console.deps.AuditStore = store
	console.deps.Audit = audit.NewLog(slog.New(slog.NewTextHandler(io.Discard, nil)), store)
	return console, store
}

func reporter(groups ...string) context.Context {
	return WithIdentity(context.Background(), access.Identity{
		Subject: "kernel:k8s:access-issuer:github-roster",
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
	events, _, _ := store.List(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("stored = %+v", events)
	}
	if events[0].Reporter != "kernel:k8s:access-issuer:github-roster" || events[0].At.IsZero() || events[0].Outcome != audit.OutcomeOK {
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
	if events, _, _ = store.List(context.Background(), audit.Query{}); len(events) != 1 {
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
	console, store := auditConsole(t)
	_, _ = store.Append(context.Background(), audit.Event{Source: "issuer", Kind: "sign-in", Subject: "ada@north.example"})
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
