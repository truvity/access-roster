package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/sinkrpc"
)

// recorder is a log over an in-memory writer, with the lines it wrote.
func recorder(t *testing.T) (*audit.Log, *audit.MemoryWriter, *bytes.Buffer) {
	t.Helper()
	var logged bytes.Buffer
	writer := audit.NewMemoryWriter(100)
	return audit.NewLog(slog.New(slog.NewJSONHandler(&logged, nil)), sinkrpc.InProcess(writer), "test-pod"), writer, &logged
}

// lines are the log's JSON lines, decoded.
func lines(t *testing.T, logged *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logged.String()), "\n") {
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("a log line is not JSON: %q", line)
		}
		out = append(out, fields)
	}
	return out
}

// Every event is a log line before it is anything else, and a writer that
// refuses costs the trail an entry, never the caller its sign-in and never
// the record its line.
func TestAnEventIsLoggedEvenWhenTheWriterRefuses(t *testing.T) {
	t.Parallel()
	log, writer, logged := recorder(t)
	writer.FailWrites(errors.New("the writer is down"))

	log.Record(context.Background(), audit.Event{
		Source: audit.SourceIssuer, Kind: "sign-in", Actor: "ada@north.example", Subject: "ada@north.example", Target: "argocd",
		Attributes: map[string]string{"how": "google"},
	})

	out := logged.String()
	for _, want := range []string{
		`"audit":true`, `"event.action":"sign-in"`, `"event.outcome":"success"`, `"access_roster.attributes.how":"google"`, "not stored",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %s:\n%s", want, out)
		}
	}
	if len(writer.Events()) != 0 {
		t.Errorf("a refusing writer kept %v", writer.Kinds())
	}
}

// The log line carries the record's ECS fields by their dotted names, flat,
// and exactly those: nothing of the old `attr.` spelling, no second
// timestamp, and the id the kept record has, so one finds the other.
func TestTheLogLineIsTheRecordsECSFields(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		event audit.Event
		want  map[string]any
	}{
		"a refused sign-in": {
			event: audit.Event{
				Source: audit.SourceConsole, Kind: "sign-in.refused", Actor: "ada@north.example", Subject: "ada@north.example",
				Target: "console", Outcome: audit.OutcomeRefused, Reason: "the directory says this account is not live",
				ClientAddress: "203.0.113.7", UserAgent: "Mozilla/5.0", RequestID: "req-1",
			},
			want: map[string]any{
				"event.kind": "event", "event.dataset": "access_roster.audit", "event.provider": "console",
				"event.action": "sign-in.refused", "event.category": []any{"authentication"}, "event.type": []any{"denied"},
				"event.outcome": "failure", "event.reason": "the directory says this account is not live",
				"user.name": "ada@north.example", "user.target.name": "ada@north.example",
				"service.target.name": "console", "access_roster.target": "console", "access_roster.outcome": "refused",
				"client.address": "203.0.113.7", "user_agent.original": "Mozilla/5.0", "http.request.id": "req-1",
			},
		},
		"a reported invitation": {
			event: audit.Event{
				Source: "github-roster", Kind: "github.member.invite", Actor: audit.ActorSystem,
				Reporter: "cluster:k8s:access-issuer:github-roster", Subject: "dana@south.example", Target: "example-org/team-platform",
				Attributes: map[string]string{"login": "dana", "role": "member"},
			},
			want: map[string]any{
				"event.kind": "event", "event.dataset": "access_roster.audit", "event.provider": "github-roster",
				"event.action": "github.member.invite", "event.category": []any{"iam"}, "event.type": []any{"user", "creation"},
				"event.outcome": "success", "user.name": "system", "user.target.name": "dana@south.example",
				"observer.name":       "cluster:k8s:access-issuer:github-roster",
				"service.target.name": "example-org/team-platform", "access_roster.target": "example-org/team-platform", "access_roster.outcome": "ok",
				"access_roster.attributes.login": "dana", "access_roster.attributes.role": "member",
			},
		},
		"a held action": {
			event: audit.Event{
				Source: "github-roster", Kind: "github.action.held", Actor: audit.ActorSystem, Reporter: "cluster:k8s:access-issuer:github-roster",
				Subject: "erin@south.example", Target: "example-org", Outcome: audit.OutcomeHeld, Reason: "the directory cannot vouch",
			},
			want: map[string]any{
				"event.kind": "event", "event.dataset": "access_roster.audit", "event.provider": "github-roster",
				"event.action": "github.action.held", "event.category": []any{"iam"}, "event.type": []any{"info"},
				"event.outcome": "unknown", "event.reason": "the directory cannot vouch", "user.name": "system",
				"user.target.name": "erin@south.example", "observer.name": "cluster:k8s:access-issuer:github-roster",
				"service.target.name": "example-org", "access_roster.target": "example-org", "access_roster.outcome": "held",
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log, writer, logged := recorder(t)
			log.Record(context.Background(), tc.event)

			kept := writer.Events()
			if len(kept) != 1 {
				t.Fatalf("kept %v, want the one event", writer.Kinds())
			}
			line := lines(t, logged)[0]
			if line["audit"] != true || line["msg"] != "audit" {
				t.Errorf("audit = %v, msg = %v; want the line selectable as ever", line["audit"], line["msg"])
			}
			if line["event.id"] != kept[0].ID || kept[0].ID == "" {
				t.Errorf("event.id = %v, the kept record's id = %q; want one id shared", line["event.id"], kept[0].ID)
			}
			if line["ecs.version"] != audit.ECSVersion {
				t.Errorf("ecs.version = %v", line["ecs.version"])
			}
			for key := range line {
				if strings.HasPrefix(key, "attr.") || key == "kind" || key == "source" || key == "@timestamp" {
					t.Errorf("the line still carries %q", key)
				}
			}
			got := maps.Clone(line)
			for _, own := range []string{"time", "level", "msg", "audit", "event.id", "ecs.version"} {
				delete(got, own)
			}
			if !equalJSON(got, tc.want) {
				t.Errorf("line fields =\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}

func equalJSON(a, b map[string]any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

// A durable record is written as such, after its line; refused, it says so
// to the caller — the one caller that refuses what it records on that —
// and the line is there regardless.
func TestADurableRecordReportsItsFailure(t *testing.T) {
	t.Parallel()
	log, writer, logged := recorder(t)
	event := audit.Event{Source: audit.SourceConsole, Kind: "recovery.sign-in", Actor: "k8s:ops:recovery", Subject: "k8s:ops:recovery"}

	if err := log.RecordDurable(context.Background(), event); err != nil {
		t.Fatalf("RecordDurable: %v", err)
	}
	if written := writer.Written(); len(written) != 1 || !written[0].Durable {
		t.Errorf("written = %+v, want one durable write", written)
	}

	writer.FailDurableWrites(errors.New("S3 is down"))
	if err := log.RecordDurable(context.Background(), event); err == nil {
		t.Error("a refused durable write reported success")
	}
	log.Record(context.Background(), event)
	if kinds := writer.Kinds(); len(kinds) != 2 {
		t.Errorf("kept %v, want the first durable event and the ordinary one written while durable writes fail", kinds)
	}
	records, warnings := 0, 0
	for _, line := range lines(t, logged) {
		switch {
		case line["audit"] == true:
			records++
		case line["msg"] == "an audit event was logged and could not be written durably":
			warnings++
		}
	}
	if records != 3 || warnings != 1 {
		t.Errorf("%d audit lines and %d warnings, want all three attempts logged and the refusal warned about once", records, warnings)
	}
}

// A listing is newest first, filtered, and pages by cursor without
// repeating or skipping an event — including events written out of the
// order their ids were assigned, which two requests recording at once do.
func TestTheMemoryWriterListsNewestFirstAndPagesWithoutGaps(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	writer := audit.NewMemoryWriter(100)
	client := sinkrpc.InProcess(writer)
	log := audit.NewLog(slog.New(slog.DiscardHandler), client, "pod")
	base := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	var events []audit.Event
	for i := range 7 {
		kind := "sign-in"
		if i%2 == 1 {
			kind = "token.exchanged"
		}
		events = append(events, audit.Event{ID: audit.NewID(base.Add(time.Duration(i)*time.Minute), "pod"),
			At: base.Add(time.Duration(i) * time.Minute), Source: audit.SourceIssuer, Kind: kind})
	}
	// Written out of order.
	for _, i := range []int{1, 0, 3, 2, 6, 4, 5} {
		log.Record(ctx, events[i])
	}

	page, cursor := listed(t, client, audit.Query{Kind: "sign-in", Limit: 2})
	if len(page) != 2 || cursor == "" {
		t.Fatalf("first page = %d events, cursor %q", len(page), cursor)
	}
	if !page[0].At.After(page[1].At) {
		t.Error("not newest first")
	}
	rest, cursor := listed(t, client, audit.Query{Kind: "sign-in", Limit: 2, Cursor: cursor})
	if len(rest) != 2 || cursor != "" {
		t.Errorf("second page = %d events, cursor %q; want the last two and the end", len(rest), cursor)
	}
	if rest[0].ID == page[1].ID {
		t.Error("the second page repeats the first page's last event")
	}

	// Capped: the oldest written go first.
	small := audit.NewMemoryWriter(3)
	smallLog := audit.NewLog(slog.New(slog.DiscardHandler), sinkrpc.InProcess(small), "pod")
	for i := range 5 {
		smallLog.Record(ctx, audit.Event{Kind: "k", Subject: string(rune('a' + i)), At: base.Add(time.Duration(i) * time.Second)})
	}
	all, _ := listed(t, sinkrpc.InProcess(small), audit.Query{})
	if subjects := subjectsOf(all); !slices.Equal(subjects, []string{"e", "d", "c"}) {
		t.Errorf("a capped writer kept %v, want the newest three", subjects)
	}
}

func subjectsOf(events []audit.Event) []string {
	var out []string
	for i := range events {
		out = append(out, events[i].Subject)
	}
	return out
}

// Only the service may record as itself; a reporter naming one of its
// sources would be forging, say, a sign-in.
func TestTheServicesOwnSourcesAreReserved(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"issuer", "Directory", " console "} {
		if !audit.Reserved(source) {
			t.Errorf("%q is not reserved", source)
		}
	}
	if audit.Reserved("github-roster") {
		t.Error("a reporter's own name is reserved")
	}
}

// What an event keeps of a request is cut to its bound on a character,
// cannot carry a line break, and never replaces what an event already
// says.
func TestRequestFieldsAreBoundedAndNeverOverwrite(t *testing.T) {
	t.Parallel()
	if got := audit.Bounded("agent\nforged=true", audit.MaxUserAgent); strings.ContainsAny(got, "\r\n") {
		t.Errorf("Bounded kept a line break: %q", got)
	}
	long := strings.Repeat("é", 100) // two bytes each
	if got := audit.Bounded(long, 63); len(got) > 63 || !strings.HasPrefix(long, got) {
		t.Errorf("Bounded(63) = %d bytes %q, want at most 63 on a character boundary", len(got), got)
	}
	e := audit.Event{ClientAddress: "198.51.100.1"}
	audit.Request{ClientAddress: "203.0.113.9", UserAgent: "curl/8", RequestID: "r"}.Apply(&e)
	if e.ClientAddress != "198.51.100.1" || e.UserAgent != "curl/8" || e.RequestID != "r" {
		t.Errorf("Apply = %+v, want the event's own address kept and the rest filled", e)
	}
}
