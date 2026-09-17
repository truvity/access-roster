package audit_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
)

// listed reads a page through a writer's client.
func listed(t *testing.T, client directoryrosterv1connect.AuditSinkServiceClient, q audit.Query) ([]audit.Event, string) {
	t.Helper()
	response, err := client.ListStoredAuditEvents(context.Background(),
		connect.NewRequest(&directoryrosterv1.ListStoredAuditEventsRequest{Query: q.Proto()}))
	if err != nil {
		t.Fatalf("ListStoredAuditEvents: %v", err)
	}
	return audit.EventsFromProto(response.Msg.GetEvents()), response.Msg.GetCursor()
}

// Every field an event has survives the record: the S3 object is the
// record, so a field that did not come back would be a field never kept.
func TestARecordRoundTripsEveryField(t *testing.T) {
	t.Parallel()
	event := audit.Event{
		ID:            "1789000000000000000-pod-7",
		At:            time.Date(2026, 9, 13, 16, 58, 1, 123456789, time.UTC),
		Source:        "github-roster",
		Kind:          "github.member.remove",
		Actor:         "ada@north.example",
		Reporter:      "cluster:k8s:access-issuer:github-roster",
		Subject:       "dana@south.example",
		Target:        "example-org/team-platform",
		Outcome:       audit.OutcomeFailed,
		Reason:        "GitHub refused",
		Attributes:    map[string]string{"login": "dana", "dotted.name": "kept whole"},
		ClientAddress: "2001:db8::1",
		UserAgent:     "github-roster/1.7.0",
		RequestID:     "0f1e2d3c",
	}
	// Every field set, checked by reflection, so a field added to Event and
	// not to the record fails here rather than in an audit.
	value := reflect.ValueOf(event)
	for i := range value.NumField() {
		if value.Field(i).IsZero() {
			t.Fatalf("the test event leaves %s empty", value.Type().Field(i).Name)
		}
	}

	line, err := audit.EncodeRecord(event)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	if strings.Contains(string(line), "\n") {
		t.Fatal("a record spans lines")
	}
	got, err := audit.DecodeRecord(line)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if !reflect.DeepEqual(got, event) {
		t.Errorf("round trip =\n%+v\nwant\n%+v", got, event)
	}

	// Nested as ECS nests, not flat.
	var document map[string]any
	if err = json.Unmarshal(line, &document); err != nil {
		t.Fatal(err)
	}
	for _, path := range [][]string{
		{"@timestamp"}, {"ecs", "version"}, {"event", "id"}, {"event", "kind"}, {"event", "dataset"}, {"event", "provider"},
		{"event", "action"}, {"event", "category"}, {"event", "type"}, {"event", "outcome"}, {"event", "reason"},
		{"user", "name"}, {"user", "target", "name"}, {"observer", "name"}, {"service", "target", "name"},
		{"client", "address"}, {"user_agent", "original"}, {"http", "request", "id"},
		{"access_roster", "outcome"}, {"access_roster", "target"}, {"access_roster", "attributes", "dotted.name"},
	} {
		if at(document, path) == nil {
			t.Errorf("the record has no %s", strings.Join(path, "."))
		}
	}
}

func at(document map[string]any, path []string) any {
	var place any = document
	for _, level := range path {
		m, ok := place.(map[string]any)
		if !ok {
			return nil
		}
		place = m[level]
	}
	return place
}

// Empty values are left out of a record rather than written as "".
func TestARecordOmitsWhatIsEmpty(t *testing.T) {
	t.Parallel()
	line, err := audit.EncodeRecord(audit.Event{ID: "1-p-1", At: time.Unix(1, 0), Source: "issuer", Kind: "session.ended", Outcome: audit.OutcomeOK})
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{`""`, `"client"`, `"user_agent"`, `"http"`, `"observer"`, `"attributes"`, `"reason"`} {
		if strings.Contains(string(line), absent) {
			t.Errorf("the record carries %s: %s", absent, line)
		}
	}
}

// What access-roster 1.6.2 wrote reads back as the event it was, and so
// will for as long as the bucket's lock keeps it.
func TestA162LineReadsBack(t *testing.T) {
	t.Parallel()
	line := `{"id":"1789000000000000000-access-issuer-7d9-1","at":"2026-09-13T16:58:01.5+02:00","source":"issuer","kind":"token.exchanged",` +
		`"actor":"system:serviceaccount:ci:runner","subject":"system:serviceaccount:ci:runner","target":"kubernetes","outcome":"refused",` +
		`"reason":"the proof holds no group this client requires","attributes":{"proof":"workload"}}`
	got, err := audit.DecodeRecord([]byte(line))
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	want := audit.Event{
		ID: "1789000000000000000-access-issuer-7d9-1", At: time.Date(2026, 9, 13, 14, 58, 1, 500000000, time.UTC),
		Source: "issuer", Kind: "token.exchanged", Actor: "system:serviceaccount:ci:runner", Subject: "system:serviceaccount:ci:runner",
		Target: "kubernetes", Outcome: audit.OutcomeRefused, Reason: "the proof holds no group this client requires",
		Attributes: map[string]string{"proof": "workload"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("1.6.2 line =\n%+v\nwant\n%+v", got, want)
	}
	for _, junk := range []string{`{}`, `[]`, `{"event":"not an object"}`, `not json`} {
		if _, err = audit.DecodeRecord([]byte(junk)); err == nil {
			t.Errorf("%s read as a record", junk)
		}
	}
}

// Every kind this repository records has its ECS category and type
// decided in one table; a kind that is not in it still gets an honest one.
func TestEveryKindHasItsECSClass(t *testing.T) {
	t.Parallel()
	type class struct{ category, types []string }
	c := func(category string, types ...string) class { return class{[]string{category}, types} }
	for _, tc := range []struct {
		kind, outcome string
		want          class
	}{
		// internal/server/http.go and internal/issuer/storage.go
		{"sign-in", "", c("authentication", "start")},
		{"sign-in.refused", "", c("authentication", "denied")},
		{"recovery.sign-in", "", c("authentication", "start", "admin")},
		// internal/issuer
		{"token.exchanged", audit.OutcomeOK, c("authentication", "access")},
		{"token.exchanged", audit.OutcomeRefused, c("authentication", "access", "denied")},
		// internal/issuer/githubtoken_http.go
		{"github.token.minted", audit.OutcomeOK, c("authentication", "access")},
		{"github.token.minted", audit.OutcomeRefused, c("authentication", "access", "denied")},
		{"github.token.minted", audit.OutcomeFailed, c("authentication", "access")},
		{"session.refresh-refused", "", c("session", "denied")},
		{"session.ended", "", c("session", "end")},
		{"session.revoked", "", c("session", "end", "admin")},
		// internal/server/console.go and http.go
		{"workspace.connected", "", c("configuration", "creation", "connection")},
		{"workspace.reconnected", "", c("configuration", "change", "connection")},
		{"workspace.disconnected", "", c("configuration", "deletion")},
		{"workspace.domains-changed", "", c("configuration", "change")},
		{"workspace.groups-changed", "", c("configuration", "change")},
		// internal/server/github_connect.go and github_link.go
		{"github.app.created", "", c("configuration", "creation")},
		{"github.org.connected", "", c("configuration", "creation", "connection")},
		{"github.org.disconnected", "", c("configuration", "deletion")},
		{"github.link-app.connected", "", c("configuration", "creation")},
		{"github.link-app.disconnected", "", c("configuration", "deletion")},
		{"github.link.created", "", c("iam", "user", "creation")},
		{"github.link.moved", "", c("iam", "user", "change")},
		// internal/server/github_safety.go
		{"github.removals.confirmed", "", c("iam", "admin", "change")},
		{"github.link.imported", "", c("iam", "user", "creation")},
		// internal/githubroster/controller, one per status.Action
		{"github.member.invite", "", c("iam", "user", "creation")},
		{"github.member.add", "", c("iam", "user", "creation")},
		{"github.member.set-role", "", c("iam", "user", "change")},
		{"github.member.remove", "", c("iam", "user", "deletion")},
		{"github.action.held", audit.OutcomeHeld, c("iam", "info")},
		{"github.owner.reported", "", c("iam", "info")},
		{"github.link.matched", "", c("iam", "user", "creation")},
		{"github.link.narrowed", "", c("iam", "user", "change")},
		{"github.link.lost", "", c("iam", "user", "deletion")},
		{"github.link.unverifiable", "", c("iam", "user", "change")},
		// Not ours: by prefix, and otherwise the default.
		{"github.member.transfer", "", c("iam", "user", "change")},
		{"session.extended", "", c("session", "info")},
		{"backup.taken", "", c("iam", "info")},
	} {
		category, types := audit.Classify(tc.kind, tc.outcome)
		if !slices.Equal(category, tc.want.category) || !slices.Equal(types, tc.want.types) {
			t.Errorf("%s (%s) = %v %v, want %v %v", tc.kind, tc.outcome, category, types, tc.want.category, tc.want.types)
		}
	}
}
