package status_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/status"
)

// What the controller writes is what the console reads, field for field.
// A report that lost a held reason on the way would show an operator a
// member stuck for no reason.
func TestAReportReadsBackAsWritten(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 9, 12, 21, 0, 0, 0, time.UTC)
	written := status.Org{
		Org:     "globex",
		Enabled: false,
		Tick:    status.Tick{At: at, Outcome: status.OutcomeDryRun, Changes: 2, Held: 1},
		Teams: []status.Team{{
			Team: "team-platform",
			Members: []status.Member{
				{Email: "ada.lovelace@globex.example", Login: "excavador", Role: status.RoleMaintainer, State: status.StateSynced},
				{Email: "a.joiner@globex.example", Role: status.RoleMember, State: status.StatePending, Action: status.ActionInvite},
				{Email: "a.leaver@globex.example", Login: "leaver", Role: status.RoleMember, State: status.StateHeld,
					Action: status.ActionRemove, Reason: "the directory cannot vouch for globex.example"},
			},
		}},
		Unlinked: []status.Account{{Login: "globex-bot", Reason: "no bound holder's address"}},
	}

	raw, err := status.Encode(written)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	read, err := status.Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if read.Version != status.Version || read.Org != "globex" || !read.Tick.At.Equal(at) {
		t.Errorf("header = %+v", read)
	}
	if len(read.Teams) != 1 || len(read.Teams[0].Members) != 3 {
		t.Fatalf("teams = %+v", read.Teams)
	}
	var held status.Member
	for _, member := range read.Teams[0].Members {
		if member.State == status.StateHeld {
			held = member
		}
	}
	if held.Action != status.ActionRemove || !strings.Contains(held.Reason, "cannot vouch") {
		t.Errorf("the held removal lost its reason: %+v", held)
	}
}

// Order is fixed so a diff between two ticks shows what changed rather
// than what moved — and producing that order never reorders the slices a
// caller handed in.
func TestEncodingOrdersTheDocumentWithoutTouchingTheCallersSlices(t *testing.T) {
	t.Parallel()
	members := []status.Member{
		{Email: "z@globex.example", State: status.StateSynced},
		{Email: "a@globex.example", State: status.StateSynced},
	}
	teams := []status.Team{{Team: "team-z", Members: members}, {Team: "team-a"}}

	raw, err := status.Encode(status.Org{Org: "globex", Teams: teams, Members: members})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Index(raw, `"team-a"`) > strings.Index(raw, `"team-z"`) {
		t.Errorf("teams are not in order: %s", raw)
	}
	if members[0].Email != "z@globex.example" || teams[0].Team != "team-z" {
		t.Error("Encode reordered the caller's slices")
	}

	again, _ := status.Encode(status.Org{Org: "globex", Teams: slices.Clone(teams), Members: slices.Clone(members)})
	if again != raw {
		t.Error("the same report encoded twice produced two documents")
	}
}

// A document of a version this build does not know is refused rather
// than rendered: a console showing a shape it does not understand would
// show a confident page that means something else.
func TestAnUnknownVersionIsRefused(t *testing.T) {
	t.Parallel()
	if _, err := status.Decode(`{"version":2,"org":"globex"}`); !errors.Is(err, status.ErrVersion) {
		t.Errorf("version 2 = %v, want ErrVersion", err)
	}
	if _, err := status.Decode(`{"org":"globex"}`); !errors.Is(err, status.ErrVersion) {
		t.Errorf("no version = %v, want ErrVersion", err)
	}
}

// An organisation's login is its key, with nothing escaped, so only a
// real login may be one — and a key this contract did not write is not
// mistaken for an organisation.
func TestAnOrganisationIsItsOwnKey(t *testing.T) {
	t.Parallel()
	if _, err := status.Encode(status.Org{Org: "not a login"}); err == nil {
		t.Error("a login with a space was encoded")
	}
	if org, ok := status.OrgOfKey(status.Key("acme")); !ok || org != "acme" {
		t.Errorf("OrgOfKey(Key(acme)) = %q, %v", org, ok)
	}
	for _, key := range []string{"acme", "README", "-bad.json", "a--b.json", ".json"} {
		if _, ok := status.OrgOfKey(key); ok {
			t.Errorf("%q was read as an organisation", key)
		}
	}
}
