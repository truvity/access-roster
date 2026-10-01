package server

import (
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

func withMembers(d *directoryrosterv1.SlackChannelDefinition, members ...string) *directoryrosterv1.SlackChannelDefinition {
	d.Members = members
	return d
}

// An ordinary channel lists individuals of its owning directory, beside or
// instead of groups; they are kept lowercase and drive the audit targets.
func TestAConsoleChannelListsIndividualAddressesOfItsOwnerDirectory(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(northOp)
	if err := h.createChannel(ctx, withMembers(chdef("acme", "eng", "partners@north.example"), " Cy@North.example ", "dee@north.example")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := h.createChannel(ctx, withMembers(chdef("acme", "solo"), "ann@north.example")); err != nil {
		t.Fatalf("create with individuals only: %v", err)
	}
	kept, err := connection.DecodeConsole(h.storedChannels(t)[connection.ConsoleKey("acme", "eng")])
	if err != nil || !slices.Equal(kept.Members, []string{"cy@north.example", "dee@north.example"}) {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	listed := h.listChannels(ctx, t)
	for _, c := range listed.Channels {
		if c.GetChannel().GetName() == "eng" && !slices.Equal(c.GetChannel().GetMembers(), []string{"cy@north.example", "dee@north.example"}) {
			t.Errorf("listed members = %v", c.GetChannel().GetMembers())
		}
	}
	// The audit record carries each individual as a target and counts them.
	var created bool
	for _, r := range h.recorded.Records() {
		if r.GetAction() != "roster.slack_console_channel.created" {
			continue
		}
		var users []string
		for _, tg := range r.GetTargets() {
			if tg.GetType() == "directory_user" {
				users = append(users, tg.GetId())
			}
		}
		if len(users) == 2 {
			created = true
		}
	}
	if !created {
		t.Errorf("no created record carries the two individuals as targets")
	}
	// Editing the list is recorded, by count.
	edited := withMembers(chdef("acme", "eng", "partners@north.example"), "cy@north.example")
	if err = h.updateChannel(ctx, edited); err != nil {
		t.Fatalf("update: %v", err)
	}
	var changed bool
	for _, r := range h.recorded.Records() {
		if strings.Contains(r.String(), "members: 2 -> 1 people (0 added, 1 removed)") {
			changed = true
		}
	}
	if !changed {
		t.Error("the edit's change line does not count the individuals")
	}
}

func TestIndividualAddressesAreRefusedWhenTheyDoNotFit(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	for _, c := range []struct {
		name    string
		members []string
		say     string
	}{
		{"another directory's user on an ordinary channel", []string{"eve@south.example"}, "not a user of the directory that owns this workspace"},
		{"a domain nobody serves", []string{"x@nowhere.example"}, "individual addresses come from the directories this channel draws from"},
		{"an address the directory does not know", []string{"ghost@north.example"}, "does not know that address"},
		{"a group entered as an email", []string{"partners@north.example"}, "is a group, not a person"},
		{"not an address", []string{"ann"}, "not an email address"},
		{"a duplicate", []string{"ann@north.example", "ANN@north.example"}, "twice"},
	} {
		err := h.createChannel(ctx, withMembers(chdef("acme", "x"), c.members...))
		wantCode(t, c.name, err, connect.CodeInvalidArgument)
		if err == nil || !strings.Contains(err.Error(), c.say) {
			t.Errorf("%s: the refusal does not say %q: %v", c.name, c.say, err)
		}
	}
	// A person's address entered as a group.
	err := h.createChannel(ctx, chdef("acme", "y", "ann@north.example"))
	wantCode(t, "an email entered as a group", err, connect.CodeInvalidArgument)
	if err == nil || !strings.Contains(err.Error(), "enter it under Individual addresses") {
		t.Errorf("an email as a group: %v", err)
	}
	// Both lists empty.
	wantCode(t, "nothing at all", h.createChannel(ctx, chdef("acme", "z")), connect.CodeInvalidArgument)
	if len(h.storedChannels(t)) != 0 {
		t.Errorf("a refused record was kept: %v", h.storedChannels(t))
	}
}

// A Slack Connect channel takes individuals of any connected directory.
func TestASharedChannelListsIndividualsOfAnyDirectory(t *testing.T) {
	h := newConnectHarness(t)
	ctx := as(everywhere)
	d := def("partners", "acme", []string{"globex"}, nil)
	d.Members = []string{"ann@north.example", "eve@south.example"}
	if err := h.create(ctx, d); err != nil {
		t.Fatalf("a shared channel with individuals of both directories: %v", err)
	}
	listed := h.list(ctx, t)
	if len(listed.Channels) != 1 || !slices.Equal(listed.Channels[0].GetChannel().GetMembers(), []string{"ann@north.example", "eve@south.example"}) {
		t.Errorf("listed = %v", listed.Channels)
	}
	bad := def("other", "acme", []string{"globex"}, nil)
	bad.Members = []string{"x@nowhere.example"}
	wantCode(t, "an address no directory serves", h.create(ctx, bad), connect.CodeInvalidArgument)
	bad.Members = []string{"partners@north.example"}
	wantCode(t, "a group as an email", h.create(ctx, bad), connect.CodeInvalidArgument)
}

// ResolveDirectoryGroups answers for individual addresses: which directory
// serves them and whether the account is active.
func TestResolveDirectoryGroupsAnswersForUsers(t *testing.T) {
	h := newConnectHarness(t)
	got, err := h.console.ResolveDirectoryGroups(as(everywhere), connect.NewRequest(&directoryrosterv1.ResolveDirectoryGroupsRequest{
		Users: []string{"Ann@north.example", "eve@south.example", "ghost@north.example", "x@nowhere.example"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	users := got.Msg.GetUsers()
	if len(users) != 4 {
		t.Fatalf("users = %v", users)
	}
	want := []struct {
		email, ws    string
		found, alive bool
	}{
		{"ann@north.example", "C0north", true, true},
		{"eve@south.example", "C0south", true, true},
		{"ghost@north.example", "C0north", false, false},
		{"x@nowhere.example", "", false, false},
	}
	for i, w := range want {
		u := users[i]
		if u.GetEmail() != w.email || u.GetWorkspaceId() != w.ws || u.GetFound() != w.found || u.GetLive() != w.alive {
			t.Errorf("user %d = %v, want %+v", i, u, w)
		}
	}
}
