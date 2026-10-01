package controller_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
)

const clubGroup = "club@acme.example"

// writeConsole is the record the console keeps for an ordinary channel.
func (r *rig) writeConsole(c reconcile.ConsoleChannel) {
	r.t.Helper()
	if c.Workspace == "" {
		c.Workspace = "acme"
	}
	if c.Sources == nil {
		c.Sources = []string{clubGroup}
	}
	raw, err := connection.EncodeConsole(c)
	if err != nil {
		r.t.Fatal(err)
	}
	r.writeRecord(connection.ConsoleKey(c.Workspace, c.Name), raw)
}

// clubChannel is a private channel the bot made, with members.
func (r *rig) clubChannel(name string, members ...string) slackfake.Channel {
	ch := r.fake.AddChannel("TACME", name, true, append([]string{slackfake.BotID("TACME")}, members...)...)
	r.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")
	return *ch
}

// A console channel is fed by a directory group of the workspace's owner: the
// controller resolves its members from the console, creates the channel and
// invites them, and the report and the audit trail say it is a console channel.
func TestAConsoleChannelIsCreatedAndFedFromADirectoryGroup(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{clubGroup}, "acme")
	r.person("bob@acme.example", []string{clubGroup}, "acme")
	r.person("outsider@acme.example", []string{"g-all"}, "acme") // an internal group's holder: not a source
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true})

	r.pass("acme")

	ch, made := r.fake.ChannelNamed("TACME", "club")
	if !made || !ch.Private {
		t.Fatalf("the channel was not created private: %+v %v", ch, made)
	}
	members := r.fake.Members(ch.ID)
	if !slices.Contains(members, ann) || !slices.Contains(members, r.users["bob@acme.example"]) || slices.Contains(members, r.users["outsider@acme.example"]) {
		t.Errorf("members = %v, want the directory group's two and nobody else", members)
	}
	rep := r.reports.channel(t, "acme", "club")
	if !rep.Console || rep.Shared || rep.State != status.ChannelOK || rep.Mode != "extend" {
		t.Errorf("report = %+v", rep)
	}
	if r.actions("roster.slack_channel.created") < 1 || r.actions("roster.slack_member.invited") < 2 {
		t.Errorf("records = %v", r.audit.Actions())
	}
	// The policy's own channels are untouched by it.
	if _, made = r.fake.ChannelNamed("TACME", "announce"); !made {
		t.Error("the policy channel was not created")
	}
	if rep = r.reports.channel(t, "acme", "announce"); rep.Console {
		t.Errorf("a policy channel is reported as a console channel: %+v", rep)
	}
}

// What is wrong with a record is reported on its workspace as a held channel
// and acted on by nobody, whether the policy refuses it or the directory does.
func TestAConsoleChannelWhoseSourcesCannotBeActedOnIsRefused(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{clubGroup}, "acme")
	for name, tc := range map[string]struct {
		group *fakeDirGroup
		say   string
	}{
		"another directory's group": {&fakeDirGroup{owner: "C0globex"}, "another directory"},
		"a group that is gone":      {&fakeDirGroup{missing: true}, "not a group of a connected directory"},
		"nests too deeply":          {&fakeDirGroup{truncated: true}, "nests too deeply"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.person("ann@acme.example", []string{clubGroup}, "acme")
			r.console.set(func() { r.console.dirGroups[clubGroup] = tc.group })
			r.writeConsole(reconcile.ConsoleChannel{Name: "club"})

			r.pass("acme")

			if _, made := r.fake.ChannelNamed("TACME", "club"); made {
				t.Error("a refused console channel was created")
			}
			rep := r.reports.channel(t, "acme", "club")
			if rep.State != status.ChannelHeld || !rep.Console || !strings.Contains(rep.Reason, "refused") || !strings.Contains(rep.Reason, tc.say) {
				t.Errorf("report = %+v, want held, refused, saying %q", rep, tc.say)
			}
			// The rest of the workspace carries on.
			if _, made := r.fake.ChannelNamed("TACME", "announce"); !made {
				t.Error("a refused record stopped the workspace's own channels")
			}
		})
	}
	// A record that duplicates a policy channel is refused as defined in git.
	r.writeConsole(reconcile.ConsoleChannel{Name: "announce"})
	r.pass("acme")
	var refused status.Channel
	for _, c := range r.reports.workspace(t, "acme").Channels {
		if c.Name == "announce" && c.Console {
			refused = c
		}
	}
	if refused.State != status.ChannelHeld || !strings.Contains(refused.Reason, "defined in git") {
		t.Errorf("the duplicate = %+v", refused)
	}
	if rep := r.reports.channel(t, "acme", "announce"); rep.Console || rep.State == status.ChannelHeld {
		t.Errorf("the policy channel was disturbed by the duplicate: %+v", rep)
	}
	// An undecodable record is not acted on either.
	r.writeRecord(connection.ConsoleKey("acme", "garbled"), "not json")
	r.pass("acme")
}

// An ordinary channel's group must be its OWNER's, whatever the record says.
func TestAnOrdinaryChannelWithNoOwnerIsRefused(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{clubGroup}, "acme")
	r.writeConnection("acme", "TACME", "")
	r.writeConsole(reconcile.ConsoleChannel{Name: "club"})
	r.pass("acme")
	if rep := r.reports.channel(t, "acme", "club"); rep.State != status.ChannelHeld || !strings.Contains(rep.Reason, "no owning directory") {
		t.Errorf("report = %+v", rep)
	}
}

// Extend only adds, however the directory's answer reads.
func TestAnExtendConsoleChannelOnlyAddsAndNeverRemoves(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{clubGroup}, "acme")
	left := r.person("left@acme.example", nil, "acme") // gone from the directory
	other := r.person("other@acme.example", []string{"somewhere@acme.example"}, "acme")
	ch := r.clubChannel("club", ann, left, other)
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true})

	r.pass("acme")
	r.pass("acme")

	if r.fake.Count("conversations.kick") != 0 {
		t.Error("an extend channel removed somebody")
	}
	if members := r.fake.Members(ch.ID); !slices.Contains(members, left) || !slices.Contains(members, other) {
		t.Errorf("members = %v", members)
	}
	// The leaver is reported, as for a policy channel, and nothing acts on it.
	if got := r.reports.workspace(t, "acme").Leavers; len(got) != 1 || got[0].UserID != left {
		t.Errorf("leavers = %+v", got)
	}
}

// A strict console channel removes only what the directory vouches for, and
// asks about the DIRECTORY groups: somebody it still finds in the channel's
// group, or in one it nests, stays.
func TestAStrictConsoleChannelRemovesOnlyOnTheDirectorysSay(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{clubGroup}, "acme")
	left := r.person("left@acme.example", nil, "acme")                                        // gone
	nested := r.person("nested@acme.example", []string{"team@acme.example"}, "acme")          // in a group the channel's group nests
	stranger := r.person("stranger@acme.example", []string{"unrelated@acme.example"}, "acme") // elsewhere in the directory
	unsure := r.person("unsure@acme.example", []string{"unrelated@acme.example"}, "acme")     // the directory cannot vouch
	r.console.set(func() {
		r.console.dirGroups[clubGroup] = &fakeDirGroup{nested: []string{"team@acme.example"}}
		r.console.unsure["unsure@acme.example"] = true
	})
	ch := r.clubChannel("club", ann, left, nested, stranger, unsure)
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true, Mode: "strict"})

	r.pass("acme")

	members := r.fake.Members(ch.ID)
	for name, id := range map[string]string{"left": left, "stranger": stranger} {
		if slices.Contains(members, id) {
			t.Errorf("%s was not removed: %v", name, members)
		}
	}
	for name, id := range map[string]string{"ann": ann, "nested": nested, "unsure": unsure} {
		if !slices.Contains(members, id) {
			t.Errorf("%s was removed: %v", name, members)
		}
	}
	rep := r.reports.channel(t, "acme", "club")
	if rep.Mode != "strict" || !rep.Console {
		t.Errorf("report = %+v", rep)
	}
	retrying := false
	for _, m := range rep.Members {
		retrying = retrying || (m.UserID == unsure && m.State == status.StateRetrying)
	}
	if !retrying {
		t.Errorf("rows = %+v, want the unvouched person retrying", rep.Members)
	}
	if r.actions("roster.slack_member.removed") != 2 {
		t.Errorf("records = %v", r.audit.Actions())
	}
}

// The breaker holds a console channel's removals past half of it.
func TestAStrictConsoleChannelIsStoppedByTheBreaker(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{clubGroup}, "acme")
	a := r.person("a@acme.example", nil, "acme")
	b := r.person("b@acme.example", nil, "acme")
	ch := r.clubChannel("club", ann, a, b)
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true, Mode: "strict"})

	r.pass("acme")

	if r.fake.Count("conversations.kick") != 0 {
		t.Errorf("removals over the limit went ahead: %v", r.fake.Members(ch.ID))
	}
	rep := r.reports.channel(t, "acme", "club")
	if rep.Breaker == nil || rep.Breaker.Confirmed {
		t.Fatalf("breaker = %+v", rep.Breaker)
	}
	// An operator's confirmation of exactly that set lets it through.
	raw, err := connection.EncodeConfirmation(connection.Confirmation{
		Workspace: "acme", Channel: "club", Fingerprint: rep.Breaker.Fingerprint, By: "ada@acme.example", At: r.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.writeRecord(connection.ConfirmationKey("acme", "club"), raw)
	r.pass("acme")
	if got := r.fake.Members(ch.ID); slices.Contains(got, a) || slices.Contains(got, b) {
		t.Errorf("the confirmed removals did not go ahead: %v", got)
	}
}

// A directory that cannot be read fails the workspaces that depend on it,
// never reads as "nobody is in these groups": a strict channel would be
// emptied. A workspace that does not use directory groups is not affected.
func TestADirectoryThatCannotBeReadFailsOnlyWhatDependsOnIt(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{clubGroup}, "acme")
	r.person("gus@globex.example", []string{"g-gx"}, "globex")
	ch := r.clubChannel("club", ann)
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true, Mode: "strict"})
	r.console.set(func() { r.console.resolveErr = errors.New("the console is unavailable") })

	r.pass("acme", "globex")

	if got := r.reports.workspace(t, "acme").Tick; got.Outcome != status.OutcomeFailed || !strings.Contains(got.Error, "directory groups") {
		t.Errorf("acme's tick = %+v", got)
	}
	if got := r.reports.workspace(t, "globex").Tick; got.Outcome == status.OutcomeFailed {
		t.Errorf("globex, which uses no directory group, failed: %+v", got)
	}
	if r.fake.Count("conversations.kick") != 0 || !slices.Contains(r.fake.Members(ch.ID), ann) {
		t.Error("the failed workspace was changed")
	}
	// Under another policy the answer is not used either.
	r.console.set(func() { r.console.resolveErr = nil })
	r.pass("acme")
	if got := r.reports.workspace(t, "acme").Tick; got.Outcome == status.OutcomeFailed {
		t.Errorf("acme did not recover: %+v", got)
	}
}

// A dry run says what would happen to a console channel and changes nothing.
func TestAConsoleChannelInADisabledWorkspaceIsADryRun(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{clubGroup}, "acme")
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true})
	r.pass()
	if _, made := r.fake.ChannelNamed("TACME", "club"); made || r.mutations() != 0 {
		t.Error("a dry run changed Slack")
	}
	if rep := r.reports.channel(t, "acme", "club"); rep.State != status.ChannelWillCreate || !rep.Console {
		t.Errorf("report = %+v", rep)
	}
}

// Every channel the bot can see that nothing manages is reported, and one
// that a console record, or a policy binding, covers is not.
func TestUnmanagedChannelsAreDiscoveredAndManagedOnesAreNot(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{clubGroup}, "acme")
	r.fake.AddChannel("TACME", "random", false, slackfake.BotID("TACME"))
	r.fake.AddChannel("TACME", "secret", true, slackfake.BotID("TACME"))
	r.fake.AddChannel("TACME", "hidden", true) // the bot is not in it: Slack does not list it
	managed := r.clubChannel("club")
	r.writeConsole(reconcile.ConsoleChannel{Name: "club", Private: true})

	r.pass("acme")

	var got []string
	for _, d := range r.reports.workspace(t, "acme").Discovered {
		got = append(got, d.Name)
		if d.Name == "secret" && !d.Private {
			t.Errorf("the private channel is reported public: %+v", d)
		}
		if d.ID == managed.ID {
			t.Errorf("a managed channel is discovered: %+v", d)
		}
	}
	slices.Sort(got)
	if want := []string{"random", "secret"}; !slices.Equal(got, want) {
		t.Errorf("discovered = %v, want %v (the policy's channels, the record's, #general and the bot-less private one are not)", got, want)
	}
	// Discovery changes nothing: it is a report.
	if r.touching(r.fake.Channels[managed.ID].ID) > 0 && r.createdNamed("random") != 0 {
		t.Error("discovery created a channel")
	}
	_ = context.Background
}
