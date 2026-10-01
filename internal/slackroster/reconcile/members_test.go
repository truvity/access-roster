package reconcile_test

import (
	"strings"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// user is an individually listed address as the directory has it.
func (e *env) user(addr string, live bool) *env {
	if e.in.DirUsers == nil {
		e.in.DirUsers = map[string]reconcile.Holder{}
	}
	e.in.DirUsers[addr] = rails.Holder{Email: addr, Live: live}
	return e
}

// A channel listing only individual addresses invites them, with no group.
func TestAnIndividuallyListedPersonIsInvited(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Sources: []string{}, Members: []string{"ann@acme.example"}}).
		user("ann@acme.example", true).account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng"}))
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "invite:eng:U1")
	if m := row(t, channelOf(t, dec, "eng"), "ann@acme.example"); m.State != status.StateWillInvite {
		t.Errorf("row = %+v", m)
	}
	for _, a := range dec.Actions {
		if !strings.Contains(a.Reason, "listed individually") {
			t.Errorf("reason = %q", a.Reason)
		}
	}
}

// Somebody in a group and listed individually is one person, invited once,
// and so is somebody whose second address is the one listed.
func TestAPersonInAGroupAndListedIndividuallyIsInvitedOnce(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Members: []string{"ann@acme.example", "j.doe@acme.example", "john@globex.example"}},
		"ann@acme.example", "j.doe@acme.example").
		user("ann@acme.example", true).user("j.doe@acme.example", true).user("john@globex.example", true).
		account("ann@acme.example", "U1").account("j.doe@acme.example", "U2").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng"}))
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec, "invite:eng:U1", "invite:eng:U2")
	if m := row(t, channelOf(t, dec, "eng"), "ann@acme.example"); !strings.Contains(m.Reason+dec.Actions[0].Reason, "and is listed individually") {
		t.Errorf("row = %+v, action = %+v", m, dec.Actions[0])
	}
}

// An individual who is suspended or gone is not invited, and is a leaver like
// a group member: extend reports them, strict removes them on the
// directory's word.
func TestALeaverListedIndividuallyIsNeverAddedAndStrictRemovesThem(t *testing.T) {
	t.Parallel()
	build := func(mode string) *env {
		e := consoleEnv(reconcile.ConsoleChannel{Private: true, Mode: mode, Sources: []string{}, Members: []string{"ann@acme.example", "bob@acme.example"}}).
			user("ann@acme.example", true).user("bob@acme.example", false).
			account("ann@acme.example", "U1").account("bob@acme.example", "U2").
			channel(ours(reconcile.Channel{ID: "C1", Name: "eng", Private: true, Members: []string{"BACME", "U1", "U2"}})).
			member("U2", "bob@acme.example")
		return e
	}
	// extend: nothing added, nothing removed, the leaver reported
	dec := build("").decide(t, vouch(rails.Vouch{Authoritative: true, Found: true, Suspended: true}, "bob@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec)
	if m := rowByUser(t, channelOf(t, dec, "eng"), "U2"); m.State != status.StateReported {
		t.Errorf("extend row = %+v", m)
	}
	// strict: removed
	dec = build(policy.SlackModeStrict).decide(t, vouch(rails.Vouch{Authoritative: true, Found: true, Suspended: true}, "bob@acme.example"), reconcile.Confirmed{})
	wantKinds(t, dec, "remove:eng:U2")
	if !strings.Contains(dec.Actions[0].Reason, "listed") {
		t.Errorf("reason = %q", dec.Actions[0].Reason)
	}
}

// An individual with no account path in the workspace, or no Slack account
// yet, is held like a group member.
func TestAnIndividualWithNoSlackAccountIsHeld(t *testing.T) {
	t.Parallel()
	e := consoleEnv(reconcile.ConsoleChannel{Sources: []string{}, Members: []string{"ann@acme.example"}}).
		user("ann@acme.example", true).noAccount("ann@acme.example").
		channel(ours(reconcile.Channel{ID: "C1", Name: "eng"}))
	dec := e.decide(t, nil, reconcile.Confirmed{})
	wantKinds(t, dec)
	if m := row(t, channelOf(t, dec, "eng"), "ann@acme.example"); m.State != status.StateHeld {
		t.Errorf("row = %+v", m)
	}
}

// A shared channel takes individuals from any directory: each is routed to the
// side that has an address for them.
func TestASharedChannelListsIndividualsOfAnyDirectory(t *testing.T) {
	t.Parallel()
	sc := reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, Members: []string{"ann@acme.example", "gus@globex.example"}}
	e := newEnv("acme").shared(sc).user("ann@acme.example", true).user("gus@globex.example", true).
		account("ann@acme.example", "U1").
		channel(ours(reconcile.Channel{ID: "C1", Name: "joint"}))
	if got := reconcile.Lookups(e.in); len(got) != 1 || got[0] != "ann@acme.example" {
		t.Errorf("Lookups (host side) = %v", got)
	}
	g := newEnv("globex").shared(sc).user("ann@acme.example", true).user("gus@globex.example", true)
	if got := reconcile.Lookups(g.in); len(got) != 1 || got[0] != "gus@globex.example" {
		t.Errorf("Lookups (guest side) = %v", got)
	}
}
