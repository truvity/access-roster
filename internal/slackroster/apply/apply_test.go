package apply_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/rails"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/apply"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// world is two Slack workspaces behind one fake, a directory, and the policy
// that binds them.
type world struct {
	t       *testing.T
	fake    *slackfake.Slack
	clients map[string]*slackapp.Client
	teams   map[string]string
	in      reconcile.Input
	// dir maps an address to the groups it holds; absent means gone.
	dir map[string][]string
	rec *audittest.Recorder
}

func newWorld(t *testing.T) *world {
	t.Helper()
	fake := slackfake.New(t)
	fake.AddTeam("TACME", "Acme")
	fake.AddTeam("TGLOBEX", "Globex")
	w := &world{
		t: t, fake: fake, teams: map[string]string{"acme": "TACME", "globex": "TGLOBEX"},
		clients: map[string]*slackapp.Client{}, dir: map[string][]string{}, rec: audittest.New(t),
	}
	for ws, team := range w.teams {
		w.clients[ws] = slackapp.New(slackfake.Token(team), slackapp.WithBaseURL(fake.URL()), slackapp.WithPageSize(2),
			slackapp.WithRetries(1), slackapp.WithSleep(func(context.Context, time.Duration) error { return nil }))
	}
	w.in = reconcile.Input{
		Workspaces: map[string]policy.SlackWorkspace{
			"acme":   {Channels: map[string]policy.SlackChannel{}},
			"globex": {Channels: map[string]policy.SlackChannel{}},
		},
		Facts: map[string]reconcile.Facts{
			"acme":   {Team: "TACME", Owner: "C0acme", Domains: []string{"acme.example"}},
			"globex": {Team: "TGLOBEX", Owner: "C0globex", Domains: []string{"globex.example"}},
		},
		People: map[string][]string{"jdoe": {"j.doe@acme.example", "john@globex.example"}},
		Bots:   map[string]string{"acme": slackfake.BotID("TACME"), "globex": slackfake.BotID("TGLOBEX")},
	}
	return w
}

func (w *world) bind(ws, name string, c policy.SlackChannel) {
	w.in.Workspaces[ws].Channels[name] = c
}

// person is a directory entry and, when ws is not empty, a Slack account.
func (w *world) person(addr string, groups []string, slackIn string) string {
	w.dir[addr] = groups
	if slackIn == "" {
		return ""
	}
	return w.fake.AddUser(w.teams[slackIn], addr).ID
}

func (w *world) holders() rails.Holders {
	out := rails.Holders{}
	for addr, groups := range w.dir {
		for _, g := range groups {
			out[g] = append(out[g], rails.Holder{Email: addr, Live: true})
		}
	}
	return out
}

func (w *world) vouches(addrs []string) map[string]rails.Vouch {
	out := map[string]rails.Vouch{}
	for _, a := range addrs {
		groups, found := w.dir[a]
		out[a] = rails.Vouch{Authoritative: true, Found: found, Groups: groups}
	}
	return out
}

// pass is one full pass over a workspace: read, decide, ask, decide, act.
func (w *world) pass(ws string, dry bool, confirmed reconcile.Confirmed) (reconcile.Decision, apply.Result, error) {
	w.t.Helper()
	in := w.in
	in.Workspace, in.Holders = ws, w.holders()
	in.DirHolders = in.Holders
	obs, err := apply.Observe(context.Background(), w.clients[ws], in)
	if err != nil {
		return reconcile.Decision{}, apply.Result{}, err
	}
	in.Observed = obs
	draft, err := reconcile.Derive(in)
	if err != nil {
		return reconcile.Decision{}, apply.Result{}, err
	}
	dec := draft.Decide(w.vouches(draft.Confirm()), confirmed)
	res := apply.Apply(context.Background(), w.clients[ws], dec, apply.Options{Workspace: ws, DryRun: dry, Audit: w.rec})
	return dec, res, nil
}

func (w *world) mustPass(ws string) (reconcile.Decision, apply.Result) {
	w.t.Helper()
	dec, res, err := w.pass(ws, false, reconcile.Confirmed{})
	if err != nil {
		w.t.Fatalf("pass %s: %v", ws, err)
	}
	if res.Failed() != 0 {
		w.t.Fatalf("pass %s: failures: %+v", ws, res.Outcomes)
	}
	return dec, res
}

func sorted(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func TestAPassCreatesTheChannelInvitesItsPeopleAndThenIsInSync(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	bob := w.person("bob@acme.example", []string{"g"}, "acme")
	w.person("new@acme.example", []string{"g"}, "") // no Slack account yet

	dec, res := w.mustPass("acme")
	if res.Done() != 3 || len(res.Outcomes) != 3 {
		t.Fatalf("outcomes = %+v", res.Outcomes)
	}
	ch, ok := w.fake.ChannelNamed("TACME", "eng")
	if !ok || ch.Private || ch.Creator != slackfake.BotID("TACME") {
		t.Fatalf("channel = %+v %v", ch, ok)
	}
	if got := sorted(w.fake.Members(ch.ID)); !slices.Equal(got, sorted([]string{slackfake.BotID("TACME"), ann, bob})) {
		t.Errorf("members = %v", got)
	}
	if len(dec.Held) != 1 || dec.Held[0].Reason != "no Slack account yet" {
		t.Errorf("held = %+v", dec.Held)
	}
	if got := w.rec.Actions(); !slices.Equal(got, []string{"roster.slack_channel.created", "roster.slack_member.invited", "roster.slack_member.invited"}) {
		t.Errorf("audit = %v", got)
	}
	if res.ChannelIDs["eng"] != ch.ID {
		t.Errorf("ChannelIDs = %v", res.ChannelIDs)
	}

	// Next pass: the channel is ours, the invitations are in; nothing to do.
	before := w.fake.Count("conversations.invite")
	dec, res = w.mustPass("acme")
	if len(dec.Actions) != 0 || len(res.Outcomes) != 0 || w.fake.Count("conversations.invite") != before {
		t.Errorf("second pass: %v", dec.Actions)
	}
	if c := dec.Report.Channels[0]; c.State != status.ChannelOK || c.ID != ch.ID {
		t.Errorf("channel = %+v", c)
	}
}

func TestADryRunCallsNothingAndRecordsNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}})
	w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res, err := w.pass("acme", true, reconcile.Confirmed{})
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Actions) != 2 || len(res.Outcomes) != 2 || res.Done() != 0 || res.Failed() != 0 {
		t.Fatalf("dec %v res %+v", dec.Actions, res)
	}
	for _, o := range res.Outcomes {
		if o.Skipped != "dry run" {
			t.Errorf("outcome = %+v", o)
		}
	}
	for _, m := range []string{"conversations.create", "conversations.invite", "conversations.kick", "conversations.join"} {
		if n := w.fake.Count(m); n != 0 {
			t.Errorf("a dry run called %s %d times", m, n)
		}
	}
	if len(w.rec.Records()) != 0 {
		t.Errorf("a dry run recorded %v", w.rec.Actions())
	}
	if _, ok := w.fake.ChannelNamed("TACME", "eng"); ok {
		t.Error("a dry run created the channel")
	}
}

func TestStrictRemovesOnlyWhatTheDirectoryVouchesForAndRecordsIt(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.bind("acme", "secret", policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g"}, Ignore: []string{"keep@acme.example"}})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	bob := w.person("bob@acme.example", []string{"g"}, "acme")
	left := w.person("left@acme.example", nil, "acme")
	keep := w.fake.AddUser("TACME", "keep@acme.example").ID // gone from the directory, but ignored
	guest := w.fake.AddUser("TACME", "guest@acme.example")
	w.fake.Users[guest.ID].Guest = true
	w.person("ex@acme.example", nil, "") // directory-known, not relevant
	ch := w.fake.AddChannel("TACME", "secret", true, slackfake.BotID("TACME"), ann, left, keep, guest.ID)
	w.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")
	_ = bob

	dec, res := w.mustPass("acme")
	if got := sorted(w.fake.Members(ch.ID)); !slices.Equal(got, sorted([]string{slackfake.BotID("TACME"), ann, bob, keep, guest.ID})) {
		t.Errorf("members = %v", got)
	}
	if res.Done() != 2 {
		t.Errorf("outcomes = %+v", res.Outcomes)
	}
	if got := w.rec.Actions(); !slices.Equal(got, []string{"roster.slack_member.invited", "roster.slack_member.removed"}) {
		t.Errorf("audit = %v", got)
	}
	// keep is ignored and, being gone from the directory, a reported leaver
	if len(dec.Report.Leavers) != 1 || dec.Report.Leavers[0].UserID != keep {
		t.Errorf("leavers = %+v", dec.Report.Leavers)
	}
	rec := apply.LeaverRecord("acme", dec.Report.Leavers[0])
	if rec.GetAction() != "roster.slack_leaver.reported" {
		t.Errorf("leaver record = %v", rec.GetAction())
	}
}

func TestADirectoryThatCannotVouchRemovesNobody(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.bind("acme", "secret", policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g"}})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	left := w.person("left@acme.example", nil, "acme")
	ch := w.fake.AddChannel("TACME", "secret", true, slackfake.BotID("TACME"), ann, left)
	w.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")

	in := w.in
	in.Workspace, in.Holders = "acme", w.holders()
	in.DirHolders = in.Holders
	obs, err := apply.Observe(context.Background(), w.clients["acme"], in)
	if err != nil {
		t.Fatal(err)
	}
	in.Observed = obs
	draft, err := reconcile.Derive(in)
	if err != nil {
		t.Fatal(err)
	}
	unreadable := map[string]rails.Vouch{}
	for _, a := range draft.Confirm() {
		unreadable[a] = rails.Vouch{Authoritative: false}
	}
	dec := draft.Decide(unreadable, reconcile.Confirmed{})
	res := apply.Apply(context.Background(), w.clients["acme"], dec, apply.Options{Workspace: "acme"})
	if len(res.Outcomes) != 0 || !slices.Contains(w.fake.Members(ch.ID), left) {
		t.Errorf("removed on an unvouched answer: %+v", res.Outcomes)
	}
	if dec.Report.Tick.Retrying != 1 {
		t.Errorf("tick = %+v", dec.Report.Tick)
	}
}

func TestAdoptingAPublicChannelJoinsItThenInvites(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	existing := w.fake.AddChannel("TACME", "legacy-name", false)
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}, Adopt: existing.ID})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	_, res := w.mustPass("acme")
	if res.Done() != 2 {
		t.Fatalf("outcomes = %+v", res.Outcomes)
	}
	if got := w.fake.Members(existing.ID); !slices.Contains(got, slackfake.BotID("TACME")) || !slices.Contains(got, ann) {
		t.Errorf("members = %v", got)
	}
	if got := w.rec.Actions(); !slices.Equal(got, []string{"roster.slack_channel.adopted", "roster.slack_member.invited"}) {
		t.Errorf("audit = %v", got)
	}
	if w.fake.Count("conversations.create") != 0 {
		t.Error("an adopted channel was created")
	}
}

// A private `adopt` the bot cannot see is held, and nothing is changed.
func TestAPrivateAdoptTheBotCannotSeeIsHeldAndChangesNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	priv := w.fake.AddChannel("TACME", "hidden", true) // the bot is not in it
	w.bind("acme", "ops", policy.SlackChannel{Private: true, From: []string{"g"}, Adopt: priv.ID})
	w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res := w.mustPass("acme")
	if len(res.Outcomes) != 0 || len(dec.Held) != 1 || !strings.Contains(dec.Held[0].Reason, "invite the bot first") {
		t.Fatalf("outcomes %+v held %+v", res.Outcomes, dec.Held)
	}
	if rec := apply.HeldRecord("acme", dec.Held[0]); rec.GetAction() != "roster.slack_action.held" {
		t.Errorf("held record = %v", rec.GetAction())
	}
}

// A channel of the declared name that already exists is taken over by name:
// a public one is joined and managed, with no `adopt` and no second channel.
func TestAnExistingPublicChannelIsAdoptedByNameJoinedThenInvited(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	existing := w.fake.AddChannel("TACME", "eng", false)
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res := w.mustPass("acme")
	if res.Done() != 2 || len(dec.Adopted) != 1 || !dec.Adopted[0].Joins {
		t.Fatalf("outcomes %+v adopted %+v", res.Outcomes, dec.Adopted)
	}
	if got := w.fake.Members(existing.ID); !slices.Contains(got, slackfake.BotID("TACME")) || !slices.Contains(got, ann) {
		t.Errorf("members = %v", got)
	}
	if w.fake.Count("conversations.create") != 0 {
		t.Error("a channel of that name was created beside the existing one")
	}
	if got := w.rec.Actions(); !slices.Equal(got, []string{"roster.slack_channel.adopted", "roster.slack_member.invited"}) {
		t.Errorf("audit = %v", got)
	}
	// The next pass finds it in step: it is managed now, not adopted again.
	if dec, res = w.mustPass("acme"); len(res.Outcomes) != 0 || len(dec.Held) != 0 {
		t.Errorf("second pass: outcomes %+v held %+v", res.Outcomes, dec.Held)
	}
}

// A private channel the bot is in is adopted by name and managed with
// nothing to join.
func TestAnExistingPrivateChannelTheBotIsInIsAdoptedByName(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	existing := w.fake.AddChannel("TACME", "eng", true, slackfake.BotID("TACME"))
	w.bind("acme", "eng", policy.SlackChannel{Private: true, From: []string{"g"}})
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res := w.mustPass("acme")
	if res.Done() != 1 || len(dec.Adopted) != 1 || dec.Adopted[0].Joins || !dec.Adopted[0].Private {
		t.Fatalf("outcomes %+v adopted %+v", res.Outcomes, dec.Adopted)
	}
	if got := w.fake.Members(existing.ID); !slices.Contains(got, ann) || w.fake.Count("conversations.join") != 0 || w.fake.Count("conversations.create") != 0 {
		t.Errorf("members %v, joins %d, creates %d", got, w.fake.Count("conversations.join"), w.fake.Count("conversations.create"))
	}
}

// A private channel of that name the bot cannot see is found out by asking
// Slack to create it: the refusal is a hold, never a duplicate under another
// name, and is not recorded as a failed change every pass.
func TestAPrivateChannelOfThatNameTheBotCannotSeeIsAHoldNotAFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.fake.AddChannel("TACME", "eng", true) // private, the bot is not in it
	channels := len(w.fake.Channels)
	w.bind("acme", "eng", policy.SlackChannel{Private: true, From: []string{"g"}})
	w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res, err := w.pass("acme", false, reconcile.Confirmed{})
	if err != nil {
		t.Fatal(err)
	}
	var held string
	for i := range res.Outcomes {
		if res.Outcomes[i].Action.Kind == "create" {
			held = res.Outcomes[i].Held
			if res.Outcomes[i].Err != nil || res.Outcomes[i].Done || res.Outcomes[i].Held == "" {
				t.Errorf("a held outcome = %+v, want a reason, no error and not done", res.Outcomes[i])
			}
		}
	}
	if held == "" || !strings.Contains(held, "a private channel named eng exists that the bot cannot see; invite the bot to it") {
		t.Fatalf("outcomes %+v: the refused create is not a hold (decision held %+v)", res.Outcomes, dec.Held)
	}
	if w.fake.Count("conversations.create") != 1 || len(w.fake.Channels) != channels {
		t.Errorf("creates %d, channels %d, want %d: nothing may be created under another name",
			w.fake.Count("conversations.create"), len(w.fake.Channels), channels)
	}
	for _, action := range w.rec.Actions() {
		if action == "roster.slack_channel.created" {
			t.Error("a hold was recorded as a failed channel creation")
		}
	}
}

// An archived channel keeps its name: it is held, never unarchived and never
// created again, and the read says so rather than the create being refused.
func TestAnArchivedChannelOfThatNameIsHeldNotUnarchived(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	old := w.fake.AddChannel("TACME", "eng", false)
	w.fake.Channels[old.ID].Archived = true
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}})
	w.person("ann@acme.example", []string{"g"}, "acme")
	dec, res := w.mustPass("acme")
	if len(res.Outcomes) != 0 || len(dec.Held) != 1 || !strings.Contains(dec.Held[0].Reason, "archived") {
		t.Fatalf("outcomes %+v held %+v", res.Outcomes, dec.Held)
	}
	if w.fake.Count("conversations.create") != 0 || w.fake.Count("conversations.join") != 0 || !w.fake.Channels[old.ID].Archived {
		t.Error("an archived channel was touched, or a second one created")
	}
}

func TestAFailedCreateSkipsItsInvitationsAndRecordsTheFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.bind("acme", "eng", policy.SlackChannel{From: []string{"g"}})
	w.person("ann@acme.example", []string{"g"}, "acme")
	w.fake.Fail("conversations.create", "restricted_action", 1)
	_, res, err := w.pass("acme", false, reconcile.Confirmed{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 2 || res.Done() != 0 || res.Failed() != 2 {
		t.Fatalf("outcomes = %+v", res.Outcomes)
	}
	if !errors.Is(res.Outcomes[0].Err, slackapp.ErrRestricted) || res.Outcomes[1].Skipped == "" {
		t.Errorf("outcomes = %+v", res.Outcomes)
	}
	if w.fake.Count("conversations.invite") != 0 {
		t.Error("invited into a channel that was not made")
	}
	recs := w.rec.Find("roster.slack_channel.created")
	if len(recs) != 1 || recs[0].GetOutcome().GetReason() == "" {
		t.Errorf("the failure was not recorded with its reason: %v", recs)
	}
}

func TestAPartialReadFailsTheWholeWorkspace(t *testing.T) {
	t.Parallel()
	setup := func(t *testing.T) *world {
		w := newWorld(t)
		w.bind("acme", "secret", policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g"}})
		ann := w.person("ann@acme.example", []string{"g"}, "acme")
		other := w.person("other@acme.example", nil, "acme")
		ch := w.fake.AddChannel("TACME", "secret", true, slackfake.BotID("TACME"), ann, other)
		w.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")
		return w
	}
	tests := map[string]struct {
		inject func(w *world)
		want   error
	}{
		"the lookup scope is missing":   {func(w *world) { w.fake.Fail("users.lookupByEmail", "missing_scope", -1) }, slackapp.ErrMissingScope},
		"the lookup is rate limited":    {func(w *world) { w.fake.RateLimit("users.lookupByEmail", "1", -1) }, slackapp.ErrRateLimited},
		"listing channels fails":        {func(w *world) { w.fake.Fail("conversations.list", "internal_error", -1) }, nil},
		"the members cannot be read":    {func(w *world) { w.fake.Fail("conversations.members", "fatal_error", -1) }, nil},
		"a member cannot be identified": {func(w *world) { w.fake.Fail("users.info", "missing_scope", -1) }, slackapp.ErrMissingScope},
		"the token is revoked":          {func(w *world) { w.fake.Fail("auth.test", "invalid_auth", -1) }, slackapp.ErrInvalidAuth},
		"members rate limited midway":   {func(w *world) { w.fake.RateLimit("conversations.members", "1", -1) }, slackapp.ErrRateLimited},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := setup(t)
			tc.inject(w)
			_, res, err := w.pass("acme", false, reconcile.Confirmed{})
			if err == nil {
				t.Fatal("the pass went on after a partial read")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if len(res.Outcomes) != 0 {
				t.Errorf("acted on a partial read: %+v", res.Outcomes)
			}
			for _, m := range []string{"conversations.create", "conversations.invite", "conversations.kick"} {
				if n := w.fake.Count(m); n != 0 {
					t.Errorf("%s called %d times", m, n)
				}
			}
		})
	}
}

func TestATokenOfAnotherWorkspaceIsRefused(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	in := w.in
	in.Workspace = "acme"
	_, err := apply.Observe(context.Background(), w.clients["globex"], in)
	if !errors.Is(err, apply.ErrWrongWorkspace) {
		t.Errorf("err = %v", err)
	}
}

// A workspace with no team recorded has no team to compare a token with, so
// no token is acted with.
func TestATokenIsRefusedWhenNoTeamIsRecorded(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	in := w.in
	in.Workspace = "acme"
	in.Facts = map[string]reconcile.Facts{"acme": {Owner: "C0acme", Domains: []string{"acme.example"}}}
	if _, err := apply.Observe(context.Background(), w.clients["acme"], in); !errors.Is(err, apply.ErrWrongWorkspace) {
		t.Errorf("err = %v", err)
	}
}

// Slack Connect, end to end over two workspaces: the host creates the
// channel and invites the guest's bot, the guest accepts, and each side then
// invites its own people.
func TestASharedChannelConvergesAcrossTwoPasses(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.in.Shared = []reconcile.SharedChannel{{Name: "platform", Host: "acme", With: []string{"globex"}, Sources: []string{"g"}}}
	ann := w.person("ann@acme.example", []string{"g"}, "acme")
	bob := w.person("bob@globex.example", []string{"g"}, "globex")
	jdoeAcme := w.person("j.doe@acme.example", []string{"g"}, "acme")
	w.fake.AddUser("TGLOBEX", "john@globex.example") // the same person's other account; not looked up

	// The guest goes first: nothing to accept yet, and that is waiting, not held.
	dec, res := w.mustPass("globex")
	if len(res.Outcomes) != 0 || dec.Report.Channels[0].State != status.ChannelWaiting || len(dec.Held) != 0 {
		t.Fatalf("guest before host: %+v %+v", dec.Report.Channels[0], res.Outcomes)
	}

	// The host creates, invites the guest bot, and invites its own people.
	dec, res = w.mustPass("acme")
	var kinds []status.Action
	for _, o := range res.Outcomes {
		kinds = append(kinds, o.Action.Kind)
	}
	if !slices.Equal(kinds, []status.Action{status.ActionCreate, status.ActionShareInvite, status.ActionInvite, status.ActionInvite}) {
		t.Fatalf("host actions = %v", kinds)
	}
	ch, _ := w.fake.ChannelNamed("TACME", "platform")
	if got := sorted(w.fake.Members(ch.ID)); !slices.Equal(got, sorted([]string{slackfake.BotID("TACME"), ann, jdoeAcme})) {
		t.Errorf("host members = %v", got)
	}

	// The host again: the invitation is pending; waiting, and nothing is resent.
	before := w.fake.Count("conversations.inviteShared")
	dec, _ = w.mustPass("acme")
	if w.fake.Count("conversations.inviteShared") != before || dec.Report.Channels[0].State != status.ChannelWaiting {
		t.Errorf("host re-sent or lost the wait: %+v", dec.Report.Channels[0])
	}

	// The guest accepts, then invites its own person (jdoe is the host's).
	dec, res = w.mustPass("globex")
	kinds = nil
	for _, o := range res.Outcomes {
		kinds = append(kinds, o.Action.Kind)
	}
	if !slices.Equal(kinds, []status.Action{status.ActionShareAccept, status.ActionInvite}) {
		t.Fatalf("guest actions = %v (%+v)", kinds, dec.Held)
	}
	if got := w.fake.Channel(ch.ID).Members; !slices.Contains(got, bob) {
		t.Errorf("shared members = %v", got)
	}
	if got := w.fake.Channel(ch.ID).Teams; !slices.Equal(got, []string{"TACME", "TGLOBEX"}) {
		t.Errorf("teams = %v", got)
	}

	// Now everything is in sync on both sides.
	for _, ws := range []string{"acme", "globex", "acme", "globex"} {
		dec, res = w.mustPass(ws)
		if len(res.Outcomes) != 0 {
			t.Fatalf("%s: not converged: %+v", ws, dec.Actions)
		}
		if dec.Report.Channels[0].State != status.ChannelOK {
			t.Errorf("%s: channel = %+v", ws, dec.Report.Channels[0])
		}
	}
	actions := w.rec.Actions()
	for _, want := range []string{"roster.slack_shared.invited", "roster.slack_shared.accepted"} {
		if !slices.Contains(actions, want) {
			t.Errorf("no %s in %v", want, actions)
		}
	}
}

func TestObserveLeavesOutInvitationsWhenNoSharedChannelNeedsThem(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	in := w.in
	in.Workspace = "acme"
	if _, err := apply.Observe(context.Background(), w.clients["acme"], in); err != nil {
		t.Fatal(err)
	}
	if n := w.fake.Count("conversations.listConnectInvites"); n != 0 {
		t.Errorf("listed invitations %d times with no shared channel", n)
	}
}
