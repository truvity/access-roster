package controller_test

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/slackapp"
	"github.com/truvity/access-roster/internal/slackapp/slackfake"
	"github.com/truvity/access-roster/internal/slackroster/connection"
	"github.com/truvity/access-roster/internal/slackroster/controller"
	"github.com/truvity/access-roster/internal/slackroster/reconcile"
	"github.com/truvity/access-roster/internal/slackroster/status"
	"github.com/truvity/access-roster/policy"
)

// testPolicy is the digest the rig's controller decides with.
const testPolicy = "rig-policy"

// console answers the two questions the controller asks, from a directory
// the test edits between passes.
type console struct {
	directoryrosterv1connect.AccessServiceClient
	mu sync.Mutex
	// dir maps an address to the groups it holds; absent means gone.
	dir map[string][]string
	// unsure are addresses the directory cannot vouch for right now.
	unsure map[string]bool
	policy string
	// explained counts the Explain questions, by address.
	explained map[string]int
}

func (c *console) ListHolders(
	_ context.Context, req *connect.Request[directoryrosterv1.ListHoldersRequest],
) (*connect.Response[directoryrosterv1.ListHoldersResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := &directoryrosterv1.ListHoldersResponse{PolicyDigest: c.policy}
	for _, addr := range slices.Sorted(maps.Keys(c.dir)) {
		if slices.Contains(c.dir[addr], req.Msg.GetGroup()) {
			out.Holders = append(out.Holders, &directoryrosterv1.Holder{Email: addr, Live: true, Authoritative: true})
		}
	}
	return connect.NewResponse(out), nil
}

func (c *console) Explain(
	_ context.Context, req *connect.Request[directoryrosterv1.ExplainRequest],
) (*connect.Response[directoryrosterv1.ExplainResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	addr := req.Msg.GetEmail()
	c.explained[addr]++
	groups, found := c.dir[addr]
	out := &directoryrosterv1.ExplainResponse{PolicyDigest: c.policy, Authoritative: !c.unsure[addr], Found: found}
	for _, g := range groups {
		out.Held = append(out.Held, &directoryrosterv1.HeldGroup{Group: g})
	}
	return connect.NewResponse(out), nil
}

func (c *console) set(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// reports keeps what the controller publishes.
type reports struct {
	mu        sync.Mutex
	documents map[string]string
	replaced  int
}

func (r *reports) Replace(_ context.Context, documents map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.documents, r.replaced = documents, r.replaced+1
	return nil
}

func (r *reports) Reports(context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.documents), nil
}

func (r *reports) workspace(t *testing.T, key string) status.Workspace {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	w, err := status.Decode(r.documents[status.Key(key)])
	if err != nil {
		t.Fatalf("the report for %s: %v", key, err)
	}
	return w
}

func (r *reports) channel(t *testing.T, ws, name string) status.Channel {
	t.Helper()
	channels := r.workspace(t, ws).Channels
	for i := range channels {
		if channels[i].Name == name {
			return channels[i]
		}
	}
	t.Fatalf("no channel %s in %s's report", name, ws)
	return status.Channel{}
}

type rig struct {
	t       *testing.T
	fake    *slackfake.Slack
	console *console
	audit   *audittest.Recorder
	reports *reports
	policy  policy.Policy
	creds   string
	records string
	users   map[string]string
	now     time.Time
	// controllers are kept across passes, one per setting: what a
	// controller remembers between passes is part of what is under test.
	controllers map[string]*controller.Controller
}

var teams = map[string]string{"acme": "TACME", "globex": "TGLOBEX"}

func (r *rig) writeCredential(ws, token string) {
	r.t.Helper()
	raw, err := connection.EncodeCredential(connection.Credential{
		Workspace: ws, AppID: "A1", ClientID: "c", ClientSecret: "s", BotToken: token,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.creds, connection.Key(ws)), raw, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) writeRecord(name, content string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(r.records, name), []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fake := slackfake.New(t)
	fake.AddTeam("TACME", "Acme")
	fake.AddTeam("TGLOBEX", "Globex")
	r := &rig{
		t: t, fake: fake, audit: audittest.New(t), reports: &reports{}, now: time.Now(),
		creds: t.TempDir(), records: t.TempDir(), users: map[string]string{}, controllers: map[string]*controller.Controller{},
		console: &console{policy: testPolicy, dir: map[string][]string{}, unsure: map[string]bool{}, explained: map[string]int{}},
		policy: policy.Policy{
			Groups: map[string]policy.Group{"g-eng": {}, "g-all": {}, "g-gx": {}},
			Slack: policy.Slack{Workspaces: map[string]policy.SlackWorkspace{
				"acme": {TeamID: "TACME", Domains: []string{"acme.example"}, Channels: map[string]policy.SlackChannel{
					"announce": {From: []string{"g-all"}},
					"eng":      {Private: true, Mode: policy.SlackModeStrict, From: []string{"g-eng"}},
				}},
				"globex": {TeamID: "TGLOBEX", Domains: []string{"globex.example"}, Channels: map[string]policy.SlackChannel{
					"ops": {From: []string{"g-gx"}},
				}},
			}},
		},
	}
	r.writeCredential("acme", slackfake.Token("TACME"))
	r.writeCredential("globex", slackfake.Token("TGLOBEX"))
	return r
}

// person is a directory entry and, when they have one, a Slack account.
func (r *rig) person(addr string, groups []string, team string) string {
	r.console.set(func() {
		if groups != nil {
			r.console.dir[addr] = groups
		}
	})
	if team == "" {
		return ""
	}
	id := r.fake.AddUser(teams[team], addr).ID
	r.users[addr] = id
	return id
}

// strictChannel is eng as it stands in Slack, made by the bot.
func (r *rig) strictChannel(members ...string) slackfake.Channel {
	ch := r.fake.AddChannel("TACME", "eng", true, append([]string{slackfake.BotID("TACME")}, members...)...)
	r.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")
	return *ch
}

func (r *rig) controller(enabled ...string) *controller.Controller {
	key := strings.Join(enabled, ",")
	if c, ok := r.controllers[key]; ok {
		return c
	}
	c := r.fresh(enabled...)
	r.controllers[key] = c
	return c
}

// fresh is a controller that remembers nothing: a restart.
func (r *rig) fresh(enabled ...string) *controller.Controller {
	on := map[string]bool{}
	for _, ws := range enabled {
		on[ws] = true
	}
	return controller.New(controller.Config{Enabled: on, CredentialsDir: r.creds, RecordsDir: r.records}, controller.Deps{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Access: r.console, Audit: r.audit, Status: r.reports, Policy: r.policy, Digest: testPolicy,
		Now: func() time.Time { return r.now },
		Slack: func(token string) *slackapp.Client {
			return slackapp.New(token, slackapp.WithBaseURL(r.fake.URL()), slackapp.WithPageSize(2), slackapp.WithRetries(1),
				slackapp.WithSleep(func(context.Context, time.Duration) error { return nil }))
		},
	})
}

// pass runs one pass with a controller that acts in the named workspaces.
func (r *rig) pass(enabled ...string) bool {
	return r.controller(enabled...).Pass(context.Background())
}

func (r *rig) mutations() int {
	n := 0
	for _, m := range []string{"conversations.create", "conversations.join", "conversations.invite", "conversations.kick", "conversations.inviteShared"} {
		n += r.fake.Count(m)
	}
	return n
}

func (r *rig) actions(action string) int {
	n := 0
	for _, a := range r.audit.Actions() {
		if a == action {
			n++
		}
	}
	return n
}

// Born disabled: every pass derives everything and changes nothing, and the
// report says what WOULD happen. Nothing is recorded, because nothing
// happened, and every workspace's report is written in one publication.
func TestADisabledWorkspaceIsADryRunThatPublishesItsReport(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	r.person("gus@globex.example", []string{"g-gx"}, "globex")

	r.pass()

	if n := r.mutations(); n != 0 {
		t.Errorf("a dry run called Slack %d times to change it", n)
	}
	if got := r.audit.Actions(); len(got) != 0 {
		t.Errorf("a dry run recorded %v", got)
	}
	if r.reports.replaced != 1 {
		t.Errorf("the reports were published %d times in one pass, want once", r.reports.replaced)
	}
	for _, ws := range []string{"acme", "globex"} {
		got := r.reports.workspace(t, ws)
		if got.Enabled || got.Tick.Outcome != status.OutcomeDryRun || got.Tick.Changes == 0 {
			t.Errorf("%s tick = %+v, want a dry run that counts what it would do", ws, got.Tick)
		}
	}
	if c := r.reports.channel(t, "acme", "eng"); c.State != status.ChannelWillCreate {
		t.Errorf("eng = %+v, want will-create", c)
	}
}

// Enabled: channels are made, people invited, the change recorded once each,
// and the next pass has nothing to do.
func TestAnEnabledWorkspaceIsMadeToMatch(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	r.person("gus@globex.example", []string{"g-gx"}, "globex")

	r.pass("acme")

	ch, ok := r.fake.ChannelNamed("TACME", "eng")
	if !ok || !ch.Private || !slices.Contains(ch.Members, ann) {
		t.Fatalf("eng = %+v (found %v), want a private channel with ann in it", ch, ok)
	}
	if _, made := r.fake.ChannelNamed("TGLOBEX", "ops"); made {
		t.Error("a workspace that is not enabled was changed")
	}
	got := r.reports.workspace(t, "acme")
	if !got.Enabled || got.Tick.Outcome != status.OutcomeApplied || got.Tick.Changes == 0 {
		t.Fatalf("tick = %+v, want applied", got.Tick)
	}
	if c := r.reports.channel(t, "acme", "eng"); c.State != status.ChannelOK || c.ID != ch.ID {
		t.Errorf("eng after the pass = %+v, want ok with the new id", c)
	}
	if r.actions("roster.slack_channel.created") != 2 || r.actions("roster.slack_member.invited") != 2 {
		t.Errorf("records = %v", r.audit.Actions())
	}
	if wsOps := r.reports.workspace(t, "globex"); wsOps.Tick.Outcome != status.OutcomeDryRun {
		t.Errorf("globex tick = %+v, want a dry run", wsOps.Tick)
	}

	recorded := len(r.audit.Actions())
	r.pass("acme")
	if got := r.reports.workspace(t, "acme"); got.Tick.Outcome != status.OutcomeInSync || got.Tick.Changes != 0 {
		t.Errorf("second pass tick = %+v, want in sync: %+v", got.Tick, got.Channels)
	}
	if len(r.audit.Actions()) != recorded {
		t.Errorf("a pass with nothing to do recorded %v", r.audit.Actions()[recorded:])
	}
}

// A console answering under another policy changes nothing, says so, and
// asks to be tried again soon; the next pass under one policy goes ahead.
func TestAnAnswerUnderAnotherPolicyChangesNothing(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	r.console.set(func() { r.console.policy = "old-policy" })

	if !r.pass("acme") {
		t.Error("a pass on answers under another policy did not ask to be tried again soon")
	}
	if n := r.mutations(); n != 0 {
		t.Errorf("changed Slack %d times on answers under another policy", n)
	}
	got := r.reports.workspace(t, "acme")
	if got.Tick.Outcome != status.OutcomeFailed || !strings.Contains(got.Tick.Error, "different policy") {
		t.Errorf("tick = %+v, want failed, naming the policy difference", got.Tick)
	}

	r.console.set(func() { r.console.policy = testPolicy })
	if r.pass("acme") {
		t.Error("a pass under one policy asked to be tried again soon")
	}
	if n := r.mutations(); n == 0 {
		t.Error("the pass under one policy changed nothing")
	}
}

// An Explain answer under another policy holds the removal it would have
// confirmed, and asks to be tried again.
func TestARemovalConfirmedUnderAnotherPolicyIsHeld(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-eng"}, "acme")
	gone := r.person("gone@acme.example", nil, "acme")
	ch := r.strictChannel(ann, gone)

	// Holders come under this policy; the replica that answers Explain is
	// still on the old one.
	other := &policySplit{console: r.console}
	c := controller.New(controller.Config{Enabled: map[string]bool{"acme": true}, CredentialsDir: r.creds, RecordsDir: r.records}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Access: other, Audit: r.audit, Status: r.reports,
		Policy: r.policy, Digest: testPolicy,
		Slack: func(token string) *slackapp.Client {
			return slackapp.New(token, slackapp.WithBaseURL(r.fake.URL()), slackapp.WithRetries(1))
		},
	})
	if !c.Pass(context.Background()) {
		t.Error("an Explain under another policy did not ask to be tried again soon")
	}
	if !slices.Contains(r.fake.Members(ch.ID), gone) {
		t.Error("a removal was confirmed by an answer under another policy")
	}
}

// policySplit answers Explain under another policy and everything else
// under the rig's.
type policySplit struct {
	directoryrosterv1connect.AccessServiceClient
	console *console
}

func (p *policySplit) ListHolders(ctx context.Context, req *connect.Request[directoryrosterv1.ListHoldersRequest],
) (*connect.Response[directoryrosterv1.ListHoldersResponse], error) {
	return p.console.ListHolders(ctx, req)
}

func (p *policySplit) Explain(ctx context.Context, req *connect.Request[directoryrosterv1.ExplainRequest],
) (*connect.Response[directoryrosterv1.ExplainResponse], error) {
	res, err := p.console.Explain(ctx, req)
	if err == nil {
		res.Msg.PolicyDigest = "old-policy"
	}
	return res, err
}

// A directory that cannot vouch for a person removes nobody: the row says
// retrying, with the reason, and the removal goes ahead when it can.
func TestAnUnvouchedRemovalHoldsAndIsRetried(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-eng"}, "acme")
	gone := r.person("gone@acme.example", nil, "acme")
	ch := r.strictChannel(ann, gone)
	announce := r.fake.AddChannel("TACME", "announce", false, slackfake.BotID("TACME"))
	r.fake.Channels[announce.ID].Creator = slackfake.BotID("TACME")
	r.console.set(func() { r.console.unsure["gone@acme.example"] = true })

	r.pass("acme")
	if !slices.Contains(r.fake.Members(ch.ID), gone) || r.fake.Count("conversations.kick") != 0 {
		t.Fatal("somebody was removed on an answer the directory could not vouch for")
	}
	eng := r.reports.channel(t, "acme", "eng")
	retrying := false
	for _, m := range eng.Members {
		retrying = retrying || (m.UserID == gone && m.State == status.StateRetrying && m.Reason != "")
	}
	if !retrying {
		t.Errorf("eng rows = %+v, want the unvouched person retrying with a reason", eng.Members)
	}
	if got := r.reports.workspace(t, "acme").Tick; got.Outcome != status.OutcomeRetrying || got.Retrying != 1 {
		t.Errorf("tick = %+v, want retrying", got)
	}

	r.console.set(func() { delete(r.console.unsure, "gone@acme.example") })
	r.pass("acme")
	if slices.Contains(r.fake.Members(ch.ID), gone) {
		t.Error("the removal did not go ahead once the directory vouched")
	}
	if r.actions("roster.slack_member.removed") != 1 {
		t.Errorf("records = %v", r.audit.Actions())
	}
}

// A hold is recorded when it becomes held, not every pass, and not again
// after a restart or a failed pass between.
func TestAHoldIsRecordedOnceAndARestartRecordsNothingAgain(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	r.person("new@acme.example", []string{"g-all"}, "") // no Slack account: held
	held := func() int { return r.actions("roster.slack_action.held") }

	r.pass("acme")
	if held() == 0 {
		t.Fatalf("a held invitation was not recorded: %v", r.audit.Actions())
	}
	first := held()
	r.pass("acme")
	if held() != first {
		t.Errorf("a hold that stayed was recorded again: %d then %d", first, held())
	}

	// A failed pass keeps the rows and what was recorded.
	r.console.set(func() { r.console.policy = "another-policy" })
	r.pass("acme")
	failed := r.reports.workspace(t, "acme")
	if failed.Tick.Outcome != status.OutcomeFailed || len(failed.Recorded) == 0 {
		t.Fatalf("failed report = %+v, want failed and still carrying what it recorded", failed)
	}
	r.console.set(func() { r.console.policy = testPolicy })

	restarted := r.fresh("acme")
	restarted.Pass(context.Background())
	if held() != first {
		t.Errorf("after a failed pass and a restart holds were recorded %d times in all, want still %d", held(), first)
	}
}

// A leaver is reported and recorded once, and nobody acts on them.
func TestALeaverIsReportedAndRecordedOnce(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-all"}, "acme")
	left := r.person("left@acme.example", nil, "acme")
	ch := r.fake.AddChannel("TACME", "announce", false, slackfake.BotID("TACME"), ann, left)
	r.fake.Channels[ch.ID].Creator = slackfake.BotID("TACME")

	r.pass("acme")
	r.pass("acme")
	r.fresh("acme").Pass(context.Background())

	leavers := r.reports.workspace(t, "acme").Leavers
	if len(leavers) != 1 || leavers[0].UserID != left {
		t.Fatalf("leavers = %+v", leavers)
	}
	if n := r.actions("roster.slack_leaver.reported"); n != 1 {
		t.Errorf("the leaver was recorded %d times, want once", n)
	}
	if r.fake.Count("conversations.kick") != 0 {
		t.Error("a leaver was removed from a public channel")
	}
}

// A dry run that has leavers and holds says so in its report and records
// nothing.
func TestADryRunRecordsNothingEvenWithHoldsAndLeavers(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-all"}, "acme")
	left := r.person("left@acme.example", nil, "acme")
	r.person("new@acme.example", []string{"g-all"}, "")
	announce := r.fake.AddChannel("TACME", "announce", false, slackfake.BotID("TACME"), ann, left)
	r.fake.Channels[announce.ID].Creator = slackfake.BotID("TACME")

	r.pass()
	r.pass()

	if got := r.audit.Actions(); len(got) != 0 {
		t.Errorf("a dry run recorded %v", got)
	}
	if got := r.reports.workspace(t, "acme"); len(got.Leavers) != 1 || got.Tick.Held == 0 || len(got.Recorded) != 0 {
		t.Errorf("report = %+v, want a leaver and holds reported, and nothing marked recorded", got)
	}
}

// One workspace failing does not stop another, and the failed one keeps the
// rows it last knew.
func TestOneWorkspacesFailureDoesNotBlockAnother(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	r.person("gus@globex.example", []string{"g-gx"}, "globex")
	r.pass("acme", "globex")
	if got := r.reports.workspace(t, "globex"); got.Tick.Outcome != status.OutcomeApplied {
		t.Fatalf("globex tick = %+v", got.Tick)
	}

	// globex's token stops working; acme gains a person.
	r.writeCredential("globex", "a-revoked-token")
	r.person("bea@acme.example", []string{"g-all"}, "acme")
	r.pass("acme", "globex")

	globex := r.reports.workspace(t, "globex")
	if globex.Tick.Outcome != status.OutcomeFailed || globex.Tick.Error == "" {
		t.Errorf("globex tick = %+v, want failed with a reason", globex.Tick)
	}
	if len(globex.Channels) == 0 {
		t.Error("the failed workspace's rows were dropped instead of kept")
	}
	acme := r.reports.workspace(t, "acme")
	if acme.Tick.Outcome != status.OutcomeApplied {
		t.Errorf("acme tick = %+v, want applied despite globex failing", acme.Tick)
	}
	if ch, _ := r.fake.ChannelNamed("TACME", "announce"); !slices.Contains(ch.Members, r.users["bea@acme.example"]) {
		t.Error("acme's new person was not invited")
	}
}

// A workspace that is not connected, or created and not installed, is
// reported so, and the rest go on.
func TestAWorkspaceWithoutABotTokenIsNotInstalled(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	r.writeCredential("globex", "")
	if err := os.Remove(filepath.Join(r.creds, connection.Key("acme"))); err != nil {
		t.Fatal(err)
	}
	// A reserved key and kubelet bookkeeping in the mounted directory are not
	// workspaces.
	for _, name := range []string{"_confirm.acme.json", "..data", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(r.creds, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	r.pass("acme", "globex")

	if got := r.reports.workspace(t, "globex").Tick; got.Outcome != status.OutcomeFailed || !strings.Contains(got.Error, "not installed") {
		t.Errorf("globex tick = %+v, want failed, not installed", got)
	}
	if got := r.reports.workspace(t, "acme").Tick; got.Outcome != status.OutcomeFailed || !strings.Contains(got.Error, "not connected") {
		t.Errorf("acme tick = %+v, want failed, not connected", got)
	}
	if n := r.mutations(); n != 0 {
		t.Errorf("a workspace with no bot token was changed %d times", n)
	}
}

// One operator confirmation of a removal set satisfies the channel's
// breaker and the workspace's.
func TestOneConfirmationSatisfiesBothBreakers(t *testing.T) {
	r := newRig(t)
	keep := []string{}
	for _, n := range []string{"a", "b"} {
		keep = append(keep, r.person(n+"@acme.example", []string{"g-eng"}, "acme"))
	}
	var leaving []string
	for _, n := range []string{"w", "x", "y", "z"} {
		leaving = append(leaving, r.person(n+"@acme.example", nil, "acme"))
	}
	ch := r.strictChannel(append(slices.Clone(keep), leaving...)...)

	r.pass("acme")
	tripped := r.reports.workspace(t, "acme")
	if tripped.Breaker == nil || tripped.Breaker.Confirmed || len(r.fake.Members(ch.ID)) != 1+6 {
		t.Fatalf("breaker = %+v, members %v: want a tripped breaker and nobody removed", tripped.Breaker, r.fake.Members(ch.ID))
	}
	if r.fake.Count("conversations.kick") != 0 {
		t.Fatal("removals went ahead over the limit")
	}
	if held := r.reports.channel(t, "acme", "eng"); held.Breaker == nil {
		t.Fatal("the channel's own breaker did not trip")
	}

	// A confirmation of some other set confirms nothing.
	stale, err := connection.EncodeConfirmation(connection.Confirmation{Workspace: "acme", Fingerprint: "0000", By: "op", At: r.now})
	if err != nil {
		t.Fatal(err)
	}
	r.writeRecord(connection.ConfirmationKey("acme", ""), stale)
	r.pass("acme")
	if r.fake.Count("conversations.kick") != 0 {
		t.Fatal("a confirmation of another set let removals through")
	}

	// One confirmation, of exactly this set, once.
	raw, err := connection.EncodeConfirmation(connection.Confirmation{
		Workspace: "acme", Fingerprint: tripped.Breaker.Fingerprint, By: "op", At: r.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.writeRecord(connection.ConfirmationKey("acme", ""), raw)
	r.pass("acme")
	if got := r.fake.Members(ch.ID); len(got) != 1+2 {
		t.Errorf("members after one confirmation = %v, want the bot and the two who belong", got)
	}
	if r.fake.Count("conversations.kick") != 4 {
		t.Errorf("kicks = %d, want 4", r.fake.Count("conversations.kick"))
	}
}

// A confirmation older than its TTL confirms nothing.
func TestAnExpiredConfirmationConfirmsNothing(t *testing.T) {
	r := newRig(t)
	var members []string
	for _, n := range []string{"a", "w", "x", "y"} {
		members = append(members, r.person(n+"@acme.example", nil, "acme"))
	}
	r.person("a@acme.example", []string{"g-eng"}, "")
	ch := r.strictChannel(members...)

	r.pass("acme")
	fp := r.reports.workspace(t, "acme").Breaker
	if fp == nil {
		t.Fatalf("no breaker tripped; members %v", r.fake.Members(ch.ID))
	}
	raw, err := connection.EncodeConfirmation(connection.Confirmation{
		Workspace: "acme", Fingerprint: fp.Fingerprint, By: "op", At: r.now.Add(-connection.ConfirmationTTL - time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.writeRecord(connection.ConfirmationKey("acme", ""), raw)
	r.pass("acme")
	if r.fake.Count("conversations.kick") != 0 {
		t.Error("an expired confirmation let removals through")
	}
}

// The directory is asked about an address once a pass, however many
// channels name the person.
func TestTheDirectoryIsAskedOncePerAddressPerPass(t *testing.T) {
	r := newRig(t)
	r.policy.Slack.Workspaces["acme"].Channels["sec"] = policy.SlackChannel{Private: true, Mode: policy.SlackModeStrict, From: []string{"g-eng"}}
	ann := r.person("ann@acme.example", []string{"g-eng"}, "acme")
	gone := r.person("gone@acme.example", nil, "acme")
	r.strictChannel(ann, gone)
	sec := r.fake.AddChannel("TACME", "sec", true, slackfake.BotID("TACME"), ann, gone)
	r.fake.Channels[sec.ID].Creator = slackfake.BotID("TACME")

	r.pass("acme")

	r.console.mu.Lock()
	defer r.console.mu.Unlock()
	if n := r.console.explained["gone@acme.example"]; n != 1 {
		t.Errorf("the directory was asked about one address %d times in a pass, want once", n)
	}
	if r.fake.Count("conversations.kick") != 2 {
		t.Errorf("kicks = %d, want the person removed from both channels", r.fake.Count("conversations.kick"))
	}
}

// Shared channel definitions the console keeps are read and validated
// against the policy: a good one is acted on, a refused one is reported on
// its host and acted on by nobody.
func TestSharedChannelRecordsAreValidatedAndReported(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	good := reconcile.SharedChannel{Name: "joint", Host: "acme", With: []string{"globex"}, From: []string{"g-all"}}
	bad := reconcile.SharedChannel{Name: "broken", Host: "acme", With: []string{"nowhere"}, From: []string{"g-all"}}
	for _, s := range []reconcile.SharedChannel{good, bad} {
		raw, err := connection.EncodeShared(s)
		if err != nil {
			t.Fatal(err)
		}
		r.writeRecord(connection.SharedKey(s.Name), raw)
	}
	r.writeRecord(connection.SharedKey("garbled"), "not json")

	r.pass("acme")

	if _, made := r.fake.ChannelNamed("TACME", "joint"); !made {
		t.Error("a valid shared channel was not created on its host")
	}
	if _, made := r.fake.ChannelNamed("TACME", "broken"); made {
		t.Error("a refused shared channel was created")
	}
	refused := r.reports.channel(t, "acme", "broken")
	if refused.State != status.ChannelHeld || !refused.Shared || !strings.Contains(refused.Reason, "nowhere") {
		t.Errorf("the refused definition = %+v, want held, naming why", refused)
	}
}
