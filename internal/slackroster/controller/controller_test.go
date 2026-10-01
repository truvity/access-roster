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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/audit/audittest"
	"github.com/truvity/access-roster/internal/kube"
	"github.com/truvity/access-roster/internal/server"
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
	// served are the domains each connected directory serves, by its
	// workspace id; servedErr is the answer when it cannot be read.
	served    map[string][]string
	servedErr error
}

func (c *console) ListServedDomains(
	context.Context, *connect.Request[directoryrosterv1.ListServedDomainsRequest],
) (*connect.Response[directoryrosterv1.ListServedDomainsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.servedErr != nil {
		return nil, c.servedErr
	}
	out := &directoryrosterv1.ListServedDomainsResponse{}
	for _, id := range slices.Sorted(maps.Keys(c.served)) {
		out.Directories = append(out.Directories, &directoryrosterv1.DirectoryDomains{
			WorkspaceId: id, PrimaryDomain: c.served[id][0], Domains: c.served[id],
		})
	}
	return connect.NewResponse(out), nil
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
		console: &console{
			policy: testPolicy, dir: map[string][]string{}, unsure: map[string]bool{}, explained: map[string]int{},
			// Each Slack workspace is owned by a directory that serves its domain.
			served: map[string][]string{"C0acme": {"acme.example"}, "C0globex": {"globex.example"}},
		},
		policy: policy.Policy{
			Groups: map[string]policy.Group{"g-eng": {}, "g-all": {}, "g-gx": {}},
			Slack: policy.Slack{Workspaces: map[string]policy.SlackWorkspace{
				"acme": {Channels: map[string]policy.SlackChannel{
					"announce": {From: []string{"g-all"}},
					"eng":      {Private: true, Mode: policy.SlackModeStrict, From: []string{"g-eng"}},
				}},
				"globex": {Channels: map[string]policy.SlackChannel{
					"ops": {From: []string{"g-gx"}},
				}},
			}},
		},
	}
	r.writeCredential("acme", slackfake.Token("TACME"))
	r.writeCredential("globex", slackfake.Token("TGLOBEX"))
	r.writeConnection("acme", "TACME", "C0acme")
	r.writeConnection("globex", "TGLOBEX", "C0globex")
	return r
}

// writeConnection is the record the console keeps when a workspace is
// connected: the team recorded at its first install and the directory chosen
// as its owner.
func (r *rig) writeConnection(ws, team, owner string) {
	r.t.Helper()
	raw, err := connection.EncodeRecord(connection.Record{
		Workspace: ws, TeamID: team, Owner: owner, AppID: "A1", BotUserID: slackfake.BotID(team),
		ConnectedAt: r.now, ConnectedBy: "ada@acme.example",
	})
	if err != nil {
		r.t.Fatal(err)
	}
	r.writeRecord(connection.Key(ws), raw)
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
	return r.freshWith(0, enabled...)
}

// freshWith is a restart that polls the credentials every poll.
func (r *rig) freshWith(poll time.Duration, enabled ...string) *controller.Controller {
	on := map[string]bool{}
	for _, ws := range enabled {
		on[ws] = true
	}
	cfg := controller.Config{Enabled: on, CredentialsDir: r.creds, RecordsDir: r.records, CredentialPoll: poll}
	if poll > 0 {
		cfg.Interval = time.Hour
	}
	return controller.New(cfg, controller.Deps{
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

func (p *policySplit) ListServedDomains(ctx context.Context, req *connect.Request[directoryrosterv1.ListServedDomainsRequest],
) (*connect.Response[directoryrosterv1.ListServedDomainsResponse], error) {
	return p.console.ListServedDomains(ctx, req)
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
// reported as WAITING (an expected state, never a failure), and the rest go on.
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

	if got := r.reports.workspace(t, "globex").Tick; got.Outcome != status.OutcomeWaiting || got.Error != "" {
		t.Errorf("globex tick = %+v, want waiting with no error (created, not installed)", got)
	}
	if got := r.reports.workspace(t, "acme").Tick; got.Outcome != status.OutcomeWaiting || got.Error != "" {
		t.Errorf("acme tick = %+v, want waiting with no error (not connected)", got)
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

// The console's shared channel service and the controller agree on the
// record: what the service writes into the ConfigMap, mounted as files, is
// read back by the controller, validated and acted on, for a channel with a
// single visibility and for one with a visibility per side.
func TestTheControllerReadsWhatTheConsoleWrites(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	// The service validates against the same policy in the shape the real
	// one has.
	declared := r.policy
	declared.Version = 1
	declared.Slack.Workspaces = maps.Clone(r.policy.Slack.Workspaces)
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatal(err)
	}
	client := kube.NewClient(k8sfake.NewClientset(), "ns", "release")
	shared := kube.NewSlackShared(client)
	console, err := server.NewConsole(context.Background(), server.ConsoleDeps{Authorizer: access.NewAuthorizer(set, nil, 0), SlackShared: shared})
	if err != nil {
		t.Fatal(err)
	}
	ctx := server.WithIdentity(context.Background(), access.Identity{Email: "ada@acme.example", Role: access.RoleOperator})
	for _, def := range []*directoryrosterv1.SlackSharedChannelDefinition{
		{Name: "joint", Host: "acme", With: []string{"globex"}, From: []string{"g-all"}, Private: true},
		{Name: "sided", Host: "acme", With: []string{"globex"}, From: []string{"g-all"}, PrivatePerSide: map[string]bool{"acme": true, "globex": false}},
	} {
		if _, err = console.CreateSlackSharedChannel(ctx, connect.NewRequest(&directoryrosterv1.CreateSlackSharedChannelRequest{Channel: def})); err != nil {
			t.Fatalf("create %s: %v", def.Name, err)
		}
	}
	cm, err := client.API().CoreV1().ConfigMaps("ns").Get(context.Background(), shared.ConfigMapName(), metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for key, raw := range cm.Data {
		r.writeRecord(key, raw)
	}

	r.pass("acme")

	for name, private := range map[string]bool{"joint": true, "sided": true} {
		ch, made := r.fake.ChannelNamed("TACME", name)
		if !made {
			t.Fatalf("the controller did not act on the record the console wrote for %s", name)
		}
		if ch.Private != private {
			t.Errorf("%s private = %v, want %v", name, ch.Private, private)
		}
		if rep := r.reports.channel(t, "acme", name); rep.State == status.ChannelHeld {
			t.Errorf("%s is held: %s", name, rep.Reason)
		}
	}
}

// A person is looked up by the OWNING directory's served domains, read from
// the console every pass: serving a second domain finds the people in it with
// no change to the policy.
func TestPeopleAreFoundByTheOwningDirectorysServedDomains(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	late := r.person("late@acme.example.org", []string{"g-all"}, "acme")

	r.pass("acme")
	announce, ok := r.fake.ChannelNamed("TACME", "announce")
	if !ok || slices.Contains(announce.Members, late) {
		t.Fatalf("announce = %+v (found %v): a person outside the served domains was invited", announce, ok)
	}
	held := false
	for _, m := range r.reports.channel(t, "acme", "announce").Members {
		held = held || (m.Email == "late@acme.example.org" && m.State == status.StateHeld)
	}
	if !held {
		t.Errorf("the person in an unserved domain is not held: %+v", r.reports.channel(t, "acme", "announce").Members)
	}

	r.console.set(func() { r.console.served["C0acme"] = []string{"acme.example", "acme.example.org"} })
	r.pass("acme")
	announce, _ = r.fake.ChannelNamed("TACME", "announce")
	if !slices.Contains(announce.Members, late) {
		t.Errorf("announce members = %v: the owner serves the domain now, so the person is invited", announce.Members)
	}
}

// Without an owner nobody can be looked up: every person is held with the
// reason, and nothing is invited.
func TestAWorkspaceWithNoOwnerHoldsItsPeople(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	r.writeConnection("acme", "TACME", "")

	r.pass("acme")

	if n := r.fake.Count("conversations.invite"); n != 0 {
		t.Errorf("%d people were invited into a workspace with no owning directory", n)
	}
	members := r.reports.channel(t, "acme", "announce").Members
	if len(members) != 1 || members[0].State != status.StateHeld || members[0].Reason != reconcile.NoOwner {
		t.Errorf("members = %+v, want one held row saying %q", members, reconcile.NoOwner)
	}
}

// A directory that cannot be read, or an owner that is not connected here,
// fails the pass rather than reading as a workspace with nobody in it: a
// strict channel must not empty itself on a question nobody answered.
func TestAnUnreadableOrUnconnectedOwnerFailsThePass(t *testing.T) {
	for name, set := range map[string]func(*rig){
		"the console cannot say": func(r *rig) { r.console.servedErr = connect.NewError(connect.CodeUnavailable, io.ErrUnexpectedEOF) },
		"the owner is not connected": func(r *rig) {
			delete(r.console.served, "C0acme")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			ann := r.person("ann@acme.example", []string{"g-eng"}, "acme")
			gone := r.person("gone@acme.example", nil, "acme")
			ch := r.strictChannel(ann, gone)
			r.console.set(func() { set(r) })

			r.pass("acme")

			if got := r.reports.workspace(t, "acme"); got.Tick.Outcome != status.OutcomeFailed || !strings.Contains(got.Tick.Error, "owning directory") {
				t.Errorf("tick = %+v, want failed, naming the owning directory", got.Tick)
			}
			if !slices.Contains(r.fake.Members(ch.ID), gone) || r.mutations() != 0 {
				t.Error("a failed read of the owner's domains changed the workspace")
			}
		})
	}
}

// A bot token for another Slack team than the one recorded at the first
// install is refused: the workspace fails, and nothing is changed.
func TestATokenForAnotherTeamThanTheRecordedOneFailsThePass(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	r.writeConnection("acme", "TGLOBEX", "C0acme")

	r.pass("acme")

	if got := r.reports.workspace(t, "acme"); got.Tick.Outcome != status.OutcomeFailed || !strings.Contains(got.Tick.Error, "recorded at the first install") {
		t.Errorf("tick = %+v, want failed with the wrong-team refusal", got.Tick)
	}
	if r.mutations() != 0 {
		t.Error("a token for the wrong team was acted with")
	}
}

// A bound channel that already exists is taken over by name, and the
// adoption is recorded once: a public one the bot joins (recorded by the
// join), a private one the bot is in (recorded when first managed), and
// neither again on the next pass or after a restart. Nothing is created
// beside them.
func TestAnExistingChannelIsAdoptedByNameAndRecordedOnce(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-all", "g-eng"}, "acme")
	public := r.fake.AddChannel("TACME", "announce", false)
	private := r.fake.AddChannel("TACME", "eng", true, slackfake.BotID("TACME"))
	adopted := func() int { return r.actions("roster.slack_channel.adopted") }

	r.pass("acme")

	if got := r.fake.Members(public.ID); !slices.Contains(got, slackfake.BotID("TACME")) || !slices.Contains(got, ann) {
		t.Errorf("the public channel's members = %v, want the bot joined and ann invited", got)
	}
	if got := r.fake.Members(private.ID); !slices.Contains(got, ann) {
		t.Errorf("the private channel's members = %v, want ann invited", got)
	}
	if r.fake.Count("conversations.create") != 0 || adopted() != 2 {
		t.Fatalf("creates %d adopted records %d (%v), want none and two", r.fake.Count("conversations.create"), adopted(), r.audit.Actions())
	}
	if c := r.reports.channel(t, "acme", "eng"); c.State != status.ChannelOK || c.ID != private.ID {
		t.Errorf("eng = %+v, want ok under the existing channel's id", c)
	}

	r.pass("acme")
	r.fresh("acme").Pass(context.Background())
	if adopted() != 2 {
		t.Errorf("adoptions were recorded %d times in all, want 2 (once each, not again after a pass or a restart)", adopted())
	}
}

// A private channel of the declared name that the bot cannot see is found out
// when Slack refuses to create it: the channel is held, saying to invite the
// bot, nothing is created under another name, the hold is recorded once and
// no failed channel creation is recorded for it, pass after pass.
func TestAPrivateChannelTheBotCannotSeeIsHeldOnceAndNeverDuplicated(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-eng"}, "acme")
	r.fake.AddChannel("TACME", "eng", true) // the bot is not in it

	r.pass("acme")
	r.pass("acme")

	eng := r.reports.channel(t, "acme", "eng")
	if eng.State != status.ChannelHeld || !strings.Contains(eng.Reason, "a private channel named eng exists that the bot cannot see; invite the bot to it") {
		t.Fatalf("eng = %+v, want held, saying to invite the bot", eng)
	}
	engs := 0
	for _, ch := range r.fake.Channels {
		if strings.Contains(ch.Name, "eng") {
			engs++
		}
	}
	if engs != 1 {
		t.Errorf("%d channels are named for eng, want the one that was there: a duplicate was made", engs)
	}
	if got := r.actions("roster.slack_channel.created"); got != 1 {
		// "announce" is created; the refused "eng" is a hold, not a failed creation.
		t.Errorf("channel creations recorded = %d (%v), want only announce's", got, r.audit.Actions())
	}
	if got := r.actions("roster.slack_action.held"); got != 1 {
		t.Errorf("the hold was recorded %d times (%v), want once", got, r.audit.Actions())
	}
	if h := r.reports.workspace(t, "acme").Tick.Held; h == 0 {
		t.Error("the tick does not count the hold")
	}
}

// An archived channel of the declared name is held and left archived.
func TestAnArchivedChannelIsHeldAndNeverUnarchived(t *testing.T) {
	r := newRig(t)
	r.person("ann@acme.example", []string{"g-all"}, "acme")
	old := r.fake.AddChannel("TACME", "announce", false)
	r.fake.Channels[old.ID].Archived = true

	r.pass("acme")

	got := r.reports.channel(t, "acme", "announce")
	if got.State != status.ChannelHeld || !strings.Contains(got.Reason, "archived: unarchive it in Slack or rename it") {
		t.Errorf("announce = %+v", got)
	}
	if !r.fake.Channels[old.ID].Archived || len(r.fake.Members(old.ID)) != 0 {
		t.Error("an archived channel was touched")
	}
}

// Adopting a strict channel is not a licence to empty it: the first pass
// after adopting it is subject to the breaker like any other, and nobody is
// removed.
func TestTheFirstPassOverAnAdoptedStrictChannelIsHeldToTheBreaker(t *testing.T) {
	r := newRig(t)
	ann := r.person("ann@acme.example", []string{"g-eng"}, "acme")
	var members []string
	for _, who := range []string{"a", "b", "c"} {
		members = append(members, r.person(who+"@acme.example", nil, "acme")) // in Slack, gone from the directory
	}
	// Made by somebody else, so the roster adopts it: one wanted, three gone.
	ch := r.fake.AddChannel("TACME", "eng", true, append([]string{slackfake.BotID("TACME"), ann}, members...)...)

	r.pass("acme")

	for _, id := range members {
		if !slices.Contains(r.fake.Members(ch.ID), id) {
			t.Fatalf("%s was removed on the first pass after adoption", id)
		}
	}
	if r.fake.Count("conversations.kick") != 0 {
		t.Errorf("%d removals went through the breaker", r.fake.Count("conversations.kick"))
	}
	if eng := r.reports.channel(t, "acme", "eng"); eng.Breaker == nil || eng.Breaker.Affected != 3 || eng.Breaker.Total != 4 {
		t.Errorf("eng breaker = %+v, want 3 of 4 held", eng.Breaker)
	}
	if r.actions("roster.slack_channel.adopted") != 1 {
		t.Errorf("adoptions recorded = %d (%v)", r.actions("roster.slack_channel.adopted"), r.audit.Actions())
	}
}

func (r *reports) published() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.replaced
}

// waitFor polls until cond holds, or fails after the timeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// An install lands as a changed credential in the mounted Secret. The
// controller notices within its poll period and passes then, instead of
// leaving the result for the full interval (an hour here); a poll that finds
// nothing changed passes nothing, and a change to a reserved key (an
// operator's confirmation, a consumed install state) is not a connect.
func TestAChangedCredentialRunsAPassWithoutWaitingForTheInterval(t *testing.T) {
	r := newRig(t)
	r.writeCredential("globex", "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.freshWith(10*time.Millisecond, "acme").Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor(t, "the first pass", func() bool { return r.reports.published() >= 1 })
	if got := r.reports.workspace(t, "globex").Tick.Outcome; got != status.OutcomeWaiting {
		t.Fatalf("globex before its install = %q, want waiting", got)
	}

	// Nothing changed: no further pass in many polls.
	time.Sleep(150 * time.Millisecond)
	if got := r.reports.published(); got != 1 {
		t.Fatalf("%d publications with nothing changed, want 1", got)
	}
	// A reserved key changing is not a credential.
	if err := os.WriteFile(filepath.Join(r.creds, "_consumed.x"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := r.reports.published(); got != 1 {
		t.Fatalf("%d publications after a reserved key changed, want 1", got)
	}

	r.writeCredential("globex", slackfake.Token("TGLOBEX"))
	waitFor(t, "a pass after the credential changed", func() bool { return r.reports.published() >= 2 })
	if got := r.reports.workspace(t, "globex").Tick.Outcome; got == status.OutcomeWaiting {
		t.Errorf("globex after its install is still %q", got)
	}
}

// An operator's request for a pass is a marker in the records. A request newer
// than the last one acted on runs a pass at once; the one that was already
// there when the controller started, and one that is not newer, run nothing.
func TestARequestedPassRunsOnceForANewerMarkerOnly(t *testing.T) {
	r := newRig(t)
	marker := func(at time.Time) {
		raw, err := connection.EncodePassRequest(connection.PassRequest{Workspace: "acme", At: at, By: "ada@acme.example"})
		if err != nil {
			t.Fatal(err)
		}
		r.writeRecord(connection.PassKey("acme"), raw)
	}
	base := time.Now().UTC().Truncate(time.Second)
	marker(base)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.freshWith(10*time.Millisecond, "acme").Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitFor(t, "the first pass", func() bool { return r.reports.published() >= 1 })
	time.Sleep(150 * time.Millisecond)
	if got := r.reports.published(); got != 1 {
		t.Fatalf("%d publications with only the marker that was there at start, want 1", got)
	}
	marker(base.Add(-time.Hour))
	time.Sleep(150 * time.Millisecond)
	if got := r.reports.published(); got != 1 {
		t.Fatalf("%d publications after an older marker, want 1", got)
	}
	marker(base.Add(time.Minute))
	waitFor(t, "a pass after a newer marker", func() bool { return r.reports.published() >= 2 })
	time.Sleep(150 * time.Millisecond)
	if got := r.reports.published(); got != 2 {
		t.Errorf("%d publications, want exactly one pass for one request", got)
	}
}
