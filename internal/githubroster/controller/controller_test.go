package controller_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	"google.golang.org/protobuf/proto"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/gen/directoryroster/v1/directoryrosterv1connect"
	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubapp/githubfake"
	"github.com/truvity/access-roster/internal/githubroster/connection"
	"github.com/truvity/access-roster/internal/githubroster/controller"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

// console answers the two questions the controller asks, from a directory
// the test edits between passes.
type console struct {
	directoryrosterv1connect.AccessServiceClient
	mu sync.Mutex
	// holders: group -> address -> live
	holders map[string]map[string]bool
	// people: address -> the directory's answer
	people map[string]*directoryrosterv1.ExplainResponse
	// policy is the digest the console answers under; explainPolicy, when
	// set, is a second replica's for Explain alone.
	policy, explainPolicy string
	// asked counts the holders questions, one per group asked about.
	asked int
}

// testPolicy is the digest the rig's controller decides with.
const testPolicy = "rig-policy"

func (c *console) ListHolders(
	_ context.Context, req *connect.Request[directoryrosterv1.ListHoldersRequest],
) (*connect.Response[directoryrosterv1.ListHoldersResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked++
	out := &directoryrosterv1.ListHoldersResponse{PolicyDigest: c.policy}
	for email, live := range c.holders[req.Msg.GetGroup()] {
		out.Holders = append(out.Holders, &directoryrosterv1.Holder{Email: email, Live: live, Authoritative: true})
	}
	return connect.NewResponse(out), nil
}

func (c *console) Explain(
	_ context.Context, req *connect.Request[directoryrosterv1.ExplainRequest],
) (*connect.Response[directoryrosterv1.ExplainResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	digest := c.policy
	if c.explainPolicy != "" {
		digest = c.explainPolicy
	}
	answer, ok := c.people[req.Msg.GetEmail()]
	if !ok {
		answer = &directoryrosterv1.ExplainResponse{Authoritative: true, Found: false}
	}
	out, _ := proto.Clone(answer).(*directoryrosterv1.ExplainResponse)
	out.PolicyDigest = digest
	return connect.NewResponse(out), nil
}

// auditLog collects what the controller reports.
type auditLog struct {
	directoryrosterv1connect.AuditServiceClient
	mu     sync.Mutex
	events []*directoryrosterv1.AuditEvent
}

func (a *auditLog) RecordAuditEvents(
	_ context.Context, req *connect.Request[directoryrosterv1.RecordAuditEventsRequest],
) (*connect.Response[directoryrosterv1.RecordAuditEventsResponse], error) {
	// Refused as the service refuses it: one event with an outcome the
	// audit stream does not have loses the whole batch.
	for i, e := range req.Msg.GetEvents() {
		switch e.GetOutcome() {
		case "", audit.OutcomeOK, audit.OutcomeRefused, audit.OutcomeFailed, audit.OutcomeHeld:
		default:
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("event %d: outcome %q", i, e.GetOutcome()))
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, req.Msg.GetEvents()...)
	return connect.NewResponse(&directoryrosterv1.RecordAuditEventsResponse{}), nil
}

func (a *auditLog) kinds() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.events {
		out = append(out, e.GetKind()+" "+e.GetSubject()+" "+e.GetOutcome())
	}
	return out
}

type report struct {
	mu        sync.Mutex
	documents map[string]string
}

func (r *report) Replace(_ context.Context, documents map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.documents = documents
	return nil
}

func (r *report) Reports(context.Context) (map[string]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.documents), nil
}

func (r *report) org(t *testing.T, login string) status.Org {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	decoded, err := status.Decode(r.documents[status.Key(login)])
	if err != nil {
		t.Fatalf("the report for %s: %v", login, err)
	}
	return decoded
}

func writeCredential(t *testing.T, dir, org string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := connection.EncodeCredential(connection.Credential{
		Org: org, AppID: 42, InstallationID: 7,
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, connection.Key(org)), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// links is the link store, in memory, with the store's revision rule.
type links struct {
	mu   sync.Mutex
	byID map[int64]link.Link
}

func (l *links) List(context.Context) ([]link.Link, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]link.Link, 0, len(l.byID))
	for _, id := range slices.Sorted(maps.Keys(l.byID)) {
		out = append(out, l.byID[id])
	}
	slices.SortFunc(out, func(a, b link.Link) int { return int(a.ID - b.ID) })
	return out, nil
}

func (l *links) Update(_ context.Context, changed []link.Link) ([]link.Link, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var written []link.Link
	for k := range changed {
		change := changed[k]
		if have, ok := l.byID[change.ID]; !ok || have.Revision != change.Revision {
			continue
		}
		change.Revision++
		l.byID[change.ID] = change
		written = append(written, change)
	}
	return written, nil
}

func (l *links) Adopt(_ context.Context, candidates []link.Link) ([]link.Link, map[int64]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	existing := make([]link.Link, 0, len(l.byID))
	for _, id := range slices.Sorted(maps.Keys(l.byID)) {
		existing = append(existing, l.byID[id])
	}
	adopted, skipped := link.Adopt(existing, candidates)
	for i := range adopted {
		l.byID[adopted[i].ID] = adopted[i]
	}
	return adopted, skipped, nil
}

func (l *links) get(id int64) link.Link {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.byID[id]
}

func (l *links) set(v link.Link) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.byID[v.ID] = v
}

func writeLinkCredential(t *testing.T, dir string) {
	t.Helper()
	raw, err := link.EncodeAppCredential(link.AppCredential{AppID: 9, ClientID: githubfake.ClientID, ClientSecret: githubfake.ClientSecret})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, link.AppKey), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

var bindings = map[string]policy.GitHubOrg{
	"globex": {
		Members: []string{"all:globex:employee"},
		Teams: map[string]policy.GitHubTeam{
			"team-platform": {Members: []string{"all:platform:engineer"}, Maintainers: []string{"all:platform:lead"}},
		},
	},
}

type rig struct {
	github  *githubfake.Org
	console *console
	audit   *auditLog
	report  *report
	links   *links
	// run passes once and says whether an answer came under another
	// policy.
	run func(enabled bool) bool
	// newbie is the joiner's linked account.
	newbie *githubfake.Account
	// appsDir holds the Apps' credentials, for a second controller.
	appsDir string
}

// link has somebody link an account through the fake, and keeps the link
// as the service would.
func (r *rig) link(t *testing.T, account *githubfake.Account, emails ...string) {
	t.Helper()
	now := time.Now()
	tokens, err := githubapp.ExchangeCode(context.Background(), r.github.Client(), githubfake.ClientID, githubfake.ClientSecret,
		r.github.Authorize(account.Login), "https://access.example/connect/github/link/callback", now)
	if err != nil {
		t.Fatalf("link %s: %v", account.Login, err)
	}
	r.links.set(link.Link{
		ID: account.ID, Login: account.Login, AppID: 9, Emails: emails, State: link.StateLinked, LinkedAt: now,
		AccessToken: tokens.AccessToken, AccessExpires: tokens.AccessExpires,
		RefreshToken: tokens.RefreshToken, RefreshExpires: tokens.RefreshExpires,
	})
}

func newRig(t *testing.T) *rig {
	t.Helper()
	github := githubfake.Start(t, "globex")
	github.AddMember("boss", true, "boss@globex.example")
	github.AddMember("ada", false, "ada@globex.example")
	github.AddMember("leaver", false, "leaver@globex.example")
	github.AddMember("bot", false)
	github.AddTeam("team-platform", "leaver", "bot")
	github.AddTeam("robots", "bot")

	dir := t.TempDir()
	writeCredential(t, dir, "globex")
	writeLinkCredential(t, dir)

	r := &rig{
		github: github,
		console: &console{
			policy: testPolicy,
			holders: map[string]map[string]bool{
				"all:globex:employee":   {"boss@globex.example": true, "ada@globex.example": true, "new@globex.example": true, "leaver@globex.example": false},
				"all:platform:engineer": {"ada@globex.example": true, "new@globex.example": true, "leaver@globex.example": false},
				"all:platform:lead":     {"ada@globex.example": true},
			},
			people: map[string]*directoryrosterv1.ExplainResponse{
				"leaver@globex.example": {Authoritative: true, Found: true, Suspended: true},
			},
		},
		audit:  &auditLog{},
		report: &report{},
		links:  &links{byID: map[int64]link.Link{}},
	}
	r.appsDir = dir
	r.newbie = github.AddAccount("newbie", "new@globex.example", "newbie@example.org")
	r.link(t, r.newbie, "new@globex.example")
	// One controller per setting, kept across passes: what it remembers
	// between passes is part of what is under test.
	controllers := map[bool]*controller.Controller{}
	r.run = func(enabled bool) bool {
		c, ok := controllers[enabled]
		if !ok {
			c = controller.New(controller.Config{AppsDir: dir, Enabled: map[string]bool{"globex": enabled}}, controller.Deps{
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: github.Client(),
				Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
			})
			controllers[enabled] = c
		}
		return c.Pass(context.Background())
	}
	return r
}

// Born disabled: every pass derives everything and changes nothing, and
// the report says what WOULD happen — which is how an organisation is
// enabled knowingly. Nothing is recorded, because nothing happened.
func TestADisabledOrganisationIsADryRun(t *testing.T) {
	r := newRig(t)
	r.run(false)

	if did := r.github.Did(); len(did) != 0 {
		t.Errorf("a disabled organisation was changed: %v", did)
	}
	if kinds := r.audit.kinds(); len(kinds) != 0 {
		t.Errorf("a dry run recorded %v", kinds)
	}
	got := r.report.org(t, "globex")
	if got.Enabled || got.Tick.Outcome != status.OutcomeDryRun || got.Tick.Changes == 0 {
		t.Errorf("tick = %+v, want a dry run that counts what it would do", got.Tick)
	}
}

// Enabled: the joiner is invited into their team, a lead is added as a
// maintainer, the suspended leaver leaves the organisation, the unlinked
// bot and the unbound team are left alone — and each change is recorded
// once in the audit stream.
func TestAnEnabledOrganisationIsMadeToMatch(t *testing.T) {
	r := newRig(t)
	r.run(true)

	did := r.github.Did()
	for _, want := range []string{"invite @newbie", "add team-platform/ada as maintainer", "remove-from-org leaver"} {
		if !slices.Contains(did, want) {
			t.Errorf("actions = %v, want %q among them", did, want)
		}
	}
	for _, change := range did {
		if strings.Contains(change, "bot") || strings.Contains(change, "robots") || strings.Contains(change, "boss") {
			t.Errorf("%q touched what must never be touched", change)
		}
	}
	if invitation := r.github.Invitations["@newbie"]; invitation == nil || !slices.Equal(invitation.Teams, []int64{r.github.Teams["team-platform"].ID}) {
		t.Errorf("the invitation does not place @newbie in team-platform: %+v", invitation)
	}

	got := r.report.org(t, "globex")
	if got.Tick.Outcome != status.OutcomeApplied || got.Tick.Changes != 3 {
		t.Errorf("tick = %+v, want three changes applied", got.Tick)
	}
	events := r.audit.kinds()
	for _, want := range []string{
		"github.member.invite new@globex.example ok", "github.member.add ada@globex.example ok", "github.member.remove leaver@globex.example ok",
	} {
		if !slices.Contains(events, want) {
			t.Errorf("audit = %v, want %q", events, want)
		}
	}
	if len(got.Unlinked) != 1 || got.Unlinked[0].Login != "bot" {
		t.Errorf("unlinked = %+v, want bot", got.Unlinked)
	}

	// The joiner accepts with the account they linked: the next pass finds
	// them linked and in the team, and does nothing.
	r.github.AcceptAccount("newbie")
	r.run(true)
	after := r.github.Did()[len(did):]
	if len(after) != 0 {
		t.Errorf("the pass after the joiner accepted did %v, want nothing", after)
	}
	if got = r.report.org(t, "globex"); got.Tick.Outcome != status.OutcomeInSync {
		t.Errorf("after accepting, tick = %+v, want in sync", got.Tick)
	}
}

// An owner who leaves the directory is reported, never removed — owners are
// managed outside — and the report is recorded when it begins and not again
// every pass after.
func TestAnOwnerWhoLeavesIsReportedAndRecordedOnce(t *testing.T) {
	r := newRig(t)
	r.console.mu.Lock()
	delete(r.console.holders["all:globex:employee"], "boss@globex.example")
	r.console.people["boss@globex.example"] = &directoryrosterv1.ExplainResponse{Authoritative: true, Found: false}
	r.console.mu.Unlock()

	r.run(true)
	r.run(true)

	if r.github.Members["boss"] == nil {
		t.Fatal("an owner was removed from the organisation")
	}
	reported := 0
	for _, kind := range r.audit.kinds() {
		if kind == "github.owner.reported boss@globex.example ok" {
			reported++
		}
	}
	if reported != 1 {
		t.Errorf("the owner was recorded %d times over two passes, want once: %v", reported, r.audit.kinds())
	}

	// A restarted controller reads the report the last one wrote, and does
	// not record the owner again: the trail is durable, and a restart is
	// not news.
	restarted := controller.New(controller.Config{AppsDir: r.appsDir, Enabled: map[string]bool{"globex": true}}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	restarted.Pass(context.Background())
	again := 0
	for _, kind := range r.audit.kinds() {
		if kind == "github.owner.reported boss@globex.example ok" {
			again++
		}
	}
	if again != 1 {
		t.Errorf("after a restart the owner was recorded %d times in all, want still once: %v", again, r.audit.kinds())
	}
}

// A failed pass reports the failure over what was last known, and a
// controller started after it still knows what it recorded: a rollout
// where a pass fails against a console on another policy, then a restart,
// records no owner a second time.
func TestAFailedPassKeepsItsRowsAndARestartAfterItRecordsNothingAgain(t *testing.T) {
	r := newRig(t)
	r.console.mu.Lock()
	delete(r.console.holders["all:globex:employee"], "boss@globex.example")
	r.console.people["boss@globex.example"] = &directoryrosterv1.ExplainResponse{Authoritative: true, Found: false}
	r.console.mu.Unlock()
	owners := func() int {
		n := 0
		for _, kind := range r.audit.kinds() {
			if kind == "github.owner.reported boss@globex.example ok" {
				n++
			}
		}
		return n
	}
	hasOwnerRow := func(o status.Org) bool {
		found := false
		each := func(members []status.Member) {
			for _, m := range members {
				if m.Login == "boss" && m.State == status.StateReported {
					found = true
				}
			}
		}
		each(o.Members)
		for _, team := range o.Teams {
			each(team.Members)
		}
		return found
	}

	r.run(true)
	if owners() != 1 {
		t.Fatalf("the owner was recorded %d times on the first pass, want once", owners())
	}

	r.console.mu.Lock()
	r.console.policy = "another-policy"
	r.console.mu.Unlock()
	r.run(true)
	failed := r.report.org(t, "globex")
	if failed.Tick.Outcome != status.OutcomeFailed {
		t.Fatalf("tick = %+v, want failed", failed.Tick)
	}
	if !hasOwnerRow(failed) {
		t.Errorf("the failed pass dropped the rows it last knew: %+v", failed)
	}

	r.console.mu.Lock()
	r.console.policy = testPolicy
	r.console.mu.Unlock()
	restarted := controller.New(controller.Config{AppsDir: r.appsDir, Enabled: map[string]bool{"globex": true}}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	restarted.Pass(context.Background())
	if owners() != 1 {
		t.Errorf("after a failed pass and a restart the owner was recorded %d times in all, want still once: %v", owners(), r.audit.kinds())
	}
}

// A directory that cannot vouch for a leaver removes nobody: the removal
// is retried next pass, with the reason on the row.
func TestAnUnvouchedLeaverIsRetried(t *testing.T) {
	r := newRig(t)
	r.console.mu.Lock()
	r.console.people["leaver@globex.example"] = &directoryrosterv1.ExplainResponse{Authoritative: false}
	r.console.mu.Unlock()

	r.run(true)

	for _, change := range r.github.Did() {
		if strings.Contains(change, "leaver") {
			t.Errorf("%q acted on an answer the directory could not vouch for", change)
		}
	}
	got := r.report.org(t, "globex")
	for _, team := range got.Teams {
		for _, m := range team.Members {
			if m.Login == "leaver" && (m.State != status.StateRetrying || !strings.Contains(m.Reason, "cannot vouch")) {
				t.Errorf("leaver's row = %+v, want retrying on the directory", m)
			}
		}
	}
}

// A policy rollout restarts the controller and the console at different
// moments. Under the old policy a team the new one binds has no holders,
// and Explain holds nobody in it — which, acted on, removes the team's
// members. So an answer under another policy changes nothing: a holders
// list fails the pass, and a confirmation does not confirm.
func TestAnAnswerUnderAnotherPolicyChangesNothing(t *testing.T) {
	setup := func(t *testing.T) *rig {
		t.Helper()
		r := newRig(t)
		r.github.AddMember("dev", false, "dev@globex.example")
		r.github.AddTeam("team-platform", "leaver", "bot", "dev")
		r.console.mu.Lock()
		defer r.console.mu.Unlock()
		// dev is employed, and — as the old policy sees it — holds
		// nothing the team binds.
		r.console.holders["all:globex:employee"]["dev@globex.example"] = true
		r.console.people["dev@globex.example"] = &directoryrosterv1.ExplainResponse{
			Authoritative: true, Found: true,
			Held: []*directoryrosterv1.HeldGroup{{Group: "all:globex:employee"}},
		}
		return r
	}
	removedDev := func(r *rig) bool {
		return slices.ContainsFunc(r.github.Did(), func(change string) bool { return strings.Contains(change, "dev") })
	}

	// The scenario has teeth: under one policy, dev leaves the team.
	same := setup(t)
	if same.run(true) {
		t.Error("a pass under one policy asked to be tried again soon")
	}
	if !removedDev(same) {
		t.Fatalf("under one policy dev was not removed from team-platform: %v", same.github.Did())
	}

	// The console answers under another policy: the pass changes nothing.
	other := setup(t)
	other.console.policy = "old-policy"
	if !other.run(true) {
		t.Error("a pass on holders under another policy did not ask to be tried again soon")
	}
	if did := other.github.Did(); len(did) != 0 {
		t.Errorf("a pass on answers under another policy changed %v", did)
	}
	if got := other.report.org(t, "globex"); got.Tick.Outcome != status.OutcomeFailed || !strings.Contains(got.Tick.Error, "different policy") {
		t.Errorf("tick = %+v, want failed, naming the policy difference", got.Tick)
	}

	// Only Explain comes from a replica still on the old policy: the
	// removal is not confirmed, and waits.
	mixed := setup(t)
	mixed.console.explainPolicy = "old-policy"
	if !mixed.run(true) {
		t.Error("a pass on a confirmation under another policy did not ask to be tried again soon")
	}
	if removedDev(mixed) {
		t.Errorf("a removal was confirmed by an answer under another policy: %v", mixed.github.Did())
	}
}

// A rollout ends: the replica still on the old policy goes, and the console
// answers under the controller's. The controller does not wait out its
// interval to notice — it tries again within seconds — and nothing is
// changed while the answers differ. A difference that never ends is tried
// a bounded number of times, then left to the interval.
func TestAnotherPolicyIsTriedAgainSoonAndChangesNothingMeanwhile(t *testing.T) {
	asked := func(r *rig) int {
		r.console.mu.Lock()
		defer r.console.mu.Unlock()
		return r.console.asked
	}
	eventually := func(t *testing.T, what string, ok func() bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !ok(); {
			if time.Now().After(deadline) {
				t.Fatalf("gave up waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	start := func(t *testing.T, r *rig) {
		t.Helper()
		// An interval no test outlives: every pass after the first is a
		// retry.
		c := controller.New(controller.Config{
			AppsDir: r.appsDir, Enabled: map[string]bool{"globex": true}, Interval: time.Hour, PolicyRetry: time.Millisecond,
		}, controller.Deps{
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
			Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.Run(ctx)
		}()
		t.Cleanup(func() { cancel(); <-done })
	}

	t.Run("a rollout that ends", func(t *testing.T) {
		r := newRig(t)
		r.console.mu.Lock()
		r.console.policy = "old-policy"
		r.console.mu.Unlock()
		start(t, r)

		// Passes against the old policy: each is tried again, and none
		// changes anything.
		eventually(t, "a third pass under the old policy", func() bool { return asked(r) >= 3 })
		if did := r.github.Did(); len(did) != 0 {
			t.Fatalf("passes on answers under another policy changed %v", did)
		}

		r.console.mu.Lock()
		r.console.policy = testPolicy
		r.console.mu.Unlock()
		eventually(t, "a pass under the same policy", func() bool {
			documents, _ := r.report.Reports(context.Background())
			got, err := status.Decode(documents[status.Key("globex")])
			return err == nil && got.Tick.Outcome == status.OutcomeApplied
		})
		if !slices.Contains(r.github.Did(), "invite @newbie") {
			t.Errorf("once both ran one policy the pass did not act: %v", r.github.Did())
		}
	})

	t.Run("a difference that does not end", func(t *testing.T) {
		r := newRig(t)
		r.console.mu.Lock()
		r.console.policy = "old-policy"
		r.console.mu.Unlock()
		start(t, r)

		// The first pass and six retries, each stopped at its first
		// holders question — then nothing until the interval.
		eventually(t, "the last retry", func() bool { return asked(r) >= 7 })
		time.Sleep(200 * time.Millisecond)
		if n := asked(r); n != 7 {
			t.Errorf("a lasting difference was asked about %d times, want a first pass and six retries", n)
		}
		if did := r.github.Did(); len(did) != 0 {
			t.Errorf("passes on answers under another policy changed %v", did)
		}
	})
}

// GitHub's refusal of one change holds that change with GitHub's words,
// records it as failed, and does not stop the rest.
func TestARefusedChangeIsHeldAndTheRestGoOn(t *testing.T) {
	r := newRig(t)
	r.github.Refuse["invite @newbie"] = "newbie is already a part of this organization"

	r.run(true)

	if !slices.Contains(r.github.Did(), "add team-platform/ada as maintainer") {
		t.Errorf("a refused invitation stopped the other changes: %v", r.github.Did())
	}
	if !slices.Contains(r.audit.kinds(), "github.member.invite new@globex.example failed") {
		t.Errorf("audit = %v, want the refused invitation recorded as failed", r.audit.kinds())
	}
	got := r.report.org(t, "globex")
	found := false
	for _, m := range got.Members {
		if m.Email == "new@globex.example" {
			found = true
			if m.State != status.StateRetrying || !strings.Contains(m.Reason, "already a part") {
				t.Errorf("new@'s row = %+v, want retrying with GitHub's words", m)
			}
		}
	}
	if !found {
		t.Error("no organisation row for new@")
	}
}

// An organisation the policy binds and nobody has connected is reported as
// failed, with what to do about it.
func TestAnUnconnectedOrganisationSaysSo(t *testing.T) {
	r := newRig(t)
	dir := t.TempDir() // no credential in it
	c := controller.New(controller.Config{AppsDir: dir, Enabled: map[string]bool{"globex": true}}, controller.Deps{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
		Access: r.console, Audit: r.audit, Status: r.report, Links: r.links, Bindings: bindings, Policy: testPolicy,
	})
	c.Pass(context.Background())

	got := r.report.org(t, "globex")
	if got.Tick.Outcome != status.OutcomeFailed || !strings.Contains(got.Tick.Error, "connect it from the console") {
		t.Errorf("tick = %+v, want failed, saying to connect it", got.Tick)
	}
	if len(r.github.Did()) != 0 {
		t.Errorf("an unconnected organisation was changed: %v", r.github.Did())
	}
}

// joined runs the rig until the joiner is a member of the organisation and
// its team, and returns how many changes that took.
func joined(t *testing.T, r *rig) int {
	t.Helper()
	r.run(true)
	r.github.AcceptAccount("newbie")
	r.run(true)
	if r.github.Members["newbie"] == nil {
		t.Fatal("the joiner never became a member")
	}
	return len(r.github.Did())
}

// A person who removes their work address from the GitHub account they
// linked — or leaves it unverified — is out of the organisation on the next
// pass. Their other, personal addresses count for nothing.
func TestAnAddressGoneFromGitHubRemovesTheAccount(t *testing.T) {
	for name, change := range map[string]func(*githubfake.Org){
		"removed":    func(g *githubfake.Org) { g.SetEmail("newbie", "new@globex.example", false, true) },
		"unverified": func(g *githubfake.Org) { g.SetEmail("newbie", "new@globex.example", false, false) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			before := joined(t, r)
			change(r.github)

			r.run(true)

			if after := r.github.Did()[before:]; !slices.Contains(after, "remove-from-org newbie") {
				t.Errorf("actions = %v, want newbie removed from the organisation", after)
			}
			got := r.links.get(r.newbie.ID)
			if got.State != link.StateLost || got.AccessToken != "" || got.RefreshToken != "" {
				t.Errorf("link = %+v, want lost with its tokens forgotten", got)
			}
			if !slices.Contains(r.audit.kinds(), "github.link.lost new@globex.example ok") {
				t.Errorf("audit = %v, want the lost link recorded", r.audit.kinds())
			}
		})
	}
}

// Revoking the authorization on GitHub is the person withdrawing the
// proof: the same as removing the address.
func TestARevokedAuthorizationRemovesTheAccount(t *testing.T) {
	r := newRig(t)
	before := joined(t, r)
	r.github.Revoke("newbie")

	r.run(true)

	if after := r.github.Did()[before:]; !slices.Contains(after, "remove-from-org newbie") {
		t.Errorf("actions = %v, want newbie removed", after)
	}
	if got := r.links.get(r.newbie.ID); got.State != link.StateLost || !strings.Contains(got.Reason, "revoked") {
		t.Errorf("link = %+v, want lost as revoked", got)
	}
}

// GitHub being down is not GitHub saying anything: nobody is removed, the
// link stays as it was, and the account is still recognised.
func TestAGitHubOutageRemovesNobody(t *testing.T) {
	r := newRig(t)
	before := joined(t, r)
	r.github.UsersDown = true

	r.run(true)

	if after := r.github.Did()[before:]; len(after) != 0 {
		t.Errorf("an outage changed %v", after)
	}
	if got := r.links.get(r.newbie.ID); got.State != link.StateLinked {
		t.Errorf("link = %+v, want still linked", got)
	}
}

// A token near its end is renewed, and the renewed pair is what is kept —
// GitHub kills the old pair the moment it issues the new one.
func TestATokenNearItsEndIsRenewedAndKept(t *testing.T) {
	r := newRig(t)
	stored := r.links.get(r.newbie.ID)
	stored.AccessExpires = time.Now().Add(30 * time.Minute)
	r.links.set(stored)
	oldAccess := stored.AccessToken

	r.run(false)

	got := r.links.get(r.newbie.ID)
	if got.State != link.StateLinked || got.AccessToken == oldAccess || got.AccessToken != r.github.Accounts["newbie"].Access {
		t.Errorf("link = %+v, want linked with the pair GitHub issued last", got)
	}
	if !got.RefreshingSince.IsZero() {
		t.Error("the refresh marker was left behind")
	}
	// And the renewed pair works: a second pass checks with it cleanly.
	r.run(false)
	if again := r.links.get(r.newbie.ID); again.State != link.StateLinked {
		t.Errorf("after renewal the link is %+v", again)
	}
}

// A refresh that was interrupted after GitHub issued a new pair leaves a
// link whose tokens are all dead. That reads exactly like a revoked
// authorization — and must not be treated as one: the link is
// unverifiable, and the person is not removed.
func TestAnInterruptedRefreshIsNotARevocation(t *testing.T) {
	r := newRig(t)
	before := joined(t, r)
	stored := r.links.get(r.newbie.ID)
	// GitHub rotated the pair; the store never heard about it.
	if _, err := githubapp.RefreshUserTokens(context.Background(), r.github.Client(), githubfake.ClientID, githubfake.ClientSecret,
		stored.RefreshToken, time.Now()); err != nil {
		t.Fatal(err)
	}
	stored.RefreshingSince = time.Now().Add(-time.Minute)
	r.links.set(stored)

	r.run(true)

	if after := r.github.Did()[before:]; slices.Contains(after, "remove-from-org newbie") {
		t.Errorf("an interrupted refresh removed the person: %v", after)
	}
	if got := r.links.get(r.newbie.ID); got.State != link.StateUnverifiable {
		t.Errorf("link = %+v, want unverifiable", got)
	}
}

// A link made with a link App that has since been replaced is never
// checked with the new App's credentials — GitHub would call its token
// unknown, and that would read as a revocation. It is unverifiable, and
// nobody is removed.
func TestALinkFromAnotherLinkAppIsNeverCalledLost(t *testing.T) {
	r := newRig(t)
	before := joined(t, r)
	stored := r.links.get(r.newbie.ID)
	stored.AppID = 1
	r.links.set(stored)

	r.run(true)

	if after := r.github.Did()[before:]; slices.Contains(after, "remove-from-org newbie") {
		t.Errorf("a link from another App removed the person: %v", after)
	}
	if got := r.links.get(r.newbie.ID); got.State != link.StateUnverifiable {
		t.Errorf("link = %+v, want unverifiable", got)
	}
}

// A member nobody linked who publishes a work address the directory has,
// live, is linked from the profile and handled like anybody linked — and a
// profile showing nothing is not asked about again every pass.
func TestAPublishedWorkAddressLinksTheMember(t *testing.T) {
	r := newRig(t)
	r.github.AddMember("pub", false)
	r.github.Public["pub"] = "Pub@Globex.example"
	r.github.AddTeam("team-platform", "leaver", "bot")
	r.console.mu.Lock()
	r.console.holders["all:platform:engineer"]["pub@globex.example"] = true
	r.console.people["pub@globex.example"] = &directoryrosterv1.ExplainResponse{InDomain: true, Authoritative: true, Found: true}
	r.console.mu.Unlock()

	r.run(true)

	if !slices.Contains(r.github.Did(), "add team-platform/pub as member") {
		t.Errorf("actions = %v, want pub added to the team through the profile link", r.github.Did())
	}
	got := r.links.get(r.github.Members["pub"].ID)
	if got.Source != link.SourceProfile || !got.Active() || got.Checked() || got.Emails[0] != "pub@globex.example" {
		t.Errorf("link = %+v, want an active profile link, never re-checked with tokens", got)
	}
	if !slices.Contains(r.audit.kinds(), "github.link.matched pub@globex.example ok") {
		t.Errorf("audit = %v, want the match recorded", r.audit.kinds())
	}
	// bot publishes nothing: remembered, not asked again next pass.
	if !slices.Contains(slices.Collect(maps.Keys(r.links.byID)), r.github.Members["pub"].ID) {
		t.Fatal("no link for pub")
	}
}

// A pass that would remove more than half the organisation removes nobody
// and reports the breaker; seats the App cannot read invite nobody; and
// outside collaborators are reported.
func TestTheOrganisationWideGuardsReachTheReport(t *testing.T) {
	r := newRig(t)
	r.github.Seats = 0 // the App cannot read the plan
	r.github.Collaborators = []string{"contractor"}
	// Everybody but boss leaves the directory at once.
	r.console.mu.Lock()
	for _, email := range []string{"ada@globex.example", "leaver@globex.example"} {
		r.console.people[email] = &directoryrosterv1.ExplainResponse{Authoritative: true, Found: false}
		for group := range r.console.holders {
			delete(r.console.holders[group], email)
		}
	}
	r.console.mu.Unlock()
	r.github.AddMember("carl", false, "carl@globex.example")
	r.console.mu.Lock()
	r.console.people["carl@globex.example"] = &directoryrosterv1.ExplainResponse{Authoritative: true, Found: false}
	r.console.mu.Unlock()

	r.run(true)

	for _, change := range r.github.Did() {
		if strings.HasPrefix(change, "remove") || strings.HasPrefix(change, "invite") {
			t.Errorf("%q happened past a guard", change)
		}
	}
	got := r.report.org(t, "globex")
	if got.Breaker == nil || got.Breaker.Affected != 3 || got.Breaker.Members != 5 {
		t.Errorf("breaker = %+v, want 3 of 5 affected", got.Breaker)
	}
	if got.Seats == nil || got.Seats.Known {
		t.Errorf("seats = %+v, want unknown", got.Seats)
	}
	if len(got.OutsideCollaborators) != 1 || got.OutsideCollaborators[0].Login != "contractor" {
		t.Errorf("outside collaborators = %+v", got.OutsideCollaborators)
	}
}
