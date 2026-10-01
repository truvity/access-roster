package audit_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/truvity/audit/gen/audit/v1"
	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/audit"
	"github.com/truvity/access-roster/internal/audit/audittest"
)

// every is one record of every action, built the way the code builds them.
func every() []*record.Record {
	person := audit.Person("A.Person@Example.com")
	app := audit.App{ID: 42, Slug: "roster-example"}
	member := audit.Member{Person: "a.person@example.com", Org: "example", Team: "platform", Login: "@APerson", Role: "member"}
	ch := audit.SlackChannel{Workspace: "acme", Name: "#platform", ID: "C0123", Private: true}
	sm := audit.SlackMember{Person: "a.person@example.com", Channel: ch, User: "U0123", Groups: []string{"platform"}, Reason: "bound to platform"}
	shared := audit.SlackShared{Host: "acme", Guest: "globex", Channel: "partners", ID: "C0456", Invite: "I0789"}
	sw := audit.SlackWorkspace{Key: "acme", Team: "T0123", App: "A0123", Owner: "C0north"}
	sharedChannel := audit.SlackSharedChannel{Name: "partners", Host: "acme", With: []string{"globex", "initech"},
		Sources: []string{"engineers@acme.example"}, Members: []string{"a.person@example.com"},
		PerSide: map[string]bool{"acme": true, "globex": false, "initech": true}}
	consoleChannel := audit.SlackConsoleChannel{Workspace: "acme", Name: "platform", Private: true, Mode: "strict",
		Sources: []string{"engineers@acme.example", "ops@acme.example"}}
	sa := audit.SlackCatalogueApp{ID: "sync", App: "A0123", Workspace: "acme", Team: "T0123", Scopes: []string{"channels:read", "users:read"}}
	return []*record.Record{
		audit.SlackWorkspaceConnected(person, sw),
		audit.SlackWorkspaceDisconnected(person, sw, true, ""),
		audit.SlackWorkspaceConnectRefused(person, sw, "installed into another team"),
		audit.SlackCatalogueAppCreated(person, audit.SlackCatalogueApp{ID: "sync", App: "A0123", Workspace: "acme"}),
		audit.SlackCatalogueAppInstalled(person, sa),
		audit.SlackCatalogueAppInstallRefused(person, sa, "installed into another workspace"),
		audit.SlackSharedChannelCreated(person, sharedChannel),
		audit.SlackSharedChannelUpdated(person, sharedChannel, "with: globex -> globex,initech"),
		audit.SlackSharedChannelDeleted(person, sharedChannel),
		audit.SlackConsoleChannelCreated(person, consoleChannel),
		audit.SlackConsoleChannelUpdated(person, consoleChannel, "sources: 1 group -> 2 groups; mode: extend -> strict"),
		audit.SlackConsoleChannelDeleted(person, consoleChannel),
		audit.SlackChannelCreated(ch, audit.Succeeded()),
		audit.SlackChannelAdopted(ch, audit.Failed("Slack refused")),
		audit.SlackChannelArchived(person, ch, audit.Succeeded()),
		audit.SlackMemberInvited(sm, audit.Succeeded()),
		audit.SlackMemberRemoved(audit.SlackMember{Channel: ch, User: "U0999"}, audit.Succeeded()),
		audit.SlackSharedInvited(shared, audit.Succeeded()),
		audit.SlackSharedAccepted(shared, audit.Succeeded()),
		audit.SlackActionHeld("acme", nil, &sm, "invite", "the person has no Slack account yet"),
		audit.SlackActionHeld("acme", &ch, nil, "adopt", "the bot is not in the private channel"),
		audit.SlackActionHeld("acme", nil, nil, "remove", "the breaker tripped"),
		audit.SlackRemovalsConfirmed(person, "acme", "", "f00d", 3),
		audit.SlackRemovalsConfirmed(person, "acme", "platform", "f00d", 1),
		audit.SlackLeaverReported("acme", "gone@example.com", "U0999", "no longer in the directory"),
		audit.SignedIn(person, "console", "google", audit.Succeeded()),
		audit.RecoverySignedIn(audit.RecoveryIdentity("system:serviceaccount:access:recovery"), "console", "recovery", audit.Succeeded()),
		audit.TokenExchanged(audit.CI("github:example/app"), "aws", "ci", audit.Denied("no group admits it")),
		audit.GitHubTokenMinted(audit.Workload("system:serviceaccount:ci:runner"), "roster-example", audit.GitHubToken{
			Proof: "workload", Org: "example", Grant: "all:github:ci", Repositories: []string{"app", "infra"},
			Permissions: "contents:read", Installation: 7, ExpiresAt: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
		}, audit.Succeeded()),
		audit.SessionEnded(person, 2),
		audit.SessionRevoked(person, "b.person@example.com", "grafana", "client", 1),
		audit.SessionRefreshRefused("b.person@example.com", "grafana", "no longer admitted"),
		audit.WorkspaceConnected(person, "ws-1", "google", "consent"),
		audit.WorkspaceReconnected(person, "ws-1", "google", "consent"),
		audit.WorkspaceDisconnected(person, "ws-1"),
		audit.WorkspaceDomainsChanged(person, "ws-1", []string{"example.com"}),
		audit.WorkspaceGroupsChanged(person, "ws-1", 3),
		audit.GitHubAppCreated(person, "example", app),
		audit.GitHubOrgConnected(person, "example", 42, 7, "C0north"),
		audit.GitHubPassRequested(person, "example"),
		audit.GitHubOrgOwnerChanged(person, "example", "", "C0north"),
		audit.SlackWorkspaceOwnerChanged(person, "acme", "C0north", ""),
		audit.GitHubOrgDisconnected(audit.System(), "example", true, "the App was uninstalled"),
		audit.GitHubRemovalsConfirmed(person, "example", "f00d", 3, 40),
		audit.LinkAppConnected(person, app, "example"),
		audit.LinkAppDisconnected(person, app, 5),
		audit.CatalogueAppCreated(person, "example", app),
		audit.CatalogueAppInstalled(person, "example", app, 7),
		audit.CatalogueAppDisconnected(person, "example", app, false, ""),
		audit.RunnerAppCreated(person, "example", app),
		audit.RunnerAppInstalled(person, "example", app, 7),
		audit.RunnerAppDisconnected(audit.System(), "example", audit.App{Slug: "runners", Tier: "stable"}, true, ""),
		audit.GitHubLinkCreated("a.person@example.com", "@APerson"),
		audit.GitHubLinkMatched("a.person@example.com", "aperson", "the work address its profile publishes"),
		audit.GitHubLinkImported(person, "b.person@example.com", "bperson", "imported"),
		audit.GitHubLinkMoved("a.person@example.com", "aperson", "moved"),
		audit.GitHubLinkNarrowed("a.person@example.com", "aperson", "narrowed"),
		audit.GitHubLinkUnverifiable("a.person@example.com", "aperson", "the token was revoked"),
		audit.GitHubLinkLost("a.person@example.com", "aperson", "the account is gone"),
		audit.GitHubMemberInvited(member, audit.Succeeded()),
		audit.GitHubMemberAdded(member, audit.Succeeded()),
		audit.GitHubMemberRoleSet(member, audit.Failed("GitHub refused")),
		audit.GitHubMemberRemoved(audit.Member{Org: "example", Login: "gone"}, audit.Succeeded()),
		audit.GitHubMemberHeld(member, "remove", "the directory cannot vouch for example.com"),
		audit.GitHubOwnerReported(audit.Member{Org: "example", Login: "owner"}, "remove", "owners are reported, not removed"),
	}
}

// Every constructor makes a record the installation's catalogue accepts, and
// every action the catalogue declares has a constructor: the vocabulary is
// the catalogue, no more and no less.
func TestTheConstructorsAreTheCatalogue(t *testing.T) {
	rec := audittest.New(t)
	built := map[string]bool{}
	for _, r := range every() {
		rec.Record(context.Background(), r)
		built[r.GetAction()] = true
	}
	c, _, err := audit.Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range c.ActionNames() {
		if !built[name] {
			t.Errorf("%s is declared and no constructor builds it", name)
		}
	}
	if got, want := len(rec.Records()), len(every()); got != want {
		t.Fatalf("kept %d of %d records", got, want)
	}
}

// The installation fills operation from the catalogue, and the tenant is the
// installation's own.
func TestRecordsAreTheInstallationsOwn(t *testing.T) {
	rec := audittest.New(t)
	rec.Record(context.Background(), audit.SignedIn(audit.Person("a@example.com"), "console", "google", audit.Succeeded()))
	r := rec.Records()[0]
	if r.GetTenantId() != record.TenantPlatform {
		t.Fatalf("tenant %q", r.GetTenantId())
	}
	if r.GetOperation() != auditv1.Operation_OPERATION_AUTHENTICATION {
		t.Fatalf("operation %v", r.GetOperation())
	}
	if r.GetSource() != audit.Source {
		t.Fatalf("source %q", r.GetSource())
	}
}

// Addresses are compared as the directory compares them, and a GitHub login
// is named without the @ the console shows.
func TestIdentifiersAreNormalised(t *testing.T) {
	r := audit.GitHubLinkCreated("A.Person@Example.COM", "@APerson")
	if got := r.GetActor().GetId(); got != "a.person@example.com" {
		t.Fatalf("actor %q", got)
	}
	if got := r.GetTargets()[0].GetId(); got != "aperson" {
		t.Fatalf("account %q", got)
	}
}

// A person's e-mail address is an identifier the profiles treat, never data:
// nothing a constructor writes into data looks like one.
func TestNoAddressIsCarriedAsData(t *testing.T) {
	for _, r := range every() {
		for name, v := range r.GetData().GetFields() {
			if strings.Contains(v.GetStringValue(), "@") {
				t.Errorf("%s carries an address in data.%s", r.GetAction(), name)
			}
			for _, item := range v.GetListValue().GetValues() {
				if strings.Contains(item.GetStringValue(), "@") {
					t.Errorf("%s carries an address in data.%s", r.GetAction(), name)
				}
			}
		}
	}
}

// Without an installation, recording validates and logs, and a block action
// still succeeds: refusing recovery on a deployment that keeps no trail would
// make recovery impossible by configuration.
func TestAnUnconnectedTrailLogsAndAllowsRecovery(t *testing.T) {
	trail, err := audit.Open(context.Background(), audit.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	if trail.Connected() {
		t.Fatal("no installation was configured")
	}
	err = trail.RecordDurable(context.Background(),
		audit.RecoverySignedIn(audit.RecoveryIdentity("recovery"), "console", "recovery", audit.Succeeded()))
	if err != nil {
		t.Fatal(err)
	}
}

// A connected trail is an address and a token: the installation records
// nothing from a caller it cannot name, so a connection without one is
// refused rather than started and found wanting later.
func TestAConnectionNeedsATokenToBeNamedBy(t *testing.T) {
	_, err := audit.Open(context.Background(), audit.Config{Writer: "http://w"})
	if err == nil || !strings.Contains(err.Error(), "token file") {
		t.Errorf("%v, want a refusal naming the token file", err)
	}
}

// With no address there is no installation, and that is a deployment keeping
// its trail in the log alone rather than a mistake.
func TestNoAddressIsNotAnError(t *testing.T) {
	trail, err := audit.Open(context.Background(), audit.Config{})
	if err != nil {
		t.Fatalf("an unconnected trail was refused: %v", err)
	}
	t.Cleanup(func() { _ = trail.Close() })
	if err := trail.RecordDurable(context.Background(),
		audit.RecoverySignedIn(audit.RecoveryIdentity("recovery"), "console", "recovery", audit.Succeeded()),
	); err != nil {
		t.Errorf("an unconnected trail refused a block record: %v", err)
	}
}

// A test recorder that cannot take a block action says so, the way the
// installation would.
func TestTheTestRecorderCanRefuse(t *testing.T) {
	rec := audittest.New(t)
	rec.Fail = errors.New("the writer is down")
	err := rec.RecordDurable(context.Background(),
		audit.RecoverySignedIn(audit.RecoveryIdentity("recovery"), "console", "recovery", audit.Succeeded()))
	if err == nil || len(rec.Records()) != 0 || slices.Contains(rec.Actions(), "") {
		t.Fatalf("err %v, records %d", err, len(rec.Records()))
	}
}

// The Slack records name the place and the person the way the GitHub ones do.
func TestSlackRecordsAreNamedByPlaceAndPerson(t *testing.T) {
	ch := audit.SlackChannel{Workspace: "acme", Name: "#platform", ID: "C0123", Private: true}
	r := audit.SlackMemberInvited(audit.SlackMember{Person: "A.Person@Example.com", Channel: ch, User: "U0123"}, audit.Succeeded())
	if r.GetSubject().GetId() != "a.person@example.com" {
		t.Fatalf("subject %q", r.GetSubject().GetId())
	}
	var got []string
	for _, tg := range r.GetTargets() {
		got = append(got, tg.GetType()+":"+tg.GetId())
	}
	if want := []string{"slack_workspace:acme", "slack_channel:acme/platform", "slack_user:U0123"}; !slices.Equal(got, want) {
		t.Fatalf("targets %v", got)
	}
	if r.GetActor().GetKind() != "system" {
		t.Fatalf("actor %v", r.GetActor())
	}
	held := audit.SlackActionHeld("acme", nil, nil, "remove", "breaker")
	if held.GetOutcome().GetResult() != auditv1.Outcome_RESULT_FAILURE {
		t.Fatalf("held outcome %v", held.GetOutcome())
	}
}

// The channel records carry the same counts, and neither writes the fields
// catalogue 1.6.0 keeps declared only so older records read: `reason` on a
// console channel, `from` on a shared one.
func TestChannelRecordsCountSourcesAndMembersAndWriteNoHistoricalField(t *testing.T) {
	shared := audit.SlackSharedChannel{Name: "partners", Host: "acme", With: []string{"globex"},
		Sources: []string{"a@example.com", "b@example.com"}, Members: []string{"c@example.com"}}
	console := audit.SlackConsoleChannel{Workspace: "acme", Name: "platform", Sources: []string{"a@example.com"},
		Members: []string{"c@example.com", "d@example.com"}}
	for _, tc := range []struct {
		name            string
		r               *record.Record
		sources, member float64
		historical      string
	}{
		{"shared", audit.SlackSharedChannelCreated(audit.System(), shared), 2, 1, "from"},
		{"console", audit.SlackConsoleChannelCreated(audit.System(), console), 1, 2, "reason"},
	} {
		fields := tc.r.GetData().GetFields()
		if got := fields["sources"].GetNumberValue(); got != tc.sources {
			t.Errorf("%s: sources = %v, want %v", tc.name, got, tc.sources)
		}
		if got := fields["members"].GetNumberValue(); got != tc.member {
			t.Errorf("%s: members = %v, want %v", tc.name, got, tc.member)
		}
		if _, written := fields[tc.historical]; written {
			t.Errorf("%s: writes %s, which is historical", tc.name, tc.historical)
		}
	}
}
