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
	return []*record.Record{
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
		audit.GitHubOrgConnected(person, "example", 42, 7),
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

// A connected trail needs everything a connection takes, and says which part
// is missing.
func TestAConnectionIsAllOrNothing(t *testing.T) {
	for _, tc := range []struct {
		cfg  audit.Config
		want string
	}{
		{audit.Config{Writer: "http://w"}, "no registry"},
		{audit.Config{Registry: "http://r"}, "no writer"},
		{audit.Config{Writer: "http://w", Registry: "http://r"}, "outbox"},
		{audit.Config{Writer: "http://w", Registry: "http://r", Outbox: t.TempDir()}, "token file"},
	} {
		_, err := audit.Open(context.Background(), tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: %v, want %q", tc.cfg, err, tc.want)
		}
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
