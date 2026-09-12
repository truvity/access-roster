package server

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	directoryrosterv1 "github.com/truvity/access-roster/gen/directoryroster/v1"
	"github.com/truvity/access-roster/internal/access"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

type reports map[string]string

func (r reports) Reports(context.Context) (map[string]string, error) { return r, nil }

type unreadable struct{}

func (unreadable) Reports(context.Context) (map[string]string, error) {
	return nil, errors.New("the API server is not answering")
}

func githubConsole(t *testing.T, store GitHubReports) *Console {
	t.Helper()
	declared, err := policy.Parse([]byte(`
version: 1
groups:
  all:platform:engineer: { members: [team-platform@truvity.com] }
  all:platform:lead: { members: [leads@truvity.com] }
  all:truvity:employee: { matchers: [{ email_domain: truvity.com }] }
github:
  truvity:
    members: [all:truvity:employee]
    teams:
      team-platform:
        members: [all:platform:engineer]
        maintainers: [all:platform:lead]
  trust-form:
    teams:
      team-platform:
        members: [all:platform:engineer]
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return &Console{deps: ConsoleDeps{Authorizer: access.NewAuthorizer(set, nil, 0), GitHub: store}}
}

func githubStatus(t *testing.T, console *Console, role access.Role) (*directoryrosterv1.GetGitHubStatusResponse, error) {
	t.Helper()
	ctx := WithIdentity(context.Background(), access.Identity{Role: role})
	response, err := console.GetGitHubStatus(ctx, connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func organisation(t *testing.T, got *directoryrosterv1.GetGitHubStatusResponse, org string) *directoryrosterv1.GitHubOrganisation {
	t.Helper()
	for _, o := range got.GetOrganisations() {
		if o.GetOrg() == org {
			return o
		}
	}
	t.Fatalf("organisations = %v, want %s among them", got.GetOrganisations(), org)
	return nil
}

// The page answers "what should each organisation look like, and what
// did the controller last find" in one call. Where the two disagree it
// shows both sides rather than hiding either: a bound team nobody has
// reported, and a report for a team the policy no longer binds.
func TestTheGitHubPageShowsBindingsBesideReports(t *testing.T) {
	t.Parallel()

	truvity, err := status.Encode(status.Org{
		Org:     "truvity",
		Enabled: false,
		Tick:    status.Tick{At: time.Date(2026, 9, 12, 21, 0, 0, 0, time.UTC), Outcome: status.OutcomeDryRun, Changes: 1},
		Teams: []status.Team{
			{Team: "team-platform", Members: []status.Member{
				{Email: "o.tsarev@truvity.com", Login: "excavador", Role: status.RoleMaintainer, State: status.StateSynced},
			}},
			// No longer in the policy: the controller's last word on it.
			{Team: "team-legacy", Members: []status.Member{
				{Email: "a@truvity.com", Login: "a", Role: status.RoleMember, State: status.StateSynced},
			}},
		},
		Unlinked: []status.Account{{Login: "truvity-bot"}},
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// A report for an organisation the policy dropped entirely.
	gone, err := status.Encode(status.Org{Org: "old-org", Tick: status.Tick{Outcome: status.OutcomeInSync}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	store := reports{
		status.Key("truvity"): truvity,
		status.Key("old-org"): gone,
		"not-a-report":        "ignored",
	}

	got, err := githubStatus(t, githubConsole(t, store), access.RoleViewer)
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	if !got.GetReportsAvailable() {
		t.Error("a deployment with a report store says it has none")
	}
	names := make([]string, 0, len(got.GetOrganisations()))
	for _, o := range got.GetOrganisations() {
		names = append(names, o.GetOrg())
	}
	if !slices.Equal(names, []string{"old-org", "trust-form", "truvity"}) {
		t.Errorf("organisations = %v, want every bound and every reported one, sorted", names)
	}

	tv := organisation(t, got, "truvity")
	if !tv.GetBound() || !tv.GetReported() || tv.GetEnabled() || tv.GetTick().GetOutcome() != "dry-run" {
		t.Errorf("truvity header = %+v", tv)
	}
	if !slices.Equal(tv.GetMemberGroups(), []string{"all:truvity:employee"}) {
		t.Errorf("truvity's own binding = %v", tv.GetMemberGroups())
	}
	if len(tv.GetUnlinked()) != 1 || tv.GetUnlinked()[0].GetLogin() != "truvity-bot" {
		t.Errorf("unlinked = %v", tv.GetUnlinked())
	}
	var platform, legacy *directoryrosterv1.GitHubTeamStatus
	for _, team := range tv.GetTeams() {
		switch team.GetTeam() {
		case "team-platform":
			platform = team
		case "team-legacy":
			legacy = team
		}
	}
	if platform == nil || !platform.GetBound() ||
		!slices.Equal(platform.GetMaintainerGroups(), []string{"all:platform:lead"}) ||
		len(platform.GetMembers()) != 1 || platform.GetMembers()[0].GetRole() != "maintainer" {
		t.Errorf("team-platform = %+v", platform)
	}
	if legacy == nil || legacy.GetBound() || len(legacy.GetMembers()) != 1 {
		t.Errorf("a reported team the policy no longer binds = %+v, want it shown unbound", legacy)
	}

	// Bound, never reported: the bindings show and nothing pretends to be
	// a report.
	tf := organisation(t, got, "trust-form")
	if !tf.GetBound() || tf.GetReported() || tf.GetTick() != nil {
		t.Errorf("trust-form = %+v, want bound and unreported", tf)
	}
	if len(tf.GetTeams()) != 1 || !tf.GetTeams()[0].GetBound() || len(tf.GetTeams()[0].GetMembers()) != 0 {
		t.Errorf("trust-form teams = %v", tf.GetTeams())
	}

	if old := organisation(t, got, "old-org"); old.GetBound() || !old.GetReported() {
		t.Errorf("old-org = %+v, want reported and unbound", old)
	}
}

// A report the console cannot read hides nothing the policy says: the
// bindings still show, beside why the report did not.
func TestAnUnreadableReportStillShowsTheBindings(t *testing.T) {
	t.Parallel()
	got, err := githubStatus(t, githubConsole(t, reports{status.Key("truvity"): `{"version":99}`}), access.RoleViewer)
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	tv := organisation(t, got, "truvity")
	if tv.GetReportError() == "" || !tv.GetReported() {
		t.Errorf("truvity = %+v, want the report's error", tv)
	}
	if len(tv.GetTeams()) != 1 || !tv.GetTeams()[0].GetBound() {
		t.Errorf("the bindings disappeared with the report: %v", tv.GetTeams())
	}
}

// With no store — a deployment keeping no state in Kubernetes — the page
// still shows the bindings and says why nothing is reported; a store that
// cannot be read is an error, never an empty page that looks true.
func TestReportsAreAbsentOrUnavailableNeverSilentlyEmpty(t *testing.T) {
	t.Parallel()
	got, err := githubStatus(t, githubConsole(t, nil), access.RoleViewer)
	if err != nil {
		t.Fatalf("GetGitHubStatus: %v", err)
	}
	if got.GetReportsAvailable() || len(got.GetOrganisations()) != 2 {
		t.Errorf("no store = %+v, want the two bound organisations and reports unavailable", got)
	}

	if _, err = githubStatus(t, githubConsole(t, unreadable{}), access.RoleViewer); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("an unreadable store = %v, want unavailable", err)
	}
}

// A report names the members of every bound team across every company,
// so it needs the installation-wide viewer role and nothing less.
func TestTheGitHubPageNeedsAnInstallationWideViewer(t *testing.T) {
	t.Parallel()
	console := githubConsole(t, reports{})
	if _, err := githubStatus(t, console, access.RoleNone); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("no role = %v, want permission denied", err)
	}
	scoped := WithIdentity(context.Background(), access.Identity{
		Role:   access.RoleNone,
		Scopes: map[string]access.Role{"C0north": access.RoleViewer},
	})
	_, err := console.GetGitHubStatus(scoped, connect.NewRequest(&directoryrosterv1.GetGitHubStatusRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a viewer of one tenant = %v, want permission denied", err)
	}
}
