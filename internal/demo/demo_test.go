package demo_test

import (
	"slices"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/demo"
	"github.com/truvity/access-roster/internal/githubapp"
	"github.com/truvity/access-roster/internal/githubroster/status"
	"github.com/truvity/access-roster/policy"
)

// A demonstration run is how every page is walked through before a real
// directory is connected, so its fixtures have to be ones the service
// accepts: a policy the loader refuses, or a report the console cannot
// read, would show a walkthrough an error instead of the mechanic.
func TestTheDemonstrationFixturesAreOnesTheServiceAccepts(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("the demonstration policy does not parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("the demonstration policy is refused: %v", err)
	}
	if len(set.GitHubTeams()) == 0 || len(set.GitHubOrgs()) == 0 {
		t.Error("the demonstration policy binds no GitHub team or organisation, so the GitHub page has nothing to show")
	}

	documents := demo.GitHubReports(time.Now())
	if len(documents) == 0 {
		t.Fatal("no demonstration report")
	}
	for key, document := range documents {
		org, ok := status.OrgOfKey(key)
		if !ok {
			t.Errorf("%q is not a report key", key)
			continue
		}
		report, err := status.Decode(document)
		if err != nil {
			t.Errorf("the %s report does not decode: %v", org, err)
			continue
		}
		// The report is only useful beside the bindings: an organisation
		// the policy does not bind would render as a stale report.
		bound := false
		for _, team := range set.GitHubTeams() {
			bound = bound || team.Org == org
		}
		if !bound {
			t.Errorf("the demonstration report is for %s, which the demonstration policy does not bind", org)
		}
		seen := map[status.State]bool{}
		for _, team := range report.Teams {
			for _, member := range team.Members {
				seen[member.State] = true
			}
		}
		for _, state := range []status.State{status.StateSynced, status.StatePending, status.StateLeaving, status.StateHeld} {
			if !seen[state] {
				t.Errorf("no team member is %s: the walkthrough cannot show it", state)
			}
		}
		// A controller reports only on an organisation it can act in, so
		// the demonstration connection is for the reported organisation.
		if connected := demo.GitHubConnection(time.Now()); connected.Org != org || !connected.Installed() {
			t.Errorf("the demonstration connection %+v does not match the report for %s", connected, org)
		}
	}
}

// The Apps page is half the GitHub console, and a demonstration that
// declares no runner tier and no catalogue cannot show it: the fixtures
// have to be ones a real deployment's rules accept, or the walkthrough
// shows a refusal instead of the mechanic.
func TestTheDemonstrationAppsAreOnesTheServiceAccepts(t *testing.T) {
	t.Parallel()

	declared, err := policy.Parse([]byte(demo.Policy))
	if err != nil {
		t.Fatalf("the demonstration policy does not parse: %v", err)
	}
	set, err := policy.NewSet(declared)
	if err != nil {
		t.Fatalf("the demonstration policy is refused: %v", err)
	}

	apps := demo.GitHubCatalogue()
	if len(apps.Apps) == 0 {
		t.Fatal("the demonstration catalogue declares no App")
	}
	if undeclared := apps.UndeclaredGroups(set.HasGroup); len(undeclared) > 0 {
		t.Errorf("the demonstration catalogue grants to groups the policy does not declare: %v", undeclared)
	}
	created := map[string]bool{}
	for _, record := range demo.GitHubCatalogueApps(time.Now()) {
		if _, ok := apps.Get(record.ID); !ok {
			t.Errorf("an App is created from %q, which the catalogue does not declare", record.ID)
		}
		created[record.ID] = true
	}
	if len(created) == len(apps.Apps) {
		t.Error("every declared App is created, so the demonstration cannot show one waiting to be")
	}

	tiers := demo.GitHubRunnerTiers()
	for _, record := range demo.GitHubRunnerApps(time.Now()) {
		if !slices.Contains(tiers, record.Tier) {
			t.Errorf("a runner App is created for tier %q, which the demonstration does not declare", record.Tier)
		}
	}
	if len(demo.GitHubRunnerApps(time.Now())) >= len(tiers) {
		t.Error("every declared tier has its App, so the demonstration cannot show one waiting to be created")
	}

	key, err := demo.GitHubAppKey()
	if err != nil {
		t.Fatalf("a key for the demonstration Apps: %v", err)
	}
	// The console signs its questions about an App with this key, so a key
	// the signer refuses is a demonstration whose Apps all read "the App's
	// stored key is not usable".
	if _, err = githubapp.AppToken(1000011, key, time.Now()); err != nil {
		t.Errorf("the demonstration App key does not sign: %v", err)
	}
}
