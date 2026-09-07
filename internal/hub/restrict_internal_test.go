package hub

import (
	"slices"
	"testing"

	"github.com/truvity/access-roster/backend"
)

// What a narrowed workspace keeps is a data-minimisation claim, and the
// routing tests would pass without any of it: an unserved domain is
// unanswerable whether or not its people are still cached. This one looks
// at what is actually kept.
func TestRestrictKeepsOnlyWhatAServedAnswerNeeds(t *testing.T) {
	t.Parallel()

	accounts := []backend.Account{
		{Email: "ada@kept.example", Live: true},
		{Email: "otto@other.example", Live: true},
	}
	groups := []backend.Group{
		{Email: "team@kept.example", Members: []string{"ada@kept.example"}},
		{Email: "empty@kept.example"},
		{Email: "shared@other.example", Members: []string{"ada@kept.example", "otto@other.example"}},
		{Email: "theirs@other.example", Members: []string{"otto@other.example"}},
	}

	keptAccounts, keptGroups := restrict(accounts, groups, []string{"kept.example"})

	if len(keptAccounts) != 1 || keptAccounts[0].Email != "ada@kept.example" {
		t.Errorf("accounts = %+v, want only the served domain's", keptAccounts)
	}
	var names []string
	for _, g := range keptGroups {
		names = append(names, g.Email)
	}
	slices.Sort(names)
	// empty@kept.example is kept although nobody is in it: a served group
	// dropped for being empty would come back as "not found", which a
	// consumer reads as gone. theirs@other.example is dropped: it is not
	// answerable and no served person is in it.
	want := []string{"empty@kept.example", "shared@other.example", "team@kept.example"}
	if !slices.Equal(names, want) {
		t.Errorf("groups = %v, want %v", names, want)
	}
	for _, g := range keptGroups {
		if g.Email == "shared@other.example" && len(g.Members) != 2 {
			t.Errorf("shared members = %v, want both: a group is never returned short", g.Members)
		}
	}

	// No narrowing means no filtering at all, including for a workspace
	// whose domains have not been discovered yet.
	sameA, sameG := restrict(accounts, groups, nil)
	if len(sameA) != len(accounts) || len(sameG) != len(groups) {
		t.Errorf("an unnarrowed workspace lost data: %d accounts, %d groups", len(sameA), len(sameG))
	}
}
