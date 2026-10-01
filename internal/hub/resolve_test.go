package hub_test

import (
	"context"
	"slices"
	"testing"
)

func emails(members []string) []string { return slices.Sorted(slices.Values(members)) }

func resolvedMembers(t *testing.T, h *harness, group string, depth, nested int) (members []string, nestedGroups []string, found, truncated bool) {
	t.Helper()
	got, err := h.hub.ResolveGroups(context.Background(), []string{group}, depth, nested)
	if err != nil || len(got) != 1 {
		t.Fatalf("ResolveGroups = %+v, %v", got, err)
	}
	for _, m := range got[0].Members {
		members = append(members, m.Email)
	}
	return members, got[0].Nested, got[0].Found, got[0].Truncated
}

// A member that is itself a snapshotted group is expanded, not read as a
// person: the people in it are the group's, and the nested group is named.
func TestResolveGroupsExpandsNestedGroups(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.WithGroup("outer@one.example", "platform@one.example", "bob@one.example", "ghost@elsewhere.example")
	if _, err := h.hub.Refresh(context.Background(), oneID); err != nil {
		t.Fatal(err)
	}
	members, nested, found, truncated := resolvedMembers(t, h, "Outer@One.example", 8, 100)
	if !found || truncated {
		t.Fatalf("found %v truncated %v", found, truncated)
	}
	if want := []string{"alice@one.example", "bob@one.example", "ghost@elsewhere.example"}; !slices.Equal(emails(members), want) {
		t.Errorf("members = %v, want %v (the nested group's person, not its address)", members, want)
	}
	if !slices.Equal(nested, []string{"platform@one.example"}) {
		t.Errorf("nested = %v", nested)
	}
	// Who is who: known and live come from the snapshots; an address no
	// snapshot reads is honestly unknown.
	got, _ := h.hub.ResolveGroups(context.Background(), []string{"outer@one.example"}, 8, 100)
	for _, m := range got[0].Members {
		switch m.Email {
		case "alice@one.example":
			if !m.Known || !m.Live || m.GivenName != "Alice" {
				t.Errorf("alice = %+v", m)
			}
		case "ghost@elsewhere.example":
			if m.Known || m.Live {
				t.Errorf("ghost = %+v", m)
			}
		}
	}
	if !got[0].Authoritative || got[0].Workspace != oneID {
		t.Errorf("the group = %+v", got[0])
	}
}

// Two groups that name each other end the expansion, each once.
func TestResolveGroupsEndsACycle(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.WithGroup("a@one.example", "b@one.example", "alice@one.example")
	h.one.WithGroup("b@one.example", "a@one.example", "bob@one.example")
	if _, err := h.hub.Refresh(context.Background(), oneID); err != nil {
		t.Fatal(err)
	}
	members, nested, found, truncated := resolvedMembers(t, h, "a@one.example", 8, 100)
	if !found || truncated {
		t.Fatalf("found %v truncated %v", found, truncated)
	}
	if !slices.Equal(emails(members), []string{"alice@one.example", "bob@one.example"}) || !slices.Equal(nested, []string{"b@one.example"}) {
		t.Errorf("members %v nested %v", members, nested)
	}
}

// A chain deeper than the bound, or wider than the ceiling, is cut and says
// so: a consumer removes nobody on a read that is not whole.
func TestResolveGroupsSaysWhenItWasCutShort(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.one.WithGroup("l1@one.example", "l2@one.example", "alice@one.example")
	h.one.WithGroup("l2@one.example", "l3@one.example", "bob@one.example")
	h.one.WithGroup("l3@one.example", "platform@one.example")
	if _, err := h.hub.Refresh(context.Background(), oneID); err != nil {
		t.Fatal(err)
	}
	if members, _, _, truncated := resolvedMembers(t, h, "l1@one.example", 8, 100); truncated || !slices.Contains(members, "alice@one.example") {
		t.Errorf("a short chain: members %v truncated %v", members, truncated)
	}
	if _, _, _, truncated := resolvedMembers(t, h, "l1@one.example", 1, 100); !truncated {
		t.Error("a chain deeper than the bound was not reported as cut")
	}
	if _, _, _, truncated := resolvedMembers(t, h, "l1@one.example", 8, 1); !truncated {
		t.Error("a chain wider than the ceiling was not reported as cut")
	}
}

// A group that is not there, a domain nobody serves and an address that is
// no address all read as not found, each in order, without failing the rest.
func TestResolveGroupsAnswersEveryGroupAskedInOrder(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	got, err := h.hub.ResolveGroups(context.Background(),
		[]string{"platform@one.example", "nope@one.example", "x@nobody.example", "not-an-address", "all@two.example"}, 8, 100)
	if err != nil || len(got) != 5 {
		t.Fatalf("ResolveGroups = %+v, %v", got, err)
	}
	for i, want := range []bool{true, false, false, false, true} {
		if got[i].Found != want {
			t.Errorf("group %d (%s) found = %v, want %v", i, got[i].Email, got[i].Found, want)
		}
	}
	if got[4].Workspace != twoID || len(got[4].Members) != 1 {
		t.Errorf("all@two = %+v", got[4])
	}
}
