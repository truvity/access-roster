package rails_test

import (
	"context"
	"errors"
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

func TestHoldersAsksEachGroupOnceSortedAndKeepsWhatItIsTold(t *testing.T) {
	t.Parallel()
	var asked []string
	d := rails.Directory{
		Guard: rails.PolicyGuard{Digest: "p"},
		ListHolders: func(_ context.Context, group string) ([]rails.Holder, string, bool, error) {
			asked = append(asked, group)
			if group == "empty" {
				return nil, "p", false, nil
			}
			return []rails.Holder{{Email: group + "@example.com", Live: true}}, "p", true, nil
		},
	}
	got, err := d.Holders(context.Background(), []string{"b", "a", "b", "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a", "b", "empty"}; len(asked) != 3 || asked[0] != want[0] || asked[1] != want[1] || asked[2] != want[2] {
		t.Errorf("asked %v, want %v", asked, want)
	}
	if len(got["a"]) != 1 || got["a"][0].Email != "a@example.com" || !got["a"][0].Live {
		t.Errorf("a = %v", got["a"])
	}
	if _, present := got["empty"]; present {
		t.Error("a group nobody holds is present")
	}
}

func TestHoldersFailsWholeOnAnErrorOrAnotherPolicy(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	cases := []struct {
		name   string
		digest string
		err    error
		is     error
	}{
		{"an error", "p", boom, boom},
		{"another policy", "old", nil, rails.ErrPolicyDiffers},
		{"no policy", "", nil, rails.ErrPolicyDiffers},
	}
	for _, c := range cases {
		d := rails.Directory{
			Guard: rails.PolicyGuard{Digest: "p"},
			ListHolders: func(_ context.Context, group string) ([]rails.Holder, string, bool, error) {
				if group == "a" {
					return nil, "p", false, nil
				}
				return nil, c.digest, false, c.err
			},
		}
		got, err := d.Holders(context.Background(), []string{"a", "b"})
		if !errors.Is(err, c.is) || got != nil {
			t.Errorf("%s: got %v, %v", c.name, got, err)
		}
	}
}

func TestVouchKeepsOnlyWhatWasAskedAndAccepted(t *testing.T) {
	t.Parallel()
	d := rails.Directory{
		Guard: rails.PolicyGuard{Digest: "p"},
		Explain: func(_ context.Context, email string) (rails.Vouch, string, error) {
			switch email {
			case "ok@example.com":
				return rails.Vouch{Authoritative: true, Found: true}, "p", nil
			case "old@example.com":
				return rails.Vouch{Authoritative: true}, "old", nil
			}
			return rails.Vouch{}, "", errors.New("down")
		},
	}
	got, other := d.Vouch(context.Background(), []string{"ok@example.com", "old@example.com", "down@example.com"})
	if len(got) != 1 || !got["ok@example.com"].Found {
		t.Errorf("got %v", got)
	}
	if !other {
		t.Error("an answer under another policy was not reported")
	}
}

func TestVouchGone(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v    rails.Vouch
		gone bool
	}{
		{rails.Vouch{Authoritative: true}, true},
		{rails.Vouch{Authoritative: true, Found: true, Suspended: true}, true},
		{rails.Vouch{Authoritative: true, Found: true}, false},
		{rails.Vouch{Found: false}, false},
	} {
		if c.v.Gone() != c.gone {
			t.Errorf("%+v Gone = %v, want %v", c.v, !c.gone, c.gone)
		}
	}
}

// Removal's four branches: not asked, not vouched, still in a wanted
// group, and none of those.
func TestRemoval(t *testing.T) {
	t.Parallel()
	wanted := []string{"staff"}
	vouch := func(v rails.Vouch) map[string]rails.Vouch { return map[string]rails.Vouch{"a@example.com": v} }
	emails := []string{"a@example.com"}
	cases := []struct {
		name    string
		vouches map[string]rails.Vouch
		reason  string
		remove  bool
	}{
		{"not asked", nil, "the directory was not asked about a@example.com", false},
		{"not vouched", vouch(rails.Vouch{}), "the directory cannot vouch for a@example.com right now", false},
		{"still holds a wanted group", vouch(rails.Vouch{Authoritative: true, Found: true, Groups: []string{"x", "staff"}}), "", false},
		{"suspended holder of a wanted group goes", vouch(rails.Vouch{Authoritative: true, Found: true, Suspended: true, Groups: []string{"staff"}}), "", true},
		{"holds only another group", vouch(rails.Vouch{Authoritative: true, Found: true, Groups: []string{"x"}}), "", true},
		{"not found", vouch(rails.Vouch{Authoritative: true}), "", true},
	}
	for _, c := range cases {
		reason, remove := rails.Removal(emails, c.vouches, wanted)
		if reason != c.reason || remove != c.remove {
			t.Errorf("%s: (%q, %v), want (%q, %v)", c.name, reason, remove, c.reason, c.remove)
		}
	}
	// One unsettled address among several settles nothing.
	two := map[string]rails.Vouch{"a@example.com": {Authoritative: true}}
	if reason, remove := rails.Removal([]string{"a@example.com", "b@example.com"}, two, wanted); remove || reason == "" {
		t.Errorf("an unasked second address: (%q, %v)", reason, remove)
	}
}
