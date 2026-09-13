package link_test

import (
	"strings"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/link"
)

// A link round-trips, and what does not decode never shows its content —
// it holds a person's tokens.
func TestALinkRoundTripsAndNeverLeaksItsTokens(t *testing.T) {
	t.Parallel()
	raw, err := link.Encode(link.Link{
		ID: 7, Login: "ada", Emails: []string{"Ada@Truvity.com", "ada@truvity.com"}, State: link.StateLinked,
		AccessToken: "uat-secret", RefreshToken: "urt-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := link.Decode(raw)
	if err != nil || len(got.Emails) != 1 || got.Emails[0] != "ada@truvity.com" || got.AccessToken != "uat-secret" {
		t.Errorf("decoded %+v, %v", got, err)
	}
	if public := got.Public(); public.AccessToken != "" || public.RefreshToken != "" {
		t.Errorf("Public kept a token: %+v", public)
	}
	_, err = link.Decode([]byte(`{"access_token":"uat-secret"`))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("a broken link's error = %v, want one that says nothing of its content", err)
	}
	if _, err = link.Encode(link.Link{ID: 7, Login: "ada", State: "maybe"}); err == nil {
		t.Error("an unknown state was written")
	}
	if id, ok := link.IDOfKey(link.Key(7)); !ok || id != 7 {
		t.Errorf("IDOfKey(Key(7)) = %d, %v", id, ok)
	}
	if _, ok := link.IDOfKey(link.AppKey); ok {
		t.Error("the App's key reads as an account's")
	}
}

// Claiming moves an address from every other active link; a link left
// with nothing is lost, and an untouched one is not rewritten.
func TestClaimMovesAddresses(t *testing.T) {
	t.Parallel()
	now := time.Now()
	existing := []link.Link{
		{ID: 1, Login: "old", Emails: []string{"ada@truvity.com"}, State: link.StateLinked, AccessToken: "t"},
		{ID: 2, Login: "both", Emails: []string{"ada@truvity.com", "ada@trustform.io"}, State: link.StateLinked},
		{ID: 3, Login: "other", Emails: []string{"bob@truvity.com"}, State: link.StateLinked},
	}
	written := link.Claim(existing, link.Link{ID: 4, Login: "new", Emails: []string{"ada@truvity.com"}, State: link.StateLinked}, now)

	byID := map[int64]link.Link{}
	for _, l := range written {
		byID[l.ID] = l
	}
	if _, rewritten := byID[3]; rewritten || len(written) != 3 {
		t.Errorf("written = %+v, want the claim and the two links it narrowed", written)
	}
	if old := byID[1]; old.State != link.StateLost || old.AccessToken != "" {
		t.Errorf("old = %+v, want lost with no tokens", old)
	}
	if both := byID[2]; both.State != link.StateLinked || len(both.Emails) != 1 || both.Emails[0] != "ada@trustform.io" {
		t.Errorf("both = %+v, want narrowed to trustform", both)
	}
}

// Adopting never displaces a link the person made, and never lets two
// accounts prove one address.
func TestAdoptNeverDisplacesALink(t *testing.T) {
	t.Parallel()
	existing := []link.Link{{ID: 1, Login: "ada-gh", Emails: []string{"ada@truvity.com"}, State: link.StateLinked}}
	candidates := []link.Link{
		{ID: 1, Login: "ada-gh", Emails: []string{"ada@truvity.com"}, Source: link.SourceImported},
		{ID: 2, Login: "ada-old", Emails: []string{"ada@truvity.com"}, Source: link.SourceImported},
		{ID: 3, Login: "bob", Emails: []string{"bob@truvity.com", "ada@truvity.com"}, Source: link.SourceProfile, AccessToken: "never"},
	}
	adopted, skipped := link.Adopt(existing, candidates)
	if len(adopted) != 1 || adopted[0].ID != 3 || len(adopted[0].Emails) != 1 || adopted[0].Emails[0] != "bob@truvity.com" ||
		adopted[0].AccessToken != "" || adopted[0].State != link.StateLinked {
		t.Errorf("adopted = %+v, want bob alone, with bob@ and no token", adopted)
	}
	if !strings.Contains(skipped[1], "already linked") || !strings.Contains(skipped[2], "@ada-gh") {
		t.Errorf("skipped = %v", skipped)
	}
	if !adopted[0].Active() || adopted[0].Checked() {
		t.Error("an adopted link must count and must not be re-checked on GitHub")
	}
}

// Disconnecting the link App touches only the links it issued tokens for:
// a profile match or an import stands, whichever App is connected.
func TestInvalidateLeavesLinksTheAppDidNotMake(t *testing.T) {
	t.Parallel()
	existing := []link.Link{
		{ID: 1, Login: "self", Emails: []string{"a@truvity.com"}, State: link.StateLinked, AccessToken: "t"},
		{ID: 2, Login: "old", Emails: []string{"b@truvity.com"}, State: link.StateLinked, Source: link.SourceSelf},
		{ID: 3, Login: "pub", Emails: []string{"c@truvity.com"}, State: link.StateLinked, Source: link.SourceProfile},
		{ID: 4, Login: "imp", Emails: []string{"d@truvity.com"}, State: link.StateLinked, Source: link.SourceImported},
	}
	changed := link.Invalidate(existing, "the link App was disconnected", time.Now())
	if len(changed) != 2 || changed[0].ID != 1 || changed[1].ID != 2 {
		t.Errorf("changed = %+v, want the two self-links alone", changed)
	}
	for i := range changed {
		if changed[i].State != link.StateUnverifiable || changed[i].AccessToken != "" {
			t.Errorf("link %d = %+v, want unverifiable with no token", changed[i].ID, changed[i])
		}
	}
}
