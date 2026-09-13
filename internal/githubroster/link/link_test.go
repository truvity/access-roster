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
