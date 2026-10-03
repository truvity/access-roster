package portstore_test

import (
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/port"
	"github.com/truvity/access-roster/internal/portstore"
)

func selfLink(id int64, login string, emails ...string) link.Link {
	now := time.Now().UTC().Truncate(time.Second)
	return link.Link{
		ID: id, Login: login, AppID: 9, Emails: emails, State: link.StateLinked, LinkedAt: now,
		AccessToken: "ghu_ACCESS_" + login, AccessExpires: now.Add(8 * time.Hour),
		RefreshToken: "ghr_REFRESH_" + login, RefreshExpires: now.Add(180 * 24 * time.Hour),
	}
}

func byID(t *testing.T, s *portstore.GitHubLinks, id int64) link.Link {
	t.Helper()
	all, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range all {
		if all[i].ID == id {
			return all[i]
		}
	}
	t.Fatalf("link %d is not stored", id)
	return link.Link{}
}

func TestALinkIsOneItemWithItsTokensSealed(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		s := portstore.NewGitHubLinks(portstore.New(set))
		written, err := s.Claim(ctx, selfLink(101, "ada", "ada@acme.example"), time.Now())
		if err != nil || len(written) != 1 || written[0].Revision != 1 {
			t.Fatalf("Claim = %+v, %v", written, err)
		}
		got := byID(t, s, 101)
		if got.AccessToken != "ghu_ACCESS_ada" || got.RefreshToken != "ghr_REFRESH_ada" || got.Revision != 1 {
			t.Fatalf("the stored link lost its tokens or its revision: %+v", got)
		}
		noPlaintext(t, set.State, "ghu_ACCESS_ada")
		noPlaintext(t, set.State, "ghr_REFRESH_ada")
		rec, err := set.State.Get(ctx, "gh.link.101")
		if err != nil {
			t.Fatalf("the link is not under gh.link.<account>: %v", err)
		}
		// The key is permanent: a link outlives its tokens (lost, profile and
		// imported links hold none).
		if len(rec.Value) == 0 {
			t.Fatal("empty item")
		}
		// A token pair copied under another account does not open: the link
		// comes back with no tokens, and is never treated as the other's.
		copyRaw(t, set.State, "gh.link.101", "gh.link.202")
		all, _ := s.List(ctx)
		for i := range all {
			if all[i].ID == 101 && all[i].AccessToken == "" {
				t.Error("the original lost its tokens")
			}
			if all[i].ID == 202 {
				t.Errorf("a link replayed under another account was read: %+v", all[i])
			}
		}
		if err = set.State.Delete(ctx, "gh.link.202"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAnUpdateOfAStaleRevisionIsNotWritten(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		s := portstore.NewGitHubLinks(e.base(t))
		if _, err := s.Claim(ctx, selfLink(101, "ada", "ada@acme.example"), time.Now()); err != nil {
			t.Fatal(err)
		}
		read := byID(t, s, 101)
		// The person links again meanwhile.
		if _, err := s.Claim(ctx, selfLink(101, "ada", "ada@acme.example"), time.Now()); err != nil {
			t.Fatal(err)
		}
		read.CheckedAt = time.Now()
		written, err := s.Update(ctx, []link.Link{read})
		if err != nil || len(written) != 0 {
			t.Fatalf("Update of a stale revision = %+v, %v; want nothing written", written, err)
		}
		fresh := byID(t, s, 101)
		fresh.CheckedAt = time.Now().UTC()
		if written, err = s.Update(ctx, []link.Link{fresh}); err != nil || len(written) != 1 || written[0].Revision != fresh.Revision+1 {
			t.Fatalf("Update = %+v, %v", written, err)
		}
	})
}

func TestOfManyWritersThatReadOneLinkExactlyOneUpdatesIt(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		stores := []*portstore.GitHubLinks{portstore.NewGitHubLinks(e.base(t)), portstore.NewGitHubLinks(e.base(t))}
		if _, err := stores[0].Claim(ctx, selfLink(101, "ada", "ada@acme.example"), time.Now()); err != nil {
			t.Fatal(err)
		}
		read := byID(t, stores[0], 101)
		var wg sync.WaitGroup
		var mu sync.Mutex
		winners := 0
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mine := read
				mine.RefreshingSince = time.Now()
				written, err := stores[i%2].Update(ctx, []link.Link{mine})
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				winners += len(written)
				mu.Unlock()
			}()
		}
		wg.Wait()
		if winners != 1 {
			t.Errorf("%d writers that read the same revision all wrote it, want exactly one", winners)
		}
	})
}

func TestClaimingAnAddressNarrowsTheOtherAccount(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		s := portstore.NewGitHubLinks(e.base(t))
		now := time.Now()
		if _, err := s.Claim(ctx, selfLink(101, "ada-old", "ada@acme.example", "ada@work.example"), now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(ctx, selfLink(102, "ada-new", "ada@acme.example"), now); err != nil {
			t.Fatal(err)
		}
		if old := byID(t, s, 101); !slices.Equal(old.Emails, []string{"ada@work.example"}) || old.State != link.StateLinked {
			t.Errorf("the old account = %+v, want narrowed to the address it still proves", old)
		}
		// Claiming its last address loses it, and forgets its tokens.
		if _, err := s.Claim(ctx, selfLink(103, "ada-third", "ada@work.example"), now); err != nil {
			t.Fatal(err)
		}
		if old := byID(t, s, 101); old.State != link.StateLost || old.AccessToken != "" || old.RefreshToken != "" {
			t.Errorf("the old account = %+v, want lost with no tokens", old)
		}
		// No claim marker is left behind.
		markers, err := portstore.New(e.open(t)).State.List(ctx, "gate.github-claim.", "", 10)
		if err != nil || len(markers.Records) != 0 {
			t.Errorf("claim markers left: %+v, %v", markers.Records, err)
		}
	})
}

// A claim whose writer died after the new link was kept and before the others
// were narrowed is finished by the next reader: the marker is the recovery.
func TestAHalfDoneClaimIsFinishedByTheNextRead(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		s := portstore.NewGitHubLinks(portstore.New(set))
		now := time.Now().UTC()
		if _, err := s.Claim(ctx, selfLink(101, "ada-old", "ada@acme.example"), now); err != nil {
			t.Fatal(err)
		}
		// What a writer that died after its second step leaves: the new link
		// stored, the marker standing, the old account untouched.
		claimed := selfLink(102, "ada-new", "ada@acme.example")
		claimed.Revision = 1
		raw, err := link.Encode(claimed)
		if err != nil {
			t.Fatal(err)
		}
		item, _ := json.Marshal(map[string]any{"v": 1, "record": json.RawMessage(raw)})
		if _, err = set.State.Put(ctx, "gh.link.102", item, 0); err != nil {
			t.Fatal(err)
		}
		marker, _ := json.Marshal(map[string]any{"id": 102, "login": "ada-new", "emails": []string{"ada@acme.example"}, "at": now})
		if _, err = set.State.Put(ctx, "gate.github-claim.102", marker, time.Hour); err != nil {
			t.Fatal(err)
		}

		if old := byID(t, s, 101); old.State != link.StateLost || old.Reason == "" {
			t.Errorf("the old account = %+v, want the claim finished: lost to the new one", old)
		}
		if _, err = set.State.Get(ctx, "gate.github-claim.102"); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("the marker outlived the finished claim: %v", err)
		}
	})
}

func TestAdoptNeverDisplacesALinkThatCounts(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		s := portstore.NewGitHubLinks(e.base(t))
		now := time.Now()
		if _, err := s.Claim(ctx, selfLink(101, "ada", "ada@acme.example"), now); err != nil {
			t.Fatal(err)
		}
		profile := link.Link{ID: 105, Login: "bob", Source: link.SourceProfile, Emails: []string{"bob@acme.example"}, LinkedAt: now}
		again := link.Link{ID: 101, Login: "ada", Source: link.SourceImported, Emails: []string{"ada@acme.example"}, LinkedAt: now}
		taken := link.Link{ID: 106, Login: "eve", Source: link.SourceImported, Emails: []string{"ada@acme.example"}, LinkedAt: now}
		written, skipped, err := s.Adopt(ctx, []link.Link{profile, again, taken})
		if err != nil || len(written) != 1 || written[0].ID != 105 || len(skipped) != 2 {
			t.Fatalf("Adopt = %+v, %v, %v", written, skipped, err)
		}
		if got := byID(t, s, 105); got.State != link.StateLinked || got.AccessToken != "" {
			t.Errorf("the adopted link = %+v", got)
		}
		if got := byID(t, s, 101); got.Source != "" && got.Source != link.SourceSelf {
			t.Errorf("a self-link was displaced by %+v", got)
		}
	})
}

func TestInvalidateMakesEverySelfLinkUnverifiableAndForgetsItsTokens(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		s := portstore.NewGitHubLinks(e.base(t))
		now := time.Now()
		if _, err := s.Claim(ctx, selfLink(101, "ada", "ada@acme.example"), now); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Claim(ctx, selfLink(102, "bob", "bob@acme.example"), now); err != nil {
			t.Fatal(err)
		}
		n, err := s.Invalidate(ctx, "the link App was disconnected", now)
		if err != nil || n != 2 {
			t.Fatalf("Invalidate = %d, %v", n, err)
		}
		for _, id := range []int64{101, 102} {
			if l := byID(t, s, id); l.State != link.StateUnverifiable || l.AccessToken != "" || l.RefreshToken != "" {
				t.Errorf("link %d = %+v", id, l)
			}
		}
		if n, err = s.Invalidate(ctx, "again", now); err != nil || n != 0 {
			t.Errorf("a second Invalidate changed %d, %v", n, err)
		}
	})
}
