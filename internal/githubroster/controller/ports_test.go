package controller_test

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/githubroster/controller"
	"github.com/truvity/access-roster/internal/githubroster/link"
	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/portstore/portstoretest"
)

// atBarrier makes every replica's first read of the links wait for the other,
// so that both have read the same revision before either writes: the race a
// refresh token, which GitHub honours once, has to survive.
type atBarrier struct {
	controller.LinkStore
	wg   *sync.WaitGroup
	once sync.Once
}

func (b *atBarrier) List(ctx context.Context) ([]link.Link, error) {
	links, err := b.LinkStore.List(ctx)
	b.once.Do(func() {
		b.wg.Done()
		b.wg.Wait()
	})
	return links, err
}

// Two replicas of the controller read the same link, both see its token near
// its end, and both go to refresh it. GitHub honours a refresh token once, so
// the exchange must happen once: the marker write that precedes it is a
// compare-and-swap on the link's item, and only the replica whose swap lands
// may exchange. The other re-reads, finds the winner's pair, and uses it.
func TestTwoReplicasNeverSpendARefreshTokenTwice(t *testing.T) {
	portstoretest.Each(t, func(t *testing.T, e portstoretest.Env) {
		r := newRig(t)
		before := joined(t, r)
		const exchange = "POST /login/oauth/access_token"

		bases := []*portstore.Base{portstore.New(e.Open(t)), portstore.New(e.Open(t))}
		seed := r.links.get(r.newbie.ID)
		seed.AccessExpires = time.Now().Add(30 * time.Minute) // inside the renewal window
		if _, err := portstore.NewGitHubLinks(bases[0]).Claim(context.Background(), seed, time.Now()); err != nil {
			t.Fatal(err)
		}
		old := seed.RefreshToken
		hits := r.github.Hit(exchange)

		var barrier sync.WaitGroup
		barrier.Add(2)
		var run sync.WaitGroup
		for _, base := range bases {
			run.Add(1)
			go func() {
				defer run.Done()
				c := controller.New(controller.Config{AppsDir: r.appsDir, Enabled: map[string]bool{"globex": true}}, controller.Deps{
					Log: slog.New(slog.NewTextHandler(io.Discard, nil)), GitHub: r.github.Client(),
					Access: r.console, Audit: r.audit, Status: r.report, Bindings: bindings, Policy: testPolicy,
					Links: &atBarrier{LinkStore: portstore.NewGitHubLinks(base), wg: &barrier},
				})
				c.Pass(context.Background())
			}()
		}
		run.Wait()

		if spent := r.github.Hit(exchange) - hits; spent != 1 {
			t.Errorf("the refresh token was exchanged %d times, want exactly once", spent)
		}
		got, err := portstore.NewGitHubLinks(bases[1]).List(context.Background())
		if err != nil || len(got) != 1 {
			t.Fatalf("links = %+v, %v", got, err)
		}
		l := got[0]
		if l.State != link.StateLinked || l.RefreshToken == old || l.AccessToken != r.github.Accounts["newbie"].Access ||
			l.RefreshToken != r.github.Accounts["newbie"].Refresh || !l.RefreshingSince.IsZero() {
			t.Errorf("the stored link is %+v, want linked with the one pair GitHub issued last and no marker", l)
		}
		if after := r.github.Did()[before:]; slices.Contains(after, "remove-from-org newbie") {
			t.Errorf("a refresh race removed the person: %v", after)
		}
	})
}
