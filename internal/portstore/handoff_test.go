package portstore_test

import (
	"testing"
	"time"

	"github.com/truvity/access-roster/internal/portstore"
	"github.com/truvity/access-roster/internal/slackroster/connection"
)

// The host's tick and the guest's tick run in separate processes: separate
// stores over the same State, here the same NATS bucket. The share record is
// what carries the share between them.
func TestAShareIsHandedFromTheHostToTheGuestAcrossProcesses(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		hostSet, guestSet := e.open(t), e.open(t)
		host := portstore.NewHandoff(portstore.New(hostSet), hostSet.Trigger)
		guest := portstore.NewHandoff(portstore.New(guestSet), guestSet.Trigger)

		woken := make(chan string, 4)
		stop := guestSet.Trigger.Subscribe(func(target string) { woken <- target })
		defer stop()

		now := time.Now().UTC()
		if err := host.Offer(ctx, "acme", "partners", "C0123", "globex", "Fi01", now); err != nil {
			t.Fatal(err)
		}
		// Writing the share asks the guest to tick.
		select {
		case target := <-woken:
			if target != "globex" {
				t.Errorf("the notification named %q, want the guest", target)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the guest's runner was not asked to tick")
		}

		waiting, err := guest.Waiting(ctx, "globex")
		if err != nil || len(waiting) != 1 {
			t.Fatalf("Waiting = %+v, %v", waiting, err)
		}
		if w := waiting[0]; w.Host != "acme" || w.Channel != "partners" || w.ChannelID != "C0123" || w.InviteID != "Fi01" {
			t.Errorf("the guest read %+v", w)
		}
		if other, _ := guest.Waiting(ctx, "initech"); len(other) != 0 {
			t.Errorf("a workspace that was not invited sees %+v", other)
		}

		if err = guest.Accepted(ctx, "acme", "partners", "C0123", "globex", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if waiting, _ = guest.Waiting(ctx, "globex"); len(waiting) != 0 {
			t.Errorf("an accepted share is still waiting: %+v", waiting)
		}
		share, found, err := host.Status(ctx, "acme", "partners")
		if err != nil || !found || !share.Settled() || share.Guests["globex"].State != connection.ShareAccepted {
			t.Fatalf("the host reads %+v, %v, %v; want the guest's side accepted", share, found, err)
		}
	})
}

func TestAShareLivesUntilAcceptedAndThenSevenDays(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		h := portstore.NewHandoff(portstore.New(set), nil)
		now := time.Now().UTC()
		if err := h.Offer(ctx, "acme", "partners", "C1", "globex", "", now); err != nil {
			t.Fatal(err)
		}
		if err := h.Offer(ctx, "acme", "partners", "C1", "initech", "", now); err != nil {
			t.Fatal(err)
		}
		// Pending outlives the accepted lifetime.
		e.advance(10 * 24 * time.Hour)
		if _, found, _ := h.Status(ctx, "acme", "partners"); !found {
			t.Fatal("a pending share expired after ten days")
		}
		// One guest of two accepting settles nothing: it stays pending.
		if err := h.Accepted(ctx, "acme", "partners", "C1", "globex", now); err != nil {
			t.Fatal(err)
		}
		share, _, _ := h.Status(ctx, "acme", "partners")
		if share.Settled() {
			t.Fatal("a share with a guest still pending is settled")
		}
		if waiting, _ := h.Waiting(ctx, "initech"); len(waiting) != 1 {
			t.Errorf("the second guest's share is not waiting: %+v", waiting)
		}
		// The second accepts: seven days from now, and then it goes by itself.
		if err := h.Accepted(ctx, "acme", "partners", "C1", "initech", now); err != nil {
			t.Fatal(err)
		}
		e.advance(6 * 24 * time.Hour)
		if _, found, _ := h.Status(ctx, "acme", "partners"); !found {
			t.Fatal("an accepted share was dropped inside its week")
		}
		e.advance(25 * time.Hour)
		if _, found, err := h.Status(ctx, "acme", "partners"); err != nil || found {
			t.Errorf("an accepted share outlived its week: %v, %v", found, err)
		}
		if _, err := set.State.Get(ctx, "share.acme.partners"); err == nil {
			t.Error("the record is still readable under share.<host>.<channel>")
		}
	})
}

func TestTwoGuestsAcceptingAtOnceLoseNeitherSide(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		a, b := e.open(t), e.open(t)
		ha, hb := portstore.NewHandoff(portstore.New(a), a.Trigger), portstore.NewHandoff(portstore.New(b), b.Trigger)
		now := time.Now().UTC()
		if err := ha.Offer(ctx, "acme", "partners", "C1", "globex", "", now); err != nil {
			t.Fatal(err)
		}
		if err := ha.Offer(ctx, "acme", "partners", "C1", "initech", "", now); err != nil {
			t.Fatal(err)
		}
		errs := make(chan error, 2)
		go func() { errs <- ha.Accepted(ctx, "acme", "partners", "C1", "globex", now) }()
		go func() { errs <- hb.Accepted(ctx, "acme", "partners", "C1", "initech", now) }()
		for range 2 {
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
		}
		share, found, err := ha.Status(ctx, "acme", "partners")
		if err != nil || !found || !share.Settled() {
			t.Errorf("share = %+v, %v, %v; want both sides accepted", share, found, err)
		}
	})
}

func TestTheUserCacheAnswersForADayAndNeverRemembersADeactivatedAccount(t *testing.T) {
	each(t, func(t *testing.T, e env) {
		set := e.open(t)
		c := portstore.NewUserCache(portstore.New(set))
		if _, hit := c.Get(ctx, "acme", "U1"); hit {
			t.Fatal("a hit on an empty cache")
		}
		c.Put(ctx, "acme", reconcileMember("U1", "ada@acme.example", false))
		got, hit := c.Get(ctx, "acme", "U1")
		if !hit || got.Email != "ada@acme.example" || got.ID != "U1" || got.TeamID != "T1" {
			t.Fatalf("Get = %+v, %v", got, hit)
		}
		if _, hit = c.Get(ctx, "globex", "U1"); hit {
			t.Error("one workspace's member answered for another's")
		}
		c.Put(ctx, "acme", reconcileMember("U2", "gone@acme.example", true))
		if _, hit = c.Get(ctx, "acme", "U2"); hit {
			t.Error("a deactivated account was cached")
		}
		if _, err := set.State.Get(ctx, "cache.slack.user.acme.U1"); err != nil {
			t.Errorf("the entry is not under cache.slack.user.<workspace>.<id>: %v", err)
		}
		e.advance(portstore.UserCacheTTL - time.Minute)
		if _, hit = c.Get(ctx, "acme", "U1"); !hit {
			t.Error("the entry expired early")
		}
		e.advance(2 * time.Minute)
		if _, hit = c.Get(ctx, "acme", "U1"); hit {
			t.Error("the entry outlived its day")
		}
		if _, err := set.State.Get(ctx, "cache.slack.user.acme.U1"); err == nil {
			t.Error("State still returns the expired entry")
		}
	})
}
