//nolint:lll // messages and fixtures are prose and one-line tables
package minter_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/sluis/internal/audit"
	"github.com/truvity/sluis/internal/cloudflare/minter"
	"github.com/truvity/sluis/internal/config"
)

// holding is a minter over e's store that holds rotated R2 credentials back
// for the default time, waiting with wait instead of a timer.
func holding(t *testing.T, e *env, wait func(ctx context.Context, d time.Duration) error) *minter.Minter {
	t.Helper()
	cfg := e.cfg
	cfg.PublishAfter = 0
	m, err := minter.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.TestOnlySleep(wait)
	return m
}

// R2 refuses a token Cloudflare has just created, at times for half a minute,
// and a consumer woken by token.minted reads the document at once. The
// scheduled rotation therefore stores an R2 credential only once it is
// DefaultPublishAfter old: until then the document names the one it replaces,
// which is still valid, and nothing announces the new one.
func TestAScheduledR2RotationIsStoredOnlyOnceItHasBeenHeldBack(t *testing.T) {
	e := setup(t)
	if res := e.m.TickPreset(ctx, "r2"); res.Err != nil {
		t.Fatal(res.Err)
	}
	var held []time.Duration
	m := holding(t, e, func(_ context.Context, d time.Duration) error {
		held = append(held, d)
		doc, _, err := e.external("r2").Get(ctx)
		if err != nil || doc.AccessKeyID != "tok001" {
			t.Errorf("while the new credential is held back the document holds %q (%v), want the credential it replaces, tok001", doc.AccessKeyID, err)
		}
		if n := len(e.rec.Find("roster.cloudflare.token.minted")); n != 1 {
			t.Errorf("token.minted records while the new credential is held back = %d, want 1 (the first rotation's)", n)
		}
		e.advance(d)
		return nil
	})
	e.advance(5 * time.Minute)
	res := m.TickPreset(ctx, "r2")
	if res.Err != nil || res.Outcome != minter.OutcomeRotated {
		t.Fatalf("tick = %+v", res)
	}
	if len(held) != 1 || held[0] != minter.DefaultPublishAfter {
		t.Fatalf("held back for %v, want once for %v", held, minter.DefaultPublishAfter)
	}
	doc, _, err := e.external("r2").Get(ctx)
	if err != nil || doc.AccessKeyID != "tok002" {
		t.Fatalf("after the hold the document holds %q (%v), want tok002", doc.AccessKeyID, err)
	}
	if n := len(e.rec.Find("roster.cloudflare.token.minted")); n != 2 {
		t.Errorf("token.minted records = %d, want 2", n)
	}
}

// A rotation stopped while its credential is held back stores nothing and
// deletes the token, as a write that failed does: the document keeps the
// credential it held, and the next tick mints again.
func TestARotationStoppedWhileHeldBackStoresNothingAndDeletesTheToken(t *testing.T) {
	e := setup(t)
	if res := e.m.TickPreset(ctx, "r2"); res.Err != nil {
		t.Fatal(res.Err)
	}
	m := holding(t, e, func(context.Context, time.Duration) error { return context.DeadlineExceeded })
	e.advance(5 * time.Minute)
	res := m.TickPreset(ctx, "r2")
	if res.Outcome != minter.OutcomeFailed || !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Fatalf("tick = %+v, want failed with the deadline", res)
	}
	if doc, _, _ := e.external("r2").Get(ctx); doc.AccessKeyID != "tok001" {
		t.Errorf("the document holds %q, want tok001", doc.AccessKeyID)
	}
	if _, ok := e.api.names()["tok002"]; ok {
		t.Error("the token minted for the stopped rotation was not deleted")
	}
	if n := len(e.rec.Find("roster.cloudflare.token.refused")); n != 1 {
		t.Errorf("refused records = %d, want 1", n)
	}
}

// Only the scheduled rotation of an R2 preset waits: an API token preset has
// no derived credential to propagate, an operator who rotates now is answered
// now, and a revoked token's replacement is needed at once.
func TestOnlyTheScheduledRotationOfAnR2PresetIsHeldBack(t *testing.T) {
	e := setup(t)
	var held atomic.Int32
	m := holding(t, e, func(context.Context, time.Duration) error { held.Add(1); return nil })
	if res := m.TickPreset(ctx, "dns"); res.Err != nil || res.Outcome != minter.OutcomeRotated {
		t.Fatalf("dns tick = %+v", res)
	}
	if _, err := m.RotateNow(ctx, "r2", audit.System()); err != nil {
		t.Fatal(err)
	}
	doc, _, _ := e.external("r2").Get(ctx)
	if _, err := m.Revoke(ctx, "r2", doc.AccessKeyID, audit.System()); err != nil {
		t.Fatal(err)
	}
	if n := held.Load(); n != 0 {
		t.Errorf("held back %d times, want none", n)
	}
}

// The presets are ticked at the same time, so the holds of several R2 presets
// overlap: a pass over N of them waits one hold, not N, and stays inside a
// Lambda function's timeout.
func TestTheTickHoldsItsR2PresetsBackAtTheSameTime(t *testing.T) {
	e := setupWith(t, nil, func(c *config.Cloudflare) {
		p := c.Presets["r2"]
		p.Description = "R2 b"
		c.Presets["r2-b"] = p
	})
	if got := e.m.Tick(ctx); got.Err() != nil {
		t.Fatal(got.Err())
	}
	var waiting atomic.Int32
	both := make(chan struct{})
	m := holding(t, e, func(ctx context.Context, _ time.Duration) error {
		if waiting.Add(1) == 2 {
			close(both)
		}
		select {
		case <-both:
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("the holds of the two R2 presets ran one after the other")
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	e.advance(5 * time.Minute)
	got := m.Tick(ctx)
	if got.Err() != nil {
		t.Fatal(got.Err())
	}
	if want := "dns=rotated dns-edge=rotated r2=rotated r2-b=rotated"; got.Summary() != want {
		t.Errorf("summary = %q, want %q (in name order)", got.Summary(), want)
	}
}
