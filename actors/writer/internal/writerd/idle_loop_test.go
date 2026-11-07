//go:build sluis_test

package writerd

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/refusal"
)

// The writer's own sealing used to feed the next seal. Every seal needs a grant from policy (batch.go, grantFor), and
// policy writes one policy.decide record for every decision it makes (actors/policy/src/service.rs; ADR 0007, "every
// decision is audited"), which reaches the writer in the next batch. With a grant asked for in every batch the log
// never went quiet: a board with no traffic made a batch every 5 s, 10 records a minute, 10 card signatures a minute
// (14,400 a day), and about 200,000 record ids in the 14-day window (MEASURED 2026-11-07).
//
// The writer now keeps the grant for its life, less grantMargin (ADR 0007: "reusable for about 60 seconds"), so the
// record of the decision is sealed under the grant that made it. The tests below play policy@'s part (one record for
// each decision the fake policy answers) in a simulated clock, one step per batch window.

// sealSim is a writer on a simulated clock, with policy@'s decision records fed back as the next input.
type sealSim struct {
	t       *testing.T
	e       *env
	clk     *testClock
	s       *Server
	em      *audit.Emitter
	pending []message // delivered to the next batch
	handled int       // decisions whose record has been made
	batches int
}

func newSealSim(t *testing.T) *sealSim {
	t.Helper()
	clk := &testClock{t: windowStart}
	e := newEnv(t)
	e.cfg.Now, e.cfg.Mono = clk.now, clk.mono
	m := &sealSim{t: t, e: e, clk: clk, em: emitterAt(t, clk.now)}
	m.s = e.direct(t)
	return m
}

// emit queues a record of the tenant, as an actor's record reaching the writer.
func (m *sealSim) emit(tenant string) {
	m.t.Helper()
	m.pending = append(m.pending, messageAt(m.t, m.em, tenant, m.clk.now()))
}

// step lets d pass and seals what is waiting as one batch; policy@ writes a record for each decision of the batch,
// which waits for the next one.
func (m *sealSim) step(d time.Duration) {
	m.t.Helper()
	m.clk.set(m.clk.now().Add(d))
	if len(m.pending) == 0 {
		return
	}
	batch := m.pending
	m.pending = nil
	process(m.t, m.s, batch...)
	m.batches++
	m.decisionRecords()
}

// decisionRecords makes the policy.decide record of each decision since the last call.
func (m *sealSim) decisionRecords() {
	m.t.Helper()
	n := len(m.e.pol.requests())
	for range n - m.handled {
		m.emit("acme")
	}
	m.handled = n
}

// run steps through the period in windows of the default batch window.
func (m *sealSim) run(period time.Duration) {
	m.t.Helper()
	for range int(period / DefaultBatchWindow) {
		m.step(DefaultBatchWindow)
	}
}

func (m *sealSim) decisions() int  { return len(m.e.pol.requests()) }
func (m *sealSim) signatures() int { return countEvents(m.e, "key.sign") }
func (m *sealSim) records() int    { return len(recordEntries(logEntries(m.t, m.e.logDir()))) }

// verifies: REQ-AUDIT-180, REQ-AUDIT-181
// From one record and no further input the writer seals it, the record of the decision it needed seals once more
// under the grant that made it, and then nothing happens for two hours: no record, no card signature and no policy
// decision. That is 0 records and 0 signatures an hour on a quiet board (it was 600 and 600).
func TestAnIdleWriterSealsOneRecordAndTheRecordOfItsDecisionAndThenGoesQuiet(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme") // the one record
	m.run(time.Minute)
	if m.batches != 2 || m.decisions() != 1 || m.signatures() != 2 || m.records() != 2 {
		t.Fatalf("after a minute: %d batches, %d decisions, %d signatures, %d records; want 2, 1, 2, 2",
			m.batches, m.decisions(), m.signatures(), m.records())
	}
	// Both batches were sealed under the one grant.
	if g := m.e.key.grantsShown(); len(g) != 2 || g[0] != g[1] {
		t.Fatalf("grants shown to key@: %v; want one grant twice", g)
	}
	if len(m.pending) != 0 {
		t.Fatalf("%d messages are still waiting; the writer feeds itself", len(m.pending))
	}
	for hour := 1; hour <= 2; hour++ {
		before := [4]int{m.batches, m.decisions(), m.signatures(), m.records()}
		m.run(time.Hour)
		if got := [4]int{m.batches, m.decisions(), m.signatures(), m.records()}; got != before {
			t.Fatalf("hour %d of a quiet board: batches, decisions, signatures, records went from %v to %v; want no change", hour, before, got)
		}
	}
	m.e.mustVerify(t)
}

// verifies: REQ-AUDIT-180, REQ-AUDIT-181
// The first record after the grant has expired is the one decision that makes one extra batch, and the loop still
// ends. A record inside the life of the grant needs no decision.
func TestARecordAfterTheGrantExpiredCostsOneDecisionAndOneExtraBatchAndTheLoopEnds(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme")
	m.run(time.Hour)
	b, d, sg := m.batches, m.decisions(), m.signatures()

	m.emit("acme") // an hour on: the grant is long expired
	m.run(time.Hour)
	if m.decisions() != d+1 || m.batches != b+2 || m.signatures() != sg+2 {
		t.Fatalf("a record after the expiry: %d decisions, %d batches, %d signatures more; want 1, 2, 2",
			m.decisions()-d, m.batches-b, m.signatures()-sg)
	}

	// A record inside the life of a grant: sealed under it, no decision, no extra batch.
	m.run(time.Hour) // quiet, and the grant expires again
	m.emit("acme")
	m.run(5 * DefaultBatchWindow) // 25 s: the record and the record of its decision are sealed; the grant is 20 s old
	b, d, sg = m.batches, m.decisions(), m.signatures()
	m.emit("acme")
	m.run(time.Hour)
	if m.decisions() != d || m.batches != b+1 || m.signatures() != sg+1 {
		t.Fatalf("a record inside the grant's life: %d decisions, %d batches, %d signatures more; want 0, 1, 1",
			m.decisions()-d, m.batches-b, m.signatures()-sg)
	}
}

// verifies: REQ-AUDIT-181
// A busy writer makes about one decision a minute, not one for every batch: a record in every batch window for
// twenty minutes is 240 batches, and the grant is asked for once in about 50 s (the 60 s of its life less grantMargin),
// which is 72 decisions an hour.
func TestABusyWriterMakesAboutOneDecisionAMinuteNotOnePerBatch(t *testing.T) {
	m := newSealSim(t)
	for range int(20 * time.Minute / DefaultBatchWindow) {
		m.emit("acme")
		m.step(DefaultBatchWindow)
	}
	// 1200 s / 50 s = 24 decisions.
	t.Logf("%d batches, %d decisions, %d signatures in 20 simulated minutes", m.batches, m.decisions(), m.signatures())
	if m.batches != 240 || m.decisions() < 23 || m.decisions() > 25 {
		t.Fatalf("20 minutes of a record in every window: %d batches and %d decisions; want 240 batches and about 24 decisions", m.batches, m.decisions())
	}
	m.e.mustVerify(t)
}

// verifies: REQ-AUDIT-182
// A grant that is refused is not kept. Policy denies: nothing is sealed, nothing is held, and the next batch asks
// again. Policy gives a grant and key@ then refuses it: the writer drops it and asks again. A grant that policy gives
// no expiry for serves its batch only.
func TestAGrantThatIsRefusedOrHasNoExpiryIsNotReused(t *testing.T) {
	ctx := context.Background()
	t.Run("denied", func(t *testing.T) {
		m := newSealSim(t)
		m.e.pol.mu.Lock()
		m.e.pol.mode = "deny"
		m.e.pol.mu.Unlock()
		m.emit("acme")
		if err := m.s.processBatch(ctx, deliveries(m.pending...)); err == nil {
			t.Fatal("a batch was sealed without a grant")
		}
		if len(m.s.held) != 0 || m.e.key.sealCount() != 0 {
			t.Fatalf("a denied decision left %d grants held and %d seals", len(m.s.held), m.e.key.sealCount())
		}
		m.e.pol.mu.Lock()
		m.e.pol.mode = ""
		m.e.pol.mu.Unlock()
		m.step(DefaultBatchWindow)
		if m.decisions() != 2 {
			t.Fatalf("%d decisions; the second batch must ask again after a denial", m.decisions())
		}
	})
	t.Run("refused by key", func(t *testing.T) {
		m := newSealSim(t)
		m.emit("acme")
		m.step(DefaultBatchWindow)
		m.step(DefaultBatchWindow) // the record of the decision, under the held grant
		if m.decisions() != 1 {
			t.Fatalf("%d decisions, want 1", m.decisions())
		}
		// key@'s clock is a minute ahead of the writer's: it finds the grant expired while the writer still holds it.
		ahead := func() time.Time { return m.clk.now().Add(time.Minute) }
		m.e.key.setClock(ahead)
		m.emit("acme")
		if err := m.s.processBatch(ctx, deliveries(m.pending...)); err == nil {
			t.Fatal("key@ sealed under an expired grant")
		}
		if len(m.s.held) != 0 {
			t.Fatal("the grant key@ refused is still held")
		}
		m.e.key.setClock(m.clk.now)
		m.step(DefaultBatchWindow)
		if m.decisions() != 2 {
			t.Fatalf("%d decisions; the writer must ask again after key@ refused its grant", m.decisions())
		}
	})
	t.Run("no expiry", func(t *testing.T) {
		m := newSealSim(t)
		m.e.pol.noExpiry = true
		m.emit("acme")
		m.run(time.Minute)
		// Every batch asks: the record of each decision is sealed under a decision of its own, so the loop goes on.
		if m.decisions() != m.batches || len(m.s.held) != 0 {
			t.Fatalf("%d decisions for %d batches with %d held; a grant without an expiry must serve one batch", m.decisions(), m.batches, len(m.s.held))
		}
	})
}

// verifies: REQ-AUDIT-182
// A permission that policy takes away reaches the writer no later than the life of the grant it holds: the writer
// seals under the grant it has until grantMargin before its expiry (50 s after the decision), and the first batch
// after that asks policy, is denied, and seals nothing. The worst case is 50 s, inside the 60 s of ADR 0007 ("a grant
// already issued outlives a tightening by at most about 60 seconds").
func TestARevokedPermissionTakesEffectNoLaterThanTheLifeOfTheGrant(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme")
	m.step(DefaultBatchWindow) // the decision, at time 0 of the grant's life
	m.e.pol.mu.Lock()
	m.e.pol.mode = "deny"
	m.e.pol.mu.Unlock()
	start := m.clk.now()

	m.clk.set(start.Add(49 * time.Second)) // inside the life: sealed under the grant it holds
	m.emit("acme")
	process(t, m.s, m.pending...)
	m.pending = nil
	if m.decisions() != 1 {
		t.Fatalf("%d decisions: the writer asked policy inside the grant's life", m.decisions())
	}

	m.clk.set(start.Add(50 * time.Second)) // the margin: the grant is no longer presented
	m.emit("acme")
	sealed := m.e.key.sealCount()
	if err := m.s.processBatch(ctx(), deliveries(m.pending...)); err == nil {
		t.Fatal("a batch was sealed after the grant's life, with the permission taken away")
	}
	if m.decisions() != 2 || m.e.key.sealCount() != sealed {
		t.Fatalf("%d decisions, %d seals more; want the second decision to deny and nothing sealed", m.decisions(), m.e.key.sealCount()-sealed)
	}
}

func ctx() context.Context { return context.Background() }

// verifies: REQ-AUDIT-182
// A restart starts with no grant: a new writer asks policy at once, whatever the grant of the one before it.
func TestARestartStartsWithNoGrant(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme")
	m.step(DefaultBatchWindow)
	if len(m.s.held) != 1 {
		t.Fatalf("%d grants held after a seal, want 1", len(m.s.held))
	}
	m.s = m.e.direct(t) // the process starts again, 5 s into the life of the grant
	if len(m.s.held) != 0 {
		t.Fatal("a new writer holds a grant")
	}
	m.emit("acme")
	m.step(DefaultBatchWindow)
	if m.decisions() != 2 {
		t.Fatalf("%d decisions; a restarted writer must ask for its own grant", m.decisions())
	}
}

// verifies: REQ-AUDIT-182
// A wall clock that is set back does not keep a grant past its life: the life is counted on the clock that does not
// step as well.
func TestAClockSetBackDoesNotKeepAGrantPastItsLife(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme")
	m.step(DefaultBatchWindow)
	m.step(DefaultBatchWindow) // the record of the decision
	m.clk.jump(m.clk.now().Add(-30 * time.Minute))
	d := m.decisions()
	m.clk.set(m.clk.now().Add(46 * time.Second)) // 51 s since the grant came; the wall clock is still before its expiry
	m.emit("acme")
	m.step(0)
	if m.decisions() != d+1 {
		t.Fatalf("%d decisions more; a grant held 51 s by the clock that does not step must not be presented", m.decisions()-d)
	}
}

// verifies: REQ-AUDIT-182
// The writer takes the expiry from policy but never keeps a grant longer than a grant may live: a policy that states an
// hour for a grant that key@ judges at 60 s is not believed. Without the clamp the writer would present the grant 65 s
// after the decision and key@ would refuse it.
func TestAnExpiryOfAnHourIsClampedToTheLifeOfAGrant(t *testing.T) {
	m := newSealSim(t)
	m.e.pol.mu.Lock()
	m.e.pol.statedLife = time.Hour
	m.e.pol.mu.Unlock()
	m.emit("acme")
	m.step(DefaultBatchWindow) // the decision
	if len(m.s.held) != 1 {
		t.Fatalf("%d grants held, want 1", len(m.s.held))
	}
	h := m.s.held["acme"]
	if life := h.until.Sub(m.clk.now()); life > maxGrantLife-grantMargin {
		t.Fatalf("the grant is kept %s by the wall clock; no more than %s", life, maxGrantLife-grantMargin)
	}
	m.clk.set(m.clk.now().Add(65 * time.Second))
	m.emit("acme")
	m.step(0) // sealed under a new grant; key@ would refuse the old one
	if m.decisions() != 2 {
		t.Fatalf("%d decisions, want 2: the grant of 65 s ago must not be presented", m.decisions())
	}
}

// verifies: REQ-AUDIT-182
// Only a refusal that names the grant drops it. A batch key@ cannot seal for another reason (a tenant whose evidence
// key is gone, a rule) is retried under the grant held, and costs no decision and no record per retry.
func TestARefusalThatIsNotAboutTheGrantKeepsIt(t *testing.T) {
	m := newSealSim(t)
	m.emit("acme")
	m.step(DefaultBatchWindow)
	m.step(DefaultBatchWindow) // the record of the decision
	if m.decisions() != 1 {
		t.Fatalf("%d decisions, want 1", m.decisions())
	}
	for name, err := range map[string]error{
		"permission_denied/rule":         refusal.New(connect.CodePermissionDenied, "rule", "purpose"),
		"failed_precondition/expired":    refusal.New(connect.CodeFailedPrecondition, "expired", "sealed_grant"),
		"permission_denied, no reason":   connect.NewError(connect.CodePermissionDenied, errors.New("no")),
		"unavailable/driver (key@ lock)": refusal.New(connect.CodeUnavailable, "driver", ""),
	} {
		m.e.key.mu.Lock()
		m.e.key.failSeal = err
		m.e.key.mu.Unlock()
		m.emit("acme")
		for range 3 { // a poison batch, retried
			if m.s.processBatch(ctx(), deliveries(m.pending...)) == nil {
				t.Fatalf("%s: the batch was sealed", name)
			}
		}
		if len(m.s.held) != 1 || m.decisions() != 1 {
			t.Fatalf("%s: %d grants held and %d decisions after 3 retries; want 1 and 1", name, len(m.s.held), m.decisions())
		}
		m.e.key.mu.Lock()
		m.e.key.failSeal = nil
		m.e.key.mu.Unlock()
		m.step(DefaultBatchWindow) // it seals once key@ can, under the grant it had
		if m.decisions() != 1 {
			t.Fatalf("%s: %d decisions after the recovery, want 1", name, m.decisions())
		}
	}
	// A refusal that names the grant drops it, whatever the code (key@ gives permission_denied/grant for an expired one).
	m.e.key.mu.Lock()
	m.e.key.failSeal = refusal.New(connect.CodePermissionDenied, "grant", "grant")
	m.e.key.mu.Unlock()
	m.emit("acme")
	if m.s.processBatch(ctx(), deliveries(m.pending...)) == nil {
		t.Fatal("the batch was sealed")
	}
	if len(m.s.held) != 0 {
		t.Fatal("a refusal of the grant left it held")
	}
}
