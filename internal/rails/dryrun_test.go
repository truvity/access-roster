package rails_test

import (
	"testing"

	"github.com/truvity/access-roster/internal/rails"
)

// Act runs its function only when the switch is on.
func TestSwitchActGatesOnItsValue(t *testing.T) {
	t.Parallel()
	ran := false
	rails.Switch(false).Act(func() { ran = true })
	if ran {
		t.Error("Act ran while off")
	}
	rails.Switch(true).Act(func() { ran = true })
	if !ran {
		t.Error("Act did not run while on")
	}
}

// Decide picks the outcome in a fixed priority: off with anything pending
// is a dry run; on with changes is applied; otherwise held, retrying and
// waiting are considered in that order, and nothing pending at all is in
// sync.
func TestSwitchDecidesInPriorityOrder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		enabled bool
		tick    rails.Tick
		want    rails.Outcome
	}{
		{"off, nothing pending, is in sync, not a dry run", false, rails.Tick{}, rails.OutcomeInSync},
		{"off with changes pending is a dry run", false, rails.Tick{Changes: 1}, rails.OutcomeDryRun},
		{"off with only held pending is still a dry run", false, rails.Tick{Held: 1}, rails.OutcomeDryRun},
		{"off with only retrying pending is still a dry run", false, rails.Tick{Retrying: 1}, rails.OutcomeDryRun},
		{"off with only waiting pending is not a dry run", false, rails.Tick{Waiting: 1}, rails.OutcomeWaiting},
		{"on with changes is applied", true, rails.Tick{Changes: 1}, rails.OutcomeApplied},
		{"on with changes and held is still applied", true, rails.Tick{Changes: 1, Held: 1}, rails.OutcomeApplied},
		{"on with held is held", true, rails.Tick{Held: 1}, rails.OutcomeHeld},
		{"on with held and retrying is held", true, rails.Tick{Held: 1, Retrying: 1}, rails.OutcomeHeld},
		{"on with retrying is retrying", true, rails.Tick{Retrying: 1}, rails.OutcomeRetrying},
		{"on with waiting alone is waiting", true, rails.Tick{Waiting: 1}, rails.OutcomeWaiting},
		{"on with nothing pending is in sync", true, rails.Tick{}, rails.OutcomeInSync},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := rails.Switch(c.enabled).Decide(c.tick); got != c.want {
				t.Errorf("Decide(%v, %+v) = %v, want %v", c.enabled, c.tick, got, c.want)
			}
		})
	}
}
