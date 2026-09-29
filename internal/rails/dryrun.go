package rails

// Switch gates whether a pass acts on what it decided, or only reports
// what it would have. False is dry-run: a target is born disabled, and
// stays that way until somebody turns it on knowingly.
type Switch bool

// Act runs f only when the switch is on.
func (s Switch) Act(f func()) {
	if s {
		f()
	}
}

// Tick is the counts one pass's outcome is decided from.
type Tick struct {
	Changes, Held, Retrying, Waiting int
}

// Outcome is one pass's result over a target, independent of whatever
// states the caller's own report uses.
type Outcome int

// The outcomes, in the order [Switch.Decide] considers them.
const (
	// OutcomeDryRun: the switch was off, and Changes, Held or Retrying
	// counts what would have happened.
	OutcomeDryRun Outcome = iota
	// OutcomeApplied: changes were made.
	OutcomeApplied
	// OutcomeHeld: something was to be done and every such action was
	// held.
	OutcomeHeld
	// OutcomeRetrying: every pending action could not be taken this pass,
	// for a reason that clears on its own.
	OutcomeRetrying
	// OutcomeWaiting: nothing to do and nothing held, but the target is
	// not fully in sync either.
	OutcomeWaiting
	// OutcomeInSync: nothing to do.
	OutcomeInSync
)

// Decide is the general shape behind a reconciler's outcome word: off and
// something pending is a dry run; on with changes made is applied;
// otherwise held, then retrying, then waiting take priority over being in
// sync.
func (s Switch) Decide(t Tick) Outcome {
	switch {
	case !bool(s) && (t.Changes > 0 || t.Held > 0 || t.Retrying > 0):
		return OutcomeDryRun
	case t.Changes > 0:
		return OutcomeApplied
	case t.Held > 0:
		return OutcomeHeld
	case t.Retrying > 0:
		return OutcomeRetrying
	case t.Waiting > 0:
		return OutcomeWaiting
	default:
		return OutcomeInSync
	}
}
