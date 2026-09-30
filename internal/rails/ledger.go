package rails

import "sync"

// Ledger remembers, per target, which held rows were recorded at the last
// pass, so that each is recorded once, when it becomes held, and not on
// every pass for as long as it stays so.
type Ledger struct {
	mu   sync.Mutex
	seen map[string]map[string]bool
}

// Fresh says, parallel to now, which keys are new since the last call for
// target. The first call for a target in this process takes "the last
// pass" from seed — the keys of the report a previous process persisted —
// so a restart does not record everything again; with no seed, or one that
// returns nothing, everything is fresh, which is the safe way to be wrong.
// Afterwards the ledger holds exactly now. A key repeated within now is
// fresh each time it is not in the last pass.
func (l *Ledger) Fresh(target string, now []string, seed func() []string) []bool {
	l.mu.Lock()
	last, known := l.seen[target]
	l.mu.Unlock()
	if !known {
		last = map[string]bool{}
		if seed != nil {
			for _, key := range seed() {
				last[key] = true
			}
		}
	}
	fresh := make([]bool, len(now))
	current := make(map[string]bool, len(now))
	for i, key := range now {
		fresh[i] = !last[key]
		current[key] = true
	}
	l.mu.Lock()
	if l.seen == nil {
		l.seen = map[string]map[string]bool{}
	}
	l.seen[target] = current
	l.mu.Unlock()
	return fresh
}
