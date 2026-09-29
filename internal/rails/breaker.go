package rails

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
)

// Fingerprint names a set of pending changes: the same set, listed in any
// order, names the same fingerprint, so an operator confirms it once and
// the confirmation holds however the set is later listed.
func Fingerprint(lines []string) string {
	sorted := slices.Clone(lines)
	slices.Sort(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:8])
}

// Breaker is a pass that would change more of a target than its threshold
// allows.
type Breaker struct {
	// Affected is how many distinct things the pending changes concern,
	// and Total is how many the target has.
	Affected, Total int
	// Fingerprint names exactly this set of changes. Confirming it lets
	// this set, and no other, go ahead.
	Fingerprint string
	// Confirmed is whether the confirmed fingerprint passed to
	// [CheckBreaker] named this exact set.
	Confirmed bool
}

// CheckBreaker trips when affected accounts for more than half of total
// (and total is nonzero), unless confirmed already names exactly the
// fingerprint of lines. It returns nil when the breaker does not trip at
// all: nothing to report, and every pending change goes ahead.
func CheckBreaker(affected int, lines []string, total int, confirmed string) *Breaker {
	if total == 0 || affected*2 <= total {
		return nil
	}
	fingerprint := Fingerprint(lines)
	return &Breaker{
		Affected: affected, Total: total, Fingerprint: fingerprint,
		Confirmed: confirmed != "" && confirmed == fingerprint,
	}
}
