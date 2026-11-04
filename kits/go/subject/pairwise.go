// Package subject holds what the units must compute the same way to agree on a subject. The pairwise `sub` of a
// person at a tenant is made twice, by session at sign-in and by exchange at token exchange, and ADR 0034 requires
// the two to be equal. Both build the input of the Mac with PairwiseInput, which is the only place the encoding is
// written; kits/conformance/subject/pairwise-vectors.json fixes its bytes.
package subject

import "encoding/binary"

// PairwiseInput is the input of the Mac under the tenant's pairwise key (label "pairwise") that makes a pairwise
// subject (ADR 0034, "Subjects and sectors"). Each part, the sector name and then the person's id, has a 4-byte
// big-endian length in front, so ("ab", "c") and ("a", "bc") differ. It is the same rule as the other Mac inputs and
// the audit pseudonym input of ADR 0029.
func PairwiseInput(sector, personID string) []byte {
	b := make([]byte, 0, 8+len(sector)+len(personID))
	for _, p := range [...]string{sector, personID} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p))) //nolint:gosec // G115: a sector and an id are bounded by the callers' checks
		b = append(b, p...)
	}
	return b
}
