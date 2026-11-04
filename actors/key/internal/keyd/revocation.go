package keyd

import (
	"context"
	"errors"

	"github.com/truvity/sluis/v2/kits/go/store"
)

// A revoked key signs nothing more (ADR 0041, "The tighten-only record"; REQ-KEYS-109). KeyRevocation is a durable,
// create-only kind that store@ guarantees only grows (REQ-KEYS-091), so key@ reads it and never has to doubt that an
// item it saw is still there. An item names one key by its kid: a declaration names exact keys and never a whole
// purpose, because a key of a card made in a ceremony has no age that a purpose cutoff could be compared with, and a
// cutoff would refuse its replacement too (ADR 0041, "The declaration"). The check reads the kind through
// store@ at every Sign: a revocation takes effect at the next call, and an unreadable store@ refuses the Sign (fail
// closed), because "not revoked" is a claim that must be verified (principle 4).

// targetKid is the target kind of a KeyRevocation item that revokes one key.
const targetKid = "kid"

// revocationID is the id of the item that revokes a target. A kid is a thumbprint with upper-case letters, which an
// address part does not allow, so it is named by the same lower-case base32 as a recipient label.
func revocationID(kind, target string) string {
	if kind == targetKid {
		return kind + "/" + recipientLabel(target)
	}
	return kind + "/" + target
}

// revoked says whether KeyRevocation lists the key: the target kind that stops it, or "" when none does.
func (s *Server) revoked(ctx context.Context, pk purposeKey) (string, error) {
	_, err := s.revocations.Get(ctx, "", revocationID(targetKid, pk.keyID))
	switch {
	case err == nil:
		return targetKid, nil
	case errors.Is(err, store.ErrNotFound):
		return "", nil
	}
	return "", err
}
