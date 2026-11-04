package keyd

import (
	"context"
	"errors"

	"github.com/truvity/sluis/v2/kits/go/store"
)

// A revoked key signs nothing more (ADR 0041, "The tighten-only record"; REQ-KEYS-109). KeyRevocation is a durable,
// create-only kind that store@ guarantees only grows (REQ-KEYS-091), so key@ reads it and never has to doubt that an
// item it saw is still there. An item names one target; a Sign is refused when the key it would use is named by its
// purpose or by its kid. The check reads the kind through store@ at every Sign: a revocation takes effect at the next
// call, and an unreadable store@ refuses the Sign (fail closed), because "not revoked" is a claim that must be verified
// (principle 4).

// The target kinds of a KeyRevocation item.
const (
	targetKid     = "kid"
	targetPurpose = "purpose"
)

// revocationID is the id of the item that revokes a target. A kid is a thumbprint with upper-case letters, which an
// address part does not allow, so it is named by the same lower-case base32 as a recipient label.
func revocationID(kind, target string) string {
	if kind == targetKid {
		return kind + "/" + recipientLabel(target)
	}
	return kind + "/" + target
}

// revoked reports whether KeyRevocation lists the key of a purpose, by the purpose or by the kid of the key.
func (s *Server) revoked(ctx context.Context, purpose, keyID string) (bool, error) {
	for _, id := range []string{revocationID(targetPurpose, purpose), revocationID(targetKid, keyID)} {
		_, err := s.revocations.Get(ctx, "", id)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, store.ErrNotFound):
		default:
			return false, err
		}
	}
	return false, nil
}
