package keyd

import (
	"context"
	"errors"
	"time"

	"github.com/truvity/sluis/v2/kits/go/store"
)

// A revoked key signs nothing more (ADR 0041, "The tighten-only record"; REQ-KEYS-109). KeyRevocation is a durable,
// create-only kind that store@ guarantees only grows (REQ-KEYS-091), so key@ reads it and never has to doubt that an
// item it saw is still there. An item names one target; a Sign is refused when the key it would use is named by its
// purpose (for the keys made before the declaration) or by its kid. The check reads the kind through store@ at every Sign: a revocation takes effect at the next
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

// clockSkew is how far ahead of this node's clock the age of a key may be and still count. A key store whose clock
// runs ahead could stamp a key as newer than a revocation; an age later than now plus this is not believed, and the
// key is treated as of unknown age (refused while its purpose is revoked). Time sync on the nodes keeps the skew small
// (ADR 0041).
const clockSkew = 5 * time.Minute

// revoked says which target of KeyRevocation stops the key of a purpose from signing: "" when none does.
//
// A revocation of the key's kid refuses it for ever. A revocation of the purpose refuses the keys made at or before
// the time of the declaration, and not a replacement made after it ("a replacement signs at once", ADR 0041): a key
// whose age the key store cannot say, or says to be later than now (plus clockSkew), is refused, because a key of
// unknown age cannot be shown to be a replacement.
func (s *Server) revoked(ctx context.Context, purpose string, pk purposeKey) (string, error) {
	if _, err := s.revocations.Get(ctx, "", revocationID(targetKid, pk.keyID)); err == nil {
		return targetKid, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	it, err := s.revocations.Get(ctx, "", revocationID(targetPurpose, purpose))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", nil
	case err != nil:
		return "", err
	}
	at := it.Value.GetRevokedAt()
	if at == nil || pk.created.IsZero() || pk.created.After(s.now().Add(clockSkew)) || !pk.created.After(at.AsTime()) {
		return targetPurpose, nil
	}
	return "", nil
}
