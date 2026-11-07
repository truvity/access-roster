package sessiond

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/session/v2alpha1"
	typev2alpha1 "github.com/truvity/sluis/v2/gen/go/sluis/type/v2alpha1"
	"github.com/truvity/sluis/v2/kits/go/audit"
	"github.com/truvity/sluis/v2/kits/go/store"
)

// refreshGrace is how long after a rotation the token it replaced is still answered, with the same successor. A
// client whose response was lost, or a second replica that read the chain before the first wrote it, presents the old
// token again within moments (REQ-SESS-013). It is the 30 seconds of v1, and a constant: the window is a property of
// the protocol's retry, not something an installation tunes.
const refreshGrace = 30 * time.Second

// labelRefreshSuccessor separates the keyed hash that makes a successor from every other use of the boundary's mac key.
const labelRefreshSuccessor = "sluis-refresh-successor-v1"

// refreshSuccessor is the refresh token that replaces the one whose SHA-384 is predecessor: a keyed hash (HMAC-SHA384
// at key@, under the boundary's mac key) of the tenant, the sid and that hash, cut to 256 bits. It is a function of
// the predecessor so that every replica, and a retry, derives the same successor without the chain holding any token:
// the store keeps hashes only (0004 "Treatment"), and the secret of a token never reaches key@. Nobody without key@
// can compute it, and a holder of an old token cannot walk forward to the current one.
func (k keys) refreshSuccessor(ctx context.Context, tenant, sid string, predecessor []byte) (string, error) {
	m, err := k.mac(ctx, "mac", "", labelRefreshSuccessor, lengthPrefixed(tenant, sid, string(predecessor)))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(m[:32]), nil
}

// refreshSkew is how far ahead of this clock another replica's stamp may be and still count as recent: the time a
// request takes, and the difference between the clocks of replicas that keep time (a few seconds). A stamp further
// ahead is not a recent rotation, it is a clock that is wrong, and the window is not opened for it.
const refreshSkew = 5 * time.Second

// inGrace says a rotation made at rotatedAt is recent enough for its predecessor to be answered again: not more than
// refreshGrace ago, and not more than refreshSkew ahead of now. A stamp from the future (a replica whose clock runs
// ahead) must not open the window for as long as the clock is ahead.
func inGrace(now time.Time, rotatedAt *timestamppb.Timestamp) bool {
	d := now.Sub(rotatedAt.AsTime())
	return d >= -refreshSkew && d <= refreshGrace
}

// stampAhead says a rotation stamp is further ahead of this clock than refreshSkew: a replica whose clock is wrong made
// it. The idle limit counts from the stamp, so a stamp from the future would hold the session open for as long as that
// clock is ahead, and the chain is not trusted: it ends like one that reached its limit. What stays is the error of
// the clocks themselves: a chain stamped by a replica a little ahead idles out later by as much (an error of any limit
// counted by several clocks).
func stampAhead(now time.Time, stamp *timestamppb.Timestamp) bool {
	return stamp.AsTime().Sub(now) > refreshSkew
}

// isSuccessor says the chain's current token is next: the presented token was the one the last rotation replaced.
func isSuccessor(chain *sessionv2alpha1.SessionChain, next string) bool {
	return hashEqual(secretHash(next), chain.GetRefreshHash())
}

// afterLostRace answers a rotation whose conditional write found the chain moved: another presentation got there first.
// It reads the chain again. If the chain now holds the successor of this very token, the other request was this
// token's twin, made moments ago, and this one gets the same answer (the chain is as it should be, and nothing is
// written). Anything else (the chain is gone, or moved on by more than this token) is not a retry: a chain that is gone
// is refused as an unknown token, and one that has moved on ends, because a spent token came back.
//
// It returns the chain to answer from, or the response to give.
func (s *Service) afterLostRace(ctx context.Context, tc *tokenCtx, sid, next string, person *audit.Subject, v *verdict) (*sessionv2alpha1.SessionChain, *connect.Response[typev2alpha1.HttpReply], error) {
	it, err := s.chains.Get(ctx, tc.tenant, sid)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Ended by whoever won: they recorded the end. This is an unknown token now.
		return nil, s.refuse(ctx, tc, person, v, reasonRefresh, errInvalidGrant()), nil
	case err != nil:
		return nil, nil, unavailable("store", err)
	}
	if isSuccessor(it.Value, next) && inGrace(tc.now, it.Value.GetRefreshedAt()) {
		return it.Value, nil, nil
	}
	if derr := s.deleteChain(ctx, tc, sid, v.grant, reasonReuse); derr != nil {
		return nil, nil, derr
	}
	return nil, s.refuse(ctx, tc, person, v, reasonReuse, errInvalidGrant()), nil
}
