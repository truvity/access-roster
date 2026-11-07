package keyd

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

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

// indexByTarget is the declared index of KeyRevocation (kinds.yaml) that maps a target to its item. key@ gives every item
// the entry, so that a reader finds one revocation, a kid that signs, with one linearizable listing of at most one item
// and not a walk over the whole kind, and a miss is a page with no item and not a refusal that store@ audits. The value is
// the target kind, a slash and the target as it is written; tests/testdata/keyrevocation/ids.json holds the readers in
// Rust to it.
const indexByTarget = "by_target"

// targetIndexValue is the value of the index entry of a revocation.
func targetIndexValue(kind, target string) []byte { return []byte(kind + "/" + target) }

// revocationPage is the page size of a listing of KeyRevocation: the kind only grows by a person's declaration, so it is
// a few items, and one page holds them.
const revocationPage = 200

// maxRevocationPages is how many pages one listing may read: the Rust readers (entry, signer) stop at the same number.
// It is 200,000 items, far beyond what a person revokes by hand; a listing that does not end is a store@ that is not
// answering as it should, and the check fails closed on it.
const maxRevocationPages = 1000

// errRevocationsNotEnded is a listing of KeyRevocation that did not end within maxRevocationPages.
var errRevocationsNotEnded = errors.New("KeyRevocation: the listing did not end")

// revokedIDs lists the ids of KeyRevocation. It lists and never asks for one id: store@ audits every refusal (ADR 0005),
// and a Get of a key that is not revoked, which is the answer nearly every time, is a refusal for the answer that is
// expected. A list of a kind with no item is an empty page and no refusal. An unreadable store@ is an error: "not
// revoked" is verified, never assumed.
//
// The listing is linearizable, as the Get it replaced was: a List that does not ask is read by the leader without
// confirming that it still leads, so a leader just deposed could answer without a revocation that was acknowledged
// moments before (ADR 0005: "Authority-relevant reads are linearizable"). A store that cannot give a linearizable read
// refuses the call, and so does a leader change that is in progress: the check then fails closed like any unreadable
// store@. The answers of the PIN release (pinReleases) are read without it: a stale one costs a poll, and a PIN is only
// ever given for an answer whose signature was verified.
func (s *Server) revokedIDs(ctx context.Context) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	token := ""
	// Every page is read before the answer is given: a revocation on a later page must not read as "not revoked", and a
	// walk that fails half way returns the error and none of the pages it did read.
	for range maxRevocationPages {
		page, next, err := s.revocations.List(ctx, "", store.PageSize(revocationPage), store.PageToken(token), store.Linearizable())
		if err != nil {
			return nil, err
		}
		for _, it := range page {
			out[it.ID] = struct{}{}
		}
		if next == "" {
			return out, nil
		}
		token = next
	}
	return nil, errRevocationsNotEnded
}

// revCacheLife is how long the listing of one releasing pass is reused for the requests after the first. A pass that holds
// many requests (a flood from a compromised store@ is the case that matters) would otherwise walk the whole kind, at the
// linearizable level, for each of them. The cache is the pass's own and is dropped with it: a revocation acknowledged
// while the pass runs is seen by the next request that comes more than this after the listing started, and by the next
// pass at the latest. A Sign never uses it, and neither does the requester, which checks once for each answer.
const revCacheLife = time.Second

// revCache is the listing a pass holds, and when it began.
type revCache struct {
	ids map[string]struct{}
	at  time.Time
}

// revocationSet is the revoked ids for a check: the cache when it is younger than revCacheLife, else a new listing
// (revokedIDs). A nil cache lists every time. A failed listing empties the cache and is an error.
func (s *Server) revocationSet(ctx context.Context, rc *revCache) (map[string]struct{}, error) {
	if rc != nil && rc.ids != nil && s.now().Sub(rc.at) < revCacheLife {
		return rc.ids, nil
	}
	began := s.now()
	ids, err := s.revokedIDs(ctx)
	if rc != nil {
		rc.ids, rc.at = ids, began
	}
	return ids, err
}

// unindexedEvery is how often the listing that covers the items with no entry in the index is taken again.
const unindexedEvery = 10 * time.Second

// unindexedRevocations is the listing of the whole kind that Sign adds to its look at the index, for an item the index does
// not know: one that an earlier key@ wrote before the index existed (or an older key@ of another board during a rollout),
// or one a restore wrote without the entry (REQ-BACKUP-064 and 065 are not built; they must write the entry too). It is
// taken at most every unindexedEvery, off the path of the Sign: a Sign uses the last one, and a stale one is replaced in
// the background, so a kind too long to list within the call's time can no more stop a signature. The first one is taken by
// the first Sign, which fails closed when it cannot. Until it is taken again an item of this kind is seen late, by at most
// unindexedEvery plus the listing; every item key@ writes is in the index and is seen at once.
type unindexedRevocations struct {
	mu        sync.Mutex
	ids       map[string]struct{}
	at        time.Time
	refreshes bool // a refresh is under way
}

// get returns the last listing, starting a refresh when it is stale. The first call lists and waits.
func (s *Server) unindexedSet(ctx context.Context) (map[string]struct{}, error) {
	u := &s.unindexed
	u.mu.Lock()
	if u.ids == nil {
		u.mu.Unlock()
		ids, err := s.revokedIDs(ctx)
		if err != nil {
			return nil, err
		}
		u.mu.Lock()
		defer u.mu.Unlock()
		u.ids, u.at = ids, s.now()
		return u.ids, nil
	}
	ids := u.ids
	if s.now().Sub(u.at) >= unindexedEvery && !u.refreshes {
		u.refreshes = true
		go s.refreshUnindexed(context.WithoutCancel(ctx))
	}
	u.mu.Unlock()
	return ids, nil
}

// refreshUnindexed lists the kind again and keeps the result; a failed listing keeps the last one and is logged.
func (s *Server) refreshUnindexed(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	began := s.now()
	ids, err := s.revokedIDs(ctx)
	u := &s.unindexed
	u.mu.Lock()
	defer u.mu.Unlock()
	u.refreshes = false
	if err != nil {
		slog.Warn("KeyRevocation cannot be listed in full: a revocation with no entry in the index is seen late", "err", err)
		u.at = began // try again after the interval, not at every Sign
		return
	}
	u.ids, u.at = ids, began
}

// revokedByIndex says whether KeyRevocation lists the key, by one linearizable listing of the index by_target: at most one
// item, however many keys are revoked, and no refusal for store@ to audit when it is not (ADR 0005).
func (s *Server) revokedByIndex(ctx context.Context, kid string) (bool, error) {
	page, _, err := s.revocations.List(ctx, "", store.ByIndex(indexByTarget, targetIndexValue(targetKid, kid)), store.PageSize(1), store.Linearizable())
	if err != nil {
		return false, err
	}
	return len(page) > 0, nil
}

// revoked says whether KeyRevocation lists the key: the target kind that stops it, or "" when none does. It asks the index
// for the key, and the last full listing for an item the index does not know. An unreadable index is an error (fail
// closed), and so is a first full listing that cannot be taken.
func (s *Server) revoked(ctx context.Context, pk purposeKey) (string, error) {
	listed, err := s.revokedByIndex(ctx, pk.keyID)
	if err != nil {
		return "", err
	}
	if listed {
		return targetKid, nil
	}
	ids, err := s.unindexedSet(ctx)
	if err != nil {
		return "", err
	}
	if _, ok := ids[revocationID(targetKid, pk.keyID)]; ok {
		return targetKid, nil
	}
	return "", nil
}
