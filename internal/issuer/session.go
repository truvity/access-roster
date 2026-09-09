package issuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// How says what produced a session, because "revoke Ada's kubectl login"
// is a different act from "revoke the console she left open", and an
// operator can only tell them apart if the issuer remembers which was
// which.
type How string

// The ways a session begins.
const (
	// HowCode is a browser sign-in: OIDC code + PKCE.
	HowCode How = "code"
	// HowDevice is a device-code flow: a CLI on a machine with no browser.
	HowDevice How = "device"
	// HowExchange is a workload or a CI job trading a token it already had.
	HowExchange How = "exchange"
)

// Session is one refresh token, described. The token itself is not here:
// this is the index that makes sessions listable and revocable, which is
// what turns "the issuer holds some state" into something an operator can
// act on and a person can audit.
//
// A session belongs to one identity and one client. That pairing is the
// unit of revocation: ending someone's ArgoCD session must not end their
// kubectl session, or an operator dealing with one incident would cut off
// work they never meant to touch.
type Session struct {
	ID            string    `json:"id"`
	Identity      string    `json:"identity"`
	ClientID      string    `json:"client_id"`
	How           How       `json:"how"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	LastRefreshed time.Time `json:"last_refreshed,omitempty"`
}

// Live reports whether the session is still usable at now. An expired
// session stays in the index until it is swept, so that "it expired" and
// "it never existed" remain different answers.
func (s Session) Live(now time.Time) bool { return now.Before(s.ExpiresAt) }

// Sessions is the per-identity index beside the refresh tokens.
//
// It lives in the SHARED state, not in the process. A browser signs in at
// one replica and refreshes at another; an operator's listing hits
// whichever the gateway picked. An index in memory would answer with the
// sessions that one pod happened to record — a list that is not wrong so
// much as arbitrary, and a revocation that reports success while the
// session goes on working at the pod next door. For a control whose whole
// job is to end access, that is the worst possible failure, so the index
// is shared or it is not worth having.
//
// Four kinds of key, and expiry belongs to exactly one of them. The
// session record `session:<id>` carries the TTL; the sets that make it
// findable hold ids and no lifetime of their own. A listing that meets an
// id whose record is gone drops it from the set as it goes, so the sets
// repair themselves and the record's expiry stays the single answer to
// "is this session still alive".
type Sessions struct {
	state    State
	now      func() time.Time
	newID    func() string
	lifetime time.Duration
}

// NewSessions returns the index over a shared store. lifetime is how long
// a refresh token lives when nothing shorter applies.
func NewSessions(state State, lifetime time.Duration) *Sessions {
	return &Sessions{
		state:    state,
		now:      time.Now,
		newID:    uuid.NewString,
		lifetime: lifetime,
	}
}

// SetClock replaces the clock, for tests.
func (s *Sessions) SetClock(now func() time.Time) { s.now = now }

// SetIDs replaces the id source, for tests.
func (s *Sessions) SetIDs(newID func() string) { s.newID = newID }

// The keys. A refresh token is a bearer secret, so it is HASHED into its
// key rather than written into the keyspace: an index that can be read
// must not be an index that can be replayed.
func sessionKey(id string) string          { return "issuer:session:" + id }
func sessionOfKey(identity string) string  { return "issuer:sessions-of:" + strings.ToLower(identity) }
func sessionForKey(clientID string) string { return "issuer:sessions-for:" + clientID }
func sessionTokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "issuer:session-token:" + hex.EncodeToString(sum[:])
}

// sessionAllKey is every session, for the operator's "what is open right
// now". It is a set of ids and nothing more; the records it points at are
// what expire.
const sessionAllKey = "issuer:sessions"

// Record files a newly issued refresh token and returns the session it
// created.
func (s *Sessions) Record(
	ctx context.Context, identity, clientID string, how How, token string,
) (Session, error) {
	now := s.now()
	session := Session{
		ID:        s.newID(),
		Identity:  strings.ToLower(identity),
		ClientID:  clientID,
		How:       how,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.lifetime),
	}

	if err := s.put(ctx, session); err != nil {
		return Session{}, err
	}

	if err := s.state.Set(ctx, sessionTokenKey(token), []byte(session.ID), s.lifetime); err != nil {
		return Session{}, err
	}

	for _, key := range []string{sessionAllKey, sessionOfKey(session.Identity), sessionForKey(session.ClientID)} {
		if err := s.state.Add(ctx, key, session.ID, s.lifetime); err != nil {
			return Session{}, err
		}
	}

	return session, nil
}

// Refreshed moves a session onto a new token, which is what a refresh
// does: the old token is spent and must stop working, and the session it
// belongs to carries on with its identity, its client and its history.
// It reports whether the old token named a live session.
func (s *Sessions) Refreshed(ctx context.Context, oldToken, newToken string) (Session, bool, error) {
	session, found, err := s.ByToken(ctx, oldToken)
	if err != nil || !found {
		return Session{}, false, err
	}

	if err = s.state.Delete(ctx, sessionTokenKey(oldToken)); err != nil {
		return Session{}, false, err
	}

	now := s.now()
	session.LastRefreshed = now
	session.ExpiresAt = now.Add(s.lifetime)

	if err = s.put(ctx, session); err != nil {
		return Session{}, false, err
	}

	if err = s.state.Set(ctx, sessionTokenKey(newToken), []byte(session.ID), s.lifetime); err != nil {
		return Session{}, false, err
	}

	// The sets carry the session forward too: their expiry is refreshed
	// with every add, so a session that keeps being used keeps being
	// findable.
	for _, key := range []string{sessionAllKey, sessionOfKey(session.Identity), sessionForKey(session.ClientID)} {
		if err = s.state.Add(ctx, key, session.ID, s.lifetime); err != nil {
			return Session{}, false, err
		}
	}

	return session, true, nil
}

// ByToken resolves a refresh token to its session.
func (s *Sessions) ByToken(ctx context.Context, token string) (Session, bool, error) {
	raw, found, err := s.state.Get(ctx, sessionTokenKey(token))
	if err != nil || !found {
		return Session{}, false, err
	}

	return s.byID(ctx, string(raw))
}

// Query narrows a listing. The zero value lists every live session, which
// is what an operator looking for what is open right now asks for.
type Query struct {
	Identity string
	ClientID string
}

// set is the narrowest set that can answer this query. Asking for one
// person's sessions must not read every session in the installation.
func (q Query) set() string {
	switch {
	case q.Identity != "":
		return sessionOfKey(q.Identity)
	case q.ClientID != "":
		return sessionForKey(q.ClientID)
	default:
		return sessionAllKey
	}
}

// List returns the live sessions a query selects, newest first.
func (s *Sessions) List(ctx context.Context, q Query) ([]Session, error) {
	sessions, err := s.collect(ctx, q)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(sessions, func(a, b Session) int {
		if d := b.IssuedAt.Compare(a.IssuedAt); d != 0 {
			return d
		}

		return strings.Compare(a.ID, b.ID)
	})

	return sessions, nil
}

// Revoke ends every session a query selects and returns how many. It is
// the only write the console has against the issuer, and it can only ever
// remove: an empty query would end everything, so a caller that means
// "this person" must say so.
func (s *Sessions) Revoke(ctx context.Context, q Query) (int, error) {
	sessions, err := s.collect(ctx, q)
	if err != nil {
		return 0, err
	}

	ended := 0

	for i := range sessions {
		gone, err := s.RevokeID(ctx, sessions[i].ID)
		if err != nil {
			// Say how many actually ended. A revocation that stops
			// halfway must not report the number it hoped for.
			return ended, err
		}

		if gone {
			ended++
		}
	}

	return ended, nil
}

// RevokeID ends one session by its id, which is what "sign this one out"
// on a person's page does. It reports whether there was one to end.
//
// The token index is NOT walked to find the token that pointed here:
// there is no way to go from a session id back to the hash of its token,
// which is the price of not keeping the secret in the keyspace. The
// pointer expires on its own, and it resolves through the record — which
// is gone — so it grants nothing in the meantime.
func (s *Sessions) RevokeID(ctx context.Context, id string) (bool, error) {
	session, found, err := s.byID(ctx, id)
	if err != nil {
		return false, err
	}

	if err = s.state.Delete(ctx, sessionKey(id)); err != nil {
		return false, err
	}

	for _, key := range []string{sessionAllKey, sessionOfKey(session.Identity), sessionForKey(session.ClientID)} {
		if err = s.state.Remove(ctx, key, id); err != nil {
			return false, err
		}
	}

	return found, nil
}

// RevokeToken ends whichever session holds this refresh token. It is what
// RFC 7009 calls at the revocation endpoint, and what a proxy's sign-out
// reaches when it hands back the token it held.
func (s *Sessions) RevokeToken(ctx context.Context, token string) (bool, error) {
	raw, found, err := s.state.Get(ctx, sessionTokenKey(token))
	if err != nil || !found {
		return false, err
	}

	if err = s.state.Delete(ctx, sessionTokenKey(token)); err != nil {
		return false, err
	}

	return s.RevokeID(ctx, string(raw))
}

// Sweep drops the ids whose records have expired from every set it can
// reach, and returns how many. Expiry itself needs no sweeper — the
// record carries the TTL and a listing repairs what it walks — so this
// exists for the sets nobody has listed lately.
func (s *Sessions) Sweep(ctx context.Context) (int, error) {
	ids, err := s.state.Members(ctx, sessionAllKey)
	if err != nil {
		return 0, err
	}

	gone := 0

	for _, id := range ids {
		if _, found, err := s.byID(ctx, id); err != nil {
			return gone, err
		} else if !found {
			gone++
		}
	}

	return gone, nil
}

// collect reads a query's sessions, dropping ids whose records are gone
// from the set as it goes.
func (s *Sessions) collect(ctx context.Context, q Query) ([]Session, error) {
	key := q.set()

	ids, err := s.state.Members(ctx, key)
	if err != nil {
		return nil, err
	}

	identity := strings.ToLower(strings.TrimSpace(q.Identity))
	out := make([]Session, 0, len(ids))

	for _, id := range ids {
		session, found, err := s.byID(ctx, id)
		if err != nil {
			return nil, err
		}

		if !found {
			// Self-repair: the record expired, so the id is not a session
			// any more and the set should stop saying it is.
			if err = s.state.Remove(ctx, key, id); err != nil {
				return nil, err
			}

			continue
		}

		// The narrowest set still needs the other half of a two-part
		// query applied: "Ada's ArgoCD sessions" reads Ada's set and then
		// keeps the ArgoCD ones.
		switch {
		case identity != "" && session.Identity != identity:
		case q.ClientID != "" && session.ClientID != q.ClientID:
		default:
			out = append(out, session)
		}
	}

	return out, nil
}

// ByID reads one session. Exported because a caller acting on a session
// id must be able to check whose it is BEFORE ending it: an id alone is
// otherwise enough to end somebody else's.
func (s *Sessions) ByID(ctx context.Context, id string) (Session, bool, error) {
	return s.byID(ctx, id)
}

// byID reads one record. An expired record is absent, which is what makes
// the TTL the whole of expiry.
func (s *Sessions) byID(ctx context.Context, id string) (Session, bool, error) {
	session, err := getJSON[Session](ctx, s.state, sessionKey(id))
	if err != nil || session == nil {
		return Session{}, false, err
	}

	if !session.Live(s.now()) {
		return Session{}, false, nil
	}

	return *session, true, nil
}

// put writes a record with the lifetime left on it, so that the store's
// own expiry and the record's agree.
func (s *Sessions) put(ctx context.Context, session Session) error {
	ttl := time.Until(session.ExpiresAt)
	if now := s.now(); !now.IsZero() {
		ttl = session.ExpiresAt.Sub(now)
	}

	if ttl <= 0 {
		return fmt.Errorf("issuer: session %s has already expired", session.ID)
	}

	return setJSON(ctx, s.state, sessionKey(session.ID), session, ttl)
}
