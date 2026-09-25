package issuer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	ID       string `json:"id"`
	Identity string `json:"identity"`
	ClientID string `json:"client_id"`
	How      How    `json:"how"`
	// Scopes are what this session was granted at sign-in. A session
	// recorded before this field existed has none, and a refresh on one
	// of those is answered with the scopes it asks for or with none —
	// which is what the code did for every session until now.
	Scopes []string `json:"scopes,omitempty"`
	// Resource is what this session's tokens are FOR, when the sign-in
	// named one (RFC 8707). Empty means the client itself, which is every
	// session recorded before resources existed and every client that
	// names none.
	//
	// It lives here because a refresh an hour from now carries a token and
	// nothing else: without it the renewed token would be minted for the
	// CLIENT while the original was minted for the resource, silently
	// changing its audience mid-session -- and the resource's own gate
	// would go unchecked for the rest of the session's life.
	Resource string `json:"resource,omitempty"`
	// SSO is the browser session this one was opened from, empty for a
	// flow with no browser (an exchange, a device code redeemed by a
	// CLI). It is what makes *sign out everywhere* one operation on the
	// parent rather than a loop the console has to get right.
	SSO string `json:"sso,omitempty"`
	// AuthTime is when the person authenticated, carried down from the
	// SSO session so that a refresh an hour from now mints the same
	// `auth_time` and a fresh `iat` — without a second store read on the
	// hottest path.
	AuthTime      time.Time `json:"auth_time,omitempty"`
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
	// absolute is the global timeout: no per-client session outlives
	// auth_time by more than this, no matter how often it is refreshed.
	// Zero or negative means no such limit -- the deployment's own choice,
	// distinct from "not configured", which [Config.withDefaults] never
	// produces (see [DefaultAbsoluteLifetime]) but a caller that builds a
	// [Sessions] directly, as every existing test does, still can.
	absolute time.Duration
}

// NewSessions returns the index over a shared store. lifetime is how long
// a refresh token lives when nothing shorter applies; absolute is the
// global timeout measured from auth_time, or zero for none.
func NewSessions(state State, lifetime, absolute time.Duration) *Sessions {
	return &Sessions{
		state:    state,
		now:      time.Now,
		newID:    uuid.NewString,
		lifetime: lifetime,
		absolute: absolute,
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

// sessionRotatedKey records what a spent refresh token became, for
// [refreshGrace] after it was spent. Hashed like the token key it shadows,
// for the same reason: an index that can be read must not be an index that
// can be replayed.
func sessionRotatedKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "issuer:session-rotated:" + hex.EncodeToString(sum[:])
}

// capEnd is a session's end: the sliding refresh window from now, or the
// absolute session limit from auth_time, whichever comes first.
//
// A session with no auth_time is a workload or a machine exchange, which
// authenticated nobody -- there is no "since sign-in" to measure the limit
// from, so only the refresh window applies, exactly as before this limit
// existed. That is the whole of how [Sessions.Record] and
// [Sessions.Refreshed] leave a machine's session alone: this is the one
// place either of them decides an end, and here it simply has nothing to
// cap against.
func capEnd(now, authTime time.Time, refresh, absolute time.Duration) time.Time {
	end := now.Add(refresh)
	if authTime.IsZero() || absolute <= 0 {
		return end
	}
	if limit := authTime.Add(absolute); limit.Before(end) {
		return limit
	}
	return end
}

// refreshGrace is how long a refresh token that has just been rotated
// still answers, with the successor it produced. It is a property of the
// protocol rather than of an estate, so it is not configurable: long
// enough to cover one page's burst of concurrent calls, short enough that
// a stolen token is worth nothing by the time anyone could use it.
const refreshGrace = 30 * time.Second

// sessionAllKey is every session, for the operator's "what is open right
// now". It is a set of ids and nothing more; the records it points at are
// what expire.
const sessionAllKey = "issuer:sessions"

// Opened is one session about to be recorded. It is a struct rather than
// a row of arguments because the last three are easy to swap by mistake
// and impossible to notice afterwards: a session filed under the wrong
// client is one an operator cannot find and cannot end.
type Opened struct {
	Identity string
	ClientID string
	// Resource is what the tokens are for, when the request named one.
	Resource string
	How      How
	// Token is the refresh token; it is hashed into its key, never stored.
	Token string
	// Scopes are what was consented to.
	Scopes []string
	// SSO is the browser session this was opened from, if any.
	SSO string
	// AuthTime is when the person authenticated; zero for a flow where
	// nobody did.
	AuthTime time.Time
}

// Record files a newly issued refresh token and returns the session it
// created.
//
// The scopes are the ones the person consented to, and the session is
// the only place they survive: a refresh arrives an hour later carrying
// a token and nothing else, and what a relying party may ask for then is
// what it was granted at sign-in, not what it asks for now.
func (s *Sessions) Record(ctx context.Context, o Opened) (Session, error) {
	now := s.now()
	session := Session{
		ID:       s.newID(),
		Identity: strings.ToLower(o.Identity),
		ClientID: o.ClientID,
		Resource: o.Resource,
		How:      o.How,
		Scopes:   o.Scopes,
		SSO:      o.SSO,
		AuthTime: o.AuthTime,
		IssuedAt: now,
		// The absolute limit applies from the moment the session is
		// OPENED, not only from its first refresh: a browser session
		// carried down from hours-old SSO (a new client added to an
		// existing sign-in) must not get a fresh 24 hours of its own.
		ExpiresAt: capEnd(now, o.AuthTime, s.lifetime, s.absolute),
	}

	if err := s.put(ctx, session); err != nil {
		return Session{}, err
	}

	if err := s.state.Set(ctx, sessionTokenKey(o.Token), []byte(session.ID), s.lifetime); err != nil {
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
func (s *Sessions) Refreshed(ctx context.Context, oldToken, newToken string) (Session, string, bool, error) {
	session, found, err := s.ByToken(ctx, oldToken)
	if err != nil {
		return Session{}, "", false, err
	}

	// The token is spent. Either this is the replay of a refresh that has
	// just happened -- in which case the caller is handed the SAME
	// successor the winner got, not a second live credential -- or it is
	// a reuse worth refusing.
	if !found {
		return s.replayed(ctx, oldToken)
	}

	if err = s.state.Delete(ctx, sessionTokenKey(oldToken)); err != nil {
		return Session{}, "", false, err
	}

	// What the spent token became, for the grace window. Written before
	// the new token is, so a replay can never find a successor that is
	// not yet resolvable.
	if err = s.state.Set(ctx, sessionRotatedKey(oldToken), []byte(newToken), refreshGrace); err != nil {
		return Session{}, "", false, err
	}

	now := s.now()
	session.LastRefreshed = now
	// Capped exactly as at open: a sliding refresher plateaus at
	// auth_time+absolute rather than sliding forever, because every
	// rotation recomputes the SAME limit from the SAME auth_time.
	session.ExpiresAt = capEnd(now, session.AuthTime, s.lifetime, s.absolute)

	if err = s.put(ctx, session); err != nil {
		return Session{}, "", false, err
	}

	if err = s.state.Set(ctx, sessionTokenKey(newToken), []byte(session.ID), s.lifetime); err != nil {
		return Session{}, "", false, err
	}

	// The sets carry the session forward too: their expiry is refreshed
	// with every add, so a session that keeps being used keeps being
	// findable.
	for _, key := range []string{sessionAllKey, sessionOfKey(session.Identity), sessionForKey(session.ClientID)} {
		if err = s.state.Add(ctx, key, session.ID, s.lifetime); err != nil {
			return Session{}, "", false, err
		}
	}

	return session, newToken, true, nil
}

// replayed answers a refresh presented with a token that was rotated
// moments ago: it returns the successor that rotation produced, so the
// loser of a race ends up holding exactly what the winner holds.
//
// A browser does not refresh once. A page that opens with several calls
// at once, behind a gateway that refreshes PER REQUEST rather than per
// session, presents one spent token several times within the same second
// -- and across replicas, so no in-process lock would see it. Refusing
// those is refusing the legitimate holder: the gateway treats the
// refusal as a dead session and sends the person back to sign in,
// intermittently and for no reason they can see.
//
// The window is deliberately short and does not mint anything. Outside
// it, reuse is refused exactly as before, which is the detection this
// rotation exists for; inside it, the replay is answered with the one
// credential already in flight rather than a second one.
func (s *Sessions) replayed(ctx context.Context, oldToken string) (Session, string, bool, error) {
	raw, found, err := s.state.Get(ctx, sessionRotatedKey(oldToken))
	if err != nil || !found {
		return Session{}, "", false, err
	}

	successor := string(raw)

	// The successor must still resolve to a live session. It may not: the
	// session can have been ended, or refreshed again, between the
	// rotation and this replay -- and an ended session must not be handed
	// back a working credential.
	session, live, err := s.ByToken(ctx, successor)
	if err != nil || !live {
		return Session{}, "", false, err
	}

	return session, successor, true, nil
}

// ByRefreshToken resolves a refresh token to its session, including one
// that was rotated within the grace window.
//
// The refresh endpoint reads the token TWICE: the library resolves it to
// a request before it asks for new tokens, so a replay that [Refreshed]
// would have answered is refused before [Refreshed] ever runs. Both
// readings have to see the same window or the grace is unreachable --
// which is exactly the shape the first attempt at this had, visible as
// the refusal changing from "not live" to `invalid_refresh_token` and
// the failures carrying on unchanged.
//
// Only the refresh path uses this. [ByToken] stays exact, because the
// other callers -- revocation, listing -- are asking whether this token
// is the live one, which is a different question.
func (s *Sessions) ByRefreshToken(ctx context.Context, token string) (Session, bool, error) {
	session, ok, err := s.ByToken(ctx, token)
	if err != nil || ok {
		return session, ok, err
	}

	session, _, ok, err = s.replayed(ctx, token)

	return session, ok, err
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
	// SSO narrows to the sessions one BROWSER opened. Ending those is
	// only half of signing that browser out — the sign-in itself has to
	// go with them, which [SessionsService.RevokeSessions] does.
	SSO string
	// Contains reads Identity and ClientID as SUBSTRINGS -- prefix,
	// suffix and middle, one rule -- rather than as exact values.
	//
	// It is a LISTING affordance and deliberately not a revoking one:
	// [Sessions.Revoke] takes the same Query, and a revoke whose scope
	// is "anything containing this" is the control that ends more than
	// its caller meant. Revoke refuses it.
	Contains bool
}

// set is the narrowest set that can answer this query. Asking for one
// person's sessions must not read every session in the installation.
func (q Query) set() string {
	switch {
	// A substring cannot know which per-identity index holds a match, so
	// there is no narrower set than all of them. This is the cost of the
	// affordance, and it is the read the unfiltered listing already does.
	case q.Contains:
		return sessionAllKey
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
	// Listing by substring is a convenience; revoking by one is a way to
	// end far more than was meant. "kar" would take kargo and karma with
	// it, and there is no undo.
	if q.Contains {
		return 0, errors.New("a substring names sessions to LIST, never sessions to end")
	}

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
	if err != nil || !found {
		return false, err
	}

	return true, s.deleteSession(ctx, session)
}

// deleteSession removes a session's record and its membership in every
// index set, given the record already in hand.
//
// It exists separately from RevokeID because RevokeID resolves its target
// through byID, and byID's whole job is to treat a session whose
// [Session.Live] has passed as though it were never there -- which is
// right for every ordinary caller, and wrong for the one case where a
// session is deliberately being cleaned up BECAUSE it is no longer live:
// [Sessions.endedByAbsoluteLimit] already has the record in hand
// precisely because it is not live, and asking RevokeID to end it would
// find "not found" and delete nothing.
func (s *Sessions) deleteSession(ctx context.Context, session Session) error {
	if err := s.state.Delete(ctx, sessionKey(session.ID)); err != nil {
		return err
	}

	for _, key := range []string{sessionAllKey, sessionOfKey(session.Identity), sessionForKey(session.ClientID)} {
		if err := s.state.Remove(ctx, key, session.ID); err != nil {
			return err
		}
	}

	return nil
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
		case identity != "" && !matches(session.Identity, identity, q.Contains):
		case q.ClientID != "" && !matches(session.ClientID, q.ClientID, q.Contains):
		case q.SSO != "" && session.SSO != q.SSO:
		default:
			out = append(out, session)
		}
	}

	return out, nil
}

// matches is the one place the two filter shapes differ. Both sides are
// already lowered by their callers, so this is a comparison and not a
// second normalisation.
func matches(have, want string, contains bool) bool {
	if contains {
		return strings.Contains(have, want)
	}

	return have == want
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

// put writes a record, refusing one that is already expired.
//
// It is kept in the store for s.lifetime from now -- the SAME horizon as
// the token pointer ([sessionTokenKey]) and the index sets, not derived
// from ExpiresAt. The two used to be the same duration always, because
// ExpiresAt was always exactly now+s.lifetime; now that the absolute
// session limit can cap ExpiresAt short of that, [Session.Live] is what
// decides whether the record still answers, and this is a different
// question. Keeping the record around a little past its own logical life
// is what lets [Sessions.endedByAbsoluteLimit] tell a refresh refused BY
// THE LIMIT apart from one refused because the session is simply gone --
// otherwise both look identical the moment the record disappears.
func (s *Sessions) put(ctx context.Context, session Session) error {
	if !session.ExpiresAt.After(s.now()) {
		return fmt.Errorf("issuer: session %s has already expired", session.ID)
	}

	return setJSON(ctx, s.state, sessionKey(session.ID), session, s.lifetime)
}

// endedByAbsoluteLimit resolves a refresh token to the session it named
// even past that session's own end, so a refresh refused BECAUSE of the
// absolute session limit can be told apart from one refused because the
// session is simply gone (an ordinary sliding-window timeout, or an
// explicit revoke, which deletes the record outright and is never found
// here) -- and given its own reason in the log and the audit record
// instead of the generic "not live" both would otherwise share.
//
// It answers true only when the record is still IN THE STORE (see [put])
// and no longer live. Given how [put] keeps it -- for s.lifetime from the
// write that set ExpiresAt, regardless of what ExpiresAt itself is -- a
// record found here with ExpiresAt already passed can only be one whose
// ExpiresAt was capped short of that horizon, which is exactly what the
// absolute limit does and nothing else does.
func (s *Sessions) endedByAbsoluteLimit(ctx context.Context, token string) (Session, bool, error) {
	raw, found, err := s.state.Get(ctx, sessionTokenKey(token))
	if err != nil || !found {
		return Session{}, false, err
	}

	session, err := getJSON[Session](ctx, s.state, sessionKey(string(raw)))
	if err != nil || session == nil || session.Live(s.now()) {
		return Session{}, false, err
	}

	return *session, true, nil
}
