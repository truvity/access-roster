package issuer

import (
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// How says what produced a session, because "revoke Ada's kubectl login"
// is a different act from "revoke the console she left open", and an
// operator can only tell them apart if the issuer remembers which was
// which.
type How string

const (
	// HowCode is an authorization-code login: a console through the proxy,
	// or accessctl with a browser.
	HowCode How = "code"
	// HowDevice is the device flow: kubelogin or a CLI on a machine with
	// no browser to redirect.
	HowDevice How = "device"
	// HowExchange is a token exchange: a CI job or a workload that swapped
	// its own token for one of ours.
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
	ID       string
	Identity string
	ClientID string
	How      How

	IssuedAt      time.Time
	ExpiresAt     time.Time
	LastRefreshed time.Time
}

// Live reports whether the session is still usable at now. An expired
// session stays in the index until it is swept, so that "it expired" and
// "it never existed" remain different answers.
func (s Session) Live(now time.Time) bool { return now.Before(s.ExpiresAt) }

// Sessions is the per-identity index beside the refresh tokens. In the
// spike it is memory; in a deployment it is Valkey, keyed the same way,
// because the operations are the same three: record one, list by
// identity or by client, revoke a set.
type Sessions struct {
	mu       sync.RWMutex
	byID     map[string]Session
	tokens   map[string]string // refresh token → session id
	now      func() time.Time
	newID    func() string
	lifetime time.Duration
}

// NewSessions returns an empty index. lifetime is how long a refresh
// token lives when nothing shorter applies.
func NewSessions(lifetime time.Duration) *Sessions {
	return &Sessions{
		byID:     map[string]Session{},
		tokens:   map[string]string{},
		now:      time.Now,
		newID:    uuid.NewString,
		lifetime: lifetime,
	}
}

// SetClock replaces the clock, for tests.
func (s *Sessions) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Record files a newly issued refresh token and returns the session it
// created.
func (s *Sessions) Record(identity, clientID string, how How, token string) Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	session := Session{
		ID:        s.newID(),
		Identity:  strings.ToLower(identity),
		ClientID:  clientID,
		How:       how,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.lifetime),
	}
	s.byID[session.ID] = session
	s.tokens[token] = session.ID
	return session
}

// Refreshed moves a session onto a new token, which is what a refresh
// does: the old token is spent and must stop working, and the session it
// belongs to carries on with its identity, its client and its history.
// It reports whether the old token named a live session.
func (s *Sessions) Refreshed(oldToken, newToken string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.tokens[oldToken]
	if !ok {
		return Session{}, false
	}
	session, ok := s.byID[id]
	if !ok || !session.Live(s.now()) {
		return Session{}, false
	}
	delete(s.tokens, oldToken)
	session.LastRefreshed = s.now()
	session.ExpiresAt = s.now().Add(s.lifetime)
	s.byID[id] = session
	s.tokens[newToken] = id
	return session, true
}

// ByToken resolves a refresh token to its session.
func (s *Sessions) ByToken(token string) (Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.tokens[token]
	if !ok {
		return Session{}, false
	}
	session, ok := s.byID[id]
	if !ok || !session.Live(s.now()) {
		return Session{}, false
	}
	return session, true
}

// Query narrows a listing. The zero value lists every live session, which
// is what an operator looking for what is open right now asks for.
type Query struct {
	Identity string
	ClientID string
}

// List returns the live sessions a query selects, newest first.
func (s *Sessions) List(q Query) []Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	identity := strings.ToLower(strings.TrimSpace(q.Identity))
	out := make([]Session, 0, len(s.byID))
	for id := range s.byID {
		session := s.byID[id]
		switch {
		case !session.Live(now):
		case identity != "" && session.Identity != identity:
		case q.ClientID != "" && session.ClientID != q.ClientID:
		default:
			out = append(out, session)
		}
	}
	slices.SortFunc(out, func(a, b Session) int {
		if d := b.IssuedAt.Compare(a.IssuedAt); d != 0 {
			return d
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// Revoke ends every session a query selects and returns how many. It is
// the only write the console has against the issuer, and it can only ever
// remove: an empty query would end everything, so a caller that means
// "this person" must say so.
func (s *Sessions) Revoke(q Query) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	identity := strings.ToLower(strings.TrimSpace(q.Identity))
	ended := map[string]bool{}
	for id := range s.byID {
		switch session := s.byID[id]; {
		case identity != "" && session.Identity != identity:
		case q.ClientID != "" && session.ClientID != q.ClientID:
		default:
			ended[id] = true
			delete(s.byID, id)
		}
	}
	for token, id := range s.tokens {
		if ended[id] {
			delete(s.tokens, token)
		}
	}
	return len(ended)
}

// RevokeID ends one session by its id, which is what "sign this one out"
// on a person's page does. It reports whether there was one to end.
func (s *Sessions) RevokeID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[id]; !ok {
		return false
	}
	delete(s.byID, id)
	for token, sid := range s.tokens {
		if sid == id {
			delete(s.tokens, token)
		}
	}
	return true
}

// RevokeToken ends whichever session holds this refresh token. It is what
// RFC 7009 calls at the revocation endpoint, and what a proxy's sign-out
// reaches when it hands back the token it held.
func (s *Sessions) RevokeToken(token string) bool {
	s.mu.Lock()
	id, ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		return false
	}
	return s.RevokeID(id)
}

// Sweep drops sessions that expired before now and returns how many, so
// that the index does not grow without bound in a long-lived process.
func (s *Sessions) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	gone := map[string]bool{}
	for id := range s.byID {
		if session := s.byID[id]; !session.Live(now) {
			gone[id] = true
			delete(s.byID, id)
		}
	}
	for token, id := range s.tokens {
		if gone[id] {
			delete(s.tokens, token)
		}
	}
	return len(gone)
}
