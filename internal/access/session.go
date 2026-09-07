package access

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CookieName is the console's session cookie.
const CookieName = "access_roster_session"

// SessionKeyBytes is the length of a session-signing key.
const SessionKeyBytes = 32

// ErrNoSession is returned when a request carries no readable session.
var ErrNoSession = errors.New("access: no session")

// Sessions issues and reads the console's session cookie.
//
// The cookie is the principal, signed with the hub's session key and
// short-lived. It is deliberately stateless: there is no session table to
// keep, and revoking everyone at once is rotating the key. What that
// cannot do — ending one person's session before it expires — is the
// gateway's job in an installation that has one, and the reason the
// lifetime is short in one that does not.
type Sessions struct {
	key      []byte
	lifetime time.Duration
	secure   bool
	now      func() time.Time
}

// NewSessions returns a session codec. The key must be [SessionKeyBytes]
// long; secure marks the cookie so, which a plain-HTTP development run
// turns off.
func NewSessions(key []byte, lifetime time.Duration, secure bool) (*Sessions, error) {
	if len(key) != SessionKeyBytes {
		return nil, fmt.Errorf("access: session key must be %d bytes, got %d", SessionKeyBytes, len(key))
	}
	if lifetime <= 0 {
		lifetime = 12 * time.Hour
	}
	return &Sessions{key: key, lifetime: lifetime, secure: secure, now: time.Now}, nil
}

// NewSessionKey returns a fresh random session key.
func NewSessionKey() ([]byte, error) {
	key := make([]byte, SessionKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("access: generate session key: %w", err)
	}
	return key, nil
}

// SetClock replaces the clock. For tests.
func (s *Sessions) SetClock(now func() time.Time) { s.now = now }

// payload is what the cookie carries.
type payload struct {
	Email   string              `json:"email,omitempty"`
	Subject string              `json:"sub,omitempty"`
	Source  Source              `json:"src"`
	Issuer  string              `json:"iss,omitempty"`
	Claims  map[string][]string `json:"claims,omitempty"`
	Expires int64               `json:"exp"`
}

// Issue signs a principal into the response's cookie.
func (s *Sessions) Issue(w http.ResponseWriter, p Principal) error {
	expires := s.now().Add(s.lifetime)
	body, err := json.Marshal(payload{
		Email:   p.Email,
		Subject: p.Subject,
		Source:  p.Source,
		Issuer:  p.Issuer,
		Claims:  p.Claims,
		Expires: expires.Unix(),
	})
	if err != nil {
		return fmt.Errorf("access: encode session: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    encoded + "." + s.sign(encoded),
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Read returns the principal a request carries.
func (s *Sessions) Read(r *http.Request) (Principal, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return Principal{}, ErrNoSession
	}
	encoded, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return Principal{}, ErrNoSession
	}
	if subtle.ConstantTimeCompare([]byte(signature), []byte(s.sign(encoded))) != 1 {
		return Principal{}, fmt.Errorf("%w: signature", ErrNoSession)
	}
	body, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: encoding", ErrNoSession)
	}
	var p payload
	if err = json.Unmarshal(body, &p); err != nil {
		return Principal{}, fmt.Errorf("%w: content", ErrNoSession)
	}
	if s.now().Unix() >= p.Expires {
		return Principal{}, fmt.Errorf("%w: expired", ErrNoSession)
	}
	return Principal{
		Email:   p.Email,
		Subject: p.Subject,
		Source:  p.Source,
		Issuer:  p.Issuer,
		Claims:  p.Claims,
	}, nil
}

// Clear removes the cookie.
func (s *Sessions) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// Lifetime is how long an issued session lasts.
func (s *Sessions) Lifetime() time.Duration { return s.lifetime }

func (s *Sessions) sign(encoded string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
