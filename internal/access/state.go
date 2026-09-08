package access

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The two flows' state cookies. Each carries its flow's state alongside
// the URL, so that a callback proves it belongs to the browser that
// started the flow.
//
// Two names, because the flows are different in the way that matters:
// consent is an operator granting this hub access to a company, sign-in
// is a person proving who they are. One cookie would let a callback
// finish a flow the browser did not start.
const (
	ConnectCookieName = "access_roster_connect"
	LoginCookieName   = "access_roster_login"
)

// ErrBadState is returned for a state that is forged, stale or malformed.
var ErrBadState = errors.New("access: state is not valid")

// ConnectCookie builds the consent flow's state cookie, and — with an
// empty value — the one that clears it.
//
// Both come from here because they were built in two places and drifted:
// the cookie was set Secure and cleared without it. Attributes are not
// part of a cookie's identity, so the clearing still worked, but a
// browser being asked to store a cookie over plain HTTP on a site that
// only ever speaks HTTPS is the kind of difference that stops being
// harmless the moment someone copies it.
func ConnectCookie(value string, secure bool, ttl time.Duration) *http.Cookie {
	return flowCookie(ConnectCookieName, value, secure, ttl)
}

// LoginCookie is the same for the sign-in flow.
func LoginCookie(value string, secure bool, ttl time.Duration) *http.Cookie {
	return flowCookie(LoginCookieName, value, secure, ttl)
}

func flowCookie(name, value string, secure bool, ttl time.Duration) *http.Cookie {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	if value == "" {
		cookie.MaxAge = -1
	}
	return cookie
}

// StateCodec signs the opaque state an OAuth flow carries. It keeps
// nothing: the state is its own record, and the cookie beside it is what
// makes the callback the same browser's.
type StateCodec struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

// NewStateCodec returns a codec over the hub's session key.
func NewStateCodec(key []byte, ttl time.Duration) *StateCodec {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &StateCodec{key: key, ttl: ttl, now: time.Now}
}

// SetClock replaces the clock. For tests.
func (c *StateCodec) SetClock(now func() time.Time) { c.now = now }

// Issue returns a signed state. Bind carries what the callback must know —
// the workspace being reconnected, or empty for a new connection.
func (c *StateCodec) Issue(bind string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("access: generate state: %w", err)
	}
	body := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString([]byte(bind)),
		strconv.FormatInt(c.now().Add(c.ttl).Unix(), 10),
	}, ":")
	return body + "." + c.sign(body), nil
}

// Verify checks a state and returns what it was bound to.
func (c *StateCodec) Verify(state string) (string, error) {
	body, signature, ok := strings.Cut(state, ".")
	if !ok {
		return "", ErrBadState
	}
	if subtle.ConstantTimeCompare([]byte(signature), []byte(c.sign(body))) != 1 {
		return "", fmt.Errorf("%w: signature", ErrBadState)
	}
	parts := strings.Split(body, ":")
	if len(parts) != 3 {
		return "", ErrBadState
	}
	expires, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: expiry", ErrBadState)
	}
	if c.now().Unix() >= expires {
		return "", fmt.Errorf("%w: expired", ErrBadState)
	}
	bind, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: binding", ErrBadState)
	}
	return string(bind), nil
}

func (c *StateCodec) sign(body string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
