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

// Binding is what a state carries from the start of a flow to its
// callback.
type Binding struct {
	// Bind is the workspace being reconnected, empty for a new one.
	Bind string
	// Actor is the identity that was authorised when the flow began.
	//
	// It is here because a third-party callback is the one request in a
	// flow whose identity cannot be assumed: it arrives as a redirect from
	// Google, and the route it lands on need not be the one the gateway
	// authenticates. The state is signed by this hub and pinned to the
	// browser by a cookie the callback checks, so it can say who started
	// the flow when nothing else in the request can.
	//
	// The authorisation itself still happens at the start, where an
	// operator asked for the consent. This only carries the answer.
	Actor string
}

// Issue returns a signed state bound to a workspace and to nobody.
func (c *StateCodec) Issue(bind string) (string, error) {
	return c.IssueAs(Binding{Bind: bind})
}

// IssueAs returns a signed state carrying the whole binding.
func (c *StateCodec) IssueAs(b Binding) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("access: generate state: %w", err)
	}
	body := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString([]byte(b.Bind)),
		base64.RawURLEncoding.EncodeToString([]byte(b.Actor)),
		strconv.FormatInt(c.now().Add(c.ttl).Unix(), 10),
	}, ":")
	return body + "." + c.sign(body), nil
}

// Verify checks a state and returns what it was bound to.
func (c *StateCodec) Verify(state string) (string, error) {
	b, err := c.VerifyBinding(state)
	return b.Bind, err
}

// VerifyBinding checks a state and returns everything it carries.
func (c *StateCodec) VerifyBinding(state string) (Binding, error) {
	body, signature, ok := strings.Cut(state, ".")
	if !ok {
		return Binding{}, ErrBadState
	}
	if subtle.ConstantTimeCompare([]byte(signature), []byte(c.sign(body))) != 1 {
		return Binding{}, fmt.Errorf("%w: signature", ErrBadState)
	}
	parts := strings.Split(body, ":")
	if len(parts) != 4 {
		return Binding{}, ErrBadState
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return Binding{}, fmt.Errorf("%w: expiry", ErrBadState)
	}
	if c.now().Unix() >= expires {
		return Binding{}, fmt.Errorf("%w: expired", ErrBadState)
	}
	bind, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Binding{}, fmt.Errorf("%w: binding", ErrBadState)
	}
	actor, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Binding{}, fmt.Errorf("%w: actor", ErrBadState)
	}
	return Binding{Bind: string(bind), Actor: string(actor)}, nil
}

func (c *StateCodec) sign(body string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
