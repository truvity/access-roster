package port

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// ErrUnauthenticated is a token [Identity] does not accept.
var ErrUnauthenticated = errors.New("port: the token proves nothing")

// permanent are the key families the layout in docs/design/ports.md marks
// as having no lifetime. Every other key needs one.
var permanent = []string{"ws.", "gh.org.", "app."}

// Permanent reports whether a key may be written with no lifetime.
func Permanent(key string) bool {
	for _, prefix := range permanent {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// CheckWrite is the refusal every adapter shares before a write: a value
// over [MaxValue] and a missing lifetime on a key that needs one.
func CheckWrite(key string, value []byte, ttl time.Duration) error {
	if len(value) > MaxValue {
		return ErrTooLarge
	}
	if ttl < 0 || (ttl == 0 && !Permanent(key)) {
		return ErrNoLifetime
	}
	return nil
}

// DefaultPage is how many records a listing returns when the caller names
// no limit.
const DefaultPage = 100

// PageToken names where the next page of a listing starts, bound to the
// prefix it was issued for.
func PageToken(prefix, last string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(prefix + "\x00" + last))
}

// PageStart reads a token back: the key after which the page starts. An
// empty token starts at the beginning, and a token from another prefix is
// [ErrBadPage].
func PageStart(prefix, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", ErrBadPage
	}
	p, last, ok := strings.Cut(string(raw), "\x00")
	if !ok || p != prefix {
		return "", ErrBadPage
	}
	return last, nil
}
