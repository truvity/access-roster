package audit

import (
	"context"
	"unicode/utf8"

	"github.com/truvity/access-roster/internal/logsafe"
)

// The bounds on what an event keeps of a request. Every one of these
// values is chosen by whoever sent the request, so each is cut to a size
// that holds any honest value — an IPv6 address with a zone, a browser's
// User-Agent, a gateway's request id — and no more.
const (
	MaxClientAddress = 64
	MaxUserAgent     = 256
	MaxRequestID     = 128
)

// Request is what an event keeps of the HTTP request that caused it:
// where it came from, what sent it, and the id the gateway gave it, which
// is the key into the gateway's own access log.
//
// It travels in the context rather than through every signature, because
// the events a request causes are recorded in places that never see the
// request: the token endpoint's storage is called by an OpenID library
// with a context and nothing else. The server reads it once, at the
// outermost handler, and whatever records under that context carries it.
type Request struct {
	ClientAddress string
	UserAgent     string
	RequestID     string
}

type requestKey struct{}

// WithRequest returns a context carrying what events recorded under it
// keep of their request.
func WithRequest(ctx context.Context, r Request) context.Context {
	return context.WithValue(ctx, requestKey{}, r)
}

// RequestFrom is the request a context carries, if any.
func RequestFrom(ctx context.Context) (Request, bool) {
	r, ok := ctx.Value(requestKey{}).(Request)
	return r, ok
}

// Apply fills the request fields an event does not carry already. An event
// that says where it came from keeps saying so.
func (r Request) Apply(e *Event) {
	if e.ClientAddress == "" {
		e.ClientAddress = r.ClientAddress
	}
	if e.UserAgent == "" {
		e.UserAgent = r.UserAgent
	}
	if e.RequestID == "" {
		e.RequestID = r.RequestID
	}
}

// Bounded is a value made safe for a log line and cut to at most limit
// bytes, never through the middle of a character.
func Bounded(value string, limit int) string {
	value = logsafe.Value(value)
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
