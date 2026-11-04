package rpc

import (
	"context"
	"net/http"
)

// HeaderCorrelation is the header that carries the correlation id of a request through every internal call it
// causes (contracts.md, "Every call"). entry makes the id; the kit passes it on and never makes one.
const HeaderCorrelation = "Sluis-Correlation-Id"

type correlationKey struct{}

// WithCorrelationID returns ctx carrying the correlation id. An id that is not a plain token (1 to 64 characters
// of letters, digits, "-" and "_") is dropped, so a hostile header cannot reach a log line or a record.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if !validCorrelationID(id) {
		return ctx
	}
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationID returns the correlation id of ctx, or "" when there is none.
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

func validCorrelationID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func correlationFrom(h http.Header) string {
	return h.Get(HeaderCorrelation)
}
