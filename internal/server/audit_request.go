package server

import (
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/truvity/audit/emit"
	"github.com/truvity/audit/record"

	"github.com/truvity/access-roster/internal/logsafe"
)

// The bounds on what a record keeps of a request. Each value is chosen by
// whoever sent the request, so each is cut rather than trusted to be short.
const (
	maxClientAddress = 64
	maxUserAgent     = 256
	maxRequestID     = 128
)

// AuditRequests puts what an audit record keeps of each request into the
// request's context, where the emitter finds it: where it came from, what
// sent it, the gateway's id for it, and the trace it belongs to.
//
// Once, at the outermost handler, rather than at every place that records.
// The events a request causes are recorded in places that never see the
// request — the token endpoint's storage is handed a context by an OpenID
// library and nothing else — and a context is the one thing all of them
// share. A handler already under it does not read the request again: the
// merged service mounts the console, which does this for itself, inside
// the issuer, which does it first.
//
// trustedHops is how many proxies of the deployment's own append to
// X-Forwarded-For in front of the service; zero takes the peer and ignores
// the header. See [clientAddress].
func AuditRequests(trustedHops int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if emit.RequestContext(r.Context()) != nil {
			next.ServeHTTP(w, r)
			return
		}
		request := auditRequest(r, trustedHops)
		next.ServeHTTP(w, r.WithContext(emit.WithRequest(r.Context(), request)))
	})
}

// auditRequest is the one reading of a request for the audit trail. Every
// value in it was chosen by whoever sent the request, so every value is
// made safe for a log line and cut to its bound.
//
// The emitter's own reading keeps the whole forwarded chain, left end and
// all; this keeps the one address the deployment's proxies vouch for,
// because that is the address a reader of the trail acts on.
func auditRequest(r *http.Request, trustedHops int) *record.Context {
	c := emit.FromRequest(r, 0)
	c.ClientAddresses = []string{clientAddress(r.Header, r.RemoteAddr, trustedHops)}
	c.UserAgent = bounded(r.Header.Get("User-Agent"), maxUserAgent)
	c.RequestId = bounded(r.Header.Get("X-Request-Id"), maxRequestID)
	return c
}

// bounded is a value made safe for a log line and cut, on a rune boundary,
// to limit bytes.
func bounded(value string, limit int) string {
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

// clientAddress is the address of whoever reached the deployment's first
// proxy, and the peer's host when that cannot be known.
//
// The count is the emitter's: the chain is X-Forwarded-For read left to
// right with the peer appended as its last, unforgeable entry, and
// trustedHops is how many entries at that near end belong to the
// deployment's own proxies -- the peer counts as one. Dropping them leaves
// the client as the last entry. So a gateway alone in front of the service
// is 1; an edge that appends the client and a gateway that appends the
// edge's connector is 2. The first entry is never trusted on its own: a
// caller who sends the header owns it, and 0 records the peer.
//
// A chain no longer than the hops did not come through those proxies, and a
// value that is not an address is not one a proxy wrote; both fall back to
// the peer.
func clientAddress(header http.Header, peer string, trustedHops int) string {
	if trustedHops > 0 {
		var chain []string
		for _, value := range header.Values("X-Forwarded-For") {
			for _, part := range strings.Split(value, ",") {
				if strings.TrimSpace(part) != "" {
					chain = append(chain, part)
				}
			}
		}
		chain = append(chain, peer)
		if len(chain) > trustedHops {
			if address, ok := addressOf(chain[len(chain)-1-trustedHops]); ok {
				return address
			}
		}
	}
	if address, ok := addressOf(peer); ok {
		return address
	}
	// A peer that is not an IP — a listener on a socket file — is still
	// named, safely.
	return bounded(peer, maxClientAddress)
}

// addressOf is the IP in a value that is an IP, with or without a port.
func addressOf(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if withPort, err := netip.ParseAddrPort(value); err == nil {
		return bounded(withPort.Addr().String(), maxClientAddress), true
	}
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return bounded(address.String(), maxClientAddress), true
	}
	return "", false
}
