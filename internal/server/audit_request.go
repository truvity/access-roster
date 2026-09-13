package server

import (
	"net/http"
	"net/netip"
	"strings"

	"github.com/truvity/access-roster/internal/audit"
)

// AuditRequests puts what an audit event keeps of each request into the
// request's context: where it came from, what sent it, and the gateway's
// id for it.
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
		if _, ok := audit.RequestFrom(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		request := auditRequest(r.Header, r.RemoteAddr, trustedHops)
		next.ServeHTTP(w, r.WithContext(audit.WithRequest(r.Context(), request)))
	})
}

// auditRequest is the one reading of a request for the audit trail. Every
// value in it was chosen by whoever sent the request, so every value is
// made safe for a log line and cut to its bound.
func auditRequest(header http.Header, peer string, trustedHops int) audit.Request {
	return audit.Request{
		ClientAddress: clientAddress(header, peer, trustedHops),
		UserAgent:     audit.Bounded(header.Get("User-Agent"), audit.MaxUserAgent),
		RequestID:     audit.Bounded(header.Get("X-Request-Id"), audit.MaxRequestID),
	}
}

// clientAddress is the address of whoever reached the deployment's first
// proxy, and the peer's host when that cannot be known.
//
// X-Forwarded-For is read from the right, because only the right end is
// written by proxies the deployment trusts: each appends the address it
// was reached from, and everything to the left of what they wrote is text
// a caller may have sent. With trustedHops proxies of the deployment's own
// appending — an edge that appends the client, then a gateway that appends
// the edge's connector is one hop in front of the service — the client is
// the entry just left of the last trustedHops. The first entry is never
// trusted: a caller who sends the header owns it.
//
// A header shorter than that did not come through those proxies, and a
// value that is not an address is not one a proxy wrote; both fall back to
// the peer.
func clientAddress(header http.Header, peer string, trustedHops int) string {
	if trustedHops > 0 {
		var hops []string
		for _, value := range header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(value, ",")...)
		}
		if at := len(hops) - 1 - trustedHops; at >= 0 {
			if address, ok := addressOf(hops[at]); ok {
				return address
			}
		}
	}
	if address, ok := addressOf(peer); ok {
		return address
	}
	// A peer that is not an IP — a listener on a socket file — is still
	// named, safely.
	return audit.Bounded(peer, audit.MaxClientAddress)
}

// addressOf is the IP in a value that is an IP, with or without a port.
func addressOf(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if withPort, err := netip.ParseAddrPort(value); err == nil {
		return audit.Bounded(withPort.Addr().String(), audit.MaxClientAddress), true
	}
	if address, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
		return audit.Bounded(address.String(), audit.MaxClientAddress), true
	}
	return "", false
}
