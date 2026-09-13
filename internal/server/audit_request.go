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
// trustForwardedFor is whether the address comes from X-Forwarded-For. Only
// a deployment that knows a gateway in front sets that header may say so:
// anybody can send it, and without a gateway to replace it the first hop is
// whatever the caller wrote.
func AuditRequests(trustForwardedFor bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := audit.RequestFrom(r.Context()); ok {
			next.ServeHTTP(w, r)
			return
		}
		request := auditRequest(r.Header, r.RemoteAddr, trustForwardedFor)
		next.ServeHTTP(w, r.WithContext(audit.WithRequest(r.Context(), request)))
	})
}

// auditRequest is the one reading of a request for the audit trail. Every
// value in it was chosen by whoever sent the request, so every value is
// made safe for a log line and cut to its bound.
func auditRequest(header http.Header, peer string, trustForwardedFor bool) audit.Request {
	return audit.Request{
		ClientAddress: clientAddress(header, peer, trustForwardedFor),
		UserAgent:     audit.Bounded(header.Get("User-Agent"), audit.MaxUserAgent),
		RequestID:     audit.Bounded(header.Get("X-Request-Id"), audit.MaxRequestID),
	}
}

// clientAddress is the first X-Forwarded-For hop when the deployment trusts
// its gateway to have set it, and the peer's host otherwise — including
// when the header holds no address at all, which a gateway does not write.
func clientAddress(header http.Header, peer string, trustForwardedFor bool) string {
	if trustForwardedFor {
		first, _, _ := strings.Cut(header.Get("X-Forwarded-For"), ",")
		if address, ok := addressOf(first); ok {
			return address
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
