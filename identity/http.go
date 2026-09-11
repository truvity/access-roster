package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// WhoAmIPath is where every adapter in this family answers, and what the
// TypeScript package asks by default. One path, so a console written
// against one service works against the next.
const WhoAmIPath = "/.access/whoami"

// Headers a token arrives in.
//
// The first is what an authenticating gateway forwards; the second is
// the ordinary bearer, for a direct caller. Both are VERIFIED here — a
// listener that trusted a header instead would be only as safe as the
// promise that nothing but the gateway can reach it, and that promise is
// one NetworkPolicy edit, one port-forward or one sidecar away from
// false. A signature is not.
const (
	HeaderForwarded     = "X-Auth-Request-Access-Token" //nolint:gosec // a header NAME, not a credential
	HeaderAuthorization = "Authorization"
)

type contextKey struct{}

// FromContext returns the caller a [Middleware] established, if any.
//
// The second return is the whole contract: false means nobody was
// established, never "somebody with no groups", so a handler cannot
// accidentally treat an unauthenticated request as an empty-group one.
func FromContext(ctx context.Context) (Verified, bool) {
	who, ok := ctx.Value(contextKey{}).(Verified)
	return who, ok
}

// WithVerified puts a caller in a context, for a test or an adapter this
// package does not ship.
func WithVerified(ctx context.Context, who Verified) context.Context {
	return context.WithValue(ctx, contextKey{}, who)
}

// Verifier is what [Middleware] needs: anything that turns a token into
// a caller. [Issuer] and [Cluster] both satisfy it.
type Verifier interface {
	Verify(ctx context.Context, token string) (Verified, error)
}

// Middleware establishes the caller and passes the request on.
//
// It does NOT refuse an unverified request, and that is deliberate: a
// listener serves pages that run before anybody is established — a
// health endpoint, a login page, a landing page — and a middleware that
// decided for them would be a middleware every such route has to be
// excluded from. Gate in the handler with [FromContext], or wrap the
// routes that need it in [Require].
//
// Several verifiers are tried in order and the first that answers wins.
// A token one of them RECOGNISED and refused stops the chain: a bearer
// with a bad signature must not be retried as a ServiceAccount token.
func Middleware(verifiers ...Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := TokenFrom(r)
			if token == "" {
				next.ServeHTTP(w, r)
				return
			}
			for _, verifier := range verifiers {
				who, err := verifier.Verify(r.Context(), token)
				if err == nil {
					next.ServeHTTP(w, r.WithContext(WithVerified(r.Context(), who)))
					return
				}
				if !errors.Is(err, ErrUnverified) {
					// The check did not happen — the issuer's keys were
					// unreachable. Trying the next verifier would turn an
					// outage into "your token is bad".
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Require refuses anything [Middleware] did not establish, and anything
// holding none of the groups named.
//
// Naming no group means "any caller this installation vouches for",
// which is a real posture: a service whose whole audience is already
// gated by the issuer's `requires` needs no second list.
func Require(groups ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			who, ok := FromContext(r.Context())
			if !ok {
				http.Error(w, "not signed in", http.StatusUnauthorized)
				return
			}
			if len(groups) > 0 && !who.HasAny(groups...) {
				// Never name the groups that would have worked: a caller
				// learning which group opens a door has learned something
				// it had no way to ask.
				http.Error(w, "not allowed", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TokenFrom reads the token a request carries, from either header.
func TokenFrom(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get(HeaderForwarded)); forwarded != "" {
		return forwarded
	}
	// The scheme is case-insensitive (RFC 6750 §2.1) and real clients
	// send both spellings, so this compares without case rather than
	// cutting a literal prefix.
	header := strings.TrimSpace(r.Header.Get(HeaderAuthorization))
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// WhoAmI is the endpoint a console asks who it is talking to.
//
// It answers rather than refuses when nobody is established, because
// "signed out" is something a console has to render and a 401 would make
// it indistinguishable from a service that is broken.
func WhoAmI(version string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"status": "signed-out"}
		if version != "" {
			body["version"] = version
		}
		if who, ok := FromContext(r.Context()); ok {
			body["status"] = "signed-in"
			body["sub"] = who.Subject
			if who.Email != "" {
				body["email"] = who.Email
			}
			if len(who.Groups) > 0 {
				body["groups"] = who.Groups
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}
