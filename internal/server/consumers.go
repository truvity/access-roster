package server

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

// Consumers is who may call the API listener.
//
// The listener answers the two directory questions for every workspace
// this hub reads — every account, every group, every membership of every
// company it serves — so "reachable" must not be the same as "allowed".
// A NetworkPolicy is a second layer and a good one; it is not an answer
// to "which workload is this", and it is one misapplied label away from
// admitting a namespace nobody meant to.
//
// The proof is a projected ServiceAccount token with this hub's audience,
// verified by the API server. The hub therefore trusts no signature of
// its own and keeps no shared secret: it asks the cluster who is calling,
// and compares the answer to a list the deployment states.
type Consumers struct {
	// Review is [kube.Client.ReviewToken]. Nil means the hub is not
	// running in a cluster and cannot check anything, which is a
	// different situation from an empty list — see [Consumers.Middleware].
	Review func(ctx context.Context, token string, audiences []string) (string, error)
	// Audience the token must have been minted for.
	Audience string
	// Allowed subjects, as the API server spells them.
	Allowed []string
	Log     *slog.Logger
}

// Middleware guards a handler.
//
// Two situations that look alike and are not. **No reviewer** is a hub
// outside a cluster — a local run, the demonstration — where there is
// nothing to verify a token against; the listener is open and the caller
// is told so at start, loudly, because that is a development posture and
// never a deployed one. **A reviewer and an empty list** is a deployment
// that named no consumers, and it admits nobody: a hub that answered
// everyone by default would be one forgotten value away from serving a
// company's directory to the cluster.
func (c *Consumers) Middleware(next http.Handler) http.Handler {
	if c == nil || c.Review == nil {
		return next
	}
	log := c.Log
	if log == nil {
		log = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			refuse(w, "this listener needs a ServiceAccount token with the audience "+c.Audience)
			return
		}
		subject, err := c.Review(r.Context(), token, []string{c.Audience})
		if err != nil {
			// One message for a rejected token and for a review that
			// could not run. The caller is unauthenticated; which of the
			// two it was is in the hub's log, where an operator can see
			// it and a caller cannot.
			log.WarnContext(r.Context(), "API call refused", "path", r.URL.Path, "error", err)
			refuse(w, "that token was not accepted")
			return
		}
		if !slices.Contains(c.Allowed, subject) {
			log.WarnContext(r.Context(), "API call refused: not a consumer",
				"path", r.URL.Path, "subject", subject)
			refuse(w, subject+" is not a consumer of this hub")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearer reads the token from the Authorization header.
func bearer(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < 7 || !strings.EqualFold(value[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[7:])
}

func refuse(w http.ResponseWriter, reason string) {
	// WWW-Authenticate so that a client library reports "unauthenticated"
	// rather than a bare transport failure.
	w.Header().Set("WWW-Authenticate", `Bearer realm="directory-roster"`)
	http.Error(w, reason, http.StatusUnauthorized)
}
